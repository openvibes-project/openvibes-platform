//! Drives the real binary against a fresh database.
// The test starts the CLI binary it verifies; this is not shipped code.
#![allow(clippy::disallowed_types)]

use std::{
    hash::{BuildHasher, Hasher},
    path::PathBuf,
    process::{Command, Output},
};

struct Fixture {
    admin_url: String,
    name: String,
    url: String,
    config: PathBuf,
}

fn with_database(url: &str, name: &str) -> String {
    let (head, query) = url
        .split_once('?')
        .map_or((url, None), |(h, q)| (h, Some(q)));
    let head = &head[..head.rfind('/').unwrap()];
    query.map_or(format!("{head}/{name}"), |query| {
        format!("{head}/{name}?{query}")
    })
}

impl Fixture {
    async fn create() -> Self {
        let admin_url = std::env::var("OPENVIBES_TEST_DATABASE_URL")
            .expect("set OPENVIBES_TEST_DATABASE_URL, see scripts/test-db.sh");
        let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
        hasher.write_u64(std::process::id().into());
        let name = format!("ov_cli_{:016x}", hasher.finish());
        let pool = platform_store::connect(&admin_url).await.unwrap();
        let client = pool.get().await.unwrap();
        client
            .batch_execute(&format!("CREATE DATABASE {name}"))
            .await
            .unwrap();
        let url = with_database(&admin_url, &name);
        let config = std::env::temp_dir().join(format!("{name}.toml"));
        std::fs::write(&config, format!("database_url = {url:?}\n")).unwrap();
        Self {
            admin_url,
            name,
            url,
            config,
        }
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_openvibes-admin"))
            .arg("--config")
            .arg(&self.config)
            .args(args)
            .env("USER", "ov-test")
            .output()
            .unwrap()
    }

    async fn audit(&self) -> Vec<(String, String, String)> {
        let pool = platform_store::connect(&self.url).await.unwrap();
        let client = pool.get().await.unwrap();
        client
            .query(
                "SELECT actor, action, result FROM audit_log ORDER BY id",
                &[],
            )
            .await
            .unwrap()
            .iter()
            .map(|row| (row.get(0), row.get(1), row.get(2)))
            .collect()
    }

    async fn drop(self) {
        let pool = platform_store::connect(&self.admin_url).await.unwrap();
        let client = pool.get().await.unwrap();
        client
            .batch_execute(&format!("DROP DATABASE {} WITH (FORCE)", self.name))
            .await
            .unwrap();
        let _ = std::fs::remove_file(&self.config);
    }
}

fn stdout(output: &Output) -> String {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout.clone()).unwrap()
}

fn row(action: &str, result: &str) -> (String, String, String) {
    ("ov-test".into(), action.into(), result.into())
}

#[tokio::test]
async fn migrate_status_and_maintenance_are_audited() {
    let fixture = Fixture::create().await;
    assert!(stdout(&fixture.run(&["migrate"])).contains("schema version 1"));
    let status = stdout(&fixture.run(&["status"]));
    for line in [
        "agents active 0",
        "agents offline 0",
        "agents revoked 0",
        "tokens usable 0",
        "partitions none",
    ] {
        assert!(
            status.lines().any(|l| l == line),
            "missing {line:?} in {status}"
        );
    }
    assert!(stdout(&fixture.run(&["maintenance"])).contains("created 8 partitions, dropped 0"));
    assert_eq!(
        fixture.audit().await,
        [
            row("migrate", "ok"),
            row("status", "ok"),
            row("maintenance", "ok")
        ]
    );
    fixture.drop().await;
}

#[tokio::test]
async fn a_failing_command_is_still_audited() {
    let fixture = Fixture::create().await;
    stdout(&fixture.run(&["migrate"]));
    let pool = platform_store::connect(&fixture.url).await.unwrap();
    pool.get()
        .await
        .unwrap()
        .batch_execute("UPDATE schema_version SET version = 99")
        .await
        .unwrap();
    let output = fixture.run(&["status"]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("newer"));
    assert_eq!(
        fixture.audit().await,
        [row("migrate", "ok"), row("status", "error")]
    );
    fixture.drop().await;
}
