//! Shared fixture: a fresh database, a config file, and the built binary.
// The tests start the CLI binary they verify; this is not shipped code.
#![allow(clippy::disallowed_types, dead_code)]

use std::{
    hash::{BuildHasher, Hasher},
    path::PathBuf,
    process::{Command, Output},
};

pub struct Fixture {
    admin_url: String,
    name: String,
    pub url: String,
    pub config: PathBuf,
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
    pub async fn create() -> Self {
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

    pub fn run(&self, args: &[&str]) -> Output {
        self.run_with(args, &[])
    }

    /// Runs the CLI with extra environment variables (for example
    /// `SUDO_USER`); `USER` is always `ov-test` and `SUDO_USER` unset unless
    /// given.
    pub fn run_with(&self, args: &[&str], env: &[(&str, &str)]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_openvibes-admin"))
            .arg("--config")
            .arg(&self.config)
            .args(args)
            .env("USER", "ov-test")
            .env_remove("SUDO_USER")
            .envs(env.iter().copied())
            .output()
            .unwrap()
    }

    pub async fn audit(&self) -> Vec<(String, String, String)> {
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

    pub async fn drop(self) {
        let pool = platform_store::connect(&self.admin_url).await.unwrap();
        let client = pool.get().await.unwrap();
        client
            .batch_execute(&format!("DROP DATABASE {} WITH (FORCE)", self.name))
            .await
            .unwrap();
        let _ = std::fs::remove_file(&self.config);
    }
}

pub fn stdout(output: &Output) -> String {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout.clone()).unwrap()
}

/// The invoking OS user as the audit log records it: the real uid, with
/// `$USER` only as a hint, since the caller can set that variable.
pub fn actor() -> String {
    use std::os::unix::fs::MetadataExt;
    format!(
        "ov-test (uid {})",
        std::fs::metadata("/proc/self").unwrap().uid()
    )
}

pub fn row(action: &str, result: &str) -> (String, String, String) {
    (actor(), action.into(), result.into())
}

impl Fixture {
    /// `(action, target, result)` of every audit row, oldest first.
    pub async fn audit_targets(&self) -> Vec<(String, Option<String>, String)> {
        let pool = platform_store::connect(&self.url).await.unwrap();
        let client = pool.get().await.unwrap();
        client
            .query(
                "SELECT action, target, result FROM audit_log ORDER BY id",
                &[],
            )
            .await
            .unwrap()
            .iter()
            .map(|row| (row.get(0), row.get(1), row.get(2)))
            .collect()
    }

    /// Runs a query on the fixture database and returns the first column of
    /// the first row as `i64`.
    pub async fn count(&self, sql: &str) -> i64 {
        let pool = platform_store::connect(&self.url).await.unwrap();
        let client = pool.get().await.unwrap();
        client.query_one(sql, &[]).await.unwrap().get(0)
    }
}

/// A fresh empty directory for one test.
pub fn scratch_dir(test: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ov-admin-{}-{test}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Runs the binary without any config file (offline commands).
pub fn offline(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_openvibes-admin"))
        .arg("--config")
        .arg("/nonexistent/openvibes-admin.toml")
        .args(args)
        .output()
        .unwrap()
}
