//! The rule signer against a real database, connected as its own role so
//! migration 32's grants are what's tested (board #107).

mod common;

use std::{os::unix::fs::PermissionsExt, path::PathBuf, sync::Arc};

use chrono::Utc;
use common::TestDb;
use openvibes_signer::{
    Signer, SignerConfig,
    request::{Refusal, SignResponse},
    state::{Seeded, State},
};
use platform_store::console_auth::{NewLocalUser, create_local_user};

const PASSWORD: &str = "a long enough test password";
const SNAPSHOT: &str = r#"{"schema_version":1,"rules":[{"id":"site.ssh-root","version":1,"title":"Root login over SSH","severity":"medium","confidence":80,"expression":"'openssh-server' in facts['package.names']","finding_message":"Check PermitRootLogin"}]}"#;

fn alarm_rules(programs: &[&str]) -> String {
    serde_json::json!({"schema_version": 1, "rules": [{
        "id": "site.shell", "version": 1, "title": "Shell", "severity": "high",
        "confidence": 80, "kind": "process_event", "programs": programs,
        "expression": "event['process.name'] == 'sh'", "finding_message": "A shell"}]})
    .to_string()
}

struct Fixture {
    db: TestDb,
    dir: PathBuf,
    config: SignerConfig,
    signer: Arc<Signer>,
}

impl Fixture {
    async fn new(seed: Option<u64>, publishes_per_hour: u32) -> Self {
        let db = TestDb::create().await;
        let mut client = db.pool.get().await.unwrap();
        platform_store::migrate(&mut client).await.unwrap();
        let phc = platform_password::hash_password(
            &platform_password::NormalizedPassword::new(PASSWORD).unwrap(),
        )
        .unwrap();
        for (n, (name, role, must_change)) in [
            ("publisher", "operator", false),
            ("watcher", "viewer", false),
            ("fresh", "admin", true),
        ]
        .into_iter()
        .enumerate()
        {
            create_local_user(
                &mut client,
                &NewLocalUser {
                    user_id: &format!("11111111-1111-4111-8111-11111111111{n}"),
                    binding_id: &format!("22222222-2222-4222-8222-22222222222{n}"),
                    username: name,
                    display_name: name,
                    password_phc: phc.as_str(),
                    role_id: role,
                    actor_id: "test",
                    actor_kind: "local_admin",
                    password_must_change: must_change,
                    now: Utc::now(),
                },
            )
            .await
            .unwrap();
        }
        let dir = std::env::temp_dir().join(format!(
            "ov-signer-{}",
            db.url().len() ^ std::process::id() as usize ^ rand_suffix()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let key = dir.join("site.key");
        std::fs::write(&key, [7u8; 32]).unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        if let Some(min) = seed {
            State::seed(&dir, min).unwrap();
        }
        let config = SignerConfig {
            socket: dir.join("sign.sock"),
            database_url: db
                .url()
                .replace("user=openvibes_test", "user=openvibes-signer"),
            key_file: key,
            issuer_key_id: "site.key".into(),
            state_dir: dir.clone(),
            publishes_per_hour,
            rules_per_publish: 2,
            validity_days: 365,
        };
        let pool = platform_store::connect(&config.database_url).await.unwrap();
        let signer = Arc::new(Signer::new(config.clone(), pool).unwrap());
        Self {
            db,
            dir,
            config,
            signer,
        }
    }

    /// A new signer over the same database and state directory, as after
    /// a restart.
    async fn reopened(self) -> Self {
        let config = self.config.clone();
        let pool = platform_store::connect(&config.database_url).await.unwrap();
        Self {
            signer: Arc::new(Signer::new(config, pool).unwrap()),
            ..self
        }
    }

    async fn sign(&self, user: &str, password: &str, set: &str, rules: &str) -> SignResponse {
        let body = serde_json::json!({
            "username": user, "password": password, "rule_set": set, "rules": rules,
        });
        self.signer.handle(body.to_string().as_bytes()).await
    }

    async fn done(self) {
        let _ = std::fs::remove_dir_all(&self.dir);
        self.db.drop().await;
    }
}

fn rand_suffix() -> usize {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .subsec_nanos() as usize
}

fn refused(response: &SignResponse) -> Option<Refusal> {
    match response {
        SignResponse::Refused { code } => Some(*code),
        SignResponse::Signed { .. } => None,
    }
}

#[tokio::test]
async fn signs_each_set_at_the_next_version() {
    let fixture = Fixture::new(Some(5), 12).await;
    let first = fixture.sign("Publisher", PASSWORD, "site", SNAPSHOT).await;
    let SignResponse::Signed {
        envelope, version, ..
    } = first
    else {
        panic!("refused: {first:?}");
    };
    assert_eq!(version, 5, "the seeded minimum");
    let envelope: serde_json::Value = serde_json::from_str(&envelope).unwrap();
    assert_eq!(envelope["rule_set_id"], "site");
    assert_eq!(envelope["payload"], SNAPSHOT, "signed byte for byte");
    let second = fixture.sign("publisher", PASSWORD, "site", SNAPSHOT).await;
    assert!(matches!(second, SignResponse::Signed { version: 6, .. }));
    let alarms = fixture
        .sign(
            "publisher",
            PASSWORD,
            "site-alarms",
            &alarm_rules(&["sh", "sh"]),
        )
        .await;
    assert!(
        matches!(alarms, SignResponse::Signed { version: 5, .. }),
        "{alarms:?}"
    );

    // The state survives a restart: the next is 7, never 5 again.
    let state = State::open(&fixture.dir);
    assert_eq!(state.next_version("site"), Some(7));
    fixture.done().await;
}

#[tokio::test]
async fn refuses_with_fixed_codes() {
    let fixture = Fixture::new(Some(1), 12).await;
    let cases = [
        (
            "publisher",
            "a wrong password, long enough",
            "site",
            SNAPSHOT.to_owned(),
            Refusal::Credentials,
        ),
        (
            "nobody-here",
            PASSWORD,
            "site",
            SNAPSHOT.to_owned(),
            Refusal::Credentials,
        ),
        (
            "bad name!",
            PASSWORD,
            "site",
            SNAPSHOT.to_owned(),
            Refusal::Credentials,
        ),
        (
            "watcher",
            PASSWORD,
            "site",
            SNAPSHOT.to_owned(),
            Refusal::Forbidden,
        ),
        (
            "fresh",
            PASSWORD,
            "site",
            SNAPSHOT.to_owned(),
            Refusal::Forbidden,
        ),
        (
            "publisher",
            PASSWORD,
            "baseline",
            SNAPSHOT.to_owned(),
            Refusal::Invalid,
        ),
        (
            "publisher",
            PASSWORD,
            "site",
            alarm_rules(&["sh"]),
            Refusal::Invalid,
        ),
        (
            "publisher",
            PASSWORD,
            "site-alarms",
            SNAPSHOT.to_owned(),
            Refusal::Invalid,
        ),
        (
            "publisher",
            PASSWORD,
            "site-alarms",
            alarm_rules(&[]),
            Refusal::Invalid,
        ),
        (
            "publisher",
            PASSWORD,
            "site-alarms",
            alarm_rules(&["a", "b", "c", "d", "e", "f", "g", "h", "i"]),
            Refusal::Limits,
        ),
        (
            "publisher",
            PASSWORD,
            "site",
            "not json".to_owned(),
            Refusal::Invalid,
        ),
    ];
    for (user, password, set, rules, expected) in cases {
        let response = fixture.sign(user, password, set, &rules).await;
        assert_eq!(refused(&response), Some(expected), "{user} {set}");
    }
    let three = serde_json::json!({"schema_version": 1, "rules": (0..3).map(|n| serde_json::json!({
        "id": format!("site.r{n}"), "version": 1, "title": "t", "severity": "low", "confidence": 50,
        "expression": "true", "finding_message": "m"})).collect::<Vec<_>>()})
    .to_string();
    assert_eq!(
        refused(&fixture.sign("publisher", PASSWORD, "site", &three).await),
        Some(Refusal::Limits),
        "over rules_per_publish"
    );
    assert_eq!(
        refused(&fixture.signer.handle(b"{\"username\":1}").await),
        Some(Refusal::Invalid)
    );

    // Refusals are counted for Health, in a file only the operators read.
    fixture.signer.flush_status().await;
    let status_path = fixture.dir.join("status.json");
    let status: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&status_path).unwrap()).unwrap();
    assert_eq!(status["refusals_last_day"]["credentials"], 3);
    assert_eq!(status["refusals_last_day"]["limits"], 2);
    assert_eq!(
        std::fs::metadata(&status_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o640
    );
    fixture.done().await;
}

#[tokio::test]
async fn wrong_passwords_lock_the_account_like_sign_in() {
    let fixture = Fixture::new(Some(1), 12).await;
    for _ in 0..5 {
        let response = fixture
            .sign(
                "publisher",
                "a wrong password, long enough",
                "site",
                SNAPSHOT,
            )
            .await;
        assert_eq!(refused(&response), Some(Refusal::Credentials));
    }
    let response = fixture.sign("publisher", PASSWORD, "site", SNAPSHOT).await;
    assert_eq!(
        refused(&response),
        Some(Refusal::Throttled),
        "locked even with the right password"
    );
    fixture.done().await;
}

#[tokio::test]
async fn no_version_state_means_no_signature() {
    let fixture = Fixture::new(None, 12).await;
    let response = fixture.sign("publisher", PASSWORD, "site", SNAPSHOT).await;
    assert_eq!(refused(&response), Some(Refusal::VersionState));
    assert!(State::seed(&fixture.dir, 0).is_err());
    assert_eq!(State::seed(&fixture.dir, 3).unwrap(), Seeded::Created);
    assert_eq!(
        State::seed(&fixture.dir, 1).unwrap(),
        Seeded::Kept,
        "a readable state is kept: seeding never lowers a version"
    );
    // A corrupt file is no state (refused), and seeding replaces it.
    std::fs::write(fixture.dir.join("versions.json"), "{not json").unwrap();
    let fixture = fixture.reopened().await;
    let response = fixture.sign("publisher", PASSWORD, "site", SNAPSHOT).await;
    assert_eq!(refused(&response), Some(Refusal::VersionState));
    assert_eq!(State::seed(&fixture.dir, 9).unwrap(), Seeded::Replaced);
    assert_eq!(State::open(&fixture.dir).next_version("site"), Some(9));
    fixture.done().await;
}

#[tokio::test]
async fn publishes_are_limited_per_hour() {
    let fixture = Fixture::new(Some(1), 2).await;
    for _ in 0..2 {
        assert!(refused(&fixture.sign("publisher", PASSWORD, "site", SNAPSHOT).await).is_none());
    }
    let response = fixture.sign("publisher", PASSWORD, "site", SNAPSHOT).await;
    assert_eq!(refused(&response), Some(Refusal::Rate));
    fixture.done().await;
}

#[tokio::test]
async fn the_socket_answers_one_request_and_drops_a_slow_one() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let fixture = Fixture::new(Some(1), 12).await;
    let path = fixture.dir.join("sign.sock");
    let listener = openvibes_signer::bind(&path).unwrap();
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o660
    );
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(Arc::clone(&fixture.signer).serve(listener, async {
        let _ = stopped.await;
    }));

    let mut stream = tokio::net::UnixStream::connect(&path).await.unwrap();
    let body = serde_json::json!({"username": "publisher", "password": PASSWORD, "rule_set": "site", "rules": SNAPSHOT});
    stream.write_all(body.to_string().as_bytes()).await.unwrap();
    stream.shutdown().await.unwrap();
    let mut answer = String::new();
    stream.read_to_string(&mut answer).await.unwrap();
    assert!(answer.contains("\"result\":\"signed\""), "{answer}");

    // A body that never ends is cut at the read timeout.
    let mut slow = tokio::net::UnixStream::connect(&path).await.unwrap();
    slow.write_all(b"{\"username\":").await.unwrap();
    let mut answer = String::new();
    slow.read_to_string(&mut answer).await.unwrap();
    assert_eq!(answer, "{\"result\":\"refused\",\"code\":\"invalid\"}");

    let _ = stop.send(());
    server.await.unwrap();
    fixture.done().await;
}

/// Two valid publishes at once get consecutive versions, never the same
/// one: one lock covers the rate check, the version and its record.
#[tokio::test]
async fn concurrent_publishes_sign_consecutive_versions() {
    let fixture = Fixture::new(Some(4), 12).await;
    let (a, b) = tokio::join!(
        fixture.sign("publisher", PASSWORD, "site", SNAPSHOT),
        fixture.sign("publisher", PASSWORD, "site", SNAPSHOT),
    );
    let mut versions: Vec<u64> = [a, b]
        .iter()
        .map(|response| match response {
            SignResponse::Signed { version, .. } => *version,
            SignResponse::Refused { code } => panic!("refused: {code:?}"),
        })
        .collect();
    versions.sort_unstable();
    assert_eq!(versions, [4, 5]);
    assert_eq!(State::open(&fixture.dir).next_version("site"), Some(6));
    fixture.done().await;
}

/// Over the connection cap, a connection is closed unread: slow clients
/// can't make the signer hold more than CONNECTIONS request buffers.
#[tokio::test]
async fn connections_over_the_cap_are_closed_unread() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let fixture = Fixture::new(Some(1), 12).await;
    let path = fixture.dir.join("sign.sock");
    let listener = openvibes_signer::bind(&path).unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(Arc::clone(&fixture.signer).serve(listener, async {
        let _ = stopped.await;
    }));
    let mut held = Vec::new();
    for _ in 0..openvibes_signer::CONNECTIONS {
        let mut stream = tokio::net::UnixStream::connect(&path).await.unwrap();
        stream.write_all(b"{").await.unwrap();
        held.push(stream);
    }
    // Let the server take them all.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let mut extra = tokio::net::UnixStream::connect(&path).await.unwrap();
    let mut answer = String::new();
    let read = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        extra.read_to_string(&mut answer),
    )
    .await;
    assert!(read.is_ok(), "closed at once, not after the read timeout");
    assert_eq!(answer, "", "nothing read, nothing answered");
    drop(held);
    let _ = stop.send(());
    server.await.unwrap();
    fixture.done().await;
}
