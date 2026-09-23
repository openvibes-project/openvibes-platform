//! `openvibes-admin token`: printed once, stored only as a hash.
// The test starts the CLI binary it verifies; this is not shipped code.
#![allow(clippy::disallowed_types)]

mod common;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use common::{Fixture, stdout};

#[tokio::test]
async fn a_token_is_shown_once_and_stored_only_as_its_hash() {
    let fixture = Fixture::create().await;
    stdout(&fixture.run(&["migrate"]));
    let created = stdout(&fixture.run(&[
        "token",
        "create",
        "--expires",
        "7d",
        "--uses",
        "3",
        "--label",
        "lab",
    ]));
    let token = created
        .lines()
        .filter(|line| !line.starts_with("token id "))
        .find_map(|line| line.strip_prefix("token "))
        .expect("a `token <value>` line")
        .to_owned();
    assert_eq!(token.len(), 43, "32 bytes, base64url without padding");
    let id = created
        .lines()
        .find_map(|line| line.strip_prefix("token id "))
        .unwrap()
        .to_owned();

    let expected: Vec<u8> = ring::digest::digest(
        &ring::digest::SHA256,
        &URL_SAFE_NO_PAD.decode(&token).unwrap(),
    )
    .as_ref()
    .to_vec();
    let pool = platform_store::connect(&fixture.url).await.unwrap();
    let client = pool.get().await.unwrap();
    let row = client
        .query_one(
            "SELECT token_sha256, max_uses, row_to_json(t)::text FROM enrollment_tokens t",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, Vec<u8>>(0), expected);
    assert_eq!(row.get::<_, i32>(1), 3);
    assert!(
        !row.get::<_, String>(2).contains(&token),
        "no column holds the token"
    );

    let list = stdout(&fixture.run(&["token", "list"]));
    assert!(list.contains(&id) && list.contains("lab") && !list.contains(&token));
    for (action, target, _) in fixture.audit_targets().await {
        assert!(!action.contains(&token) && !target.unwrap_or_default().contains(&token));
    }

    for bad in [
        &["token", "create", "--expires", "0d"][..],
        &["token", "create", "--expires", "366d"],
        &["token", "create", "--expires", "7x"],
        &["token", "create", "--expires", "7d", "--uses", "0"],
    ] {
        assert_eq!(fixture.run(bad).status.code(), Some(2), "{bad:?}");
    }
    assert_eq!(
        fixture
            .count("SELECT count(*) FROM enrollment_tokens")
            .await,
        1
    );

    stdout(&fixture.run(&["token", "revoke", &id]));
    assert!(
        stdout(&fixture.run(&["status"]))
            .lines()
            .any(|l| l == "tokens usable 0")
    );
    let again = fixture.run(&["token", "revoke", &id]);
    assert!(!again.status.success());
    assert!(String::from_utf8_lossy(&again.stderr).contains("already revoked"));
    let audit = fixture.audit_targets().await;
    let last = audit.last().unwrap();
    assert_eq!(
        (last.0.as_str(), last.1.as_deref(), last.2.as_str()),
        ("token revoke", Some(id.as_str()), "error")
    );
    fixture.drop().await;
}
