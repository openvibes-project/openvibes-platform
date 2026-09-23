//! Enrollment tokens: only hashes are stored; revocation is final.

mod common;

use chrono::{Duration, Utc};
use common::TestDb;
use platform_store::tokens::{self, NewToken};

fn new_token(byte: u8, max_uses: i32) -> NewToken {
    NewToken {
        token_sha256: [byte; 32],
        label: Some(format!("lab {byte}")),
        created_by: "ov-test (uid 1000)".into(),
        expires_at: Utc::now() + Duration::days(7),
        max_uses,
    }
}

#[tokio::test]
async fn tokens_are_created_listed_and_revoked() {
    let db = TestDb::create().await;
    let mut client = db.pool.get().await.unwrap();
    platform_store::migrate(&mut client).await.unwrap();
    let first = tokens::create(&client, &new_token(1, 1)).await.unwrap();
    let second = tokens::create(&client, &new_token(2, 2)).await.unwrap();
    let listed = tokens::list(&client).await.unwrap();
    assert_eq!(listed.len(), 2);
    assert!(listed.iter().all(|token| token.uses == 0 && !token.revoked));
    assert_eq!(
        listed
            .iter()
            .find(|t| t.token_id == second)
            .unwrap()
            .max_uses,
        2
    );
    let stored: Vec<u8> = client
        .query_one(
            "SELECT token_sha256 FROM enrollment_tokens WHERE token_id = $1::text::uuid",
            &[&first],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(stored, [1u8; 32]);

    let before = platform_store::status(&client, Utc::now()).await.unwrap();
    assert_eq!(before.tokens_usable, 2);
    assert!(tokens::revoke(&client, &first, Utc::now()).await.unwrap());
    assert!(!tokens::revoke(&client, &first, Utc::now()).await.unwrap());
    let unknown = "00000000-0000-4000-8000-000000000000";
    assert!(!tokens::revoke(&client, unknown, Utc::now()).await.unwrap());
    assert_eq!(
        tokens::revoke(&client, "not-a-uuid", Utc::now())
            .await
            .err(),
        Some(platform_store::StoreError::Query)
    );
    let after = platform_store::status(&client, Utc::now()).await.unwrap();
    assert_eq!(after.tokens_usable, 1);
    assert!(
        tokens::list(&client)
            .await
            .unwrap()
            .iter()
            .any(|t| t.token_id == first && t.revoked)
    );
    drop(client);
    db.drop().await;
}
