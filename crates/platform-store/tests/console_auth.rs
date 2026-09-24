//! Console authentication state is hash-only and transactional.

mod common;

use chrono::{Duration, Utc};
use common::TestDb;
use platform_store::console_auth::{
    NewLocalUser, NewPreauth, NewSession, clear_login_throttle, consume_preauth, create_local_user,
    create_preauth, create_session, credential_by_username, disable_local_user, list_local_users,
    login_is_throttled, record_login_failure, rehash_password, replace_password,
    revoke_user_sessions, session, touch_session, unlock_local_user, user_role_bindings,
};
use sha2::{Digest, Sha256};

const USER_ID: &str = "11111111-1111-4111-8111-111111111111";
const BINDING_ID: &str = "22222222-2222-4222-8222-222222222222";

async fn new_user(client: &mut platform_store::Client, now: chrono::DateTime<Utc>) {
    create_local_user(
        client,
        &NewLocalUser {
            user_id: USER_ID,
            binding_id: BINDING_ID,
            username: "alice",
            display_name: "Alice Example",
            password_phc: "$argon2id$v=19$m=19456,t=2,p=1$opaque-salt$opaque-hash",
            role_id: "admin",
            actor_id: "bootstrap-cli",
            now,
        },
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn administrative_user_listing_and_unlock_are_non_secret_and_audited() {
    let db = TestDb::create().await;
    let mut client = db.pool.get().await.unwrap();
    platform_store::migrate(&mut client).await.unwrap();
    let now = Utc::now();
    new_user(&mut client, now).await;
    let mut digest = Sha256::new();
    digest.update(b"openvibes-console-login-throttle-v1\0account\0alice");
    let bucket: [u8; 32] = digest.finalize().into();
    let buckets: [&[u8]; 1] = [&bucket];
    record_login_failure(
        &mut client,
        &buckets,
        now,
        Duration::minutes(15),
        1,
        Duration::minutes(15),
        &platform_store::console_auth::AuditContext::default(),
    )
    .await
    .unwrap();
    assert!(login_is_throttled(&client, &buckets, now).await.unwrap());
    let users = list_local_users(&client).await.unwrap();
    assert_eq!(users.len(), 1);
    assert_eq!(users[0].username, "alice");
    assert_eq!(users[0].role_ids, ["admin"]);
    assert!(!format!("{users:?}").contains("opaque-hash"));

    assert!(
        unlock_local_user(
            &mut client,
            "alice",
            now,
            "operator uid 1000",
            "local_admin"
        )
        .await
        .unwrap()
    );
    assert!(!login_is_throttled(&client, &buckets, now).await.unwrap());
    let audit = client
        .query_one(
            "SELECT action, target_kind, target_id FROM audit_log
             WHERE action = 'user.unlocked'",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(audit.get::<_, &str>(0), "user.unlocked");
    assert_eq!(audit.get::<_, &str>(1), "user");
    assert_eq!(audit.get::<_, &str>(2), USER_ID);
    assert!(
        !unlock_local_user(
            &mut client,
            "alice",
            now,
            "operator uid 1000",
            "local_admin"
        )
        .await
        .unwrap()
    );
    drop(client);
    db.drop().await;
}

#[tokio::test]
async fn credentials_sessions_and_password_reset_revocation_round_trip() {
    let db = TestDb::create().await;
    let mut client = db.pool.get().await.unwrap();
    platform_store::migrate(&mut client).await.unwrap();
    let now = Utc::now();
    new_user(&mut client, now).await;
    assert_eq!(
        user_role_bindings(&client, USER_ID).await.unwrap(),
        vec![platform_store::console_auth::UserRoleBinding {
            role_id: "admin".into(),
            asset_group_id: None,
        }]
    );

    let credential = credential_by_username(&client, "alice")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(credential.user_id, USER_ID);
    assert!(credential.enabled);
    assert_eq!(credential.auth_generation, 0);
    assert_eq!(
        credential.password_phc,
        "$argon2id$v=19$m=19456,t=2,p=1$opaque-salt$opaque-hash"
    );
    assert!(
        credential_by_username(&client, "missing")
            .await
            .unwrap()
            .is_none()
    );
    let invalid_user = NewLocalUser {
        user_id: "44444444-4444-4444-8444-444444444444",
        binding_id: "55555555-5555-4555-8555-555555555555",
        username: "bob",
        display_name: "Bob Example",
        password_phc: "$argon2id$test-only-invalid-role",
        role_id: "missing_role",
        actor_id: "bootstrap-cli",
        now,
    };
    assert!(matches!(
        create_local_user(&mut client, &invalid_user).await,
        Err(platform_store::StoreError::Query)
    ));
    assert!(
        credential_by_username(&client, "bob")
            .await
            .unwrap()
            .is_none()
    );

    let session_hash = [3_u8; 32];
    let csrf_hash = [5_u8; 32];
    assert!(
        create_session(
            &mut client,
            &NewSession {
                session_sha256: &session_hash,
                previous_session_sha256: None,
                csrf_sha256: &csrf_hash,
                user_id: USER_ID,
                auth_generation: 0,
                now,
                idle_expires_at: now + Duration::minutes(30),
                absolute_expires_at: now + Duration::hours(8),
                audit: platform_store::console_auth::AuditContext {
                    request_id: Some("req-login-1"),
                    source_address: Some("127.0.0.1"),
                    user_agent: Some("integration-test"),
                },
            },
        )
        .await
        .unwrap()
    );
    let live = session(&client, &session_hash, now + Duration::seconds(1))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(live.user_id, USER_ID);
    assert_eq!(live.csrf_sha256, csrf_hash);
    let login_audit = client
        .query_one(
            "SELECT request_id, actor_kind, authentication_method, source_address::text,
                    user_agent, detail::text
             FROM audit_log WHERE action = 'auth.login.succeeded'",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(
        login_audit.get::<_, Option<String>>(0).as_deref(),
        Some("req-login-1")
    );
    assert_eq!(
        login_audit.get::<_, Option<String>>(1).as_deref(),
        Some("user")
    );
    assert_eq!(
        login_audit.get::<_, Option<String>>(2).as_deref(),
        Some("local_password")
    );
    assert_eq!(
        login_audit.get::<_, Option<String>>(3).as_deref(),
        Some("127.0.0.1/32")
    );
    assert_eq!(
        login_audit.get::<_, Option<String>>(4).as_deref(),
        Some("integration-test")
    );
    assert_eq!(login_audit.get::<_, String>(5), "{}");
    assert!(
        rehash_password(
            &mut client,
            USER_ID,
            0,
            "$argon2id$v=19$m=19456,t=2,p=1$upgraded-salt$upgraded-hash",
            now + Duration::seconds(1),
            &platform_store::console_auth::AuditContext::default(),
        )
        .await
        .unwrap()
    );
    assert!(
        session(&client, &session_hash, now + Duration::seconds(2))
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        touch_session(
            &client,
            &session_hash,
            now + Duration::minutes(2),
            Duration::minutes(30)
        )
        .await
        .unwrap()
    );
    let idle_expires_at = session(&client, &session_hash, now + Duration::minutes(2))
        .await
        .unwrap()
        .unwrap()
        .idle_expires_at;
    assert_eq!(
        idle_expires_at.timestamp_micros(),
        (now + Duration::minutes(32)).timestamp_micros()
    );
    let rotated_session_hash = [6_u8; 32];
    assert!(
        create_session(
            &mut client,
            &NewSession {
                session_sha256: &rotated_session_hash,
                previous_session_sha256: Some(&session_hash),
                csrf_sha256: &csrf_hash,
                user_id: USER_ID,
                auth_generation: 0,
                now: now + Duration::minutes(2) + Duration::seconds(1),
                idle_expires_at: now + Duration::minutes(32),
                absolute_expires_at: now + Duration::hours(8),
                audit: platform_store::console_auth::AuditContext::default(),
            },
        )
        .await
        .unwrap()
    );
    assert!(
        session(&client, &session_hash, now + Duration::minutes(3))
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        session(&client, &rotated_session_hash, now + Duration::minutes(3))
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        replace_password(
            &mut client,
            USER_ID,
            "$argon2id$v=19$m=19456,t=2,p=1$new-salt$new-hash",
            now + Duration::minutes(3),
            &platform_store::console_auth::AuditContext::default(),
            USER_ID,
            "user",
        )
        .await
        .unwrap()
    );
    assert!(
        session(&client, &session_hash, now + Duration::minutes(3))
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        credential_by_username(&client, "alice")
            .await
            .unwrap()
            .unwrap()
            .auth_generation,
        1
    );
    assert_eq!(
        credential_by_username(&client, "alice")
            .await
            .unwrap()
            .unwrap()
            .password_phc,
        "$argon2id$v=19$m=19456,t=2,p=1$new-salt$new-hash"
    );
    let next_session_hash = [8_u8; 32];
    assert!(
        create_session(
            &mut client,
            &NewSession {
                session_sha256: &next_session_hash,
                previous_session_sha256: None,
                csrf_sha256: &csrf_hash,
                user_id: USER_ID,
                auth_generation: 1,
                now: now + Duration::minutes(3),
                idle_expires_at: now + Duration::minutes(33),
                absolute_expires_at: now + Duration::hours(8),
                audit: platform_store::console_auth::AuditContext::default(),
            },
        )
        .await
        .unwrap()
    );
    assert!(
        revoke_user_sessions(
            &mut client,
            USER_ID,
            now + Duration::minutes(4),
            &platform_store::console_auth::AuditContext::default(),
            USER_ID,
            "user",
            "password_reset",
        )
        .await
        .unwrap()
    );
    assert!(
        session(&client, &next_session_hash, now + Duration::minutes(4))
            .await
            .unwrap()
            .is_none()
    );
    let revocation_events: i64 = client
        .query_one(
            "SELECT count(*) FROM audit_log WHERE action = 'auth.sessions.revoked'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(revocation_events, 1);
    assert!(
        disable_local_user(
            &mut client,
            USER_ID,
            now + Duration::minutes(5),
            &platform_store::console_auth::AuditContext::default(),
            USER_ID,
            "user",
        )
        .await
        .unwrap()
    );
    let disabled = credential_by_username(&client, "alice")
        .await
        .unwrap()
        .unwrap();
    assert!(!disabled.enabled);
    assert_eq!(disabled.auth_generation, 3);
    assert!(
        !revoke_user_sessions(
            &mut client,
            "33333333-3333-4333-8333-333333333333",
            now,
            &platform_store::console_auth::AuditContext::default(),
            USER_ID,
            "user",
            "password_reset",
        )
        .await
        .unwrap()
    );
    drop(client);
    db.drop().await;
}

#[tokio::test]
async fn preauth_is_one_use_and_bound_to_browser_and_csrf() {
    let db = TestDb::create().await;
    let mut client = db.pool.get().await.unwrap();
    platform_store::migrate(&mut client).await.unwrap();
    let now = Utc::now();
    let (token, csrf, browser) = ([1_u8; 32], [2_u8; 32], [3_u8; 32]);
    create_preauth(
        &client,
        &NewPreauth {
            token_sha256: &token,
            csrf_sha256: &csrf,
            browser_sha256: &browser,
            created_at: now,
            expires_at: now + Duration::minutes(5),
        },
    )
    .await
    .unwrap();
    assert!(
        !consume_preauth(&client, &token, &csrf, &[4_u8; 32], now)
            .await
            .unwrap()
    );
    assert!(
        consume_preauth(&client, &token, &csrf, &browser, now)
            .await
            .unwrap()
    );
    assert!(
        !consume_preauth(&client, &token, &csrf, &browser, now)
            .await
            .unwrap()
    );
    drop(client);
    db.drop().await;
}

#[tokio::test]
async fn account_and_source_login_buckets_lock_and_clear_together() {
    let db = TestDb::create().await;
    let mut client = db.pool.get().await.unwrap();
    platform_store::migrate(&mut client).await.unwrap();
    let now = Utc::now();
    let (account_bucket, source_bucket) = ([6_u8; 32], [7_u8; 32]);
    let buckets: [&[u8]; 2] = [&account_bucket, &source_bucket];
    assert!(!login_is_throttled(&client, &buckets, now).await.unwrap());
    for _ in 0..3 {
        record_login_failure(
            &mut client,
            &buckets,
            now,
            Duration::minutes(10),
            3,
            Duration::minutes(5),
            &platform_store::console_auth::AuditContext {
                request_id: Some("req-login-fail"),
                source_address: Some("127.0.0.1"),
                user_agent: Some("integration-test"),
            },
        )
        .await
        .unwrap();
    }
    assert!(login_is_throttled(&client, &buckets, now).await.unwrap());
    let failures: i64 = client
        .query_one(
            "SELECT count(*) FROM audit_log
             WHERE action = 'auth.login.failed' AND reason_code = 'invalid_credentials'
               AND actor_id IS NULL AND source_address = '127.0.0.1'::inet",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(failures, 3);
    clear_login_throttle(&client, &buckets, now + Duration::minutes(1))
        .await
        .unwrap();
    assert!(
        !login_is_throttled(&client, &buckets, now + Duration::minutes(1))
            .await
            .unwrap()
    );
    drop(client);
    db.drop().await;
}
