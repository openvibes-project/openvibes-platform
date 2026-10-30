//! Single sign-on storage, run as the real console role.

mod common;

use chrono::{Duration, Utc};
use platform_store::console_sso::{
    NewRequest, Person, SignIn, sign_in, start_request, take_request,
};

fn person<'a>(subject: &'a str, groups: &'a [String], assertion: &'a str) -> Person<'a> {
    let now = Utc::now();
    Person {
        issuer: "https://idp.example/",
        subject,
        display_name: "Pat",
        email: Some("pat@example.com"),
        assertion_id: assertion,
        assertion_expires_at: now + Duration::minutes(5),
        groups,
        now,
    }
}

#[tokio::test]
async fn a_request_is_used_once_and_only_by_its_browser() {
    let (db, client) = common::migrated().await;
    client
        .batch_execute("SET ROLE \"openvibes-console\"")
        .await
        .unwrap();
    let now = Utc::now();
    let new = NewRequest {
        relay_sha256: &[1; 32],
        request_id: "_abcdef0123456789",
        browser_sha256: &[2; 32],
        now,
        expires_at: now + Duration::minutes(5),
    };
    assert!(start_request(&client, &new).await.unwrap());
    assert_eq!(
        take_request(&client, &[1; 32], &[9; 32], now)
            .await
            .unwrap(),
        None
    );
    assert_eq!(
        take_request(&client, &[1; 32], &[2; 32], now)
            .await
            .unwrap()
            .as_deref(),
        Some("_abcdef0123456789")
    );
    assert_eq!(
        take_request(&client, &[1; 32], &[2; 32], now)
            .await
            .unwrap(),
        None
    );
    let late = now + Duration::minutes(6);
    let new = NewRequest {
        relay_sha256: &[3; 32],
        expires_at: now + Duration::minutes(5),
        ..new
    };
    start_request(&client, &new).await.unwrap();
    assert_eq!(
        take_request(&client, &[3; 32], &[2; 32], late)
            .await
            .unwrap(),
        None
    );
    drop(client);
    db.drop().await;
}

#[tokio::test]
async fn groups_become_roles_and_a_replay_is_refused() {
    let (db, mut client) = common::migrated().await;
    client
        .batch_execute("SET ROLE \"openvibes-console\"")
        .await
        .unwrap();
    let role = client
        .query_one(
            "SELECT role_id, lower(display_name) FROM console_roles ORDER BY role_id LIMIT 1",
            &[],
        )
        .await
        .unwrap();
    let name: String = role.get(1);
    let groups = vec![name.clone(), "unrelated".to_owned()];
    let first = sign_in(&mut client, &person("u-1", &groups, "a1"))
        .await
        .unwrap();
    let SignIn::Allowed {
        user_id, created, ..
    } = first
    else {
        panic!("{first:?}")
    };
    assert!(created);
    assert_eq!(
        sign_in(&mut client, &person("u-1", &groups, "a1"))
            .await
            .unwrap(),
        SignIn::Replay
    );
    // dropped from the group: no role, so no sign-in, bindings revoked
    let none = vec!["unrelated".to_owned()];
    assert_eq!(
        sign_in(&mut client, &person("u-1", &none, "a2"))
            .await
            .unwrap(),
        SignIn::NoRole
    );
    let active: i64 = client
        .query_one(
            "SELECT count(*) FROM console_role_bindings WHERE user_id = $1::text::uuid AND revoked_at IS NULL",
            &[&user_id],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(active, 0);
    // never created without a role
    assert_eq!(
        sign_in(&mut client, &person("u-2", &none, "a3"))
            .await
            .unwrap(),
        SignIn::NoRole
    );
    let users: i64 = client
        .query_one("SELECT count(*) FROM console_sso_users", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(users, 1);
    // back in the group, then disabled by an administrator
    assert!(matches!(
        sign_in(&mut client, &person("u-1", &groups, "a4"))
            .await
            .unwrap(),
        SignIn::Allowed { created: false, .. }
    ));
    client.batch_execute("RESET ROLE").await.unwrap();
    client
        .execute(
            "UPDATE console_users SET enabled = false, disabled_at = now()",
            &[],
        )
        .await
        .unwrap();
    client
        .batch_execute("SET ROLE \"openvibes-console\"")
        .await
        .unwrap();
    assert_eq!(
        sign_in(&mut client, &person("u-1", &groups, "a5"))
            .await
            .unwrap(),
        SignIn::Disabled
    );
    drop(client);
    db.drop().await;
}

#[tokio::test]
async fn the_cleanup_removes_the_inactive_and_spares_the_busy() {
    let (db, mut client) = common::migrated().await;
    let role = client
        .query_one(
            "SELECT lower(display_name) FROM console_roles ORDER BY role_id LIMIT 1",
            &[],
        )
        .await
        .unwrap()
        .get::<_, String>(0);
    let groups = vec![role];
    let mut ids = Vec::new();
    for (subject, assertion) in [("old", "a1"), ("busy", "a2"), ("recent", "a3")] {
        let SignIn::Allowed { user_id, .. } =
            sign_in(&mut client, &person(subject, &groups, assertion))
                .await
                .unwrap()
        else {
            panic!("signed in")
        };
        ids.push(user_id);
    }
    let long_ago = Utc::now() - Duration::days(200);
    for id in &ids[..2] {
        client
            .execute(
                "UPDATE console_users SET last_sign_in_at = $2 WHERE user_id = $1::text::uuid",
                &[id, &long_ago],
            )
            .await
            .unwrap();
    }
    // "busy" opened a case, so it cannot be deleted
    client
        .execute(
            "INSERT INTO cases (case_id, title, status, severity, opened_by_user_id, created_at, updated_at)
             VALUES (gen_random_uuid(), 't', 'open', 'low', $1::text::uuid, now(), now())",
            &[&ids[1]],
        )
        .await
        .unwrap();
    // and holds a role granted by hand, which must go too
    client
        .execute(
            "INSERT INTO console_role_bindings (binding_id, user_id, role_id, created_at, created_by)
             SELECT gen_random_uuid(), $1::text::uuid, role_id, now(), 'test' FROM console_roles
             WHERE role_id NOT IN (SELECT role_id FROM console_role_bindings WHERE user_id = $1::text::uuid)
             LIMIT 1",
            &[&ids[1]],
        )
        .await
        .unwrap();
    client
        .execute(
            "INSERT INTO console_saml_seen (assertion_sha256, expires_at) VALUES (sha256('x'::bytea), now() - interval '1 day')",
            &[],
        )
        .await
        .unwrap();
    client
        .batch_execute("SET ROLE \"openvibes-console\"")
        .await
        .unwrap();
    client.batch_execute("RESET ROLE").await.unwrap();

    let done = platform_store::console_sso::clean(&mut client, 90, Utc::now())
        .await
        .unwrap();
    assert_eq!((done.removed, done.access_removed), (1, 1));
    assert!(done.expired >= 1);
    let left: Vec<String> = client
        .query(
            "SELECT user_id::text FROM console_sso_users ORDER BY 1",
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|row| row.get(0))
        .collect();
    assert!(!left.contains(&ids[0]) && left.contains(&ids[1]) && left.contains(&ids[2]));
    let busy_roles: i64 = client
        .query_one("SELECT count(*) FROM console_role_bindings WHERE user_id = $1::text::uuid AND revoked_at IS NULL", &[&ids[1]])
        .await
        .unwrap()
        .get(0);
    assert_eq!(busy_roles, 0);
    // a second pass has nothing left to do
    let again = platform_store::console_sso::clean(&mut client, 90, Utc::now())
        .await
        .unwrap();
    assert_eq!((again.removed, again.access_removed), (0, 0));
    let actions: Vec<String> = client
        .query(
            "SELECT action FROM audit_log WHERE action IN ('user.removed', 'user.access_removed') ORDER BY action",
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|row| row.get(0))
        .collect();
    assert_eq!(actions, ["user.access_removed", "user.removed"]);
    drop(client);
    db.drop().await;
}
