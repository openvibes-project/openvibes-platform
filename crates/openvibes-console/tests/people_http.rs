//! The People API (spec §4.3–4.6, §9.1, §13): people with their roles and
//! sign-in source, the share on who an editor sees and changes, the last
//! Administrator, the person page, reset password and edit details.

use axum::http::StatusCode;
use openvibes_console::Permission;
use platform_store::console_roles::Reach;
use serde_json::{Value, json};

mod common;
use common::http::sign_in;
use common::people::{Fx, WIN, uid};

fn usernames(list: &Value) -> Vec<&str> {
    list.as_array()
        .unwrap()
        .iter()
        .map(|row| row["username"].as_str().unwrap())
        .collect()
}

#[tokio::test]
async fn people_list_shows_roles_with_reach_and_sign_in_source() {
    let Some(fx) = Fx::new().await else { return };
    fx.db.user("bob", &fx.win_viewers, 3).await;
    let (status, list) = fx.call(&fx.admin, "GET", "/api/v1/users", None).await;
    assert_eq!(status, StatusCode::OK, "{list}");
    assert_eq!(usernames(&list), ["alice", "bob"]);
    let (alice, bob) = (&list[0], &list[1]);
    assert_eq!(alice["auth_source"], "password");
    assert!(alice["last_sign_in_at"].is_string(), "{alice}");
    assert!(bob["last_sign_in_at"].is_null());
    assert_eq!(alice["roles"][0]["role_id"], "admin");
    assert_eq!(alice["roles"][0]["reach"]["kind"], "all");
    assert_eq!(bob["roles"][0]["name"], "Win viewers");
    assert_eq!(bob["roles"][0]["reach"]["groups"][0]["name"], "win");

    let (status, groups) = fx.call(&fx.admin, "GET", "/api/v1/host-groups", None).await;
    assert_eq!(status, StatusCode::OK, "{groups}");
    assert_eq!(groups[0]["name"], "win");
    assert_eq!(groups[0]["roles"][0]["name"], "Win viewers");
    fx.db.drop().await;
}

#[tokio::test]
async fn a_team_admin_sees_only_people_inside_their_share() {
    let Some(fx) = Fx::new().await else { return };
    fx.db.user("bob", &fx.win_viewers, 3).await;
    let wl = fx.windows_lead().await;
    let (status, list) = fx.call(&wl, "GET", "/api/v1/users", None).await;
    assert_eq!(status, StatusCode::OK, "{list}");
    assert_eq!(usernames(&list), ["bob", "wl"]);
    let alice = format!("/api/v1/users/{}", uid(1));
    let (status, _) = fx.call(&wl, "GET", &alice, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = fx
        .call(&wl, "POST", &format!("{alice}/disable"), None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    fx.db.drop().await;
}

#[tokio::test]
async fn giving_a_role_needs_the_whole_role_inside_the_share() {
    let Some(fx) = Fx::new().await else { return };
    let wl = fx.windows_lead().await;
    let revokers = fx
        .role(
            "Revokers",
            &["hosts.read", "hosts.revoke"],
            Reach::Groups(vec![WIN.into()]),
        )
        .await;
    let new = json!({"username": "carol", "display_name": "Carol", "role_ids": [fx.win_viewers]});
    let (status, created) = fx.call(&wl, "POST", "/api/v1/users", Some(new)).await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    assert_eq!(created["one_time_password"].as_str().unwrap().len(), 23);
    let carol = created["user_id"].as_str().unwrap().to_owned();

    let uri = format!("/api/v1/users/{carol}/roles/{revokers}");
    let (status, refused) = fx.call(&wl, "PUT", &uri, None).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{refused}");
    assert!(
        refused["title"].as_str().unwrap().contains("Revoke a host"),
        "{refused}"
    );
    let wide = json!({"username": "dave", "display_name": "Dave", "role_ids": [revokers]});
    let (status, _) = fx.call(&wl, "POST", "/api/v1/users", Some(wide)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // An Administrator may; giving it twice is the same as once.
    for _ in 0..2 {
        let (status, body) = fx.call(&fx.admin, "PUT", &uri, None).await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    }
    let (status, _) = fx.call(&fx.admin, "DELETE", &uri, None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let actions = fx.db.audit_actions().await;
    assert!(actions.contains(&"rbac.binding.created".to_owned()));
    assert!(actions.contains(&"rbac.binding.revoked".to_owned()));

    // Service accounts follow the same rule.
    let sa = json!({"name": "ci", "role_ids": [fx.win_viewers]});
    let (status, account) = fx
        .call(&fx.admin, "POST", "/api/v1/service-accounts", Some(sa))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{account}");
    let sa_uri = format!(
        "/api/v1/service-accounts/{}/roles/{revokers}",
        account["service_account_id"].as_str().unwrap()
    );
    let (status, _) = fx.call(&wl, "PUT", &sa_uri, None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = fx.call(&fx.admin, "PUT", &sa_uri, None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = fx.call(&fx.admin, "DELETE", &sa_uri, None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    fx.db.drop().await;
}

#[tokio::test]
async fn nobody_changes_their_own_roles() {
    let Some(fx) = Fx::new().await else { return };
    let me = format!("/api/v1/users/{}", uid(1));
    let give = format!("{me}/roles/{}", fx.win_viewers);
    let (status, _) = fx.call(&fx.admin, "PUT", &give, None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = fx
        .call(&fx.admin, "DELETE", &format!("{me}/roles/admin"), None)
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = fx
        .call(&fx.admin, "POST", &format!("{me}/disable"), None)
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    fx.db.drop().await;
}

#[tokio::test]
async fn two_concurrent_removals_leave_one_administrator() {
    let Some(fx) = Fx::new().await else { return };
    fx.db.user("bert", "admin", 3).await;
    // Both also hold every permission through a custom role, so whichever
    // removal lands second still passes the permission and share checks
    // and meets the store's last-Administrator guard.
    let every: Vec<&str> = Permission::ALL.iter().map(|p| p.id()).collect();
    let everything = fx.role("Everything", &every, Reach::All).await;
    {
        let client = fx.db.pool.get().await.unwrap();
        for user in [uid(1), uid(3)] {
            client
                .execute(
                    "INSERT INTO console_role_bindings
                         (binding_id, user_id, role_id, created_at, created_by)
                     VALUES (gen_random_uuid(), $1::text::uuid, $2, now(), 'test')",
                    &[&user, &everything],
                )
                .await
                .unwrap();
        }
    }
    let bert = sign_in(&fx.router, "bert").await;
    let alice_admin = format!("/api/v1/users/{}/roles/admin", uid(1));
    let bert_admin = format!("/api/v1/users/{}/roles/admin", uid(3));
    let ((a, _), (b, _)) = tokio::join!(
        fx.call(&fx.admin, "DELETE", &bert_admin, None),
        fx.call(&bert, "DELETE", &alice_admin, None),
    );
    let mut statuses = [a, b];
    statuses.sort();
    assert_eq!(statuses, [StatusCode::NO_CONTENT, StatusCode::CONFLICT]);

    // The one still holding Administrator cannot be disabled either.
    let (remover, kept) = if a == StatusCode::NO_CONTENT {
        (&bert, uid(1))
    } else {
        (&fx.admin, uid(3))
    };
    let (status, refused) = fx
        .call(
            remover,
            "POST",
            &format!("/api/v1/users/{kept}/disable"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{refused}");
    assert_eq!(refused["code"], "last_administrator");
    fx.db.drop().await;
}

#[tokio::test]
async fn person_page_lists_access_by_where_it_applies_and_recent_activity() {
    let Some(fx) = Fx::new().await else { return };
    let auditors = fx.role("Auditors", &["audit.read"], Reach::None).await;
    let alarms = fx.role("All alarms", &["alarms.read"], Reach::All).await;
    fx.db.user("bob", &fx.win_viewers, 3).await;
    let bob_uri = format!("/api/v1/users/{}", uid(3));
    for role in [&auditors, &alarms] {
        let (status, _) = fx
            .call(&fx.admin, "PUT", &format!("{bob_uri}/roles/{role}"), None)
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
    }
    let bob = sign_in(&fx.router, "bob").await;
    let (status, _) = fx
        .call(
            &bob,
            "PATCH",
            &bob_uri,
            Some(json!({"display_name": "Bob"})),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, page) = fx.call(&fx.admin, "GET", &bob_uri, None).await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert_eq!(page["roles"].as_array().unwrap().len(), 3);
    let line = |permission: &str| {
        page["access"]
            .as_array()
            .unwrap()
            .iter()
            .find(|line| line["permission"] == permission)
            .unwrap_or_else(|| panic!("no {permission} in {page}"))
            .clone()
    };
    let hosts = line("hosts.read");
    assert_eq!(hosts["applies"], "groups");
    assert_eq!(hosts["groups"][0]["name"], "win");
    assert_eq!(hosts["from_role"], "Win viewers");
    assert_eq!(hosts["label"], "View hosts");
    assert_eq!(line("audit.read")["applies"], "platform");
    assert_eq!(line("alarms.read")["applies"], "all");
    assert_eq!(page["recent"][0]["action"], "user.updated");
    assert!(page["recent"].as_array().unwrap().len() <= 10);

    // Anyone may read their own page.
    let (status, own) = fx.call(&bob, "GET", &bob_uri, None).await;
    assert_eq!((status, &own["username"]), (StatusCode::OK, &json!("bob")));
    fx.db.drop().await;
}

#[tokio::test]
async fn reset_password_returns_a_one_time_password_and_ends_sessions() {
    let Some(fx) = Fx::new().await else { return };
    fx.db.user("bob", &fx.win_viewers, 3).await;
    let bob = sign_in(&fx.router, "bob").await;
    let uri = format!("/api/v1/users/{}/reset-password", uid(3));
    let (status, reset) = fx.call(&fx.admin, "POST", &uri, None).await;
    assert_eq!(status, StatusCode::OK, "{reset}");
    assert_eq!(reset["one_time_password"].as_str().unwrap().len(), 23);
    let (status, _) = fx.call(&bob, "GET", "/api/v1/session", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let must: bool = fx
        .db
        .pool
        .get()
        .await
        .unwrap()
        .query_one(
            "SELECT password_must_change FROM console_users WHERE username = 'bob'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert!(must);
    assert!(
        fx.db
            .audit_actions()
            .await
            .contains(&"user.password_reset".to_owned())
    );
    // Disable and enable, while we are here.
    let user = format!("/api/v1/users/{}", uid(3));
    for (action, enabled) in [("disable", false), ("enable", true)] {
        let (status, _) = fx
            .call(&fx.admin, "POST", &format!("{user}/{action}"), None)
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (_, page) = fx.call(&fx.admin, "GET", &user, None).await;
        assert_eq!(page["enabled"], enabled);
    }
    fx.db.drop().await;
}

#[tokio::test]
async fn editing_details_works_for_self_and_validates_email() {
    let Some(fx) = Fx::new().await else { return };
    fx.db.user("bob", &fx.win_viewers, 3).await;
    let bob = sign_in(&fx.router, "bob").await;
    let uri = format!("/api/v1/users/{}", uid(3));
    let edit = json!({"display_name": "Bob Builder", "email": "bob@example.com"});
    let (status, _) = fx.call(&bob, "PATCH", &uri, Some(edit)).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (_, page) = fx.call(&bob, "GET", &uri, None).await;
    assert_eq!(page["display_name"], "Bob Builder");
    assert_eq!(page["email"], "bob@example.com");

    let (status, refused) = fx
        .call(
            &bob,
            "PATCH",
            &uri,
            Some(json!({"email": "not an address"})),
        )
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{refused}");
    // Someone else's details need access.users.
    let alice = format!("/api/v1/users/{}", uid(1));
    let (status, _) = fx
        .call(&bob, "PATCH", &alice, Some(json!({"display_name": "X"})))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    // An empty email clears it.
    let (status, _) = fx
        .call(&bob, "PATCH", &uri, Some(json!({"email": ""})))
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (_, page) = fx.call(&bob, "GET", &uri, None).await;
    assert!(page["email"].is_null());
    assert!(
        fx.db
            .audit_actions()
            .await
            .contains(&"user.updated".to_owned())
    );
    fx.db.drop().await;
}
