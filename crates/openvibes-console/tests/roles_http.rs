//! The roles API (spec §4.1–4.4): create, edit and delete roles, closure
//! under needs, the protected Administrator, and the share check.

use axum::http::StatusCode;
use openvibes_console::authenticated_router;
use platform_store::console_roles::Reach;
use serde_json::{Value, json};

mod common;
use common::http::{Session, TestDb, call, sign_in};

const WIN: &str = "31111111-1111-4111-8111-111111111111";

struct Fx {
    db: TestDb,
    router: axum::Router,
    admin: Session,
}

impl Fx {
    async fn new() -> Option<Self> {
        let db = TestDb::create("roles").await?;
        db.user("alice", "admin", 1).await;
        db.pool
            .get()
            .await
            .unwrap()
            .batch_execute(&format!(
                "INSERT INTO console_asset_groups (asset_group_id, name, created_at, created_by)
                 VALUES ('{WIN}', 'win', now(), 'test')"
            ))
            .await
            .unwrap();
        let router = authenticated_router(db.pool.clone(), common::http::ORIGIN);
        let admin = sign_in(&router, "alice").await;
        Some(Self { db, router, admin })
    }

    async fn call(
        &self,
        who: &Session,
        method: &str,
        uri: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        call(&self.router, method, uri, who, body).await
    }

    async fn role(&self, name: &str, permissions: &[&str], reach: Reach) -> String {
        let mut client = self.db.pool.get().await.unwrap();
        common::create_role(&mut client, name, permissions, reach).await
    }
}

fn save(name: &str, permissions: &[&str], reach: Value, version: Option<i32>) -> Value {
    json!({"name": name, "permissions": permissions, "reach": reach, "version": version})
}

#[tokio::test]
async fn an_admin_creates_edits_and_deletes_a_role() {
    let Some(fx) = Fx::new().await else { return };
    let a = &fx.admin;
    let body = json!({"name": " Triage ", "description": "Night shift",
        "permissions": ["alarms.read", "alarms.triage"], "reach": {"kind": "all"}});
    let (status, created) = fx.call(a, "POST", "/api/v1/roles", Some(body)).await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    assert_eq!(created["name"], "Triage");
    assert_eq!(created["version"], 1);
    let id = created["role_id"].as_str().unwrap().to_owned();
    let uri = format!("/api/v1/roles/{id}");

    let (status, got) = fx.call(a, "GET", &uri, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(got["members"], 0);
    assert_eq!(got["builtin"], false);
    assert_eq!(got["reach"], json!({"kind": "all"}));
    assert_eq!(got["permissions"], json!(["alarms.read", "alarms.triage"]));

    let edit = save("Triage", &["alarms.read"], json!({"kind": "none"}), Some(1));
    let (status, edited) = fx.call(a, "PATCH", &uri, Some(edit.clone())).await;
    assert_eq!(status, StatusCode::OK, "{edited}");
    assert_eq!(edited["version"], 2);
    assert_eq!(edited["reach"], json!({"kind": "none"}));
    let (status, stale) = fx.call(a, "PATCH", &uri, Some(edit)).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(stale["code"], "stale_role");

    // Bad input is refused before anything is stored.
    for (bad, code) in [
        (
            save("   ", &[], json!({"kind": "none"}), None),
            "invalid_role",
        ),
        (
            save(&"x".repeat(65), &[], json!({"kind": "none"}), None),
            "invalid_role",
        ),
        (
            save("a\u{7}b", &[], json!({"kind": "none"}), None),
            "invalid_role",
        ),
        (
            save(
                "G",
                &["hosts.read"],
                json!({"kind": "groups", "asset_group_ids": []}),
                None,
            ),
            "invalid_role",
        ),
        (
            save(
                "G",
                &["hosts.read"],
                json!({"kind": "groups", "asset_group_ids": [WIN, WIN]}),
                None,
            ),
            "invalid_role",
        ),
        (
            save(
                "G",
                &["hosts.read"],
                json!({"kind": "groups", "asset_group_ids": ["nope"]}),
                None,
            ),
            "unknown_group",
        ),
        (
            save(
                "G",
                &["hosts.read"],
                json!({"kind": "groups",
                "asset_group_ids": ["41111111-1111-4111-8111-111111111111"]}),
                None,
            ),
            "unknown_group",
        ),
    ] {
        let (status, answer) = fx.call(a, "POST", "/api/v1/roles", Some(bad.clone())).await;
        assert_eq!(answer["code"], code, "{bad} -> {status} {answer}");
    }
    let long = json!({"name": "D", "description": "d".repeat(501), "permissions": [], "reach": {"kind": "none"}});
    let (status, _) = fx.call(a, "POST", "/api/v1/roles", Some(long)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = fx
        .call(
            a,
            "PATCH",
            &uri,
            Some(save("T", &[], json!({"kind": "none"}), None)),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "PATCH needs a version");

    let (status, _) = fx.call(a, "DELETE", &uri, None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, gone) = fx.call(a, "GET", &uri, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(gone["code"], "role_not_found");
    let actions = fx.db.audit_actions().await;
    for action in [
        "rbac.role.created",
        "rbac.role.updated",
        "rbac.role.deleted",
    ] {
        assert!(actions.iter().any(|a| a == action), "{action}: {actions:?}");
    }
    fx.db.drop().await;
}

#[tokio::test]
async fn role_names_are_unique_regardless_of_case() {
    let Some(fx) = Fx::new().await else { return };
    let a = &fx.admin;
    let none = || json!({"kind": "none"});
    let (status, _) = fx
        .call(
            a,
            "POST",
            "/api/v1/roles",
            Some(save("Analyst", &[], none(), None)),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, taken) = fx
        .call(
            a,
            "POST",
            "/api/v1/roles",
            Some(save("analyst", &[], none(), None)),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(taken["code"], "role_name_taken");
    let (_, other) = fx
        .call(
            a,
            "POST",
            "/api/v1/roles",
            Some(save("Other", &[], none(), None)),
        )
        .await;
    let uri = format!("/api/v1/roles/{}", other["role_id"].as_str().unwrap());
    let (status, taken) = fx
        .call(
            a,
            "PATCH",
            &uri,
            Some(save("ANALYST", &[], none(), Some(1))),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(taken["code"], "role_name_taken");
    fx.db.drop().await;
}

#[tokio::test]
async fn permissions_must_include_what_they_need() {
    let Some(fx) = Fx::new().await else { return };
    let body = save("Assigners", &["cases.assign"], json!({"kind": "all"}), None);
    let (status, refused) = fx
        .call(&fx.admin, "POST", "/api/v1/roles", Some(body))
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(refused["code"], "missing_needs");
    assert_eq!(refused["permission"], "cases.assign");
    assert_eq!(refused["needs"], "cases.write");
    fx.db.drop().await;
}

#[tokio::test]
async fn the_administrator_role_cannot_be_changed_or_deleted() {
    let Some(fx) = Fx::new().await else { return };
    let uri = "/api/v1/roles/admin";
    let edit = save("Administrator", &[], json!({"kind": "all"}), Some(1));
    let (status, refused) = fx.call(&fx.admin, "PATCH", uri, Some(edit)).await;
    assert_eq!(
        (status, refused["code"].clone()),
        (StatusCode::FORBIDDEN, json!("protected_role"))
    );
    let (status, refused) = fx.call(&fx.admin, "DELETE", uri, None).await;
    assert_eq!(
        (status, refused["code"].clone()),
        (StatusCode::FORBIDDEN, json!("protected_role"))
    );
    fx.db.drop().await;
}

#[tokio::test]
async fn a_held_role_cannot_be_deleted() {
    let Some(fx) = Fx::new().await else { return };
    let id = fx.role("Held", &["alarms.read"], Reach::All).await;
    fx.db.user("holder", &id, 2).await;
    let (status, refused) = fx
        .call(&fx.admin, "DELETE", &format!("/api/v1/roles/{id}"), None)
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(refused["code"], "role_in_use");
    assert_eq!(refused["holders"], 1);
    fx.db.drop().await;
}

#[tokio::test]
async fn team_admin_cannot_widen_a_role_they_hold() {
    let Some(fx) = Fx::new().await else { return };
    let perms = ["access.read", "access.roles", "hosts.read"];
    let id = fx
        .role("Windows lead", &perms, Reach::Groups(vec![WIN.into()]))
        .await;
    fx.db.user("wl", &id, 2).await;
    let wl = sign_in(&fx.router, "wl").await;

    let widen = save("Windows lead", &perms, json!({"kind": "all"}), Some(1));
    let (status, refused) = fx
        .call(&wl, "PATCH", &format!("/api/v1/roles/{id}"), Some(widen))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{refused}");
    assert_eq!(refused["code"], "permission_denied");
    assert!(
        refused["title"].as_str().unwrap().contains("View hosts"),
        "{refused}"
    );

    let win = || json!({"kind": "groups", "asset_group_ids": [WIN]});
    let revoke = save("Revokers", &["hosts.read", "hosts.revoke"], win(), None);
    let (status, refused) = fx.call(&wl, "POST", "/api/v1/roles", Some(revoke)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(refused["code"], "permission_denied");
    assert!(
        refused["title"].as_str().unwrap().contains("Revoke a host"),
        "{refused}"
    );

    let fits = save("Windows viewers", &["hosts.read"], win(), None);
    let (status, created) = fx.call(&wl, "POST", "/api/v1/roles", Some(fits)).await;
    assert_eq!(status, StatusCode::CREATED, "{created}");

    // A role wider than wl's share can be neither narrowed nor deleted.
    let all = fx.role("Everywhere", &["hosts.read"], Reach::All).await;
    let uri = format!("/api/v1/roles/{all}");
    let narrow = save("Everywhere", &["hosts.read"], win(), Some(1));
    for (method, body) in [("PATCH", Some(narrow)), ("DELETE", None)] {
        let (status, refused) = fx.call(&wl, method, &uri, body).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{method} {refused}");
        assert_eq!(refused["code"], "permission_denied");
        assert!(
            refused["title"].as_str().unwrap().contains("View hosts"),
            "{method} {refused}"
        );
    }
    fx.db.drop().await;
}

/// Gives role `id` a permission id this console does not know.
async fn legacy(fx: &Fx, id: &str) {
    fx.db
        .pool
        .get()
        .await
        .unwrap()
        .batch_execute(&format!(
            "INSERT INTO console_permissions (permission_id, scope_class)
             VALUES ('legacy.thing', 'global') ON CONFLICT DO NOTHING;
             INSERT INTO console_role_permissions (role_id, permission_id)
             VALUES ('{id}', 'legacy.thing')"
        ))
        .await
        .unwrap();
}

#[tokio::test]
async fn a_stored_permission_the_console_does_not_know_is_refused() {
    let Some(fx) = Fx::new().await else { return };
    let perms = ["access.read", "access.roles", "alarms.read"];
    let editors = fx.role("Editors", &perms, Reach::All).await;
    fx.db.user("ed", &editors, 2).await;
    let ed = sign_in(&fx.router, "ed").await;
    let id = fx.role("Legacy", &["alarms.read"], Reach::All).await;
    legacy(&fx, &id).await;
    let uri = format!("/api/v1/roles/{id}");
    let edit = || save("Legacy", &["alarms.read"], json!({"kind": "all"}), Some(1));
    for (method, body) in [("PATCH", Some(edit())), ("DELETE", None)] {
        let (status, refused) = fx.call(&ed, method, &uri, body).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{method} {refused}");
        assert_eq!(refused["code"], "permission_denied");
        assert!(
            refused["title"].as_str().unwrap().contains("legacy.thing"),
            "{method} {refused}"
        );
    }
    // An Administrator holds everything: they may clean such roles up.
    let (status, saved) = fx.call(&fx.admin, "PATCH", &uri, Some(edit())).await;
    assert_eq!(status, StatusCode::OK, "{saved}");
    assert_eq!(saved["permissions"], json!(["alarms.read"]));
    let other = fx.role("Legacy two", &["alarms.read"], Reach::All).await;
    legacy(&fx, &other).await;
    let (status, _) = fx
        .call(&fx.admin, "DELETE", &format!("/api/v1/roles/{other}"), None)
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    fx.db.drop().await;
}

#[tokio::test]
async fn roles_are_listed_with_their_reach_and_members() {
    let Some(fx) = Fx::new().await else { return };
    let id = fx
        .role("Windows", &["hosts.read"], Reach::Groups(vec![WIN.into()]))
        .await;
    fx.db.user("bob", &id, 2).await;
    let (status, roles) = fx.call(&fx.admin, "GET", "/api/v1/roles", None).await;
    assert_eq!(status, StatusCode::OK);
    let roles = roles.as_array().unwrap();
    assert_eq!(roles[0]["role_id"], "admin");
    assert_eq!(roles[0]["builtin"], true);
    assert_eq!(roles[0]["reach"], json!({"kind": "all"}));
    let windows = roles.iter().find(|r| r["role_id"] == id.as_str()).unwrap();
    assert_eq!(windows["members"], 1);
    assert_eq!(
        windows["reach"],
        json!({"kind": "groups", "groups": [{"asset_group_id": WIN, "name": "win"}]})
    );

    // The catalogue and templates are open to anyone signed in.
    let bob = sign_in(&fx.router, "bob").await;
    let (status, catalogue) = fx.call(&bob, "GET", "/api/v1/permissions", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(catalogue.as_array().unwrap().len(), 48);
    let (status, templates) = fx.call(&bob, "GET", "/api/v1/role-templates", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(templates.as_array().unwrap().len(), 6);
    // Listing roles needs access.read.
    let (status, _) = fx.call(&bob, "GET", "/api/v1/roles", None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    fx.db.drop().await;
}
