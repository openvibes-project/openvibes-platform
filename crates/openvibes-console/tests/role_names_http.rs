//! Roles appear by name wherever the console shows them, and the pickers
//! that choose one load for whoever may use them: the role list for
//! `service_accounts.manage`, the caller's own roles for dashboard sharing.

use axum::http::StatusCode;
use platform_store::console_roles::Reach;
use serde_json::{Value, json};

mod common;
use common::http::sign_in;
use common::people::Fx;

fn ids(roles: &Value) -> Vec<&str> {
    roles
        .as_array()
        .unwrap()
        .iter()
        .map(|role| role["role_id"].as_str().unwrap())
        .collect()
}

#[tokio::test]
async fn service_accounts_show_role_names_and_their_managers_list_roles() {
    let Some(fx) = Fx::new().await else { return };
    let (status, made) = fx
        .call(
            &fx.admin,
            "POST",
            "/api/v1/service-accounts",
            Some(json!({"name": "ci", "role_ids": [fx.win_viewers, "admin"]})),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{made}");
    let mut expected = vec![
        json!({"role_id": "admin", "name": "Administrator"}),
        json!({"role_id": fx.win_viewers, "name": "Win viewers"}),
    ];
    expected.sort_by_key(|role| role["role_id"].as_str().unwrap().to_owned());
    assert_eq!(made["roles"], json!(expected), "{made}");
    let (_, list) = fx
        .call(&fx.admin, "GET", "/api/v1/service-accounts", None)
        .await;
    assert_eq!(list["items"][0]["roles"], json!(expected), "{list}");

    // A service-account manager without access.read still lists roles.
    let manage = ["service_accounts.read", "service_accounts.manage"];
    let manager = fx.role("Robots", &manage, Reach::None).await;
    fx.db.user("max", &manager, 3).await;
    let max = sign_in(&fx.router, "max").await;
    let (status, roles) = fx.call(&max, "GET", "/api/v1/roles", None).await;
    assert_eq!(status, StatusCode::OK, "{roles}");
    assert!(ids(&roles).contains(&fx.win_viewers.as_str()), "{roles}");
    // Without either permission the list stays closed.
    fx.db.user("nia", &fx.win_viewers, 4).await;
    let nia = sign_in(&fx.router, "nia").await;
    let (status, _) = fx.call(&nia, "GET", "/api/v1/roles", None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    fx.db.drop().await;
}

#[tokio::test]
async fn sharers_list_the_roles_they_hold_and_see_the_shared_role_by_name() {
    let Some(fx) = Fx::new().await else { return };
    let sharers = fx.role("Sharers", &["dashboards.share"], Reach::None).await;
    fx.db.user("sal", &sharers, 3).await;
    let sal = sign_in(&fx.router, "sal").await;
    let (status, held) = fx.call(&sal, "GET", "/api/v1/roles?held=true", None).await;
    assert_eq!(status, StatusCode::OK, "{held}");
    assert_eq!(ids(&held), [sharers.as_str()]);
    assert_eq!(held[0]["name"], "Sharers");
    // Anyone signed in may list their own roles; the full list stays closed.
    fx.db.user("nia", &fx.win_viewers, 4).await;
    let nia = sign_in(&fx.router, "nia").await;
    let (status, held) = fx.call(&nia, "GET", "/api/v1/roles?held=true", None).await;
    assert_eq!(
        (status, ids(&held)),
        (StatusCode::OK, vec![fx.win_viewers.as_str()])
    );
    let (status, _) = fx.call(&sal, "GET", "/api/v1/roles", None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let layout = json!({"schema": 1, "widgets": [{"id": "w1", "type": "number", "x": 0, "y": 0, "w": 3, "h": 2, "config": {"metric": "agents.active"}}]});
    let (status, made) = fx
        .call(
            &sal,
            "POST",
            "/api/v1/dashboards",
            Some(json!({"name": "Ours", "layout": layout})),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{made}");
    assert_eq!(made["shared_role_name"], Value::Null, "{made}");
    let sharing = format!(
        "/api/v1/dashboards/{}/sharing",
        made["dashboard_id"].as_str().unwrap()
    );
    let (status, shared) = fx
        .call(&sal, "PUT", &sharing, Some(json!({"role_id": sharers})))
        .await;
    assert_eq!(status, StatusCode::OK, "{shared}");
    assert_eq!(shared["shared_role_name"], "Sharers", "{shared}");
    let (_, list) = fx.call(&sal, "GET", "/api/v1/dashboards", None).await;
    assert_eq!(list["items"][0]["shared_role_name"], "Sharers", "{list}");
    fx.db.drop().await;
}
