//! The share and self rules on every People route (spec §4.4): who sees
//! and changes whom, and the Service accounts list.

use axum::http::StatusCode;
use platform_store::console_roles::Reach;
use serde_json::{Value, json};

mod common;
use common::http::sign_in;
use common::people::{Fx, WIN, uid};

/// Self-only allowances use the session's user id, never stretch to
/// others, and people outside the share look absent (security review).
#[tokio::test]
async fn self_allowances_and_the_share_hold_on_every_person_route() {
    let Some(fx) = Fx::new().await else { return };
    fx.db.user("bob", &fx.win_viewers, 3).await;
    let wl = fx.windows_lead().await;
    let bob = sign_in(&fx.router, "bob").await;
    let alice = format!("/api/v1/users/{}", uid(1));
    let nobody = "/api/v1/users/99999999-9999-4999-8999-999999999999";
    let routes = |user: &str| {
        vec![
            ("GET", user.to_owned(), None),
            ("PATCH", user.to_owned(), Some(json!({"display_name": "X"}))),
            ("POST", format!("{user}/disable"), None),
            ("POST", format!("{user}/enable"), None),
            ("POST", format!("{user}/reset-password"), None),
            ("PUT", format!("{user}/roles/{}", fx.win_viewers), None),
            ("DELETE", format!("{user}/roles/admin"), None),
        ]
    };
    // Bob holds no access permission: his own page is fine, nobody else's.
    let (status, _) = fx.call(&bob, "GET", "/api/v1/users", None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    for (method, uri, body) in routes(&alice) {
        let (status, _) = fx.call(&bob, method, &uri, body).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "bob {method} {uri}");
    }
    // The Windows lead holds the permissions, but Alice is outside the
    // share: every route answers exactly as for someone who does not exist.
    for ((method, uri, body), (_, missing, _)) in routes(&alice).into_iter().zip(routes(nobody)) {
        let (status, outside) = fx.call(&wl, method, &uri, body.clone()).await;
        let (_, absent) = fx.call(&wl, method, &missing, body).await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "wl {method} {uri}: {outside}"
        );
        assert_eq!(
            (&outside["code"], &outside["title"]),
            (&absent["code"], &absent["title"]),
            "wl {method} {uri}"
        );
    }
    // Self: the lead may not disable themself or change their own roles.
    let me = format!("/api/v1/users/{}", uid(2));
    for (method, uri) in [
        ("POST", format!("{me}/disable")),
        ("PUT", format!("{me}/roles/{}", fx.win_viewers)),
    ] {
        let (status, _) = fx.call(&wl, method, &uri, None).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{method} {uri}");
    }
    // A session that must still set its password reaches none of this,
    // not even its own page.
    fx.db
        .pool
        .get()
        .await
        .unwrap()
        .execute(
            "UPDATE console_users SET password_must_change = true WHERE username = 'bob'",
            &[],
        )
        .await
        .unwrap();
    let own = format!("/api/v1/users/{}", uid(3));
    for (method, uri, body) in routes(&own) {
        let (status, refused) = fx.call(&bob, method, &uri, body).await;
        assert_eq!(
            (status, &refused["code"]),
            (StatusCode::FORBIDDEN, &json!("password_change_required")),
            "{method} {uri}"
        );
    }
    fx.db.drop().await;
}

#[tokio::test]
async fn service_accounts_are_listed_only_inside_the_share() {
    let Some(fx) = Fx::new().await else { return };
    for (name, role) in [("ci", fx.win_viewers.clone()), ("ops", "admin".to_owned())] {
        let body = json!({"name": name, "role_ids": [role]});
        let (status, _) = fx
            .call(&fx.admin, "POST", "/api/v1/service-accounts", Some(body))
            .await;
        assert_eq!(status, StatusCode::CREATED);
    }
    let lead = fx
        .role(
            "Accounts lead",
            &["service_accounts.read", "hosts.read"],
            Reach::Groups(vec![WIN.into()]),
        )
        .await;
    fx.db.user("sal", &lead, 4).await;
    let sal = sign_in(&fx.router, "sal").await;
    let names = |page: &Value| -> Vec<String> {
        page["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| a["name"].as_str().unwrap().to_owned())
            .collect()
    };
    let (status, page) = fx.call(&sal, "GET", "/api/v1/service-accounts", None).await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert_eq!(names(&page), ["ci"]);
    let (_, page) = fx
        .call(&fx.admin, "GET", "/api/v1/service-accounts", None)
        .await;
    assert_eq!(names(&page), ["ci", "ops"]);
    fx.db.drop().await;
}
