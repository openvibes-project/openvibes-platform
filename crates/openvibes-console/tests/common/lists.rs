//! Checks the assets lists' HTTP tests (ports, services) have in common.
use axum::http::StatusCode;
use platform_store::console_roles::Reach;
use serde_json::{Value, json};

use super::http::Session;
use super::people::Fx;

/// Each bad query answers 400 `invalid_query` naming its field (and an
/// over-long `q` does too); each good one answers 200; no session answers 401.
pub async fn assert_queries_validated(fx: &Fx, url: &str, bad: &[(&str, &str)], ok: &[&str]) {
    for (query, field) in bad {
        let (status, body) = fx
            .call(&fx.admin, "GET", &format!("{url}?{query}"), None)
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{query}");
        assert_eq!(body["code"], "invalid_query", "{query}");
        assert_eq!(body["field_errors"][0]["field"], *field, "{query}");
    }
    let long = "x".repeat(201);
    let (status, body) = fx
        .call(&fx.admin, "GET", &format!("{url}?q={long}"), None)
        .await;
    assert_eq!(
        (status, &body["field_errors"][0]["field"]),
        (StatusCode::BAD_REQUEST, &"q".into())
    );
    for query in ok {
        let (status, _) = fx
            .call(&fx.admin, "GET", &format!("{url}?{query}"), None)
            .await;
        assert_eq!(status, StatusCode::OK, "{query}");
    }
    assert_unauthorized(fx, url).await;
}

/// No session answers 401.
pub async fn assert_unauthorized(fx: &Fx, uri: &str) {
    let request = axum::http::Request::builder()
        .uri(uri)
        .body(axum::body::Body::empty())
        .unwrap();
    let response = tower::ServiceExt::oneshot(fx.router.clone(), request)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// A page's Hosts route refuses a bad segment, offset, limit and any other parameter.
pub async fn assert_hosts_queries_refused(fx: &Fx, hosts: impl Fn(&str) -> String) {
    for (query, field) in [
        ("segment=gone", "segment"),
        ("offset=-1", "offset"),
        ("offset=100001", "offset"),
        ("limit=0", "limit"),
        ("limit=101", "limit"),
    ] {
        let (status, body) = fx
            .call(&fx.admin, "GET", &hosts(&format!("?{query}")), None)
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{query}");
        assert_eq!(body["field_errors"][0]["field"], field, "{query}");
    }
    let (status, _) = fx.call(&fx.admin, "GET", &hosts("?surprise=1"), None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

/// `hosts.read` is required for each of `uris`; export and add-to-case are
/// separate permissions that need a host in the `win` group's reach.
pub async fn assert_page_permissions(fx: &Fx, uris: &[String], summary: &str) {
    let role = fx.role("Cases only", &["cases.read"], Reach::All).await;
    fx.db.user("co", &role, 5).await;
    let co = super::http::sign_in(&fx.router, "co").await;
    for uri in uris {
        let (status, _) = fx.call(&co, "GET", uri, None).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{uri}");
    }
    let role = fx
        .role(
            "Export and cases",
            &["hosts.read", "hosts.export", "cases.read", "cases.write"],
            Reach::Groups(vec![super::people::WIN.into()]),
        )
        .await;
    fx.db.user("ec", &role, 6).await;
    let ec = super::http::sign_in(&fx.router, "ec").await;
    let (_, body) = fx.call(&ec, "GET", summary, None).await;
    assert_eq!(
        (
            body["can"]["export"].clone(),
            body["can"]["add_to_case"].clone()
        ),
        (json!(true), json!(true))
    );
}

/// The count of one value of a facet in a list's `counts`.
pub fn count(body: &Value, facet: &str, v: &str) -> Value {
    body["counts"][facet]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["value"] == v)
        .unwrap()["count"]
        .clone()
}

/// A viewer whose reach leaves a group out sees neither its chip nor its hosts
/// (`queries` name a host or a group outside the reach) and needs `hosts.read`.
pub async fn assert_out_of_reach(
    fx: &Fx,
    lead: &Session,
    url: &str,
    outside_group: &str,
    queries: &[String],
) {
    let (_, body) = fx.call(lead, "GET", url, None).await;
    assert!(
        body["counts"]["group"]
            .as_array()
            .unwrap()
            .iter()
            .all(|g| g["value"] != outside_group)
    );
    for q in queries {
        let (status, body) = fx.call(lead, "GET", &format!("{url}?{q}"), None).await;
        assert_eq!(
            (status, body["total"].clone()),
            (StatusCode::OK, 0.into()),
            "{q}"
        );
    }
    // hosts.read is required
    let role = fx.role("Cases only", &["cases.read"], Reach::All).await;
    fx.db.user("co", &role, 5).await;
    let co = super::http::sign_in(&fx.router, "co").await;
    let (status, _) = fx.call(&co, "GET", url, None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

/// A page keeps saved views and the person's hidden columns, and refuses to
/// hide `fixed`.
pub async fn assert_views_and_columns(
    fx: &Fx,
    page: &str,
    view: (&str, &str),
    hidden: &[&str],
    fixed: &str,
) {
    let a = &fx.admin;
    let (status, _) = fx
        .call(
            a,
            "POST",
            "/api/v1/saved-views",
            Some(json!({"page": page, "name": view.0, "query": view.1})),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let cols = format!("/api/v1/list-columns/{page}");
    let (status, _) = fx
        .call(a, "PUT", &cols, Some(json!({ "hidden": hidden })))
        .await;
    assert_eq!(status, StatusCode::OK);
    let (status, body) = fx
        .call(a, "PUT", &cols, Some(json!({ "hidden": [fixed] })))
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
}
