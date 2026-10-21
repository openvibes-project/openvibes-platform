//! Saved views and hidden list columns over `/api/v1`: session only,
//! per person, validated, CSRF on writes.

use axum::http::StatusCode;
use serde_json::json;

mod common;
use common::people::Fx;

const VIEWS: &str = "/api/v1/saved-views";
const COLUMNS: &str = "/api/v1/list-columns/hosts";

#[tokio::test]
async fn saved_views_are_validated_per_person_and_csrf_guarded() {
    let Some(fx) = Fx::new().await else { return };
    let a = &fx.admin;

    // no session
    let request = axum::http::Request::builder()
        .uri(format!("{VIEWS}?page=hosts"))
        .body(axum::body::Body::empty())
        .unwrap();
    let response = tower::ServiceExt::oneshot(fx.router.clone(), request)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let (status, body) = fx.call(a, "GET", &format!("{VIEWS}?page=nope"), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["code"], "list_page_not_found");
    let (status, body) = fx
        .call(a, "GET", &format!("{VIEWS}?page=hosts"), None)
        .await;
    assert_eq!((status, &body["items"]), (StatusCode::OK, &json!([])));

    for (name, query, field) in [
        ("".to_string(), "a=b".to_string(), "name"),
        ("n".repeat(61), "a=b".to_string(), "name"),
        ("ok".to_string(), "q".repeat(1001), "query"),
        ("bad\0name".to_string(), "a=b".to_string(), "name"),
        ("ok".to_string(), "a=b\u{7}".to_string(), "query"),
    ] {
        let (status, body) = fx
            .call(
                a,
                "POST",
                VIEWS,
                Some(json!({"page": "hosts", "name": name, "query": query})),
            )
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(body["code"], "invalid_saved_view");
        assert_eq!(body["field_errors"][0]["field"], field);
    }
    let (status, body) = fx
        .call(
            a,
            "POST",
            VIEWS,
            Some(json!({"page": "nope", "name": "x", "query": ""})),
        )
        .await;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::NOT_FOUND, &json!("list_page_not_found"))
    );

    let new = json!({"page": "hosts", "name": "Prod online", "query": "status=online"});
    let (status, created) = fx.call(a, "POST", VIEWS, Some(new.clone())).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(created["name"], "Prod online");
    let id = created["id"].as_str().unwrap().to_string();
    let (status, body) = fx
        .call(
            a,
            "POST",
            VIEWS,
            Some(json!({"page": "hosts", "name": "PROD ONLINE", "query": ""})),
        )
        .await;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::CONFLICT, &json!("view_name_taken"))
    );

    // another person cannot delete it
    let viewer = fx
        .role(
            "Viewer",
            &["hosts.read"],
            platform_store::console_roles::Reach::All,
        )
        .await;
    fx.db.user("vera", &viewer, 3).await;
    let vera = common::http::sign_in(&fx.router, "vera").await;
    let (_, body) = fx
        .call(&vera, "GET", &format!("{VIEWS}?page=hosts"), None)
        .await;
    assert_eq!(body["items"], json!([]));
    let (status, body) = fx
        .call(&vera, "DELETE", &format!("{VIEWS}/{id}"), None)
        .await;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::NOT_FOUND, &json!("saved_view_not_found"))
    );

    // no CSRF header: refused
    let request = axum::http::Request::builder()
        .method("POST")
        .uri(VIEWS)
        .header(axum::http::header::COOKIE, &a.0)
        .header(axum::http::header::ORIGIN, common::http::ORIGIN)
        .header("sec-fetch-site", "same-origin")
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(new.to_string()))
        .unwrap();
    let response = tower::ServiceExt::oneshot(fx.router.clone(), request)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    for i in 1..50 {
        let (status, _) = fx
            .call(
                a,
                "POST",
                VIEWS,
                Some(json!({"page": "hosts", "name": format!("v{i}"), "query": ""})),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED);
    }
    let (status, body) = fx
        .call(
            a,
            "POST",
            VIEWS,
            Some(json!({"page": "hosts", "name": "v51", "query": ""})),
        )
        .await;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::CONFLICT, &json!("too_many_views"))
    );

    let (status, _) = fx.call(a, "DELETE", &format!("{VIEWS}/{id}"), None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn hidden_columns_are_validated_and_remembered() {
    let Some(fx) = Fx::new().await else { return };
    let a = &fx.admin;
    let (status, body) = fx.call(a, "GET", COLUMNS, None).await;
    assert_eq!((status, &body["hidden"]), (StatusCode::OK, &json!([])));
    let (status, body) = fx.call(a, "GET", "/api/v1/list-columns/nope", None).await;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::NOT_FOUND, &json!("list_page_not_found"))
    );

    let many: Vec<String> = (0..33).map(|i| format!("c{i}")).collect();
    for bad in [
        json!(["host"]),
        json!(["nope"]),
        json!(many),
        json!(["os", "os"]),
    ] {
        let (status, body) = fx
            .call(a, "PUT", COLUMNS, Some(json!({"hidden": bad})))
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{bad}");
        assert_eq!(body["code"], "invalid_columns");
    }
    let (_, body) = fx
        .call(a, "PUT", COLUMNS, Some(json!({"hidden": ["host"]})))
        .await;
    assert_eq!(body["title"], "The Host column can't be hidden");

    let (status, body) = fx
        .call(
            a,
            "PUT",
            COLUMNS,
            Some(json!({"hidden": ["labels", "agent"]})),
        )
        .await;
    assert_eq!(
        (status, &body["hidden"]),
        (StatusCode::OK, &json!(["labels", "agent"]))
    );
    let (_, body) = fx.call(a, "GET", COLUMNS, None).await;
    assert_eq!(body["hidden"], json!(["labels", "agent"]));

    let request = axum::http::Request::builder()
        .method("PUT")
        .uri(COLUMNS)
        .header(axum::http::header::COOKIE, &a.0)
        .header(axum::http::header::ORIGIN, common::http::ORIGIN)
        .header("sec-fetch-site", "same-origin")
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(json!({"hidden": []}).to_string()))
        .unwrap();
    let response = tower::ServiceExt::oneshot(fx.router.clone(), request)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}
