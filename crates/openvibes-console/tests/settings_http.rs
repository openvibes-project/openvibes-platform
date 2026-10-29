//! The general settings API (roles spec §7): who may read and change them,
//! typed validation, and the audited change list.

use axum::http::StatusCode;
use platform_store::console_roles::Reach;
use serde_json::json;

mod common;
use common::people::Fx;

const REQUIRE: &str = "/api/v1/settings/suppressions.require_approval";
const INACTIVE: &str = "/api/v1/settings/sso.remove_inactive_days";

#[tokio::test]
async fn settings_are_typed_guarded_and_audited() {
    let Some(fx) = Fx::new().await else { return };
    let a = &fx.admin;

    let (status, body) = fx.call(a, "GET", "/api/v1/settings", None).await;
    assert_eq!(status, StatusCode::OK);
    let items = body["items"].as_array().unwrap();
    assert_eq!(items.len(), 14);
    let find = |key: &str| items.iter().find(|i| i["key"] == key).unwrap();
    assert_eq!(find("suppressions.require_approval")["value"], json!(false));
    assert_eq!(find("sso.remove_inactive_days")["value"], json!(90));
    assert_eq!(find("sso.remove_inactive_days")["kind"], json!("int"));
    assert_eq!(body["recent"], json!([]));

    let viewer = fx.role("Viewer", &["hosts.read"], Reach::All).await;
    fx.db.user("vera", &viewer, 3).await;
    let vera = common::http::sign_in(&fx.router, "vera").await;
    let (status, body) = fx.call(&vera, "GET", "/api/v1/settings", None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["code"], "permission_denied");
    let (status, _) = fx
        .call(&vera, "PATCH", REQUIRE, Some(json!({"value": true})))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    for bad in [json!(0), json!(3651), json!("90"), json!(1.5)] {
        let (status, body) = fx
            .call(a, "PATCH", INACTIVE, Some(json!({"value": bad})))
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{bad}");
        assert_eq!(body["code"], "invalid_setting");
        assert_eq!(body["field_errors"][0]["field"], "value");
    }
    let (status, body) = fx
        .call(a, "PATCH", INACTIVE, Some(json!({"value": 30})))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["value"], json!(30));

    // a missing value is refused too
    let (status, body) = fx.call(a, "PATCH", INACTIVE, Some(json!({}))).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["code"], "invalid_setting");

    // no CSRF header: refused
    let request = axum::http::Request::builder()
        .method("PATCH")
        .uri(REQUIRE)
        .header(axum::http::header::COOKIE, &a.0)
        .header(axum::http::header::ORIGIN, common::http::ORIGIN)
        .header("sec-fetch-site", "same-origin")
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(json!({"value": true}).to_string()))
        .unwrap();
    let response = tower::ServiceExt::oneshot(fx.router.clone(), request)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let (status, _) = fx
        .call(a, "PATCH", REQUIRE, Some(json!({"value": 1})))
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    let (status, body) = fx
        .call(a, "PATCH", REQUIRE, Some(json!({"value": true})))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["value"], json!(true));
    assert!(body["changed_by"].as_str().is_some());

    let (status, body) = fx
        .call(
            a,
            "PATCH",
            "/api/v1/settings/unknown.key",
            Some(json!({"value": 1})),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["code"], "setting_not_found");

    let (_, body) = fx.call(a, "GET", "/api/v1/settings", None).await;
    let recent = body["recent"].as_array().unwrap();
    assert_eq!(recent.len(), 2);
    assert_eq!(recent[0]["key"], "suppressions.require_approval");
    assert_eq!(
        (&recent[0]["old"], &recent[0]["new"]),
        (&json!(null), &json!(true))
    );
    assert_eq!(recent[1]["key"], "sso.remove_inactive_days");
    assert_eq!(
        (&recent[1]["old"], &recent[1]["new"]),
        (&json!(null), &json!(30))
    );

    // The audit list filters by action prefix (Recent changes on the pages).
    let since = "/api/v1/audit-events?since=2000-01-01T00%3A00%3A00Z";
    let (status, body) = fx
        .call(a, "GET", &format!("{since}&action_prefix=settings."), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    let items = body["items"].as_array().unwrap();
    assert_eq!(items.len(), 2);
    assert!(items.iter().all(|i| i["action"] == "settings.changed"));
    let long = "a".repeat(65);
    for bad in ["", "Settings.", "settings-", "settings.%25", long.as_str()] {
        let (status, body) = fx
            .call(a, "GET", &format!("{since}&action_prefix={bad}"), None)
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}");
        assert_eq!(body["code"], "invalid_query");
    }
    fx.db.drop().await;
}

#[tokio::test]
async fn text_and_secret_settings_reset_and_never_show_a_secret() {
    let Some(fx) = Fx::new().await else { return };
    let a = &fx.admin;
    let proxy = "/api/v1/settings/vulns.proxy_url";
    let key = "/api/v1/settings/vulns.nvd_api_key";

    let (_, body) = fx.call(a, "GET", "/api/v1/settings", None).await;
    let items = body["items"].as_array().unwrap();
    let find = |key: &str| items.iter().find(|i| i["key"] == key).unwrap().clone();
    assert_eq!(find("vulns.proxy_url")["kind"], json!("text"));
    assert_eq!(find("vulns.proxy_url")["applies"], json!("live"));
    assert_eq!(find("vulns.nvd_api_key")["kind"], json!("secret"));
    assert_eq!(find("vulns.nvd_api_key")["is_set"], json!(false));

    // text is checked, stored, and put back with null
    for bad in [
        json!("ftp://x"),
        json!(5),
        json!("http://a b"),
        json!("http://u:p@proxy.example:3128"),
    ] {
        let (status, body) = fx
            .call(a, "PATCH", proxy, Some(json!({"value": bad})))
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{bad}");
        assert_eq!(body["code"], "invalid_setting");
    }
    let (status, body) = fx
        .call(
            a,
            "PATCH",
            proxy,
            Some(json!({"value": "http://proxy.example:3128"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["value"], json!("http://proxy.example:3128"));
    let (status, body) = fx
        .call(a, "PATCH", proxy, Some(json!({"value": null})))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["value"], json!(""));
    assert!(body.get("changed_at").is_none());

    // a secret is set, reported as set, never returned, and removed with null
    for bad in [json!(5), json!("  "), json!("a b"), json!("kéy")] {
        let (status, _) = fx.call(a, "PATCH", key, Some(json!({"value": bad}))).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{bad}");
    }
    let (status, body) = fx
        .call(a, "PATCH", key, Some(json!({"value": "s3cret-key\n"})))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["is_set"], json!(true));
    assert_eq!(body["value"], json!(null));
    let (_, body) = fx.call(a, "GET", "/api/v1/settings", None).await;
    assert!(!body.to_string().contains("s3cret-key"));
    let set = body["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["key"] == "vulns.nvd_api_key")
        .unwrap()
        .clone();
    assert_eq!(set["is_set"], json!(true));
    assert!(set["changed_by"].as_str().is_some());
    // the audit line says set or not set, never the value
    let recent = body["recent"].to_string();
    assert!(recent.contains("\"set\""), "{recent}");
    let (status, body) = fx.call(a, "PATCH", key, Some(json!({"value": null}))).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["is_set"], json!(false));
    fx.db.drop().await;
}
