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
    assert_eq!(items.len(), 2);
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
    fx.db.drop().await;
}
