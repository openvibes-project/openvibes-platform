//! `openvibes-admin sso`: the state, and turning single sign-on off.
// The tests start the CLI binary they verify; this is not shipped code.
#![allow(clippy::disallowed_types)]

mod common;

use chrono::Utc;
use common::{Fixture, stdout};
use serde_json::json;

async fn set(fixture: &Fixture, key: &str, value: serde_json::Value) {
    let pool = platform_store::connect(&fixture.url).await.unwrap();
    let mut client = pool.get().await.unwrap();
    platform_store::console_settings::set(&mut client, key, &value, "test", Utc::now())
        .await
        .unwrap();
}

#[tokio::test]
async fn off_flips_only_a_switch_that_is_on_and_says_what_it_found() {
    let fixture = Fixture::create().await;
    stdout(&fixture.run(&["migrate"]));
    assert_eq!(stdout(&fixture.run(&["sso", "status"])), "not set up\n");
    assert_eq!(stdout(&fixture.run(&["sso", "off"])), "not set up\n");

    set(&fixture, "sso.idp_entity_id", json!("https://idp.example")).await;
    set(
        &fixture,
        "sso.idp_sso_url",
        json!("https://idp.example/sso"),
    )
    .await;
    set(
        &fixture,
        "sso.idp_certificates",
        json!("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----"),
    )
    .await;
    assert_eq!(stdout(&fixture.run(&["sso", "status"])), "off\n");
    assert_eq!(stdout(&fixture.run(&["sso", "off"])), "already off\n");

    set(&fixture, "sso.enabled", json!(true)).await;
    assert_eq!(stdout(&fixture.run(&["sso", "status"])), "on\n");
    assert_eq!(stdout(&fixture.run(&["sso", "off"])), "off\n");
    assert_eq!(stdout(&fixture.run(&["sso", "status"])), "off\n");

    let pool = platform_store::connect(&fixture.url).await.unwrap();
    let client = pool.get().await.unwrap();
    let changes: i64 = client
        .query_one(
            "SELECT count(*) FROM audit_log WHERE action = 'settings.changed'
               AND detail->>'key' = 'sso.enabled' AND detail->'new' = 'false'::jsonb",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(changes, 1);
    drop(client);
    fixture.drop().await;
}
