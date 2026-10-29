//! The console's `ingest.*` settings over `ingest.toml`.

use std::collections::HashMap;

use openvibes_ingest::IngestConfig;
use serde_json::{Value, json};

fn file(database_url: &str) -> IngestConfig {
    let dir = std::env::temp_dir().join(format!("ov-ingest-stored-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    // Tests run in parallel: one file each.
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let path = dir.join(format!(
        "{}-ingest.toml",
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::write(
        &path,
        format!(
            r#"listen = "0.0.0.0:18423"
health_listen = "127.0.0.1:18480"
server_certificate_file = "/etc/openvibes/tls/ingest.crt"
server_key_file = "/etc/openvibes/tls/ingest.key"
client_ca_file = "/etc/openvibes/pki/intermediate.crt"
issuing_certificate_file = "/etc/openvibes/pki/intermediate.crt"
issuing_key_file = "/var/lib/openvibes-ingest/intermediate.key"
database_url = "{database_url}"
max_in_flight = 100
"#
        ),
    )
    .unwrap();
    openvibes_ingest::load_config(&path).unwrap()
}

fn stored(rows: &[(&str, Value)]) -> HashMap<String, Value> {
    rows.iter()
        .map(|(k, v)| ((*k).to_owned(), v.clone()))
        .collect()
}

#[test]
fn stored_values_win_over_the_file_and_the_rest_is_the_files() {
    let config = file("postgresql:///x").with_stored(&stored(&[
        ("ingest.client_certificate_days", json!(7)),
        ("ingest.max_inventory_in_flight", json!(8)),
        ("ingest.finding_retention_days", json!(30)),
        ("ingest.request_timeout_seconds", json!(20)),
        ("ingest.inventory_request_timeout_seconds", json!(300)),
        ("ingest.max_connections", json!(2048)),
    ]));
    assert_eq!(config.client_certificate_days, 7);
    assert_eq!(config.max_inventory_in_flight, 8);
    assert_eq!(config.finding_retention_days, 30);
    assert_eq!(config.request_timeout_seconds, 20);
    assert_eq!(config.inventory_request_timeout_seconds, 300);
    assert_eq!(config.max_connections, 2048);
    // not stored: the file's value
    assert_eq!(config.max_in_flight, 100);
    config.validate().unwrap();
}

#[test]
fn a_wrong_type_is_ignored_and_an_out_of_range_value_fails_validation() {
    let base = file("postgresql:///x");
    let ignored = base.with_stored(&stored(&[(
        "ingest.client_certificate_days",
        json!("many"),
    )]));
    assert_eq!(ignored.client_certificate_days, 30);
    let bad = base.with_stored(&stored(&[("ingest.client_certificate_days", json!(4000))]));
    assert!(bad.validate().is_err());
}

#[tokio::test]
async fn an_unreachable_database_leaves_the_file_as_it_is() {
    let config = file("postgresql://nobody@127.0.0.1:1/none")
        .with_console_settings()
        .await;
    assert_eq!(config.max_in_flight, 100);
}
