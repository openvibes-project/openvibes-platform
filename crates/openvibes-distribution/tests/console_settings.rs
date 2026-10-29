//! The console's `distribution.*` settings over `distribution.toml`.

use std::collections::HashMap;

use openvibes_distribution::DistributionConfig;
use serde_json::{Value, json};

fn file(database_url: &str) -> DistributionConfig {
    let dir = std::env::temp_dir().join(format!("ov-dist-stored-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    // Tests run in parallel: one file each.
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let path = dir.join(format!(
        "{}-distribution.toml",
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::write(
        &path,
        format!(
            r#"listen = "0.0.0.0:18424"
health_listen = "127.0.0.1:18481"
server_certificate_file = "/etc/openvibes/tls/distribution.crt"
server_key_file = "/etc/openvibes/tls/distribution.key"
client_ca_file = "/etc/openvibes/pki/intermediate.crt"
database_url = "{database_url}"
max_in_flight = 100
"#
        ),
    )
    .unwrap();
    openvibes_distribution::load_config(&path).unwrap()
}

fn stored(rows: &[(&str, Value)]) -> HashMap<String, Value> {
    rows.iter()
        .map(|(k, v)| ((*k).to_owned(), v.clone()))
        .collect()
}

#[test]
fn stored_values_win_over_the_file_and_the_rest_is_the_files() {
    let config = file("postgresql:///x").with_stored(&stored(&[
        ("distribution.request_timeout_seconds", json!(30)),
        ("distribution.max_connections", json!(512)),
    ]));
    assert_eq!(config.request_timeout_seconds, 30);
    assert_eq!(config.max_connections, 512);
    assert_eq!(config.max_in_flight, 100);
    config.validate().unwrap();
}

#[test]
fn a_wrong_type_is_ignored_and_an_out_of_range_value_fails_validation() {
    let base = file("postgresql:///x");
    let ignored = base.with_stored(&stored(&[("distribution.max_connections", json!("many"))]));
    assert_eq!(ignored.max_connections, 1024);
    let bad = base.with_stored(&stored(&[(
        "distribution.request_timeout_seconds",
        json!(0),
    )]));
    assert!(bad.validate().is_err());
}

#[tokio::test]
async fn an_unreachable_database_leaves_the_file_as_it_is() {
    let config = file("postgresql://nobody@127.0.0.1:1/none")
        .with_console_settings()
        .await;
    assert_eq!(config.max_in_flight, 100);
}
