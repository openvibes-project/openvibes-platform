//! The console's assistant settings over the configuration file.

use std::collections::HashMap;

use platform_assistant::{AssistantConfig, Location, Profile};
use serde_json::{Value, json};

use super::stored::{overlay, resolve};

fn stored(pairs: &[(&str, Value)]) -> HashMap<String, Value> {
    pairs
        .iter()
        .map(|(key, value)| ((*key).to_owned(), value.clone()))
        .collect()
}

fn file(value: Value) -> AssistantConfig {
    serde_json::from_value(value).unwrap()
}

#[test]
fn without_stored_settings_the_file_is_unchanged() {
    assert!(overlay(None, &stored(&[("vulns.proxy_url", json!("http://p:1"))])).is_none());
    let config = file(
        json!({"enabled": true, "max_lookups": 2, "backend": {"url": "http://127.0.0.1:8080/v1", "model": "m"}}),
    );
    let same = overlay(Some(&config), &stored(&[])).unwrap();
    assert_eq!(same.max_lookups, Some(2));
    assert!(same.enabled);
}

#[test]
fn a_stored_setting_wins_and_the_rest_keeps_the_files_value() {
    let config = file(
        json!({"enabled": true, "max_lookups": 2, "profile": "large", "backend": {"url": "http://127.0.0.1:8080/v1", "model": "file-model", "ca_file": "/etc/ca.pem"}}),
    );
    let merged = overlay(
        Some(&config),
        &stored(&[
            ("assistant.max_lookups", json!(5)),
            ("assistant.backend.model", json!("stored-model")),
            ("assistant.backend.pseudonymize", json!("on")),
        ]),
    )
    .unwrap();
    assert_eq!(merged.max_lookups, Some(5));
    assert_eq!(merged.profile, Profile::Large);
    let backend = merged.backend.unwrap();
    assert_eq!(backend.model, "stored-model");
    assert_eq!(backend.url, "http://127.0.0.1:8080/v1");
    assert_eq!(backend.pseudonymize, Some(true));
    assert_eq!(backend.ca_file.unwrap().to_str(), Some("/etc/ca.pem"));
}

#[test]
fn settings_alone_can_turn_the_assistant_on() {
    let settings = stored(&[
        ("assistant.enabled", json!(true)),
        ("assistant.backend.url", json!("http://127.0.0.1:8080/v1")),
        ("assistant.backend.model", json!("qwen")),
        ("assistant.profile", json!("medium")),
        ("assistant.lookup_mode", json!("json_schema")),
    ]);
    let assistant = resolve(None, &settings, Some("key-1".into()))
        .unwrap()
        .unwrap();
    let backend = assistant.backend.unwrap();
    assert_eq!(backend.model, "qwen");
    assert_eq!(backend.location, Location::Local);
    assert_eq!(assistant.profile, Profile::Medium);
    assert!(format!("{backend:?}").contains("[REDACTED]"));
}

#[test]
fn off_means_no_assistant() {
    let settings = stored(&[("assistant.enabled", json!(false))]);
    assert!(resolve(None, &settings, None).unwrap().is_none());
}

#[test]
fn settings_that_fail_the_assistants_rules_leave_it_off() {
    // plain http to another host is refused by the assistant's own rules
    let config = file(
        json!({"enabled": true, "backend": {"url": "http://127.0.0.1:8080/v1", "model": "file-model"}}),
    );
    let settings = stored(&[("assistant.backend.url", json!("http://llm.example/v1"))]);
    assert!(resolve(Some(&config), &settings, None).unwrap().is_none());
    // enabled without a backend, from settings alone
    let settings = stored(&[("assistant.enabled", json!(true))]);
    assert!(resolve(None, &settings, None).unwrap().is_none());
}

#[test]
fn a_restriction_set_in_the_console_is_never_undone_by_a_looser_file() {
    let config = file(
        json!({"enabled": true, "backend": {"url": "https://llm.example/v1", "model": "m", "allow_remote": true, "data_location": "external"}}),
    );
    assert!(
        resolve(Some(&config), &stored(&[]), None)
            .unwrap()
            .is_some()
    );
    // switching "allow a backend off this host" off must not fall back to the file
    let settings = stored(&[("assistant.backend.allow_remote", json!(false))]);
    assert!(resolve(Some(&config), &settings, None).unwrap().is_none());
}

#[test]
fn an_invalid_file_with_nothing_stored_is_still_an_error() {
    let config = file(json!({"enabled": true}));
    assert!(resolve(Some(&config), &stored(&[]), None).is_err());
}

#[test]
fn a_remote_backend_needs_its_declarations() {
    let settings = stored(&[
        ("assistant.enabled", json!(true)),
        ("assistant.backend.url", json!("https://llm.example/v1")),
        ("assistant.backend.model", json!("m")),
        ("assistant.backend.allow_remote", json!(true)),
        ("assistant.backend.data_location", json!("external")),
    ]);
    let assistant = resolve(None, &settings, None).unwrap().unwrap();
    assert_eq!(assistant.backend.unwrap().location, Location::External);
}
