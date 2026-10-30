use chrono::{Duration, Utc};

use super::certificates::summaries;
use super::service_provider::{addresses, xml_attribute};

fn certificate() -> String {
    platform_pki::generate_root(Utc::now())
        .expect("root")
        .cert_pem
}

#[test]
fn no_certificate_is_an_empty_list() {
    assert!(summaries("", Utc::now(), true).expect("empty").is_empty());
}

#[test]
fn a_certificate_shows_its_fingerprint_and_dates() {
    let views = summaries(&certificate(), Utc::now(), true).expect("one");
    assert_eq!(views.len(), 1);
    assert_eq!(views[0].fingerprint.split(':').count(), 32);
    assert!(!views[0].expired);
}

#[test]
fn two_different_certificates_are_kept_and_the_same_twice_is_refused() {
    let (a, b) = (certificate(), certificate());
    assert_eq!(
        summaries(&format!("{a}\n{b}"), Utc::now(), true)
            .expect("two")
            .len(),
        2
    );
    let twice = summaries(&format!("{a}\n{a}"), Utc::now(), true).expect_err("twice");
    assert!(twice.contains("twice"), "{twice}");
}

#[test]
fn an_unreadable_or_expired_certificate_is_refused() {
    let broken = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----";
    assert!(
        summaries(broken, Utc::now(), true)
            .expect_err("broken")
            .contains("cannot be read")
    );
    let later = Utc::now() + Duration::days(365 * 100);
    let pem = certificate();
    assert!(
        summaries(&pem, later, true)
            .expect_err("expired")
            .contains("expired")
    );
    // a stored one that has expired since is still listed, marked
    let listed = summaries(&pem, later, false).expect("listed");
    assert!(listed[0].expired);
}

#[test]
fn our_addresses_come_from_the_public_origin() {
    let ours = addresses("https://vibes.example/");
    assert_eq!(ours.entity_id, "https://vibes.example/auth/saml/metadata");
    assert_eq!(ours.acs_url, "https://vibes.example/auth/saml/acs");
}

#[test]
fn xml_attributes_are_escaped() {
    assert_eq!(xml_attribute("a&b\"<>"), "a&amp;b&quot;&lt;&gt;");
}

#[test]
fn indented_pasted_lines_are_read() {
    let indented: String = certificate()
        .lines()
        .map(|l| format!("    {l}\n"))
        .collect();
    assert_eq!(
        summaries(&indented, Utc::now(), true)
            .expect("indented")
            .len(),
        1
    );
}

#[test]
fn the_switch_needs_a_certificate_that_has_not_expired() {
    use serde_json::json;
    use std::collections::HashMap;
    let pem = certificate();
    let stored: HashMap<String, serde_json::Value> = HashMap::from([
        ("sso.idp_entity_id".into(), json!("https://idp.example")),
        ("sso.idp_sso_url".into(), json!("https://idp.example/sso")),
        ("sso.idp_certificates".into(), json!(pem)),
    ]);
    let on = json!(true);
    assert!(super::change::check_change_at(&stored, "sso.enabled", &on, Utc::now()).is_ok());
    let later = Utc::now() + Duration::days(365 * 100);
    let refused =
        super::change::check_change_at(&stored, "sso.enabled", &on, later).expect_err("expired");
    assert!(refused.contains("expired"), "{refused}");
}

fn settings(pem: &str, enabled: bool) -> std::collections::HashMap<String, serde_json::Value> {
    use serde_json::json;
    std::collections::HashMap::from([
        ("sso.enabled".into(), json!(enabled)),
        ("sso.idp_entity_id".into(), json!("https://idp.example")),
        ("sso.idp_sso_url".into(), json!("https://idp.example/sso")),
        ("sso.idp_certificates".into(), json!(pem)),
    ])
}

#[test]
fn sign_in_needs_everything_and_ignores_an_expired_certificate() {
    use super::provider::config;
    let pem = certificate();
    assert!(config(&settings(&pem, true), Utc::now()).is_some());
    assert!(config(&settings(&pem, false), Utc::now()).is_none());
    let later = Utc::now() + Duration::days(365 * 100);
    assert!(config(&settings(&pem, true), later).is_none());
    for key in [
        "sso.idp_entity_id",
        "sso.idp_sso_url",
        "sso.idp_certificates",
    ] {
        let mut stored = settings(&pem, true);
        stored.remove(key);
        assert!(config(&stored, Utc::now()).is_none(), "{key}");
    }
    // one expired and one current: only the current one counts
    let two = format!("{pem}\n{}", certificate());
    let bodies = super::certificates::current_bodies(&two, Utc::now());
    assert_eq!(bodies.len(), 2);
    assert!(super::certificates::current_bodies(&two, later).is_empty());
}

#[test]
fn indented_certificates_are_trimmed_when_checking_a_response() {
    let indented: String = certificate()
        .lines()
        .map(|l| format!("    {l}\n"))
        .collect();
    let bodies = super::certificates::current_bodies(&indented, Utc::now());
    assert_eq!(bodies.len(), 1);
    assert!(!bodies[0].contains(char::is_whitespace) && !bodies[0].contains('-'));
}
