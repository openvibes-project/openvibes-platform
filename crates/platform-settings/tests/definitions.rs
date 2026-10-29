use platform_settings::{Kind, all, find};
use serde_json::json;

#[test]
fn keys_are_unique_and_shaped_like_the_table_allows() {
    let keys: Vec<&str> = all().map(|d| d.key).collect();
    for key in &keys {
        // console_settings.key: ^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$
        assert!(key.contains('.'), "{key}");
        assert!(
            key.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'.'),
            "{key}"
        );
        assert!(key.as_bytes()[0].is_ascii_lowercase(), "{key}");
    }
    let mut sorted = keys.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), keys.len());
}

#[test]
fn every_default_passes_its_own_check() {
    for definition in all().filter(|d| !d.is_secret()) {
        assert_eq!(
            definition.check(&definition.default_value()),
            Ok(()),
            "{}",
            definition.key
        );
    }
}

#[test]
fn a_secret_has_no_default_and_must_be_one_clean_line() {
    let key = find("vulns.nvd_api_key").unwrap();
    assert!(matches!(key.kind, Kind::Secret));
    assert!(key.default_value().is_null());
    assert!(key.check(&json!("abc-123")).is_ok());
    for bad in [
        json!(""),
        json!("a b"),
        json!("a\nb"),
        json!("kéy"),
        json!("x".repeat(513)),
        json!(7),
    ] {
        assert!(key.check(&bad).is_err(), "{bad}");
    }
}

#[test]
fn urls_must_be_https_or_empty_where_empty_turns_the_source_off() {
    let kev = find("vulns.kev_url").unwrap();
    for good in [
        "",
        "https://example.org/kev.json",
        "http://127.0.0.1:8080/x",
        "http://localhost/x",
    ] {
        assert!(kev.check(&json!(good)).is_ok(), "{good}");
    }
    for bad in [
        "http://example.org/x",
        "ftp://x",
        "https://",
        "https://a b",
        "example.org",
        "http://127.0.0.1.evil.org/x",
    ] {
        assert!(kev.check(&json!(bad)).is_err(), "{bad}");
    }
    let mirror = find("vulns.metalink_url").unwrap();
    assert!(mirror.check(&json!("")).is_err());
}

#[test]
fn the_proxy_may_be_empty_or_http() {
    let proxy = find("vulns.proxy_url").unwrap();
    for good in ["", "http://proxy.example:3128", "https://proxy.example"] {
        assert!(proxy.check(&json!(good)).is_ok(), "{good}");
    }
    assert!(proxy.check(&json!("socks5://p:1")).is_err());
}

#[test]
fn the_interval_and_sizes_have_ranges() {
    let every = find("vulns.check_interval_minutes").unwrap();
    assert!(every.check(&json!(15)).is_ok() && every.check(&json!(1440)).is_ok());
    assert!(every.check(&json!(14)).is_err() && every.check(&json!(1441)).is_err());
    assert!(every.check(&json!("60")).is_err());
    assert!(find("vulns.arch").unwrap().check(&json!("x86 64")).is_err());
    assert!(find("vulns.arch").unwrap().check(&json!("aarch64")).is_ok());
}

#[test]
fn the_consoles_own_settings_are_still_there() {
    assert!(find("suppressions.require_approval").is_some());
    assert!(
        find("sso.remove_inactive_days")
            .unwrap()
            .check(&json!(3651))
            .is_err()
    );
}

#[test]
fn an_address_may_not_carry_a_user_name_and_password() {
    let proxy = find("vulns.proxy_url").unwrap();
    assert!(proxy.check(&json!("http://proxy.example:3128")).is_ok());
    for bad in [
        "http://user:pass@proxy.example:3128",
        "https://u@proxy.example",
    ] {
        assert!(proxy.check(&json!(bad)).is_err(), "{bad}");
    }
    let kev = find("vulns.kev_url").unwrap();
    assert!(
        kev.check(&json!("https://user:pw@example.org/kev.json"))
            .is_err()
    );
    // an @ in the path is not credentials
    assert!(kev.check(&json!("https://example.org/a@b.json")).is_ok());
}
