use serde_json::json;

use super::*;

fn base() -> VulnsConfig {
    VulnsConfig {
        database_url: "postgresql:///openvibes".into(),
        health_listen: "127.0.0.1:18483".parse().unwrap(),
        check_interval_minutes: 60,
        metalink_url: crate::fetch::FEDORA_METALINK.into(),
        arch: "x86_64".into(),
        proxy_url: Some("http://file-proxy:3128".into()),
        max_download_bytes: 64 << 20,
        kev_url: crate::fetch::KEV_URL.into(),
        epss_url: crate::fetch::EPSS_URL.into(),
        nvd_url: crate::sources::NVD_URL.into(),
        nvd_api_key_file: None,
        euvd_url: crate::sources::EUVD_URL.into(),
        osv_url: crate::osv_fetch::OSV_URL.into(),
        osv_dir: "/var/lib/openvibes-vulns".into(),
        osv_max_download_bytes: 2 << 30,
    }
}

fn stored(rows: &[(&str, Value)]) -> Stored {
    Stored {
        values: rows
            .iter()
            .map(|(k, v)| ((*k).to_owned(), v.clone()))
            .collect(),
        nvd_key: None,
    }
}

#[test]
fn nothing_stored_leaves_the_file_as_it_is() {
    let file = base();
    let config = overlay(&file, &Stored::default());
    assert_eq!(config.proxy_url, file.proxy_url);
    assert_eq!(config.check_interval_minutes, 60);
    assert_eq!(config.max_download_bytes, 64 << 20);
}

#[test]
fn stored_values_win_over_the_file_and_mib_become_bytes() {
    let config = overlay(
        &base(),
        &stored(&[
            ("vulns.check_interval_minutes", json!(30)),
            ("vulns.max_download_mib", json!(10)),
            ("vulns.osv_max_download_mib", json!(512)),
            ("vulns.arch", json!("aarch64")),
            ("vulns.kev_url", json!("")),
            ("vulns.proxy_url", json!("http://proxy.example:3128")),
        ]),
    );
    assert_eq!(config.check_interval_minutes, 30);
    assert_eq!(config.max_download_bytes, 10 << 20);
    assert_eq!(config.osv_max_download_bytes, 512 << 20);
    assert_eq!(config.arch, "aarch64");
    assert_eq!(config.kev_url, "");
    assert_eq!(
        config.proxy_url.as_deref(),
        Some("http://proxy.example:3128")
    );
    config.validate().unwrap();
}

#[test]
fn an_empty_proxy_turns_the_files_proxy_off() {
    let config = overlay(&base(), &stored(&[("vulns.proxy_url", json!(""))]));
    assert_eq!(config.proxy_url, None);
}

#[test]
fn a_wrong_type_is_ignored_and_a_bad_value_fails_validation() {
    let config = overlay(
        &base(),
        &stored(&[("vulns.check_interval_minutes", json!("fast"))]),
    );
    assert_eq!(config.check_interval_minutes, 60);
    let bad = overlay(
        &base(),
        &stored(&[("vulns.check_interval_minutes", json!(5))]),
    );
    assert!(bad.validate().is_err());
}

#[test]
fn only_the_vulns_prefix_and_the_key_are_kept() {
    assert!(platform_settings::vulns_keys::PREFIX.starts_with("vulns"));
    let with_key = Stored {
        values: HashMap::new(),
        nvd_key: Some("k".into()),
    };
    assert_eq!(with_key.nvd_key(), Some("k"));
    assert_ne!(with_key, Stored::default());
}
