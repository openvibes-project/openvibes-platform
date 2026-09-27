//! `[assistant]` configuration rules (spec §3, §7, §8): off by default,
//! loopback-only plain HTTP, explicit consent and declaration for anything
//! remote, owner-only secrets, bounded numbers.

mod support;

use std::time::Duration;

use platform_assistant::{AssistantConfig, ConfigError, Location, LookupMode, Profile};
use support::{assistant, scratch, write};

fn backend_toml(url: &str, extra: &str) -> String {
    format!("enabled = true\n[backend]\nurl = \"{url}\"\nmodel = \"qwen3.5-4b\"\n{extra}")
}

#[test]
fn off_by_default_and_needs_a_backend_when_on() {
    let empty = assistant("").unwrap();
    assert!(!empty.enabled);
    assert!(empty.backend.is_none());
    assert_eq!(empty.profile, Profile::Small);
    assert_eq!(empty.lookup_mode, LookupMode::Auto);
    assert_eq!(empty.conversation_retention_days, 30);
    assert_eq!(empty.max_lookups, 4);
    assert_eq!(
        assistant("enabled = true").unwrap_err(),
        ConfigError::MissingBackend
    );
    // Unknown keys fail loudly.
    assert!(toml::from_str::<AssistantConfig>("enabeld = true").is_err());
    assert!(
        toml::from_str::<AssistantConfig>(&backend_toml("http://127.0.0.1:8080/v1", "urll = 1"))
            .is_err()
    );
}

#[test]
fn loopback_backends_are_local_and_may_use_plain_http() {
    for url in [
        "http://127.0.0.1:8080/v1",
        "http://127.0.0.2:8080/v1",
        "http://[::1]:8080/v1",
        "http://localhost:8080/v1",
        "https://localhost/v1",
    ] {
        let backend = assistant(&backend_toml(url, "")).unwrap().backend.unwrap();
        assert_eq!(backend.location, Location::Local, "{url}");
        assert_eq!(backend.concurrency, 1);
        assert_eq!(backend.deadline, Duration::from_secs(60));
        assert!(!backend.pseudonymize);
        assert_eq!(backend.base_url, url);
    }
    // Remote-only settings are refused on loopback rather than ignored.
    for extra in [
        "data_location = \"external\"",
        "proxy_url = \"http://proxy.example:3128\"",
    ] {
        assert_eq!(
            assistant(&backend_toml("http://127.0.0.1:8080/v1", extra)).unwrap_err(),
            ConfigError::RemoteSettingOnLocal,
            "{extra}"
        );
    }
}

#[test]
fn a_remote_backend_needs_https_consent_and_a_declared_location() {
    let url = "https://gpu.example:8000/v1";
    assert_eq!(
        assistant(&backend_toml(
            "http://gpu.example:8000/v1",
            "allow_remote = true\ndata_location = \"own-network\""
        ))
        .unwrap_err(),
        ConfigError::PlainHttpRemote
    );
    assert_eq!(
        assistant(&backend_toml(url, "data_location = \"own-network\"")).unwrap_err(),
        ConfigError::RemoteNotAllowed
    );
    assert_eq!(
        assistant(&backend_toml(url, "allow_remote = true")).unwrap_err(),
        ConfigError::DataLocationRequired
    );
    // An own-network server must be trusted through the operator's CA.
    assert_eq!(
        assistant(&backend_toml(
            url,
            "allow_remote = true\ndata_location = \"own-network\""
        ))
        .unwrap_err(),
        ConfigError::CaRequired
    );
    let dir = scratch("remote");
    let ca = write(&dir, "ca.pem", &support::pki().root_pem, 0o644);
    let own = assistant(&backend_toml(
        url,
        &format!("allow_remote = true\ndata_location = \"own-network\"\nca_file = {ca:?}"),
    ))
    .unwrap()
    .backend
    .unwrap();
    assert_eq!(own.location, Location::OwnNetwork);
    assert_eq!(own.concurrency, 4);
    assert_eq!(own.deadline, Duration::from_secs(120));
    assert!(!own.pseudonymize);
    // An external provider may use public roots; pseudonymization defaults on.
    let external = assistant(&backend_toml(
        "https://api.provider.example/v1",
        "allow_remote = true\ndata_location = \"external\"",
    ))
    .unwrap()
    .backend
    .unwrap();
    assert_eq!(external.location, Location::External);
    assert!(external.pseudonymize);
    let opted_out = assistant(&backend_toml(
        "https://api.provider.example/v1",
        "allow_remote = true\ndata_location = \"external\"\npseudonymize = false",
    ))
    .unwrap()
    .backend
    .unwrap();
    assert!(!opted_out.pseudonymize);
}

#[test]
fn malformed_urls_are_refused() {
    for url in [
        "ftp://127.0.0.1/v1",
        "127.0.0.1:8080/v1",
        "http://127.0.0.1:8080/v1/",
        "http://user:pw@127.0.0.1:8080/v1",
        "http://127.0.0.1:8080/v1?x=1",
        "http://127.0.0.1:8080/v1#x",
        "http://:8080/v1",
        "http://127.0.0.1:0/v1",
        "http://127.0.0.1:99999/v1",
        "http://127.0.0.1:port/v1",
        "http://[::1/v1",
        "http://127.0.0.1:8080/v 1",
    ] {
        assert_eq!(
            assistant(&backend_toml(url, "")).unwrap_err(),
            ConfigError::InvalidUrl,
            "{url}"
        );
    }
}

#[test]
fn secrets_must_be_absolute_owner_only_and_well_formed() {
    let dir = scratch("secrets");
    let url = "http://127.0.0.1:8080/v1";
    assert_eq!(
        assistant(&backend_toml(url, "api_key_file = \"key.txt\"")).unwrap_err(),
        ConfigError::RelativePath
    );
    let good = write(&dir, "good", "sk-local-123\n", 0o600);
    assert!(assistant(&backend_toml(url, &format!("api_key_file = {good:?}"))).is_ok());
    #[cfg(unix)]
    {
        let loose = write(&dir, "loose", "sk-local-123\n", 0o640);
        assert_eq!(
            assistant(&backend_toml(url, &format!("api_key_file = {loose:?}"))).unwrap_err(),
            ConfigError::SecretFileInsecure
        );
    }
    for (name, text) in [
        ("empty", ""),
        ("blank", " \n"),
        ("two-words", "a b\n"),
        ("control", "a\u{1}b"),
    ] {
        let path = write(&dir, name, text, 0o600);
        assert_eq!(
            assistant(&backend_toml(url, &format!("api_key_file = {path:?}"))).unwrap_err(),
            ConfigError::FileInvalid,
            "{name}"
        );
    }
    assert_eq!(
        assistant(&backend_toml(
            url,
            &format!("api_key_file = {:?}", dir.join("absent"))
        ))
        .unwrap_err(),
        ConfigError::FileInvalid
    );
    assert_eq!(
        assistant(&backend_toml(url, &format!("api_key_file = {dir:?}"))).unwrap_err(),
        ConfigError::FileInvalid,
        "a directory"
    );
    // The key never appears in debug output.
    let backend = assistant(&backend_toml(url, &format!("api_key_file = {good:?}")))
        .unwrap()
        .backend
        .unwrap();
    assert!(!format!("{backend:?}").contains("sk-local-123"));
}

#[test]
fn a_client_identity_needs_both_files_and_https() {
    let dir = scratch("identity");
    let cert = write(&dir, "client.crt", "cert", 0o644);
    let key = write(&dir, "client.key", "key", 0o600);
    let both = format!("client_certificate_file = {cert:?}\nclient_key_file = {key:?}");
    assert!(assistant(&backend_toml("https://127.0.0.1:8443/v1", &both)).is_ok());
    assert_eq!(
        assistant(&backend_toml("http://127.0.0.1:8080/v1", &both)).unwrap_err(),
        ConfigError::ClientIdentityIncomplete,
        "never over plain HTTP"
    );
    assert_eq!(
        assistant(&backend_toml(
            "https://127.0.0.1:8443/v1",
            &format!("client_certificate_file = {cert:?}")
        ))
        .unwrap_err(),
        ConfigError::ClientIdentityIncomplete
    );
    #[cfg(unix)]
    {
        let loose = write(&dir, "loose.key", "key", 0o644);
        assert_eq!(
            assistant(&backend_toml(
                "https://127.0.0.1:8443/v1",
                &format!("client_certificate_file = {cert:?}\nclient_key_file = {loose:?}")
            ))
            .unwrap_err(),
            ConfigError::SecretFileInsecure
        );
    }
}

#[test]
fn numbers_and_names_are_bounded() {
    let url = "http://127.0.0.1:8080/v1";
    for (setting, name) in [
        ("max_lookups = 0", "max_lookups"),
        ("max_lookups = 9", "max_lookups"),
        (
            "conversation_retention_days = 0",
            "conversation_retention_days",
        ),
        (
            "questions_per_user_per_hour = 0",
            "questions_per_user_per_hour",
        ),
        ("concurrency = 0", "concurrency"),
        ("concurrency = 65", "concurrency"),
    ] {
        let toml = format!("{setting}\n{}", backend_toml(url, ""));
        assert_eq!(
            assistant(&toml).unwrap_err(),
            ConfigError::OutOfRange(name),
            "{setting}"
        );
    }
    for deadline in ["deadline_seconds = 1", "deadline_seconds = 601"] {
        assert_eq!(
            assistant(&backend_toml(url, deadline)).unwrap_err(),
            ConfigError::OutOfRange("deadline_seconds")
        );
    }
    // TOML string literals: empty, blank, and a control character.
    for model in [r#""""#, r#""   ""#, r#""a\u0007b""#] {
        let toml = format!("enabled = true\n[backend]\nurl = \"{url}\"\nmodel = {model}\n");
        assert_eq!(
            assistant(&toml).unwrap_err(),
            ConfigError::InvalidModel,
            "{model:?}"
        );
    }
    let profiled = assistant(&format!(
        "profile = \"large\"\nlookup_mode = \"json_schema\"\n{}",
        backend_toml(url, "")
    ))
    .unwrap();
    assert_eq!(profiled.profile, Profile::Large);
    assert_eq!(profiled.profile.budget().prompt_tokens, 32_000);
    assert_eq!(profiled.lookup_mode, LookupMode::JsonSchema);
}

#[test]
fn errors_name_the_setting_never_its_value() {
    let dir = scratch("messages");
    let path = write(&dir, "secret-key", "sk-should-not-leak\n", 0o644);
    let error = assistant(&backend_toml(
        "http://127.0.0.1:8080/v1",
        &format!("api_key_file = {path:?}"),
    ))
    .unwrap_err();
    let text = error.to_string();
    assert!(
        !text.contains("sk-should-not-leak") && !text.contains("secret-key"),
        "{text}"
    );
}
