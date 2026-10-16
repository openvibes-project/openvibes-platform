//! Unit tests for credential parsing, passwords and session secrets.

use axum::http::{HeaderMap, HeaderValue, header};

use super::{
    CredentialParseError, NormalizedPassword, PasswordError, PresentedCredentials,
    SESSION_ABSOLUTE_TIMEOUT_MS, SESSION_IDLE_TIMEOUT_MS, SessionLifetime, SessionSecret,
    browser_origin_allowed, csrf_token_matches, hash_password, presented_credentials,
    session_cookie, session_csrf, session_digest, verify_password,
};

#[test]
fn session_cookie_is_opaque_and_only_the_digest_is_persistable() {
    let secret = SessionSecret::generate().unwrap();
    let cookie = session_cookie(&secret);
    assert!(cookie.starts_with("__Host-openvibes-session="));
    assert!(cookie.ends_with("; Secure; HttpOnly; SameSite=Lax; Path=/"));
    assert_eq!(secret.cookie_value().len(), 43);
    assert_eq!(secret.hash().len(), 64);
    assert!(!format!("{secret:?}").contains(secret.cookie_value()));
    assert_ne!(secret.hash(), secret.cookie_value());
}

#[test]
fn browser_origin_requires_one_exact_origin_and_rejects_cross_site_metadata() {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::ORIGIN,
        HeaderValue::from_static("https://console.example"),
    );
    assert!(browser_origin_allowed(&headers, "https://console.example"));
    assert!(!browser_origin_allowed(&headers, "https://other.example"));

    headers.insert("sec-fetch-site", HeaderValue::from_static("cross-site"));
    assert!(!browser_origin_allowed(&headers, "https://console.example"));
    headers.insert("sec-fetch-site", HeaderValue::from_static("same-origin"));
    assert!(browser_origin_allowed(&headers, "https://console.example"));

    headers.append(
        header::ORIGIN,
        HeaderValue::from_static("https://console.example"),
    );
    assert!(!browser_origin_allowed(&headers, "https://console.example"));
}

#[test]
fn csrf_token_requires_one_exact_constant_time_comparable_value() {
    let expected = "x".repeat(43);
    let mut headers = HeaderMap::new();
    assert!(!csrf_token_matches(&headers, &expected));
    headers.insert("x-csrf-token", HeaderValue::from_static("wrong"));
    assert!(!csrf_token_matches(&headers, &expected));
    headers.insert("x-csrf-token", HeaderValue::from_str(&expected).unwrap());
    assert!(csrf_token_matches(&headers, &expected));
    headers.append("x-csrf-token", HeaderValue::from_str(&expected).unwrap());
    assert!(!csrf_token_matches(&headers, &expected));
}

#[test]
fn session_csrf_is_stable_and_bound_to_one_cookie_secret() {
    let (token, stored_digest) = session_csrf("high-entropy-cookie-value");
    let (same_token, same_digest) = session_csrf("high-entropy-cookie-value");
    let (other_token, _) = session_csrf("another-cookie-value");
    assert_eq!(token, same_token);
    assert_eq!(stored_digest, same_digest);
    assert_ne!(token, other_token);
    assert_eq!(stored_digest, session_digest(&token));
    let mut headers = HeaderMap::new();
    headers.insert("x-csrf-token", HeaderValue::from_str(&token).unwrap());
    assert!(csrf_token_matches(&headers, &token));
}

#[test]
fn credential_selection_rejects_mixed_duplicate_and_malformed_credentials() {
    let secret = SessionSecret::generate().unwrap();
    let mut headers = HeaderMap::new();
    assert!(matches!(
        presented_credentials(&headers).unwrap(),
        PresentedCredentials::Anonymous
    ));

    headers.insert(
        header::COOKIE,
        HeaderValue::from_str(&format!(
            "theme=dark; __Host-openvibes-session={}",
            secret.cookie_value()
        ))
        .unwrap(),
    );
    let parsed = presented_credentials(&headers).unwrap();
    let PresentedCredentials::Session(parsed_secret) = parsed else {
        panic!("session cookie must be selected");
    };
    assert_eq!(parsed_secret.expose_secret(), secret.cookie_value());
    assert!(!format!("{parsed_secret:?}").contains(secret.cookie_value()));

    headers.insert(
        header::AUTHORIZATION,
        HeaderValue::from_static("bEaReR service-token"),
    );
    assert_eq!(
        presented_credentials(&headers).unwrap_err(),
        CredentialParseError::Conflicting
    );

    headers.remove(header::COOKIE);
    assert!(matches!(
        presented_credentials(&headers).unwrap(),
        PresentedCredentials::Bearer(_)
    ));
    headers.append(
        header::AUTHORIZATION,
        HeaderValue::from_static("Bearer another-token"),
    );
    assert_eq!(
        presented_credentials(&headers).unwrap_err(),
        CredentialParseError::Invalid
    );

    headers.remove(header::AUTHORIZATION);
    headers.insert(
        header::COOKIE,
        HeaderValue::from_static("__Host-openvibes-session=not-a-valid-token"),
    );
    assert_eq!(
        presented_credentials(&headers).unwrap_err(),
        CredentialParseError::Invalid
    );
}

#[test]
fn sessions_expire_on_idle_or_absolute_deadline_and_cannot_be_revived() {
    let now = 1_000_000;
    let mut idle = SessionLifetime::start(now);
    let idle_deadline = now + SESSION_IDLE_TIMEOUT_MS;
    assert!(idle.is_active_at(idle_deadline - 1));
    assert!(!idle.touch(idle_deadline));
    assert!(!idle.is_active_at(idle_deadline));

    let mut active = SessionLifetime::start(now);
    let absolute_deadline = now + SESSION_ABSOLUTE_TIMEOUT_MS;
    let mut last_seen = now;
    while last_seen + SESSION_IDLE_TIMEOUT_MS < absolute_deadline {
        last_seen += SESSION_IDLE_TIMEOUT_MS - 1;
        assert!(active.touch(last_seen));
    }
    assert!(active.is_active_at(absolute_deadline - 1));
    assert!(active.touch(absolute_deadline - 1));
    assert!(!active.is_active_at(absolute_deadline));
    assert!(!active.touch(absolute_deadline));
    assert!(SessionLifetime::restore(now + 1, now).is_none());
}

#[test]
fn password_validation_normalizes_and_enforces_code_point_bounds() {
    let composed = NormalizedPassword::new("é".repeat(15).as_str()).unwrap();
    let decomposed = NormalizedPassword::new("e\u{301}".repeat(15).as_str()).unwrap();
    assert_eq!(composed.as_bytes(), decomposed.as_bytes());
    assert!(NormalizedPassword::new("short").is_err());
    assert!(NormalizedPassword::new(&"x".repeat(129)).is_err());
    assert!(NormalizedPassword::new(&"x".repeat(4_097)).is_err());
    let spaced = NormalizedPassword::new(&format!(" {} ", "x".repeat(13))).unwrap();
    assert_eq!(spaced.as_bytes().first(), Some(&b' '));
    assert!(!format!("{composed:?}").contains("é"));
    assert!(matches!(
        NormalizedPassword::new("short"),
        Err(PasswordError::TooShort)
    ));
    assert!(matches!(
        NormalizedPassword::new("correct horse battery staple"),
        Err(PasswordError::CommonPassword)
    ));
    assert!(NormalizedPassword::new("Correct horse battery staple").is_ok());
}

#[test]
fn argon2id_hashes_verify_and_reject_unbounded_credentials() {
    let password = NormalizedPassword::new("correct horse battery").unwrap();
    let other = NormalizedPassword::new("different password phrase").unwrap();
    let hash = hash_password(&password).unwrap();
    assert!(hash.as_str().starts_with("$argon2id$v=19$m=19456,t=2,p=1$"));
    assert!(verify_password(&password, hash.as_str()).unwrap().valid);
    let wrong = verify_password(&other, hash.as_str()).unwrap();
    assert!(!wrong.valid);
    assert!(!wrong.needs_rehash);
    assert!(!format!("{hash:?}").contains(hash.as_str()));
    assert!(verify_password(&password, "$argon2id$v=19$m=4294967295,t=2,p=1$salt$hash").is_err());
}

#[test]
fn successful_verification_marks_below_floor_hashes_for_upgrade() {
    use argon2::{Algorithm, Argon2, Params, Version, password_hash::PasswordHasher};

    let password = NormalizedPassword::new("correct horse battery").unwrap();
    let old_params = Params::new(8, 1, 1, Some(32)).unwrap();
    let old_hasher = Argon2::new(Algorithm::Argon2id, Version::V0x13, old_params);
    let old_hash = old_hasher
        .hash_password(password.as_bytes())
        .unwrap()
        .to_string();
    let result = verify_password(&password, &old_hash).unwrap();
    assert!(result.valid);
    assert!(result.needs_rehash);
}
