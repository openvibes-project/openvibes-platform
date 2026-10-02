//! Small primitives for server-side browser sessions.

use std::fmt;

use axum::http::{HeaderMap, header};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::{
    digest,
    rand::{SecureRandom, SystemRandom},
};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

const SESSION_SECRET_BYTES: usize = 32;
const SESSION_IDLE_TIMEOUT_MS: u64 = 30 * 60 * 1_000;
const SESSION_ABSOLUTE_TIMEOUT_MS: u64 = 8 * 60 * 60 * 1_000;

// The password rules and Argon2id live in `platform-password`, shared with
// the rule signer (board #107).
pub use platform_password::{
    NormalizedPassword, PasswordError, PasswordHash, PasswordHashError, PasswordVerification,
    hash_password, verify_password,
};

/// Persisted timestamps used to enforce session idle and absolute expiry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionLifetime {
    created_at_ms: u64,
    last_seen_at_ms: u64,
}

impl SessionLifetime {
    /// Starts a session with the approved 30-minute idle and eight-hour absolute defaults.
    pub fn start(now_ms: u64) -> Self {
        Self {
            created_at_ms: now_ms,
            last_seen_at_ms: now_ms,
        }
    }

    /// Restores persisted timestamps, rejecting an impossible ordering.
    pub fn restore(created_at_ms: u64, last_seen_at_ms: u64) -> Option<Self> {
        (created_at_ms <= last_seen_at_ms).then_some(Self {
            created_at_ms,
            last_seen_at_ms,
        })
    }

    /// Returns the idle deadline, or `None` if adding the timeout overflows.
    pub fn idle_expires_at_ms(self) -> Option<u64> {
        self.last_seen_at_ms.checked_add(SESSION_IDLE_TIMEOUT_MS)
    }

    /// Returns the absolute deadline, or `None` if adding the timeout overflows.
    pub fn absolute_expires_at_ms(self) -> Option<u64> {
        self.created_at_ms.checked_add(SESSION_ABSOLUTE_TIMEOUT_MS)
    }

    /// Returns whether the session is active at `now_ms`.
    pub fn is_active_at(self, now_ms: u64) -> bool {
        now_ms >= self.last_seen_at_ms
            && self
                .idle_expires_at_ms()
                .is_some_and(|expires_at| now_ms < expires_at)
            && self
                .absolute_expires_at_ms()
                .is_some_and(|expires_at| now_ms < expires_at)
    }

    /// Refreshes activity for a currently active session.
    pub fn touch(&mut self, now_ms: u64) -> bool {
        if !self.is_active_at(now_ms) {
            return false;
        }
        self.last_seen_at_ms = now_ms;
        true
    }
}

/// Credentials presented by one request, selected before authentication.
#[derive(Debug)]
pub enum PresentedCredentials {
    /// No browser cookie or bearer token was provided.
    Anonymous,
    /// One syntactically valid browser session cookie was provided.
    Session(PresentedSecret),
    /// One bearer credential was provided without a session cookie.
    Bearer(PresentedSecret),
}

/// Secret credential bytes parsed from one request header.
pub struct PresentedSecret(String);

impl PresentedSecret {
    /// Returns the secret value for authentication against its stored digest.
    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

/// Computes the byte digest used by the console store for a presented session.
pub(crate) fn session_digest(secret: &str) -> [u8; 32] {
    let digest = digest::digest(&digest::SHA256, secret.as_bytes());
    let mut output = [0; 32];
    output.copy_from_slice(digest.as_ref());
    output
}

/// Derives a stable, session-bound synchronizer token and its storage digest.
/// The token is reproducible from the high-entropy session cookie so it never
/// needs to be stored in plaintext.
pub(crate) fn session_csrf(secret: &str) -> (String, [u8; 32]) {
    let mut input = b"openvibes-console-csrf-v1\0".to_vec();
    input.extend_from_slice(secret.as_bytes());
    let token = URL_SAFE_NO_PAD.encode(digest::digest(&digest::SHA256, &input).as_ref());
    let token_digest = session_digest(&token);
    input.zeroize();
    (token, token_digest)
}

pub(crate) fn named_cookie(
    headers: &HeaderMap,
    name: &str,
) -> Result<Option<PresentedSecret>, CredentialParseError> {
    let mut secret = None;
    for cookie_header in headers.get_all(header::COOKIE).iter() {
        let cookie_header = cookie_header
            .to_str()
            .map_err(|_| CredentialParseError::Invalid)?;
        for pair in cookie_header.split(';') {
            let Some((cookie_name, value)) = pair.trim().split_once('=') else {
                continue;
            };
            if cookie_name.trim() != name {
                continue;
            }
            let value = value.trim();
            if secret.is_some() || !valid_session_token(value) {
                return Err(CredentialParseError::Invalid);
            }
            secret = Some(PresentedSecret(value.to_owned()));
        }
    }
    Ok(secret)
}

impl Drop for PresentedSecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for PresentedSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PresentedSecret([REDACTED])")
    }
}

/// Invalid or conflicting credentials in request headers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CredentialParseError {
    /// A credential header is malformed, repeated, or contains an invalid session token.
    Invalid,
    /// The request supplied both a browser session cookie and a bearer token.
    Conflicting,
}

/// Parses one session cookie or one bearer token and rejects ambiguous input.
pub fn presented_credentials(
    headers: &HeaderMap,
) -> Result<PresentedCredentials, CredentialParseError> {
    let session = session_cookie_from_headers(headers)?;
    let mut authorization = headers.get_all(header::AUTHORIZATION).iter();
    let bearer = if let Some(value) = authorization.next() {
        if authorization.next().is_some() {
            return Err(CredentialParseError::Invalid);
        }
        let value = value.to_str().map_err(|_| CredentialParseError::Invalid)?;
        let (scheme, token) = value.split_once(' ').ok_or(CredentialParseError::Invalid)?;
        if !scheme.eq_ignore_ascii_case("bearer")
            || token.is_empty()
            || token.bytes().any(|byte| byte.is_ascii_whitespace())
        {
            return Err(CredentialParseError::Invalid);
        }
        Some(PresentedSecret(token.to_owned()))
    } else {
        None
    };

    match (session, bearer) {
        (Some(_), Some(_)) => Err(CredentialParseError::Conflicting),
        (Some(secret), None) => Ok(PresentedCredentials::Session(secret)),
        (None, Some(secret)) => Ok(PresentedCredentials::Bearer(secret)),
        (None, None) => Ok(PresentedCredentials::Anonymous),
    }
}

fn session_cookie_from_headers(
    headers: &HeaderMap,
) -> Result<Option<PresentedSecret>, CredentialParseError> {
    named_cookie(headers, "__Host-openvibes-session")
}

fn valid_session_token(value: &str) -> bool {
    if value.len() != 43 {
        return false;
    }
    URL_SAFE_NO_PAD.decode(value).is_ok_and(|bytes| {
        bytes.len() == SESSION_SECRET_BYTES && URL_SAFE_NO_PAD.encode(bytes) == value
    })
}

/// Newly generated opaque session secret and its database-safe SHA-256 digest.
///
/// The raw value is only for setting the browser cookie. Persist the `hash`
/// field instead. Debug output intentionally omits both values.
pub struct SessionSecret {
    value: String,
    hash: String,
}

impl SessionSecret {
    /// Generates a cryptographically random secret and its lowercase hex digest.
    pub fn generate() -> Result<Self, ring::error::Unspecified> {
        let mut bytes = [0; SESSION_SECRET_BYTES];
        SystemRandom::new().fill(&mut bytes)?;
        let value = URL_SAFE_NO_PAD.encode(bytes);
        let hash = hex(digest::digest(&digest::SHA256, value.as_bytes()).as_ref());
        Ok(Self { value, hash })
    }

    /// Returns the one-time value to place in the session cookie.
    pub fn cookie_value(&self) -> &str {
        &self.value
    }

    /// Returns the lowercase SHA-256 digest to persist instead of the secret.
    pub fn hash(&self) -> &str {
        &self.hash
    }
}

impl Drop for SessionSecret {
    fn drop(&mut self) {
        self.value.zeroize();
        self.hash.zeroize();
    }
}

impl fmt::Debug for SessionSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionSecret([REDACTED])")
    }
}

/// Builds the approved host-only session cookie value and attributes.
pub fn session_cookie(secret: &SessionSecret) -> String {
    format!(
        "__Host-openvibes-session={}; Secure; HttpOnly; SameSite=Lax; Path=/",
        secret.cookie_value()
    )
}

/// Checks the browser origin and rejects an explicitly cross-site request.
///
/// `configured_origin` must be the canonical external origin from validated
/// runtime configuration. Exactly one matching `Origin` header is required.
pub fn browser_origin_allowed(headers: &HeaderMap, configured_origin: &str) -> bool {
    let mut origins = headers.get_all(header::ORIGIN).iter();
    if origins.next().and_then(|value| value.to_str().ok()) != Some(configured_origin)
        || origins.next().is_some()
    {
        return false;
    }

    !headers
        .get_all("sec-fetch-site")
        .iter()
        .any(|value| value.as_bytes().eq_ignore_ascii_case(b"cross-site"))
}

/// Checks for exactly one matching synchronizer token in `X-CSRF-Token`.
pub fn csrf_token_matches(headers: &HeaderMap, expected: &str) -> bool {
    let mut values = headers.get_all("x-csrf-token").iter();
    let Some(provided) = values.next().map(axum::http::HeaderValue::as_bytes) else {
        return false;
    };
    if values.next().is_some() || provided.len() != expected.len() {
        return false;
    }
    bool::from(expected.as_bytes().ct_eq(provided))
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
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
        assert!(
            verify_password(&password, "$argon2id$v=19$m=4294967295,t=2,p=1$salt$hash").is_err()
        );
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
}
