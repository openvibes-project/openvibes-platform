//! Small primitives for server-side browser sessions.

use std::fmt;

use argon2::{
    Algorithm, Argon2, Params, Version,
    password_hash::{PasswordHasher, PasswordVerifier, phc::PasswordHash as PhcPasswordHash},
};
use axum::http::{HeaderMap, header};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::{
    digest,
    rand::{SecureRandom, SystemRandom},
};
use subtle::ConstantTimeEq;
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroize;

const SESSION_SECRET_BYTES: usize = 32;
const SESSION_IDLE_TIMEOUT_MS: u64 = 30 * 60 * 1_000;
const SESSION_ABSOLUTE_TIMEOUT_MS: u64 = 8 * 60 * 60 * 1_000;
// ponytail: normalization accepts at most 4,096 raw code points to bound CPU and allocation.
const MAX_RAW_PASSWORD_CODE_POINTS: usize = 4_096;
const MIN_PASSWORD_CODE_POINTS: usize = 15;
const MAX_PASSWORD_CODE_POINTS: usize = 128;
// ponytail: small local list rejects famous weak passphrases; add a reviewed breach corpus before production login.
const BLOCKED_PASSWORDS: &[&str] = &[
    "correct horse battery staple",
    "correcthorsebatterystaple",
    "passwordpassword",
    "password1234567",
    "password123456789",
    "password123!@#1",
    "qwertyuiopasdfghjkl",
    "qwerty1234567890",
    "123456789012345",
    "1234567890123456",
    "12345678901234567890",
    "letmeinletmein1",
    "iloveyouiloveyou",
    "changemechangeme",
    "adminadminadmin",
    "welcomehome1234",
    "monkeymonkey123",
    "trustno1trustno1",
    "dragon-dragon-dragon",
    "superman12345678",
    "footballfootball",
    "baseballbaseball",
    "sunshinesunshinesunshine",
    "michaelmichael123",
];
// OWASP Password Storage Cheat Sheet floor for Argon2id: 19 MiB, t=2, p=1.
const ARGON2_MEMORY_KIB: u32 = 19_456;
const ARGON2_ITERATIONS: u32 = 2;
const ARGON2_PARALLELISM: u32 = 1;
const ARGON2_MAX_MEMORY_KIB: u32 = 65_536;
const ARGON2_MAX_ITERATIONS: u32 = 5;
const ARGON2_MAX_PARALLELISM: u32 = 4;
const MAX_PASSWORD_HASH_LENGTH: usize = 512;

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

/// An NFC-normalized password that is cleared when dropped.
pub struct NormalizedPassword(String);

impl NormalizedPassword {
    /// Normalizes and validates a password without trimming or truncating it.
    pub fn new(password: &str) -> Result<Self, PasswordError> {
        if password.chars().count() > MAX_RAW_PASSWORD_CODE_POINTS {
            return Err(PasswordError::TooLong);
        }

        let mut normalized: String = password.nfc().collect();
        let length = normalized.chars().count();
        if length < MIN_PASSWORD_CODE_POINTS {
            normalized.zeroize();
            return Err(PasswordError::TooShort);
        }
        if length > MAX_PASSWORD_CODE_POINTS {
            normalized.zeroize();
            return Err(PasswordError::TooLong);
        }
        if BLOCKED_PASSWORDS.contains(&normalized.as_str()) {
            normalized.zeroize();
            return Err(PasswordError::CommonPassword);
        }
        Ok(Self(normalized))
    }

    /// Returns normalized UTF-8 bytes for a password-hashing operation.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl Drop for NormalizedPassword {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for NormalizedPassword {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("NormalizedPassword([REDACTED])")
    }
}

/// Rejection reason from local password length validation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PasswordError {
    /// Fewer than 15 Unicode code points after NFC normalization.
    TooShort,
    /// More than 128 normalized code points, or more than 4,096 raw code points.
    TooLong,
    /// The password exactly matches a locally blocked common choice.
    CommonPassword,
}

/// PHC-formatted Argon2id credential that redacts debug output.
pub struct PasswordHash(String);

impl PasswordHash {
    /// Returns the PHC string for secure database storage.
    pub fn as_str(&self) -> &str {
        &self.0
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
    let mut secret = None;
    for cookie_header in headers.get_all(header::COOKIE).iter() {
        let cookie_header = cookie_header
            .to_str()
            .map_err(|_| CredentialParseError::Invalid)?;
        for pair in cookie_header.split(';') {
            let Some((name, value)) = pair.trim().split_once('=') else {
                continue;
            };
            if name.trim() != "__Host-openvibes-session" {
                continue;
            }
            if secret.is_some() || !valid_session_token(value.trim()) {
                return Err(CredentialParseError::Invalid);
            }
            secret = Some(PresentedSecret(value.trim().to_owned()));
        }
    }
    Ok(secret)
}

fn valid_session_token(value: &str) -> bool {
    if value.len() != 43 {
        return false;
    }
    URL_SAFE_NO_PAD.decode(value).is_ok_and(|bytes| {
        bytes.len() == SESSION_SECRET_BYTES && URL_SAFE_NO_PAD.encode(bytes) == value
    })
}

impl fmt::Debug for PasswordHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PasswordHash([REDACTED])")
    }
}

/// Verification result, including whether the stored work factor needs an upgrade.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PasswordVerification {
    /// Whether the normalized password matches the credential.
    pub valid: bool,
    /// Whether a successful login should replace this hash with the current floor.
    pub needs_rehash: bool,
}

/// Failure while hashing or parsing a persisted password credential.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PasswordHashError {
    /// The hashing implementation could not generate a credential.
    HashingFailed,
    /// The stored PHC value is malformed, unsupported, or exceeds resource bounds.
    InvalidCredential,
}

/// Hashes a normalized password using a per-password random salt and Argon2id.
pub fn hash_password(password: &NormalizedPassword) -> Result<PasswordHash, PasswordHashError> {
    let params = current_argon2_params().map_err(|_| PasswordHashError::HashingFailed)?;
    let hasher = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let hash = hasher
        .hash_password(password.as_bytes())
        .map_err(|_| PasswordHashError::HashingFailed)?
        .to_string();
    Ok(PasswordHash(hash))
}

/// Verifies a normalized password against a bounded Argon2id PHC credential.
pub fn verify_password(
    password: &NormalizedPassword,
    credential: &str,
) -> Result<PasswordVerification, PasswordHashError> {
    if credential.len() > MAX_PASSWORD_HASH_LENGTH {
        return Err(PasswordHashError::InvalidCredential);
    }
    let parsed =
        PhcPasswordHash::new(credential).map_err(|_| PasswordHashError::InvalidCredential)?;
    if parsed.algorithm.as_str() != "argon2id" || parsed.version != Some(0x13) {
        return Err(PasswordHashError::InvalidCredential);
    }
    let params = Params::try_from(&parsed).map_err(|_| PasswordHashError::InvalidCredential)?;
    if params.m_cost() > ARGON2_MAX_MEMORY_KIB
        || params.t_cost() > ARGON2_MAX_ITERATIONS
        || params.p_cost() > ARGON2_MAX_PARALLELISM
    {
        return Err(PasswordHashError::InvalidCredential);
    }

    let current = current_argon2_params().map_err(|_| PasswordHashError::HashingFailed)?;
    let hasher = Argon2::new(Algorithm::Argon2id, Version::V0x13, current);
    let valid = hasher.verify_password(password.as_bytes(), &parsed).is_ok();
    Ok(PasswordVerification {
        valid,
        needs_rehash: params.m_cost() < ARGON2_MEMORY_KIB
            || params.t_cost() < ARGON2_ITERATIONS
            || params.p_cost() < ARGON2_PARALLELISM,
    })
}

fn current_argon2_params() -> Result<Params, argon2::Error> {
    Params::new(
        ARGON2_MEMORY_KIB,
        ARGON2_ITERATIONS,
        ARGON2_PARALLELISM,
        Some(32),
    )
}

/// Newly generated opaque session secret and its database-safe SHA-256 digest.
///
/// The raw value is only for setting the browser cookie. Persist [`hash`]
/// instead. Debug output intentionally omits both values.
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
        session_cookie, verify_password,
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
