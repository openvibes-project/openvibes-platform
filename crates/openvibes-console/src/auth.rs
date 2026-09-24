//! Small primitives for server-side browser sessions.

use std::fmt;

use axum::http::{HeaderMap, header};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::{
    digest,
    rand::{SecureRandom, SystemRandom},
};
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroize;

const SESSION_SECRET_BYTES: usize = 32;
// ponytail: normalization accepts at most 4,096 raw code points to bound CPU and allocation.
const MAX_RAW_PASSWORD_CODE_POINTS: usize = 4_096;
const MIN_PASSWORD_CODE_POINTS: usize = 15;
const MAX_PASSWORD_CODE_POINTS: usize = 128;

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
        let hash = hex(&digest::digest(&digest::SHA256, value.as_bytes()).as_ref());
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
        NormalizedPassword, PasswordError, SessionSecret, browser_origin_allowed, session_cookie,
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
    }
}
