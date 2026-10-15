//! Sign-in throttle buckets: failure limits per account and per source address.

use zeroize::Zeroize;

/// Failed password checks per account (sign-in and set-password together)
/// before the account is locked for the window.
pub(crate) const ACCOUNT_FAILURE_LIMIT: i32 = 5;
pub(super) const SOURCE_FAILURE_LIMIT: i32 = 25;

/// The per-account throttle bucket sign-in uses; set-password counts a wrong
/// current password against it too (#85).
pub(crate) fn account_throttle_bucket(username: &str) -> [u8; 32] {
    login_throttle_buckets(Some(username), None).0
}

fn throttle_digest(kind: &[u8], value: &[u8]) -> [u8; 32] {
    let mut input = b"openvibes-console-login-throttle-v1\0".to_vec();
    input.extend_from_slice(kind);
    input.push(0);
    input.extend_from_slice(value);
    let digest = ring::digest::digest(&ring::digest::SHA256, &input);
    let mut output = [0; 32];
    output.copy_from_slice(digest.as_ref());
    input.zeroize();
    output
}

pub(super) fn login_throttle_buckets(
    username: Option<&str>,
    source: Option<&str>,
) -> ([u8; 32], Option<[u8; 32]>) {
    let username = username.unwrap_or("invalid");
    let account = throttle_digest(b"account", username.as_bytes());
    let source = source.map(|source| throttle_digest(b"source-address", source.as_bytes()));
    (account, source)
}

#[cfg(test)]
mod login_throttle_tests {
    use super::login_throttle_buckets;

    #[test]
    fn source_throttle_is_per_address_and_account_throttle_is_per_user() {
        let alice = login_throttle_buckets(Some("alice"), Some("192.0.2.9"));
        let bob = login_throttle_buckets(Some("bob"), Some("192.0.2.9"));
        let alice_elsewhere = login_throttle_buckets(Some("alice"), Some("192.0.2.10"));
        assert_ne!(alice.0, bob.0);
        assert_eq!(alice.1, bob.1);
        assert_eq!(alice.0, alice_elsewhere.0);
        assert_ne!(alice.1, alice_elsewhere.1);
        assert_eq!(login_throttle_buckets(Some("alice"), None).1, None);
    }
}
