//! Console passwords: the length and blocklist rules, Argon2id hashing and
//! bounded verification. Shared by the console and the rule signer (board
//! #107), so both check a password exactly the same way.

use std::{fmt, sync::OnceLock};

use argon2::{
    Algorithm, Argon2, Params, Version,
    password_hash::{PasswordHasher, PasswordVerifier, phc::PasswordHash as PhcPasswordHash},
};
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroize;

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

    /// NFC-normalizes a bounded password for verification without applying
    /// registration policy to existing credentials.
    pub fn for_verification(password: &str) -> Result<Self, PasswordError> {
        if password.chars().count() > MAX_RAW_PASSWORD_CODE_POINTS {
            return Err(PasswordError::TooLong);
        }
        Ok(Self(password.nfc().collect()))
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

/// A valid Argon2id credential no account has, for verifying against when
/// the user is unknown, so an unknown name costs the same time as a wrong
/// password and can't be told apart.
pub fn dummy_password_phc() -> Option<&'static str> {
    static DUMMY_PHC: OnceLock<Option<String>> = OnceLock::new();
    DUMMY_PHC
        .get_or_init(|| {
            let password = NormalizedPassword::new("internal-only-dummy-console-password").ok()?;
            hash_password(&password)
                .ok()
                .map(|hash| hash.as_str().to_owned())
        })
        .as_deref()
}
