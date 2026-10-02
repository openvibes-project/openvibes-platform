//! What the console sends and what it gets back: one JSON object each way
//! per connection.

use std::fmt;

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// The rule sets the signer signs: findings rules and alarm rules (D2).
pub const SITE: &str = "site";
/// The site's alarm rules; agents treat them as restricted.
pub const SITE_ALARMS: &str = "site-alarms";

/// A request to sign a rule set. Never `Debug`-prints the password.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignRequest {
    /// The console user who publishes.
    pub username: String,
    /// Their password, re-typed for this publish.
    pub password: Secret,
    /// `site` or `site-alarms`.
    pub rule_set: String,
    /// The rule set JSON, signed byte for byte.
    pub rules: String,
}

impl fmt::Debug for SignRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignRequest")
            .field("username", &self.username)
            .field("rule_set", &self.rule_set)
            .finish_non_exhaustive()
    }
}

/// A string cleared when dropped and never printed.
#[derive(Deserialize)]
#[serde(transparent)]
pub struct Secret(String);

impl Secret {
    /// The secret, for a password check only.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Secret([REDACTED])")
    }
}

/// Why a request was refused: fixed codes, never echoing input.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Refusal {
    /// Unknown user, wrong password or disabled account: one answer.
    Credentials,
    /// The account is locked after too many wrong passwords.
    Throttled,
    /// The account must change its password, or lacks `rules.upload`.
    Forbidden,
    /// Over a limit: rules per publish, or the `programs` caps.
    Limits,
    /// Not a valid request or rule set.
    Invalid,
    /// Too many publishes this hour.
    Rate,
    /// No version state: the signer won't guess a version (Setup seeds it).
    VersionState,
    /// The database or the key could not be used.
    Unavailable,
}

impl Refusal {
    /// The code as sent and logged.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::Credentials => "credentials",
            Self::Throttled => "throttled",
            Self::Forbidden => "forbidden",
            Self::Limits => "limits",
            Self::Invalid => "invalid",
            Self::Rate => "rate",
            Self::VersionState => "version_state",
            Self::Unavailable => "unavailable",
        }
    }
}

/// The answer.
#[derive(Debug, Serialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum SignResponse {
    /// The signed envelope, ready to publish.
    Signed {
        /// The envelope JSON.
        envelope: String,
        /// Its version.
        version: u64,
        /// When it expires.
        expires_at_unix_ms: i64,
    },
    /// Refused, with why.
    Refused {
        /// The fixed code.
        code: Refusal,
    },
}
