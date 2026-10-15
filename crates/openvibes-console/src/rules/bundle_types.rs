use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Published rule-set summary for the console.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct RuleSetView {
    /// Rule-set identifier.
    pub rule_set_id: String,
    /// Highest published version, when present.
    pub current_version: Option<i64>,
    /// Current signed expiry, in Unix milliseconds.
    pub current_expires_at_ms: Option<i64>,
    /// Issuer of the current bundle.
    pub current_issuer_key_id: Option<String>,
    /// True when the current bundle's signer has been removed from trust.
    pub current_signer_removed: bool,
    /// Number of currently trusted public keys.
    pub trusted_keys: i64,
    /// Whether operators retired this set.
    pub retired: bool,
}

/// A published signed-bundle metadata row.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct RuleBundleView {
    /// Monotonically increasing version.
    pub version: i64,
    /// SHA-256 of exact signed bytes, lower-case hexadecimal.
    pub envelope_sha256: String,
    /// Trusted issuer key id at publish time.
    pub issuer_key_id: String,
    /// Signed creation and expiry instants, in Unix milliseconds.
    pub created_at_ms: i64,
    /// Signed expiry instant, in Unix milliseconds.
    pub expires_at_ms: i64,
    /// Server-side publish instant.
    pub published_at: String,
    /// Operator who published it.
    pub published_by: String,
    /// Stored envelope bytes.
    pub bytes: i32,
}

/// Published rule-set inventory.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct RuleSetPage {
    /// Rule sets sorted by identifier.
    pub items: Vec<RuleSetView>,
}

/// Published bundle history for one set.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct RuleBundlePage {
    /// Bundles newest first.
    pub items: Vec<RuleBundleView>,
}

/// Signature and version details returned by upload preview.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct RuleBundlePreview {
    /// Rule-set identifier.
    pub rule_set_id: String,
    /// Signed version.
    pub version: i64,
    /// Trusted issuer key id.
    pub issuer_key_id: String,
    /// Signed expiry instant, in Unix milliseconds.
    pub expires_at_ms: i64,
    /// SHA-256 of exact envelope bytes.
    pub envelope_sha256: String,
    /// Token to send with the exact same bytes to publish.
    pub preview_token: String,
    /// Current version at preview time.
    pub current_version: Option<i64>,
}

/// Accepted signed-envelope JSON shape for preview and publish requests.
#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SignedRuleEnvelopeRequest {
    /// Envelope schema version (currently 1).
    pub schema_version: u16,
    /// Stable rule-set identifier.
    pub rule_set_id: String,
    /// Monotonically increasing version.
    pub rule_set_version: u64,
    /// Trusted Ed25519 issuer identifier.
    pub issuer_key_id: String,
    /// Creation time in Unix milliseconds.
    pub created_at_unix_ms: i64,
    /// Expiry time in Unix milliseconds.
    pub expires_at_unix_ms: i64,
    /// Payload encoding (`json` or `yaml`).
    pub payload_encoding: String,
    /// Exact UTF-8 signed payload.
    pub payload: String,
    /// Lowercase SHA-256 digest of the payload.
    pub payload_sha256_hex: String,
    /// Base64url Ed25519 signature.
    pub signature_base64url: String,
}
