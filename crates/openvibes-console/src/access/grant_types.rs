//! Request and response types of service accounts and their tokens.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Request to create a service identity holding roles.
#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateServiceAccountRequest {
    /// Unique operator name, at most 128 characters.
    pub name: String,
    /// 1 to 64 roles, each inside the creator's own access.
    pub role_ids: Vec<String>,
}

/// Request to issue one expiring service bearer token.
#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateServiceTokenRequest {
    /// Operator label, 1 to 128 characters.
    pub label: String,
    /// Lifetime from one through 8760 hours.
    pub expires_in_hours: u32,
}

/// Safe service-account inventory row.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct ServiceAccountView {
    /// Stable service-account UUID.
    pub service_account_id: String,
    /// Operator-selected name.
    pub name: String,
    /// Whether the account can authenticate.
    pub enabled: bool,
    /// Creation instant.
    pub created_at: String,
    /// Active token count.
    pub active_tokens: i64,
    /// Its roles, by id.
    pub roles: Vec<RoleName>,
}

/// A role as a list shows it: its id and name.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct RoleName {
    /// Stable role id.
    pub role_id: String,
    /// Its name; Administrator's is "Administrator".
    pub name: String,
}

/// Bounded service-account inventory.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct ServiceAccountPage {
    /// Accounts sorted by name.
    pub items: Vec<ServiceAccountView>,
}

/// Safe service-token metadata row.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct ServiceTokenView {
    /// Stable token UUID.
    pub token_id: String,
    /// Operator label.
    pub label: String,
    /// Creation instant.
    pub created_at: String,
    /// Expiry instant.
    pub expires_at: String,
    /// Whether the token was revoked.
    pub revoked: bool,
}

/// Token metadata for one service account.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct ServiceTokenPage {
    /// Tokens newest first, without secret material.
    pub items: Vec<ServiceTokenView>,
}

/// Newly issued service token, whose secret appears only in this response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct CreatedServiceToken {
    /// Stable token UUID.
    pub token_id: String,
    /// Bearer secret; never returned after creation.
    pub token: Option<String>,
    /// Whether this response is a safe replay of an earlier issuance.
    pub replayed: bool,
    /// Whether the plaintext secret is included.
    pub secret_available: bool,
    /// Expiry instant.
    pub expires_at: String,
}
