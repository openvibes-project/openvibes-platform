//! Request and response types of roles, bindings, asset groups, host tags and service accounts.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Exact tag key and value proposed for an agent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentTagInput {
    /// Tag key.
    pub key: String,
    /// Tag value.
    pub value: String,
}

/// Proposed exact agent tag set.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentTagChangeRequest {
    /// Complete replacement tag set.
    pub tags: Vec<AgentTagInput>,
}

/// Confirmed tag update request, bound to an impact preview.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ApplyAgentTagsRequest {
    /// Complete replacement tag set.
    pub tags: Vec<AgentTagInput>,
    /// Opaque preview token.
    pub preview_token: String,
}

/// Asset group affected by a proposed tag change.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct AgentTagGroupImpact {
    /// Group identifier.
    pub asset_group_id: String,
    /// Group name.
    pub name: String,
}

/// Exact-tag impact preview.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct AgentTagPreviewResponse {
    /// Existing tags.
    pub current: Vec<AgentTagInput>,
    /// Proposed tags.
    pub proposed: Vec<AgentTagInput>,
    /// Groups the agent will enter.
    pub gained_groups: Vec<AgentTagGroupImpact>,
    /// Groups the agent will leave.
    pub lost_groups: Vec<AgentTagGroupImpact>,
    /// Active scoped bindings gained.
    pub gained_bindings: Vec<AgentTagBindingImpact>,
    /// Active scoped bindings lost.
    pub lost_bindings: Vec<AgentTagBindingImpact>,
    /// Token required to apply this proposal.
    pub preview_token: String,
}

/// Binding affected by a proposed agent tag change.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct AgentTagBindingImpact {
    /// Binding UUID.
    pub binding_id: String,
    /// Username.
    pub username: String,
    /// Role identifier.
    pub role_id: String,
    /// Asset group name.
    pub asset_group_name: String,
}

/// Manual asset group and exact selectors.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct AccessAssetGroup {
    /// Stable group identifier.
    pub asset_group_id: String,
    /// Operator-facing group name.
    pub name: String,
    /// Exact `key=value` selectors, all of which must match.
    pub selectors: Vec<String>,
}

/// Exact tag selector used to define asset-group membership.
#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct AssetGroupSelectorInput {
    /// Tag key.
    pub key: String,
    /// Exact tag value.
    pub value: String,
}

/// Request to create or replace an asset group's complete selector set.
#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SaveAssetGroupRequest {
    /// Operator-facing group name.
    pub name: String,
    /// Complete conjunction of exact selectors, from one through 32.
    pub selectors: Vec<AssetGroupSelectorInput>,
}

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
