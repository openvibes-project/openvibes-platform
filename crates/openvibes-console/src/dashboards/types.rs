use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// One dashboard as the viewer sees it.
#[derive(Clone, Debug, PartialEq, Serialize, ToSchema)]
pub struct DashboardView {
    /// Stable UUID.
    pub dashboard_id: String,
    /// 1–80 characters.
    pub name: String,
    /// Display name of the owner.
    pub owner_display_name: String,
    /// Whether the viewer owns it (only owners may change it).
    pub mine: bool,
    /// Who may view it besides the owner: `private`, `roles` or `everyone`.
    pub visibility: String,
    /// The roles it is shared with. The owner sees all of them; anyone else
    /// only the roles they hold themselves.
    pub roles: Vec<DashboardRole>,
    /// Version for `If-Match`.
    pub version: u64,
    /// Layout: `{ "schema": 1, "widgets": [...] }`.
    #[schema(value_type = Object)]
    pub layout: serde_json::Value,
    /// RFC 3339 creation time.
    pub created_at: String,
    /// RFC 3339 last change.
    pub updated_at: String,
}

/// A role a dashboard is shared with.
#[derive(Clone, Debug, PartialEq, Serialize, ToSchema)]
pub struct DashboardRole {
    /// Role id.
    pub role_id: String,
    /// Role name.
    pub name: String,
}

/// Dashboards visible to the viewer: own first, then shared.
#[derive(Clone, Debug, PartialEq, Serialize, ToSchema)]
pub struct DashboardPage {
    /// At most 100 own dashboards plus those shared with the viewer's roles.
    pub items: Vec<DashboardView>,
}

/// Create or replace a dashboard's name and layout.
#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SaveDashboardRequest {
    /// 1–80 characters.
    pub name: String,
    /// Layout document (validated; at most 64 KiB and 40 widgets).
    #[schema(value_type = Object)]
    pub layout: serde_json::Value,
}

/// Who a dashboard is shared with.
#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ShareDashboardRequest {
    /// `private` (stop sharing), `roles` or `everyone`.
    pub visibility: String,
    /// For `roles`: one or more roles the caller holds. Ignored otherwise.
    #[serde(default)]
    pub role_ids: Vec<String>,
}

/// The dashboard that opens first; `null` is the built-in Overview.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct HomeDashboard {
    /// Visible dashboard id, or `null`.
    pub dashboard_id: Option<String>,
}
