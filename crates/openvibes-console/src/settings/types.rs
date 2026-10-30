//! Request and response types of the settings endpoints.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;

/// One setting with its current value.
#[derive(Serialize, ToSchema)]
pub(crate) struct SettingView {
    /// The key, such as `sso.remove_inactive_days`.
    pub key: String,
    /// The section it is shown under.
    pub section: String,
    /// Short name.
    pub label: String,
    /// One-sentence explanation.
    pub help: String,
    /// `bool`, `int`, `text`, `choice` or `secret`.
    pub kind: String,
    /// `live` (reaches the service within about a minute) or `restart` (at
    /// the service's next start).
    pub applies: String,
    /// Smallest allowed value (`int` only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min: Option<i64>,
    /// Largest allowed value (`int` only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max: Option<i64>,
    /// The allowed words (`choice` only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<Vec<String>>,
    /// The value when nobody changed it.
    pub default: Value,
    /// The value now; null for a secret, which is never shown.
    pub value: Value,
    /// Whether a secret is set (`secret` only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_set: Option<bool>,
    /// Each certificate of a certificate setting, as read from its value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificates: Option<Vec<crate::sso::IdpCertificateView>>,
    /// When it was last changed (RFC 3339), if ever.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub changed_at: Option<String>,
    /// Who last changed it, if anyone.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub changed_by: Option<String>,
}

/// One recorded change.
#[derive(Serialize, ToSchema)]
pub(crate) struct SettingChangeView {
    /// When (RFC 3339).
    pub at: String,
    /// Who.
    pub actor: String,
    /// The key.
    pub key: String,
    /// The value before; null when it had its default.
    pub old: Value,
    /// The value after.
    pub new: Value,
}

/// All settings and the latest changes.
#[derive(Serialize, ToSchema)]
pub(crate) struct SettingsView {
    /// Every setting, in display order.
    pub items: Vec<SettingView>,
    /// The last five changes, newest first.
    pub recent: Vec<SettingChangeView>,
}

/// The new value.
#[derive(Deserialize, ToSchema)]
pub(crate) struct UpdateSetting {
    /// A boolean, whole number or text, as the setting's kind says. Null
    /// puts the setting back to its default (a secret: removes it).
    pub value: Value,
}
