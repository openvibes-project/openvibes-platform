//! General settings (roles spec §7): the typed list and changing one value.

use axum::{Router, routing::get};

use handlers::{list_settings, update_setting};

use crate::http::AuthHttpState;

pub(crate) mod handlers;
mod types;

pub(crate) use types::{SettingChangeView, SettingView, SettingsView, UpdateSetting};

/// The settings paths.
pub(crate) fn routes() -> Router<AuthHttpState> {
    Router::new()
        .route("/v1/settings", get(list_settings))
        .route("/v1/settings/{key}", axum::routing::patch(update_setting))
}
