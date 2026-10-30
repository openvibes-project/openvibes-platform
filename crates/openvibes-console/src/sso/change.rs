//! What a change to a single sign-on setting must also satisfy.

use chrono::{DateTime, Utc};
use platform_settings::sso_keys;
use serde_json::Value;
use std::collections::HashMap;

use super::certificates::summaries;

const NOT_READY: &str = "Set the entity ID, the sign-in address and a certificate first";
const NO_VALID_CERTIFICATE: &str = "Every stored certificate has expired; add a current one first";
const IS_ON: &str = "Turn single sign-on off before removing this";

/// Whether `key` may take `value` (null puts it back to its default). Only
/// single sign-on keys have extra rules: certificates must parse, and the
/// switch needs the three things the identity provider gives us.
///
/// # Errors
/// The words to show next to the field.
pub(crate) fn check_change(
    stored: &HashMap<String, Value>,
    key: &str,
    value: &Value,
) -> Result<(), String> {
    check_change_at(stored, key, value, Utc::now())
}

pub(super) fn check_change_at(
    stored: &HashMap<String, Value>,
    key: &str,
    value: &Value,
    now: DateTime<Utc>,
) -> Result<(), String> {
    let needed = [
        sso_keys::IDP_ENTITY_ID,
        sso_keys::IDP_SSO_URL,
        sso_keys::IDP_CERTIFICATES,
    ];
    if key == sso_keys::IDP_CERTIFICATES
        && let Some(text) = value.as_str()
        && let Err(message) = summaries(text, now, true)
    {
        return Err(message);
    }
    if key != sso_keys::ENABLED && !needed.contains(&key) {
        return Ok(());
    }
    let text = |name: &str, own: &Value| -> bool {
        let value = if name == key {
            own
        } else {
            stored.get(name).unwrap_or(&Value::Null)
        };
        value.as_str().is_some_and(|text| !text.trim().is_empty())
    };
    if key == sso_keys::ENABLED {
        let ready = needed.iter().all(|name| text(name, &Value::Null));
        // A certificate that has expired since it was pasted no longer counts.
        let current = stored
            .get(sso_keys::IDP_CERTIFICATES)
            .and_then(Value::as_str)
            .and_then(|pem| summaries(pem, now, false).ok())
            .is_some_and(|list| list.iter().any(|c| !c.expired));
        if value == &Value::Bool(true) && ready && !current {
            return Err(NO_VALID_CERTIFICATE.into());
        }
        return if value == &Value::Bool(true) && !ready {
            Err(NOT_READY.into())
        } else {
            Ok(())
        };
    }
    let on = stored.get(sso_keys::ENABLED) == Some(&Value::Bool(true));
    if on && !text(key, value) {
        Err(IS_ON.into())
    } else {
        Ok(())
    }
}
