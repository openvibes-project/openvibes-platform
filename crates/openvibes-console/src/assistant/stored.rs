//! The assistant's settings as the console page stores them, applied over
//! `[assistant]` of `console.toml` when the console starts. A setting nobody
//! changed keeps the file's value.

use std::collections::HashMap;

use platform_assistant::{Assistant, AssistantConfig, BackendConfig, DataLocation};
use platform_settings::assistant_keys as key;
use serde_json::Value;

fn number(stored: &HashMap<String, Value>, name: &str) -> Option<u32> {
    stored
        .get(name)
        .and_then(Value::as_u64)
        .and_then(|n| u32::try_from(n).ok())
}

fn text<'a>(stored: &'a HashMap<String, Value>, name: &str) -> Option<&'a str> {
    stored.get(name).and_then(Value::as_str)
}

/// `file` with every stored `assistant.*` setting on top.
pub(crate) fn overlay(
    file: Option<&AssistantConfig>,
    stored: &HashMap<String, Value>,
) -> Option<AssistantConfig> {
    if !stored.keys().any(|name| name.starts_with(key::PREFIX)) {
        return file.cloned();
    }
    let mut config = file.cloned().unwrap_or_default();
    if let Some(enabled) = stored.get(key::ENABLED).and_then(Value::as_bool) {
        config.enabled = enabled;
    }
    if let Some(profile) =
        text(stored, key::PROFILE).and_then(|word| serde_json::from_value(Value::from(word)).ok())
    {
        config.profile = profile;
    }
    if let Some(mode) = text(stored, key::LOOKUP_MODE)
        .and_then(|word| serde_json::from_value(Value::from(word)).ok())
    {
        config.lookup_mode = mode;
    }
    config.conversation_retention_days =
        number(stored, key::CONVERSATION_RETENTION_DAYS).or(config.conversation_retention_days);
    config.max_lookups = number(stored, key::MAX_LOOKUPS).or(config.max_lookups);
    config.questions_per_user_per_hour =
        number(stored, key::QUESTIONS_PER_USER_PER_HOUR).or(config.questions_per_user_per_hour);
    config.concurrency = number(stored, key::CONCURRENCY).or(config.concurrency);

    let backend_keys = [
        key::URL,
        key::MODEL,
        key::ALLOW_REMOTE,
        key::DATA_LOCATION,
        key::PSEUDONYMIZE,
        key::PROXY_URL,
        key::DEADLINE_SECONDS,
    ];
    if config.backend.is_some() || backend_keys.iter().any(|name| stored.contains_key(*name)) {
        let mut backend = config.backend.take().unwrap_or(BackendConfig {
            url: String::new(),
            model: String::new(),
            api_key_file: None,
            ca_file: None,
            client_certificate_file: None,
            client_key_file: None,
            allow_remote: false,
            data_location: None,
            pseudonymize: None,
            proxy_url: None,
            deadline_seconds: None,
        });
        if let Some(url) = text(stored, key::URL) {
            url.clone_into(&mut backend.url);
        }
        if let Some(model) = text(stored, key::MODEL) {
            model.clone_into(&mut backend.model);
        }
        if let Some(allow) = stored.get(key::ALLOW_REMOTE).and_then(Value::as_bool) {
            backend.allow_remote = allow;
        }
        if let Some(word) = text(stored, key::DATA_LOCATION) {
            backend.data_location = match word {
                "own-network" => Some(DataLocation::OwnNetwork),
                "external" => Some(DataLocation::External),
                _ => None,
            };
        }
        if let Some(word) = text(stored, key::PSEUDONYMIZE) {
            backend.pseudonymize = match word {
                "on" => Some(true),
                "off" => Some(false),
                _ => None,
            };
        }
        if let Some(proxy) = text(stored, key::PROXY_URL) {
            backend.proxy_url = (!proxy.is_empty()).then(|| proxy.to_owned());
        }
        if let Some(seconds) = number(stored, key::DEADLINE_SECONDS) {
            backend.deadline_seconds = Some(u64::from(seconds));
        }
        config.backend = Some(backend);
    }
    Some(config)
}

/// The checked assistant: the file with the console's settings on top and
/// the stored API key, or, when those do not pass the assistant's own rules,
/// the file alone (a wrong setting must not stop the console starting).
///
/// # Errors
/// The file alone is not valid either.
pub(crate) fn resolve(
    file: Option<&AssistantConfig>,
    stored: &HashMap<String, Value>,
    api_key: Option<String>,
) -> Result<Option<Assistant>, platform_assistant::ConfigError> {
    let checked = overlay(file, stored)
        .filter(|config| config.enabled)
        .map(|config| config.validate());
    match checked {
        Some(Ok(mut assistant)) => {
            if let (Some(backend), Some(key)) = (assistant.backend.as_mut(), api_key) {
                backend.set_api_key(Some(key));
            }
            Ok(Some(assistant))
        }
        Some(Err(error)) => {
            tracing::warn!(%error, "the assistant settings from the console are not valid; using the configuration file alone");
            file.filter(|config| config.enabled)
                .map(AssistantConfig::validate)
                .transpose()
        }
        None => Ok(None),
    }
}
