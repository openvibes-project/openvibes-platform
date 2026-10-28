//! The console's `vulns.*` settings applied over `vulns.toml`: the file
//! still decides where the database and health listener are and is what
//! applies when no setting was changed. The values were checked by the
//! console with the same rules ([`platform_settings`]); [`VulnsConfig::validate`]
//! checks the result again, so a bad row can never stop the service.

use std::{collections::HashMap, time::Duration};

use platform_settings::vulns_keys as key;
use platform_store::{Pool, console_settings};
use serde_json::Value;

use crate::config::VulnsConfig;

/// How often the database is asked whether a setting changed.
pub const POLL: Duration = Duration::from_secs(60);

/// The `vulns.*` rows and the NVD API key as stored.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Stored {
    values: HashMap<String, Value>,
    nvd_key: Option<String>,
}

impl Stored {
    /// The NVD API key set in the console, if any.
    #[must_use]
    pub fn nvd_key(&self) -> Option<&str> {
        self.nvd_key.as_deref()
    }
}

/// Reads the rows and the secret.
///
/// # Errors
/// The database could not be read.
pub async fn load(pool: &Pool) -> Result<Stored, String> {
    let client = pool.get().await.map_err(|error| error.to_string())?;
    let mut values = console_settings::values(&client)
        .await
        .map_err(|error| error.to_string())?;
    values.retain(|name, _| name.starts_with(key::PREFIX));
    let nvd_key = console_settings::secret(&client, key::NVD_API_KEY)
        .await
        .map_err(|error| error.to_string())?;
    Ok(Stored { values, nvd_key })
}

/// Resolves when the stored settings differ from `seen`; read errors are
/// logged and tried again at the next poll.
pub async fn changed(pool: &Pool, seen: &Stored, poll: Duration) -> Stored {
    loop {
        tokio::time::sleep(poll).await;
        match load(pool).await {
            Ok(now) if now != *seen => return now,
            Ok(_) => {}
            Err(error) => tracing::warn!(%error, "cannot read the console settings"),
        }
    }
}

/// `base` with every stored value applied. A value that is not the right
/// type is ignored (the console does not store one).
#[must_use]
pub fn overlay(base: &VulnsConfig, stored: &Stored) -> VulnsConfig {
    let mut config = base.clone();
    let text = |name: &str| stored.values.get(name).and_then(Value::as_str);
    let number = |name: &str| stored.values.get(name).and_then(Value::as_u64);
    if let Some(minutes) = number(key::CHECK_INTERVAL_MINUTES) {
        config.check_interval_minutes = minutes;
    }
    if let Some(url) = text(key::METALINK_URL) {
        config.metalink_url = url.to_owned();
    }
    if let Some(arch) = text(key::ARCH) {
        config.arch = arch.to_owned();
    }
    if let Some(proxy) = text(key::PROXY_URL) {
        config.proxy_url = (!proxy.is_empty()).then(|| proxy.to_owned());
    }
    if let Some(mib) = number(key::MAX_DOWNLOAD_MIB) {
        config.max_download_bytes = mib.saturating_mul(1 << 20);
    }
    if let Some(url) = text(key::KEV_URL) {
        config.kev_url = url.to_owned();
    }
    if let Some(url) = text(key::EPSS_URL) {
        config.epss_url = url.to_owned();
    }
    if let Some(url) = text(key::NVD_URL) {
        config.nvd_url = url.to_owned();
    }
    if let Some(url) = text(key::EUVD_URL) {
        config.euvd_url = url.to_owned();
    }
    if let Some(url) = text(key::OSV_URL) {
        config.osv_url = url.to_owned();
    }
    if let Some(mib) = number(key::OSV_MAX_DOWNLOAD_MIB) {
        config.osv_max_download_bytes = mib.saturating_mul(1 << 20);
    }
    config
}

#[cfg(test)]
#[path = "settings_tests.rs"]
mod tests;
