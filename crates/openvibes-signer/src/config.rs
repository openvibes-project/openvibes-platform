//! `/etc/openvibes/signer.toml`.

use std::path::PathBuf;

use serde::Deserialize;

fn default_publishes() -> u32 {
    12
}
fn default_rules() -> usize {
    200
}
fn default_days() -> u32 {
    365
}

/// The rule signer's configuration (board #107).
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerConfig {
    /// The Unix socket it listens on (mode 0660; the console's user is in
    /// the socket's group).
    pub socket: PathBuf,
    /// PostgreSQL connection for the `openvibes-signer` role.
    pub database_url: String,
    /// The site key: 32 bytes, 0600, readable only by the signer.
    pub key_file: PathBuf,
    /// The issuer key id agents trust the site key under.
    pub issuer_key_id: String,
    /// Holds `versions.json`, the last signed rules and `status.json`.
    pub state_dir: PathBuf,
    /// Signed publishes per hour, all users together.
    #[serde(default = "default_publishes")]
    pub publishes_per_hour: u32,
    /// Rules per publish.
    #[serde(default = "default_rules")]
    pub rules_per_publish: usize,
    /// How long a signed set stays valid.
    #[serde(default = "default_days")]
    pub validity_days: u32,
}

impl SignerConfig {
    /// Checks paths and bounds.
    ///
    /// # Errors
    /// A relative path, or a bound out of range.
    pub fn check(&self) -> Result<(), String> {
        platform_config::require_absolute(&[&self.socket, &self.key_file, &self.state_dir])
            .map_err(|error| error.to_string())?;
        if !(1..=1_000).contains(&self.publishes_per_hour)
            || !(1..=10_000).contains(&self.rules_per_publish)
            || !(1..=3_650).contains(&self.validity_days)
        {
            return Err("a limit is out of range".into());
        }
        openvibes_core::Identifier::new(&self.issuer_key_id)
            .map_err(|_| "issuer_key_id is not an identifier".to_owned())?;
        Ok(())
    }
}
