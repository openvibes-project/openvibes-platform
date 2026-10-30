//! `openvibes-admin sso`: whether single sign-on is on, and the one way to
//! turn it off without the console (when the identity provider is down or
//! misconfigured and nobody can sign in with it). The local `admin` always
//! signs in with its password; this only flips the stored setting, audited
//! like any settings change.

use chrono::Utc;
use clap::Subcommand;
use platform_settings::sso_keys;
use platform_store::{Client, console_settings};
use serde_json::{Value, json};

#[derive(Subcommand)]
pub enum SsoCommand {
    /// Prints `on`, `off` or `not set up`.
    Status,
    /// Turns single sign-on off; prints `off`, `already off` or `not set up`.
    Off,
}

impl SsoCommand {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Status => "sso status",
            Self::Off => "sso.off",
        }
    }
}

/// `on`, `off` (set up but switched off) or `not set up` (no entity ID,
/// sign-in address or certificate yet).
async fn state(client: &Client) -> Result<&'static str, String> {
    let stored = console_settings::values(client)
        .await
        .map_err(|error| error.to_string())?;
    let text = |key: &str| {
        stored
            .get(key)
            .and_then(Value::as_str)
            .is_some_and(|text| !text.trim().is_empty())
    };
    Ok(if stored.get(sso_keys::ENABLED) == Some(&json!(true)) {
        "on"
    } else if text(sso_keys::IDP_ENTITY_ID)
        && text(sso_keys::IDP_SSO_URL)
        && text(sso_keys::IDP_CERTIFICATES)
    {
        "off"
    } else {
        "not set up"
    })
}

pub async fn run(
    command: &SsoCommand,
    client: &mut Client,
    actor: &str,
) -> (Result<String, String>, Option<String>) {
    let target = Some(sso_keys::ENABLED.to_owned());
    let result = match command {
        SsoCommand::Status => state(client).await.map(|state| format!("{state}\n")),
        SsoCommand::Off => match state(client).await {
            Ok("on") => {
                console_settings::set(client, sso_keys::ENABLED, &json!(false), actor, Utc::now())
                    .await
                    .map(|_| "off\n".to_owned())
                    .map_err(|error| error.to_string())
            }
            Ok("off") => Ok("already off\n".to_owned()),
            Ok(other) => Ok(format!("{other}\n")),
            Err(error) => Err(error),
        },
    };
    (result, target)
}
