//! Audited local console-account administration.

use chrono::{SecondsFormat, Utc};
use clap::{Subcommand, ValueEnum};
use openvibes_console::{NormalizedPassword, hash_password};
use platform_store::{
    Client,
    console_auth::{
        self, AuditContext, NewLocalUser, disable_local_user, list_local_users, replace_password,
        unlock_local_user,
    },
};
use ring::rand::{SecureRandom, SystemRandom};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum BuiltInRole {
    Viewer,
    Analyst,
    Operator,
    Admin,
}

impl BuiltInRole {
    fn as_str(self) -> &'static str {
        match self {
            Self::Viewer => "viewer",
            Self::Analyst => "analyst",
            Self::Operator => "operator",
            Self::Admin => "admin",
        }
    }
}

#[derive(Subcommand)]
pub enum UserCommand {
    /// Create a local user and initial global role binding.
    Create {
        /// Local username; ASCII case is normalized to lowercase.
        #[arg(long)]
        username: String,
        /// Operator-facing display name.
        #[arg(long)]
        display_name: String,
        /// Initial built-in role.
        #[arg(long, value_enum, default_value = "admin")]
        role: BuiltInRole,
    },
    /// List local users without credential or token material.
    List,
    /// Disable a local user and revoke active sessions.
    Disable {
        /// Local username.
        username: String,
    },
    /// Clear an active account-level login lock.
    Unlock {
        /// Local username.
        username: String,
    },
    /// Replace a user's password and revoke every active session.
    #[command(name = "reset-password")]
    ResetPassword {
        /// Local username.
        username: String,
    },
}

impl UserCommand {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Create { .. } => "user.create",
            Self::List => "user.list",
            Self::Disable { .. } => "user.disable",
            Self::Unlock { .. } => "user.unlock",
            Self::ResetPassword { .. } => "user.reset_password",
        }
    }
}

pub async fn run(
    command: &UserCommand,
    client: &mut Client,
    actor: &str,
) -> (Result<String, String>, Option<String>) {
    match command {
        UserCommand::Create {
            username,
            display_name,
            role,
        } => {
            let username = match canonical_username(username) {
                Ok(username) => username,
                Err(error) => return (Err(error), None),
            };
            if display_name.trim().is_empty()
                || display_name.chars().count() > 160
                || display_name.chars().any(char::is_control)
            {
                return (
                    Err("display name must contain 1 to 160 printable characters".into()),
                    Some(username),
                );
            }
            let password = match confirmed_password() {
                Ok(password) => password,
                Err(error) => return (Err(error), Some(username)),
            };
            let credential = match hash_password(&password) {
                Ok(credential) => credential,
                Err(_) => {
                    return (
                        Err("could not hash the supplied password".into()),
                        Some(username),
                    );
                }
            };
            let user_id = match random_uuid() {
                Ok(id) => id,
                Err(error) => return (Err(error), Some(username)),
            };
            let binding_id = match random_uuid() {
                Ok(id) => id,
                Err(error) => return (Err(error), Some(username)),
            };
            let now = Utc::now();
            let result = console_auth::create_local_user(
                client,
                &NewLocalUser {
                    user_id: &user_id,
                    binding_id: &binding_id,
                    username: &username,
                    display_name: display_name.trim(),
                    password_phc: credential.as_str(),
                    role_id: role.as_str(),
                    actor_id: actor,
                    now,
                },
            )
            .await
            .map(|()| {
                format!(
                    "created local user {username} with role {}\n",
                    role.as_str()
                )
            })
            .map_err(|error| error.to_string());
            (result, Some(username))
        }
        UserCommand::List => {
            let users = match list_local_users(client).await {
                Ok(users) => users,
                Err(error) => return (Err(error.to_string()), None),
            };
            let mut output = String::from("USERNAME\tSTATUS\tROLES\tDISPLAY NAME\tLAST SEEN\n");
            for user in users {
                let roles = if user.role_ids.is_empty() {
                    "none".to_owned()
                } else {
                    user.role_ids.join(",")
                };
                let last_seen = user
                    .last_seen_at
                    .map(|time| time.to_rfc3339_opts(SecondsFormat::Secs, true))
                    .unwrap_or_else(|| "never".into());
                output.push_str(&format!(
                    "{}\t{}\t{}\t{}\t{}\n",
                    user.username,
                    if user.enabled { "enabled" } else { "disabled" },
                    roles,
                    printable_field(&user.display_name),
                    last_seen,
                ));
            }
            (Ok(output), None)
        }
        UserCommand::Disable { username } => {
            let username = match canonical_username(username) {
                Ok(username) => username,
                Err(error) => return (Err(error), None),
            };
            let credential = match console_auth::credential_by_username(client, &username).await {
                Ok(Some(credential)) => credential,
                Ok(None) => {
                    return (
                        Err(format!("no local user named {username}")),
                        Some(username),
                    );
                }
                Err(error) => return (Err(error.to_string()), Some(username)),
            };
            if !credential.enabled {
                return (
                    Err(format!("local user {username} is already disabled")),
                    Some(username),
                );
            }
            let result = disable_local_user(
                client,
                &credential.user_id,
                Utc::now(),
                &AuditContext::default(),
                actor,
                "local_admin",
            )
            .await
            .map_err(|error| error.to_string())
            .and_then(|disabled| {
                disabled
                    .then(|| format!("disabled local user {username}\n"))
                    .ok_or_else(|| format!("local user {username} changed concurrently"))
            });
            (result, Some(username))
        }
        UserCommand::Unlock { username } => {
            let username = match canonical_username(username) {
                Ok(username) => username,
                Err(error) => return (Err(error), None),
            };
            let result = unlock_local_user(client, &username, Utc::now(), actor, "local_admin")
                .await
                .map_err(|error| error.to_string())
                .and_then(|unlocked| {
                    unlocked
                        .then(|| format!("unlocked local user {username}\n"))
                        .ok_or_else(|| format!("local user {username} has no active account lock"))
                });
            (result, Some(username))
        }
        UserCommand::ResetPassword { username } => {
            let username = match canonical_username(username) {
                Ok(username) => username,
                Err(error) => return (Err(error), None),
            };
            let credential = match console_auth::credential_by_username(client, &username).await {
                Ok(Some(credential)) => credential,
                Ok(None) => {
                    return (
                        Err(format!("no local user named {username}")),
                        Some(username),
                    );
                }
                Err(error) => return (Err(error.to_string()), Some(username)),
            };
            let password = match confirmed_password() {
                Ok(password) => password,
                Err(error) => return (Err(error), Some(username)),
            };
            let password_hash = match hash_password(&password) {
                Ok(hash) => hash,
                Err(_) => {
                    return (
                        Err("could not hash the supplied password".into()),
                        Some(username),
                    );
                }
            };
            let changed = replace_password(
                client,
                &credential.user_id,
                password_hash.as_str(),
                Utc::now(),
                &AuditContext::default(),
                actor,
                "local_admin",
            )
            .await
            .map_err(|error| error.to_string());
            let result = changed.and_then(|changed| {
                changed
                    .then(|| {
                        format!(
                            "reset password for local user {username}; all sessions were revoked\n"
                        )
                    })
                    .ok_or_else(|| format!("local user {username} no longer exists"))
            });
            (result, Some(username))
        }
    }
}

fn canonical_username(username: &str) -> Result<String, String> {
    if username.is_empty()
        || username.len() > 64
        || !username.is_ascii()
        || !username
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._@+-".contains(&byte))
    {
        return Err("username must use 1 to 64 ASCII letters, digits, or ._@+- characters".into());
    }
    Ok(username.to_ascii_lowercase())
}

fn confirmed_password() -> Result<NormalizedPassword, String> {
    let password = read_secret("New password: ")?;
    let normalized = NormalizedPassword::new(&password).map_err(|_| {
        "password must be 15 to 128 Unicode characters and not a blocked common passphrase"
            .to_owned()
    })?;
    let confirmation = read_secret("Repeat password: ")?;
    let confirmed = NormalizedPassword::new(&confirmation).map_err(|_| {
        "password must be 15 to 128 Unicode characters and not a blocked common passphrase"
            .to_owned()
    })?;
    if normalized.as_bytes() != confirmed.as_bytes() {
        return Err("password entries did not match".into());
    }
    Ok(normalized)
}

fn read_secret(prompt: &str) -> Result<Zeroizing<String>, String> {
    rpassword::prompt_password(prompt)
        .map(Zeroizing::new)
        .map_err(|_| "password input requires an interactive terminal".into())
}

fn random_uuid() -> Result<String, String> {
    let mut bytes = [0_u8; 16];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| "could not generate a random account identifier".to_owned())?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Ok(format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15],
    ))
}

fn printable_field(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{BuiltInRole, UserCommand, canonical_username, printable_field, random_uuid};
    use clap::Parser;

    #[derive(Parser)]
    struct TestCli {
        #[command(subcommand)]
        command: UserCommand,
    }

    #[test]
    fn usernames_are_canonical_ascii_and_passwords_are_not_cli_arguments() {
        assert_eq!(
            canonical_username("Alice.Example+1"),
            Ok("alice.example+1".into())
        );
        let too_long = "x".repeat(65);
        for invalid in ["", "has space", "é", too_long.as_str()] {
            assert!(canonical_username(invalid).is_err());
        }
        let parsed = TestCli::try_parse_from([
            "openvibes-admin",
            "create",
            "--username",
            "alice",
            "--display-name",
            "Alice",
        ])
        .unwrap();
        assert!(matches!(
            parsed.command,
            UserCommand::Create {
                role: BuiltInRole::Admin,
                ..
            }
        ));
        assert!(
            TestCli::try_parse_from([
                "openvibes-admin",
                "create",
                "--username",
                "alice",
                "--display-name",
                "Alice",
                "--password",
                "secret",
            ])
            .is_err()
        );
    }

    #[test]
    fn account_ids_are_v4_and_listing_fields_cannot_inject_rows() {
        let id = random_uuid().unwrap();
        assert_eq!(id.len(), 36);
        assert_eq!(&id[14..15], "4");
        assert!(matches!(&id[19..20], "8" | "9" | "a" | "b"));
        assert_eq!(printable_field("Analyst\nroot\t"), "Analyst root ");
    }
}
