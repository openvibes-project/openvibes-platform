//! Audited local console-account administration.

use chrono::{SecondsFormat, Utc};
use clap::Subcommand;
use openvibes_console::{NormalizedPassword, hash_password};
use platform_store::{
    Client,
    console_auth::{
        self, AuditContext, DisableOutcome, NewLocalUser, disable_local_user, enable_local_user,
        list_local_users, replace_password, unlock_local_user,
    },
    console_roles,
};
use ring::rand::{SecureRandom, SystemRandom};
use zeroize::Zeroizing;

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
        /// Initial role, by ID (`admin` is the Administrator; the console's
        /// Roles page shows the others).
        #[arg(long, default_value = "admin")]
        role: String,
        /// Read the password from one line of standard input instead of
        /// prompting twice (for scripts and Setup).
        #[arg(long)]
        password_stdin: bool,
        /// Make the user set their own password at first console sign-in
        /// (treat the given password as one-time), as the console's New
        /// user does.
        #[arg(long)]
        must_change: bool,
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
    /// Replace a user's password and revoke every active session; a
    /// disabled or locked user is enabled and unlocked too (break-glass).
    #[command(name = "reset-password")]
    ResetPassword {
        /// Local username.
        username: String,
        /// Read the password from one line of standard input instead of
        /// prompting twice (for scripts and the TUI's Console sign-in).
        #[arg(long)]
        password_stdin: bool,
        /// Make the user set their own password at the next console
        /// sign-in (treat the given password as one-time).
        #[arg(long)]
        must_change: bool,
        /// Break-glass (`helper admin-reset`): also enable the account and
        /// clear its sign-in lock.
        #[arg(long)]
        recover: bool,
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
            password_stdin,
            must_change,
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
            let password = if *password_stdin {
                password_from_stdin()
            } else {
                confirmed_password()
            };
            let password = match password {
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
            match console_roles::role(client, role).await {
                Ok(Some(_)) => {}
                Ok(None) => return (Err(format!("no role with ID {role}")), Some(username)),
                Err(error) => return (Err(error.to_string()), Some(username)),
            }
            let now = Utc::now();
            let result = console_auth::create_local_user(
                client,
                &NewLocalUser {
                    user_id: &user_id,
                    binding_id: &binding_id,
                    username: &username,
                    display_name: display_name.trim(),
                    password_phc: credential.as_str(),
                    role_id: role,
                    actor_id: actor,
                    actor_kind: "local_admin",
                    password_must_change: *must_change,
                    now,
                },
            )
            .await
            .map(|()| format!("created local user {username} with role {role}\n"))
            .map_err(|error| error.to_string());
            (result, Some(username))
        }
        UserCommand::List => {
            let users = match list_local_users(client).await {
                Ok(users) => users,
                Err(error) => return (Err(error.to_string()), None),
            };
            let names = match console_roles::list_roles(client).await {
                Ok(roles) => roles
                    .into_iter()
                    .map(|role| (role.role_id, role.name))
                    .collect::<std::collections::HashMap<_, _>>(),
                Err(error) => return (Err(error.to_string()), None),
            };
            let mut output = String::from("USERNAME\tSTATUS\tROLES\tDISPLAY NAME\tLAST SEEN\n");
            for user in users {
                let roles = if user.role_ids.is_empty() {
                    "none".to_owned()
                } else {
                    let name = |id: &String| printable_field(names.get(id).unwrap_or(id));
                    user.role_ids.iter().map(name).collect::<Vec<_>>().join(",")
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
            .and_then(|outcome| match outcome {
                DisableOutcome::Disabled => Ok(format!("disabled local user {username}\n")),
                DisableOutcome::NotFound => {
                    Err(format!("local user {username} changed concurrently"))
                }
                DisableOutcome::LastAdministrator => {
                    Err("That is the last enabled Administrator.".to_owned())
                }
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
        UserCommand::ResetPassword {
            username,
            password_stdin,
            must_change,
            recover,
        } => {
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
            let password = if *password_stdin {
                password_from_stdin()
            } else {
                confirmed_password()
            };
            let password = match password {
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
            let now = Utc::now();
            // The password first: a failed replace leaves a disabled
            // account disabled.
            match replace_password(
                client,
                &credential.user_id,
                password_hash.as_str(),
                *must_change,
                now,
                &AuditContext::default(),
                actor,
                "local_admin",
            )
            .await
            {
                Ok(true) => {}
                Ok(false) => {
                    return (
                        Err(format!("local user {username} no longer exists")),
                        Some(username),
                    );
                }
                Err(error) => return (Err(error.to_string()), Some(username)),
            }
            // Break-glass: a reset that left the account disabled or locked
            // would fail exactly when nobody can sign in (ruling 2).
            if *recover {
                let recovered = async {
                    enable_local_user(client, &username, now, actor, "local_admin").await?;
                    unlock_local_user(client, &username, now, actor, "local_admin").await
                };
                if let Err(error) = recovered.await {
                    return (Err(error.to_string()), Some(username));
                }
            }
            (
                Ok(format!(
                    "reset password for local user {username}; all sessions were revoked\n"
                )),
                Some(username),
            )
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

/// One line of standard input as the new password (at most 1 KiB).
fn password_from_stdin() -> Result<NormalizedPassword, String> {
    use std::io::{BufRead, Read};
    let mut line = Zeroizing::new(String::new());
    std::io::stdin()
        .lock()
        .take(1024)
        .read_line(&mut line)
        .map_err(|_| "could not read the password from standard input".to_owned())?;
    let password = line.trim_end_matches(['\n', '\r']);
    NormalizedPassword::new(password).map_err(|_| {
        "password must be 15 to 128 Unicode characters and not a blocked common passphrase".into()
    })
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
    use super::{UserCommand, canonical_username, printable_field, random_uuid};
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
            UserCommand::Create { ref role, .. } if role == "admin"
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
