//! `openvibes-admin rules …`: trust keys and verified publishing of
//! offline-signed rule envelopes for the distribution service.

use std::{io::Read, path::PathBuf};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, SecondsFormat, Utc};
use clap::Subcommand;
use openvibes_core::{Identifier, ResourceLimits, SignedRuleEnvelope};
use openvibes_rules::{LoadContext, LoadError, RuleLoader, TrustedRuleKey};
use platform_store::rules::{self, NewBundle, Published, TrustAdded};
use sha2::{Digest, Sha256};

/// Largest envelope accepted: the V1 document limit.
const MAX_ENVELOPE: u64 = 1_048_576;
/// Publishing warns when the bundle expires sooner than this.
const WARN_MS: i64 = 7 * 24 * 3_600_000;

#[derive(Subcommand)]
pub enum RulesCommand {
    /// Keys trusted to sign a rule set.
    Trust {
        #[command(subcommand)]
        command: TrustCommand,
    },
    /// Verify a signed envelope and publish it as the set's current bundle.
    Publish {
        /// Signed rule envelope (JSON, at most 1 MiB).
        file: PathBuf,
    },
    /// List rule sets with their current version.
    List,
    /// Show a rule set's published bundles, newest first.
    Show {
        /// Rule set id.
        rule_set: String,
    },
    /// Stop serving a rule set (its bundles are kept).
    Retire {
        /// Rule set id.
        rule_set: String,
    },
}

#[derive(Subcommand)]
pub enum TrustCommand {
    /// Trust an Ed25519 public key for a rule set (creating the set).
    Add {
        /// Rule set id.
        rule_set: String,
        /// Issuer key id named in envelopes.
        issuer_key_id: String,
        /// Public key, 32 bytes, base64url without padding.
        public_key: String,
    },
    /// List trusted keys, removed ones included.
    List {
        /// Only this rule set.
        rule_set: Option<String>,
    },
    /// Stop trusting a key; its id is never re-used.
    Remove {
        /// Rule set id.
        rule_set: String,
        /// Issuer key id.
        issuer_key_id: String,
    },
}

impl RulesCommand {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Trust {
                command: TrustCommand::Add { .. },
            } => "rules trust add",
            Self::Trust {
                command: TrustCommand::List { .. },
            } => "rules trust list",
            Self::Trust {
                command: TrustCommand::Remove { .. },
            } => "rules trust remove",
            Self::Publish { .. } => "rules publish",
            Self::List => "rules list",
            Self::Show { .. } => "rules show",
            Self::Retire { .. } => "rules retire",
        }
    }
}

fn time(at: DateTime<Utc>) -> String {
    at.to_rfc3339_opts(SecondsFormat::Secs, true)
}

fn time_ms(ms: i64) -> String {
    DateTime::from_timestamp_millis(ms).map_or_else(|| "-".into(), time)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn identifier(value: &str) -> Result<Identifier, String> {
    Identifier::new(value).map_err(|_| "invalid identifier".to_owned())
}

fn public_key(value: &str) -> Result<[u8; 32], String> {
    const INVALID: &str = "invalid public key (32-byte Ed25519, base64url)";
    let bytes = URL_SAFE_NO_PAD.decode(value).map_err(|_| INVALID)?;
    let key: [u8; 32] = bytes.try_into().map_err(|_| INVALID)?;
    match ed25519_dalek::VerifyingKey::from_bytes(&key) {
        Ok(verifying) if !verifying.is_weak() => Ok(key),
        _ => Err(INVALID.into()),
    }
}

fn store(error: platform_store::StoreError) -> String {
    error.to_string()
}

/// Runs a rules command; returns the output and the audit target.
pub async fn run(
    command: &RulesCommand,
    client: &mut platform_store::Client,
    actor: &str,
) -> (Result<String, String>, Option<String>) {
    match command {
        RulesCommand::Trust { command } => trust(command, client).await,
        RulesCommand::Publish { file } => publish(file, client, actor).await,
        RulesCommand::List => (list(client).await, None),
        RulesCommand::Show { rule_set } => (show(client, rule_set).await, Some(rule_set.clone())),
        RulesCommand::Retire { rule_set } => {
            let result = match rules::retire(client, rule_set).await {
                Ok(true) => Ok(format!("retired {rule_set}\n")),
                Ok(false) => Err("unknown or already retired rule set".into()),
                Err(error) => Err(store(error)),
            };
            (result, Some(rule_set.clone()))
        }
    }
}

async fn trust(
    command: &TrustCommand,
    client: &mut platform_store::Client,
) -> (Result<String, String>, Option<String>) {
    match command {
        TrustCommand::Add {
            rule_set,
            issuer_key_id,
            public_key: key,
        } => {
            let target = Some(format!("{rule_set}/{issuer_key_id}"));
            let checked = identifier(rule_set)
                .and_then(|_| identifier(issuer_key_id))
                .and_then(|_| public_key(key));
            let result = match checked {
                Err(error) => Err(error),
                Ok(key) => match rules::add_trust_key(client, rule_set, issuer_key_id, key).await {
                    Ok(TrustAdded::Added) => Ok("trusted\n".into()),
                    Ok(TrustAdded::AlreadyTrusted) => Ok("already trusted\n".into()),
                    Ok(TrustAdded::Conflict) => {
                        Err("issuer key id already used for a different or removed key".into())
                    }
                    Ok(TrustAdded::Retired) => Err("rule set is retired".into()),
                    Err(error) => Err(store(error)),
                },
            };
            (result, target)
        }
        TrustCommand::List { rule_set } => {
            let result = rules::trust_keys(client, rule_set.as_deref())
                .await
                .map_err(store)
                .map(|keys| {
                    keys.iter()
                        .map(|key| {
                            let removed = key
                                .removed_at
                                .map_or_else(String::new, |at| format!(" removed {}", time(at)));
                            format!(
                                "{} {} {} added {}{removed}\n",
                                key.rule_set_id,
                                key.issuer_key_id,
                                URL_SAFE_NO_PAD.encode(key.public_key),
                                time(key.added_at),
                            )
                        })
                        .collect()
                });
            (result, rule_set.clone())
        }
        TrustCommand::Remove {
            rule_set,
            issuer_key_id,
        } => {
            let result = match rules::remove_trust_key(client, rule_set, issuer_key_id).await {
                Ok(true) => Ok("removed\n".into()),
                Ok(false) => Err("no such trusted key".into()),
                Err(error) => Err(store(error)),
            };
            (result, Some(format!("{rule_set}/{issuer_key_id}")))
        }
    }
}

fn read_envelope(file: &PathBuf) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    std::fs::File::open(file)
        .and_then(|opened| opened.take(MAX_ENVELOPE + 1).read_to_end(&mut bytes))
        .map_err(|_| "cannot read the envelope file".to_owned())?;
    if bytes.len() as u64 > MAX_ENVELOPE {
        return Err(format!("envelope is larger than {MAX_ENVELOPE} bytes"));
    }
    Ok(bytes)
}

fn load_error(error: LoadError) -> String {
    match error {
        LoadError::UntrustedIssuer => "untrusted issuer".into(),
        LoadError::InvalidSignature | LoadError::DigestMismatch => "invalid signature".into(),
        LoadError::Expired => "envelope has expired".into(),
        LoadError::NotYetValid => "envelope is created in the future".into(),
        other => format!("envelope refused: {other}"),
    }
}

async fn publish(
    file: &PathBuf,
    client: &mut platform_store::Client,
    actor: &str,
) -> (Result<String, String>, Option<String>) {
    let bytes = match read_envelope(file) {
        Ok(bytes) => bytes,
        Err(error) => return (Err(error), None),
    };
    let Ok(envelope) = serde_json::from_slice::<SignedRuleEnvelope>(&bytes) else {
        return (Err("not a signed rule envelope".into()), None);
    };
    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    let set = envelope.rule_set_id.as_str().to_owned();
    let version = envelope.rule_set_version;
    let target = Some(format!("{set} v{version} sha256:{}", hex(&digest)));
    let result = verify_and_store(client, actor, &bytes, &envelope, digest).await;
    (result, target)
}

async fn verify_and_store(
    client: &mut platform_store::Client,
    actor: &str,
    bytes: &[u8],
    envelope: &SignedRuleEnvelope,
    digest: [u8; 32],
) -> Result<String, String> {
    let set = envelope.rule_set_id.as_str();
    let version = envelope.rule_set_version;
    let mut keys = Vec::new();
    for (key, issuer) in rules::active_trust_keys(client, set).await.map_err(store)? {
        let trusted = TrustedRuleKey::new(envelope.rule_set_id.clone(), identifier(&issuer)?, key)
            .map_err(load_error)?;
        keys.push(trusted);
    }
    let now = Utc::now().timestamp_millis();
    // The rollback floor is the stored current version, checked by the
    // store; the loader checks trust, signature, and time.
    RuleLoader::new(keys, ResourceLimits::V1)
        .and_then(|loader| {
            loader.load_json(
                bytes,
                LoadContext {
                    expected_rule_set_id: &envelope.rule_set_id,
                    now_unix_ms: now,
                    last_accepted: None,
                },
            )
        })
        .map_err(load_error)?;
    let stored_version = i64::try_from(version).map_err(|_| "version out of range")?;
    let bundle = NewBundle {
        rule_set_id: set,
        version: stored_version,
        envelope: bytes,
        envelope_sha256: digest,
        issuer_key_id: envelope.issuer_key_id.as_str(),
        created_at_ms: envelope.created_at_unix_ms,
        expires_at_ms: envelope.expires_at_unix_ms,
        published_by: actor,
    };
    let output = match rules::publish(client, &bundle).await.map_err(store)? {
        Published::Stored => format!("published {set} v{version}\n"),
        Published::Unchanged => format!("unchanged: {set} v{version} already published\n"),
        Published::VersionConflict => {
            return Err(format!(
                "version {version} already published with different content"
            ));
        }
        Published::NotAboveCurrent(current) => {
            return Err(format!(
                "version {version} is not above current version {current}"
            ));
        }
        Published::Retired => return Err("rule set is retired".into()),
        // No keys means the loader already refused it; UntrustedIssuer means
        // the key was removed after verification.
        Published::UnknownSet | Published::UntrustedIssuer => {
            return Err("untrusted issuer".into());
        }
    };
    if envelope.expires_at_unix_ms - now < WARN_MS {
        eprintln!("openvibes-admin: warning: bundle expires in less than 7 days");
    }
    Ok(output)
}

async fn list(client: &platform_store::Client) -> Result<String, String> {
    let sets = rules::list(client).await.map_err(store)?;
    Ok(sets
        .iter()
        .map(|set| {
            let version = set
                .current_version
                .map_or_else(|| "none".into(), |v| format!("v{v}"));
            let expires = set
                .current_expires_at_ms
                .map_or_else(|| "-".into(), time_ms);
            let retired = if set.retired_at.is_some() {
                " retired"
            } else {
                ""
            };
            // Still served, but agents that dropped the key will refuse it.
            let removed = if set.current_signer_removed {
                " signer-removed"
            } else {
                ""
            };
            format!(
                "{} {version} keys {} expires {expires}{removed}{retired}\n",
                set.rule_set_id, set.trusted_keys
            )
        })
        .collect())
}

async fn show(client: &platform_store::Client, set: &str) -> Result<String, String> {
    let known = rules::list(client)
        .await
        .map_err(store)?
        .iter()
        .any(|row| row.rule_set_id == set);
    if !known {
        return Err("unknown rule set".into());
    }
    let bundles = rules::bundles(client, set).await.map_err(store)?;
    Ok(bundles
        .iter()
        .map(|bundle| {
            format!(
                "v{} sha256:{} issuer {} bytes {} published {} by {} expires {}\n",
                bundle.version,
                hex(&bundle.envelope_sha256),
                bundle.issuer_key_id,
                bundle.bytes,
                time(bundle.published_at),
                bundle.published_by,
                time_ms(bundle.expires_at_ms),
            )
        })
        .collect())
}
