//! `rules publish`: verifies a signed envelope against the set's active
//! trust keys, stores it, and indexes it for the console's alarm pages.

use chrono::Utc;
use openvibes_core::{ResourceLimits, SignedRuleEnvelope};
use openvibes_rules::{LoadContext, RuleLoader, TrustedRuleKey};
use platform_store::rules::{self, NewBundle, Published};

use crate::rules::{WARN_MS, identifier, load_error, store};

pub(super) async fn verify_and_store(
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
    // For the console's alarm pages; its next start retries a failure.
    match openvibes_console::index_rule_bundle(client, set, stored_version).await {
        Ok(true) => {}
        Ok(false) => eprintln!("openvibes-admin: warning: bundle not indexed for alarm pages"),
        Err(_) => eprintln!("openvibes-admin: warning: indexing for alarm pages failed"),
    }
    if envelope.expires_at_unix_ms - now < WARN_MS {
        eprintln!("openvibes-admin: warning: bundle expires in less than 7 days");
    }
    Ok(output)
}
