use chrono::Utc;

/// Shared signature verifier for exact signed-envelope request bytes.
pub(super) async fn verify_console_rule_envelope(
    client: &platform_store::Client,
    bytes: &[u8],
) -> Result<(openvibes_core::SignedRuleEnvelope, [u8; 32]), ()> {
    use openvibes_core::{Identifier, ResourceLimits, SignedRuleEnvelope};
    use openvibes_rules::{RuleLoader, TrustedRuleKey};
    use ring::digest;
    if bytes.is_empty() || bytes.len() > 1_048_576 {
        return Err(());
    }
    let envelope: SignedRuleEnvelope = serde_json::from_slice(bytes).map_err(|_| ())?;
    let set = envelope.rule_set_id.as_str();
    let trusted = platform_store::rules::active_trust_keys(client, set)
        .await
        .map_err(|_| ())?
        .into_iter()
        .map(|(key, issuer)| {
            let issuer = Identifier::new(&issuer).map_err(|_| ())?;
            TrustedRuleKey::new(envelope.rule_set_id.clone(), issuer, key).map_err(|_| ())
        })
        .collect::<Result<Vec<_>, ()>>()?;
    let loader = RuleLoader::new(trusted, ResourceLimits::V1).map_err(|_| ())?;
    loader
        .load_json(
            bytes,
            openvibes_rules::LoadContext {
                expected_rule_set_id: &envelope.rule_set_id,
                now_unix_ms: Utc::now().timestamp_millis(),
                last_accepted: None,
            },
        )
        .map_err(|_| ())?;
    let mut hash = [0u8; 32];
    hash.copy_from_slice(digest::digest(&digest::SHA256, bytes).as_ref());
    Ok((envelope, hash))
}

pub(super) fn digest_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
