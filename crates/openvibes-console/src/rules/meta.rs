//! The rule-metadata index (`platform_store::rule_meta`): built from stored
//! bundles that verify, with the same verification as the historical rule
//! read (`alarms/detection.rs`). `explain` and `check` are not in the agent's
//! rule contract, so they are read from the verified payload's JSON.

use openvibes_core::{Identifier, PayloadEncoding};
use platform_store::{
    Client, StoreError,
    rule_meta::{self, RuleMetaRow},
};
use serde_json::Value;

use crate::alarms::detection::{stored_loader, verify_stored};

/// Longest `explain` or `check` text kept, in characters (protocol limit).
const TEXT_CHARS: usize = 600;
/// Most bundles one start-up backfill examines; the rest wait for the next start.
const BACKFILL_LIMIT: i64 = 10_000;

/// Indexes stored bundle `set` v`version`. `Ok(false)` when it is missing or
/// does not verify; it is then not indexed and alarms fall back.
pub async fn index_bundle(client: &Client, set: &str, version: i64) -> Result<bool, StoreError> {
    let Ok(set_id) = Identifier::new(set) else {
        return Ok(false);
    };
    let Some(bytes) = platform_store::rules::observation_bundles(client, set, Some(version))
        .await?
        .pop()
    else {
        return Ok(false);
    };
    let Some(loader) = stored_loader(client, &set_id).await? else {
        return Ok(false);
    };
    let Some((envelope, bundle)) = verify_stored(&loader, &set_id, &bytes) else {
        return Ok(false);
    };
    if i64::try_from(envelope.rule_set_version) != Ok(version) {
        tracing::warn!(
            set,
            version,
            "stored bundle's version differs from its envelope"
        );
        return Ok(false);
    }
    // ponytail: YAML payloads get no explain/check (no YAML parser here); add
    // one when a YAML rule set carries the text.
    let raw: Vec<Value> = if envelope.payload_encoding == PayloadEncoding::Json {
        serde_json::from_str::<Value>(&envelope.payload)
            .ok()
            .and_then(|payload| payload["rules"].as_array().cloned())
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    let rows: Vec<RuleMetaRow> = bundle
        .rules()
        .rules
        .iter()
        .filter_map(|rule| {
            let raw = raw.iter().find(|raw| raw["id"] == rule.id.as_str());
            let text = |field: &str| {
                raw.and_then(|raw| raw[field].as_str())
                    .map(|text| text.chars().take(TEXT_CHARS).collect())
            };
            Some(RuleMetaRow {
                rule_id: rule.id.as_str().into(),
                rule_version: i64::try_from(rule.version).ok()?,
                title: rule.title.clone(),
                message: rule.finding_message.clone(),
                explain: text("explain"),
                check: text("check"),
                attack: rule
                    .attack
                    .iter()
                    .flatten()
                    .map(|pair| (pair.tactic.clone(), pair.technique.clone()))
                    .collect(),
            })
        })
        .collect();
    rule_meta::upsert_from_bundle(client, set, version, &rows).await?;
    Ok(true)
}

/// What one backfill did.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Backfill {
    /// Bundles indexed.
    pub indexed: usize,
    /// Bundles that did not verify (they stay unindexed).
    pub skipped: usize,
}

/// Indexes stored bundles not yet indexed, at most `BACKFILL_LIMIT` (10,000).
pub async fn backfill(client: &Client) -> Result<Backfill, StoreError> {
    let mut done = Backfill::default();
    for (set, version) in rule_meta::missing_bundles(client, BACKFILL_LIMIT).await? {
        if index_bundle(client, &set, version).await? {
            done.indexed += 1;
        } else {
            done.skipped += 1;
        }
    }
    Ok(done)
}

/// The console's one-time start-up backfill, logged; errors are logged and
/// the next start tries again.
pub(crate) async fn backfill_on_start(pool: platform_store::Pool) {
    let Ok(client) = pool.get().await else {
        tracing::warn!("rule-metadata backfill skipped: database unavailable");
        return;
    };
    match backfill(&client).await {
        Ok(done) if done.indexed + done.skipped > 0 => tracing::info!(
            indexed = done.indexed,
            unverifiable = done.skipped,
            "rule-metadata backfill finished"
        ),
        Ok(_) => {}
        Err(error) => tracing::warn!(%error, "rule-metadata backfill failed"),
    }
}

/// Indexes a bundle the console just stored; a failure is logged, not
/// returned: the alarm page falls back and the next start's backfill retries.
pub(crate) async fn index_published(client: &Client, set: &str, version: i64) {
    match index_bundle(client, set, version).await {
        Ok(true) => {}
        Ok(false) => tracing::warn!(
            set,
            version,
            "stored rule bundle did not verify for indexing"
        ),
        Err(error) => tracing::warn!(%error, set, version, "rule-metadata indexing failed"),
    }
}
