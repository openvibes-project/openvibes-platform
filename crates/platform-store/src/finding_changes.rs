//! Finding changes (protocol P13): a P13 agent's rule matches as change
//! sets, applied under the agent's row lock and checked against the match
//! digest. Per-scan agents (`source = 'scan'`) are never touched here.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use openvibes_core::{
    Confidence, Finding, FindingChanges, Identifier, SchemaVersion, Severity, digest_from_hex,
    match_digest,
};

use crate::{
    Client, StoreError,
    ingest::{Origin, StoredFinding, store_findings_in},
};

/// What [`apply`] did.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    /// Applied, and the new digest recorded.
    Stored,
    /// Nothing stored: the agent must send a replace (409 `findings_resync`).
    Resync,
}

/// The document's findings, checked and converted by the caller
/// (`wire::finding`), in the document's order.
#[derive(Clone, Debug, Default)]
pub struct Rows {
    /// `started`, as stored.
    pub started: Vec<StoredFinding>,
    /// `changed`, as stored.
    pub changed: Vec<StoredFinding>,
    /// `transient`, as stored, with when each ended.
    pub transient: Vec<(StoredFinding, DateTime<Utc>)>,
}

/// (rule set, rule).
type Key = (String, String);

fn wire_key(finding: &Finding) -> Key {
    (
        finding
            .rule_set_id
            .as_ref()
            .map_or_else(String::new, |set| set.as_str().to_owned()),
        finding.rule_id.as_str().to_owned(),
    )
}

/// A stored open match as the digest sees it; the other fields are not
/// part of the digest.
fn digest_finding(
    set: &str,
    rule: &str,
    version: i64,
    severity: &str,
    message: String,
    evidence: &[String],
) -> Option<Finding> {
    Some(Finding {
        schema_version: SchemaVersion::V1,
        finding_id: Identifier::new("finding.stored").ok()?,
        scan_id: Identifier::new("scan.stored").ok()?,
        rule_set_id: Some(Identifier::new(set).ok()?),
        rule_id: Identifier::new(rule).ok()?,
        rule_version: u64::try_from(version).ok()?,
        observed_at_unix_ms: 0,
        severity: serde_json::from_value::<Severity>(serde_json::Value::from(severity)).ok()?,
        confidence: Confidence::new(100).ok()?,
        message,
        evidence: evidence
            .iter()
            .map(|key| Identifier::new(key.as_str()))
            .collect::<Result<_, _>>()
            .ok()?,
    })
}

/// Applies `changes` for the authenticated `agent_id`, or answers
/// [`Outcome::Resync`] and stores nothing: the stored digest is not
/// `base_sha256` (unless `replace`), a `started` match is already open, a
/// `changed` or `ended` one is not, or the result's digest is not `sha256`.
///
/// # Errors
///
/// A database error.
pub async fn apply(
    client: &mut Client,
    agent_id: &str,
    changes: &FindingChanges,
    rows: &Rows,
    now: DateTime<Utc>,
) -> Result<Outcome, StoreError> {
    let (Some(base), Some(expected)) = (
        digest_from_hex(&changes.base_sha256),
        digest_from_hex(&changes.sha256),
    ) else {
        return Ok(Outcome::Resync);
    };
    let scanned_at =
        DateTime::from_timestamp_millis(changes.scanned_at_unix_ms).ok_or(StoreError::Query)?;
    let transaction = client.transaction().await?;
    let stored: Option<Vec<u8>> = transaction
        .query_one(
            "SELECT match_sha256 FROM agents WHERE agent_id = $1 FOR UPDATE",
            &[&agent_id],
        )
        .await?
        .get(0);
    let stored = stored.unwrap_or_else(|| match_digest(&[]).to_vec());
    if !changes.replace && stored != base {
        return Ok(Outcome::Resync);
    }
    let mut open: BTreeMap<Key, Finding> = BTreeMap::new();
    for row in transaction
        .query(
            "SELECT rule_set_id, rule_id, rule_version, severity, message, evidence
             FROM current_findings
             WHERE agent_id = $1 AND source = 'changes' AND ended_at IS NULL",
            &[&agent_id],
        )
        .await?
    {
        let (set, rule): (String, String) = (row.get(0), row.get(1));
        let evidence: Vec<String> = row.get(5);
        let finding = digest_finding(&set, &rule, row.get(2), row.get(3), row.get(4), &evidence)
            .ok_or(StoreError::Query)?;
        open.insert((set, rule), finding);
    }
    // What ends, and how: (key, when, approximate).
    let mut ends: Vec<(Key, DateTime<Utc>, bool)> = Vec::new();
    if changes.replace {
        let next: BTreeMap<Key, Finding> = changes
            .started
            .iter()
            .map(|f| (wire_key(f), f.clone()))
            .collect();
        ends.extend(
            open.keys()
                .filter(|k| !next.contains_key(*k))
                .map(|k| (k.clone(), scanned_at, true)),
        );
        open = next;
    } else {
        for finding in &changes.started {
            if open.insert(wire_key(finding), finding.clone()).is_some() {
                return Ok(Outcome::Resync);
            }
        }
        for finding in &changes.changed {
            if open.insert(wire_key(finding), finding.clone()).is_none() {
                return Ok(Outcome::Resync);
            }
        }
        for ended in &changes.ended {
            let key = (
                ended.rule_set_id.as_str().to_owned(),
                ended.rule_id.as_str().to_owned(),
            );
            if open.remove(&key).is_none() {
                return Ok(Outcome::Resync);
            }
            let at =
                DateTime::from_timestamp_millis(ended.ended_at_unix_ms).ok_or(StoreError::Query)?;
            ends.push((key, at, false));
        }
    }
    let result: Vec<Finding> = open.values().cloned().collect();
    if match_digest(&result) != expected {
        return Ok(Outcome::Resync);
    }

    // History, and the automatic reopen of completed triage, as for every
    // delivered finding (the insert skips ids stored before).
    let transient: Vec<StoredFinding> = rows.transient.iter().map(|(f, _)| f.clone()).collect();
    for batch in [&rows.started, &rows.changed, &transient] {
        store_findings_in(&transaction, agent_id, batch, Origin::Online, now).await?;
    }
    // The match itself: P13, open, current as of now, with the reported
    // content even when its start is older than the row's last observation.
    for row in rows.started.iter().chain(&rows.changed) {
        mark(&transaction, agent_id, row, None, false, now).await?;
    }
    for (row, ended_at) in &rows.transient {
        let key = (row.rule_set_id.clone(), row.rule_id.clone());
        if !open.contains_key(&key) {
            mark(&transaction, agent_id, row, Some(*ended_at), false, now).await?;
        }
    }
    for ((set, rule), at, approximate) in &ends {
        transaction
            .execute(
                "UPDATE current_findings SET ended_at = $4, end_approximate = $5
                 WHERE agent_id = $1 AND rule_set_id = $2 AND rule_id = $3",
                &[&agent_id, set, rule, at, approximate],
            )
            .await?;
    }
    transaction
        .execute(
            "UPDATE agents SET match_sha256 = $2 WHERE agent_id = $1",
            &[&agent_id, &expected.as_slice()],
        )
        .await?;
    transaction.commit().await?;
    Ok(Outcome::Stored)
}

/// Sets a P13 match's row to `row`'s content, open (`ended_at` `None`) or
/// ended, and current as of `now`.
async fn mark(
    transaction: &tokio_postgres::Transaction<'_>,
    agent_id: &str,
    row: &StoredFinding,
    ended_at: Option<DateTime<Utc>>,
    approximate: bool,
    now: DateTime<Utc>,
) -> Result<(), StoreError> {
    let seen = ended_at.unwrap_or(now);
    transaction
        .execute(
            "UPDATE current_findings SET source = 'changes', ended_at = $4,
                 end_approximate = $5, last_finding_id = $6, rule_version = $7,
                 severity = $8, confidence = $9, message = $10, evidence = $11,
                 scan_id = $12, last_observed_at = $13, last_observed_day = $14
             WHERE agent_id = $1 AND rule_set_id = $2 AND rule_id = $3",
            &[
                &agent_id,
                &row.rule_set_id,
                &row.rule_id,
                &ended_at,
                &approximate,
                &row.finding_id,
                &row.rule_version,
                &row.severity,
                &row.confidence,
                &row.message,
                &row.evidence,
                &row.scan_id,
                &seen,
                &seen.date_naive(),
            ],
        )
        .await?;
    Ok(())
}
