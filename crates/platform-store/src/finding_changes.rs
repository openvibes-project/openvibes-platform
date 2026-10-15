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
        detection: None,
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
                "UPDATE current_findings SET ended_at = $4, end_approximate = $5,
                     end_recorded_at = $6
                 WHERE agent_id = $1 AND rule_set_id = $2 AND rule_id = $3",
                &[&agent_id, set, rule, at, approximate, &now],
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
/// ended (its end recorded at `now`), and current as of `now`.
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
                 end_recorded_at = CASE WHEN $4::timestamptz IS NULL THEN NULL ELSE $16::timestamptz END,
                 end_approximate = $5, last_finding_id = $6, rule_version = $7,
                 severity = $8, confidence = $9, message = $10, evidence = $11,
                 scan_id = $12, last_observed_at = $13, last_observed_day = $14, detection = $15
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
                &row.detection,
                &now,
            ],
        )
        .await?;
    Ok(())
}

/// A P13 heartbeat's `match_sha256`: returns `true` (the agent must send a
/// replace, 409 `findings_resync`) when it is not the stored digest.
/// Otherwise keeps the agent's open P13 matches current and reopens
/// completed triage that a scan after it confirmed (`last_scan_at`).
///
/// ponytail: `last_observed_at` of open matches is refreshed at most once an
/// hour (the console's shortest window is 24 h); if that write rate is ever
/// measured hot, read `greatest(last_observed_at, agents.last_seen_at)` for
/// open P13 rows instead, with an expression index.
///
/// # Errors
///
/// A database error.
pub async fn heartbeat(
    client: &mut Client,
    agent_id: &str,
    match_sha256: [u8; 32],
    last_scan_at: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> Result<bool, StoreError> {
    let transaction = client.transaction().await?;
    let stored: Option<Vec<u8>> = transaction
        .query_one(
            "SELECT match_sha256 FROM agents WHERE agent_id = $1 FOR UPDATE",
            &[&agent_id],
        )
        .await?
        .get(0);
    if stored.unwrap_or_else(|| match_digest(&[]).to_vec()) != match_sha256 {
        return Ok(true);
    }
    transaction
        .execute(
            "UPDATE current_findings SET last_observed_at = $2, last_observed_day = $3
             WHERE agent_id = $1 AND source = 'changes' AND ended_at IS NULL
               AND last_observed_at < $2::timestamptz - interval '1 hour'",
            &[&agent_id, &now, &now.date_naive()],
        )
        .await?;
    // A scan finished after the triage closed still has the match open.
    if let Some(confirmed_at) = last_scan_at.map(|at| at.min(now)) {
        let rows = transaction
            .query(
                "SELECT c.rule_set_id, c.rule_id, c.rule_version
                 FROM current_findings c
                 JOIN console_finding_triage t USING (agent_id, rule_set_id, rule_id)
                 WHERE c.agent_id = $1 AND c.source = 'changes' AND c.ended_at IS NULL
                   AND t.state IN ('mitigated', 'accepted_risk')",
                &[&agent_id],
            )
            .await?;
        for row in rows {
            let (set, rule): (String, String) = (row.get(0), row.get(1));
            crate::console_triage::reopen_if_due(
                &transaction,
                agent_id,
                &set,
                &rule,
                row.get(2),
                confirmed_at,
                now,
            )
            .await?;
        }
    }
    transaction.commit().await?;
    Ok(false)
}

/// History note when a match ends because its set is off for the host
/// (spec 2026-10-14 §5).
pub const NOT_ASSIGNED_NOTE: &str = "rule set no longer assigned to this host";

/// The agent reported `sets` as `not_assigned` (P20). Call it before
/// `ingest::heartbeat` stores the report: it acts only on the transition,
/// an assignable set (`rule_set_assignment`) the stored report did not
/// already list as `not_assigned`. For such a set, under the agent's row
/// lock and in one transaction, this host's still-open matches end (as when
/// the host stops matching), and every match of the set whose end was
/// recorded since the stored report (`end_recorded_at >= health_at`, both
/// the platform's clock, so the agent's clock never matters; none stored:
/// only those ended here), whoever ended it, gets one triage-history entry by `system` with
/// [`NOT_ASSIGNED_NOTE`], its state unchanged (from = to). The agent
/// usually ends them itself through P13 in the scan that got the 410, just
/// before this report (lab check, task 9). Matches that ended earlier get
/// no note; a match never gets the note twice. Triage is never touched; no
/// audit row, as for any match end. Returns how many notes were written; a
/// repeated report writes nothing.
///
/// # Errors
///
/// A database error.
pub async fn end_unassigned(
    client: &mut Client,
    agent_id: &str,
    sets: &[String],
    now: DateTime<Utc>,
) -> Result<u64, StoreError> {
    let transaction = client.transaction().await?;
    let Some(row) = transaction
        .query_opt(
            "SELECT COALESCE(a.health_at, $3),
                 ARRAY(SELECT s FROM unnest($2::text[]) s
                       WHERE s IN (SELECT rule_set_id FROM rule_set_assignment)
                         AND NOT EXISTS (
                             SELECT 1 FROM jsonb_array_elements(
                                 COALESCE(a.health->'rule_sets', '[]')) r
                             WHERE r->>'id' = s AND r->>'state' = 'not_assigned'))
             FROM agents a WHERE a.agent_id = $1 FOR UPDATE",
            &[&agent_id, &sets, &now],
        )
        .await?
    else {
        return Ok(0);
    };
    let (since, switched): (DateTime<Utc>, Vec<String>) = (row.get(0), row.get(1));
    if switched.is_empty() {
        return Ok(0);
    }
    transaction
        .execute(
            "UPDATE current_findings SET ended_at = $3, end_recorded_at = $3,
                 end_approximate = true
             WHERE agent_id = $1 AND rule_set_id = ANY($2) AND ended_at IS NULL",
            &[&agent_id, &switched, &now],
        )
        .await?;
    let noted = transaction
        .execute(
            "INSERT INTO console_finding_triage_history (agent_id, rule_set_id, rule_id,
                 from_state, to_state, note, changed_at, changed_by, rule_version)
             SELECT c.agent_id, c.rule_set_id, c.rule_id, COALESCE(t.state, 'open'),
                 COALESCE(t.state, 'open'), $5, $3, 'system', c.rule_version
             FROM current_findings c
             LEFT JOIN console_finding_triage t USING (agent_id, rule_set_id, rule_id)
             WHERE c.agent_id = $1 AND c.rule_set_id = ANY($2) AND c.end_recorded_at >= $4
               AND NOT EXISTS (
                   SELECT 1 FROM console_finding_triage_history h
                   WHERE (h.agent_id, h.rule_set_id, h.rule_id)
                         = (c.agent_id, c.rule_set_id, c.rule_id)
                     AND h.note = $5 AND h.changed_at >= c.end_recorded_at)",
            &[&agent_id, &switched, &now, &since, &NOT_ASSIGNED_NOTE],
        )
        .await?;
    transaction.commit().await?;
    Ok(noted)
}
