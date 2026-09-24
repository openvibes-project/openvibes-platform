use axum::{Json, body::Bytes, extract::State, http::StatusCode};
use std::collections::BTreeSet;

use chrono::{DateTime, Duration, NaiveDate, Utc};
use openvibes_core::{
    DeliveryAcknowledgement, Finding, FindingBatch, Heartbeat, Identifier, RejectedFinding,
    SchemaVersion, Severity,
};
use platform_store::ingest::{self, StoredFinding};

use crate::{auth::AuthenticatedAgent, error::ApiError, request::parse, server::AppState};

/// Findings observed further ahead than this are refused
/// (`future_observation`); the protocol states the window.
const MAX_FUTURE_MINUTES: i64 = 60;

/// `POST /v1/heartbeat`: records liveness for the authenticated agent.
pub(crate) async fn heartbeat(
    State(state): State<AppState>,
    AuthenticatedAgent(agent_id): AuthenticatedAgent,
    body: Bytes,
) -> Result<StatusCode, ApiError> {
    let heartbeat: Heartbeat = parse(&body)?;
    if heartbeat.agent_id.as_str() != agent_id {
        return Err(ApiError::BadRequest);
    }
    let capabilities: Vec<String> = heartbeat
        .capabilities
        .iter()
        .map(|capability| capability.as_str().to_owned())
        .collect();
    let client = state.pool.get().await.map_err(|_| ApiError::Unavailable)?;
    ingest::heartbeat(
        &client,
        &agent_id,
        &heartbeat.scanner_version,
        heartbeat.hostname.as_deref(),
        &capabilities,
        Utc::now(),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

fn severity(severity: Severity) -> &'static str {
    match severity {
        Severity::Info => "info",
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

fn stored(finding: &Finding, observed_at: DateTime<Utc>, rule_version: i64) -> StoredFinding {
    StoredFinding {
        finding_id: finding.finding_id.as_str().to_owned(),
        scan_id: finding.scan_id.as_str().to_owned(),
        rule_id: finding.rule_id.as_str().to_owned(),
        rule_version,
        observed_at,
        severity: severity(finding.severity).to_owned(),
        confidence: i16::from(finding.confidence.value()),
        message: finding.message.clone(),
        evidence: finding
            .evidence
            .iter()
            .map(|key| key.as_str().to_owned())
            .collect(),
    }
}

/// The observation time and rule version to store, or the reason the
/// finding is refused permanently.
fn refusal(
    finding: &Finding,
    oldest: DateTime<Utc>,
    latest: DateTime<Utc>,
    partitions: &BTreeSet<NaiveDate>,
) -> Result<(DateTime<Utc>, i64), &'static str> {
    let observed =
        DateTime::from_timestamp_millis(finding.observed_at_unix_ms).ok_or("out_of_range")?;
    let rule_version = i64::try_from(finding.rule_version).map_err(|_| "out_of_range")?;
    if observed > latest {
        return Err("future_observation");
    }
    if observed < oldest {
        return Err("retention_expired");
    }
    if !partitions.contains(&observed.date_naive()) {
        // No partition for a day inside retention: an operator must fix
        // maintenance; retrying cannot help this finding.
        return Err("unstorable");
    }
    Ok((observed, rule_version))
}

/// `POST /v1/findings`: stores a batch for the authenticated agent in one
/// transaction and acknowledges every finding in it, including ones stored
/// before. One bad finding never fails the batch: a finding observed more
/// than an hour in the future, older than the retention window, with a value
/// the store cannot represent, or for a day without a partition is refused
/// on its own, acknowledged, and listed in `rejected_findings`.
pub(crate) async fn findings(
    State(state): State<AppState>,
    AuthenticatedAgent(agent_id): AuthenticatedAgent,
    body: Bytes,
) -> Result<Json<DeliveryAcknowledgement>, ApiError> {
    let batch: FindingBatch = parse(&body)?;
    let now = Utc::now();
    let oldest = now - Duration::days(i64::from(state.finding_retention_days));
    let latest = now + Duration::minutes(MAX_FUTURE_MINUTES);
    let mut client = state.pool.get().await.map_err(|_| ApiError::Unavailable)?;
    let partitions = platform_store::partition_days(&client).await?;
    let mut keep = Vec::with_capacity(batch.findings.len());
    let mut rejected = Vec::new();
    for finding in &batch.findings {
        match refusal(finding, oldest, latest, &partitions) {
            Ok((observed, rule_version)) => keep.push(stored(finding, observed, rule_version)),
            Err(reason) => rejected.push(RejectedFinding {
                finding_id: finding.finding_id.clone(),
                reason: Identifier::new(reason).map_err(|_| ApiError::Unavailable)?,
            }),
        }
    }
    if let Err(error) = ingest::store_findings(&mut client, &agent_id, &keep, now).await {
        tracing::warn!(
            endpoint = "/v1/findings",
            agent_id,
            "findings not stored (database error)"
        );
        return Err(error.into());
    }
    Ok(Json(DeliveryAcknowledgement {
        schema_version: SchemaVersion::V1,
        accepted_finding_ids: batch
            .findings
            .iter()
            .map(|finding| finding.finding_id.clone())
            .collect(),
        acknowledged_at_unix_ms: now.timestamp_millis(),
        rejected_findings: rejected,
    }))
}
