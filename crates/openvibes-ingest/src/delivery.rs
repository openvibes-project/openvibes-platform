use axum::{Json, body::Bytes, extract::State, http::StatusCode};
use chrono::{DateTime, Duration, Utc};
use openvibes_core::{
    DeliveryAcknowledgement, Finding, FindingBatch, Heartbeat, SchemaVersion, Severity,
};
use platform_store::ingest::{self, StoredFinding};

use crate::{auth::AuthenticatedAgent, error::ApiError, request::parse, server::AppState};

/// Findings observed further ahead than this fail the batch.
const MAX_FUTURE_MINUTES: i64 = 5;

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

fn stored(finding: &Finding, observed_at: DateTime<Utc>) -> Result<StoredFinding, ApiError> {
    Ok(StoredFinding {
        finding_id: finding.finding_id.as_str().to_owned(),
        scan_id: finding.scan_id.as_str().to_owned(),
        rule_id: finding.rule_id.as_str().to_owned(),
        rule_version: i64::try_from(finding.rule_version).map_err(|_| ApiError::BadRequest)?,
        observed_at,
        severity: severity(finding.severity).to_owned(),
        confidence: i16::from(finding.confidence.value()),
        message: finding.message.clone(),
        evidence: finding
            .evidence
            .iter()
            .map(|key| key.as_str().to_owned())
            .collect(),
    })
}

/// `POST /v1/findings`: stores a batch for the authenticated agent in one
/// transaction and acknowledges every finding in it, including ones stored
/// before. A finding more than 5 minutes in the future fails the batch;
/// findings older than the retention window are acknowledged unstored.
pub(crate) async fn findings(
    State(state): State<AppState>,
    AuthenticatedAgent(agent_id): AuthenticatedAgent,
    body: Bytes,
) -> Result<Json<DeliveryAcknowledgement>, ApiError> {
    let batch: FindingBatch = parse(&body)?;
    let now = Utc::now();
    let oldest = now - Duration::days(i64::from(state.finding_retention_days));
    let latest = now + Duration::minutes(MAX_FUTURE_MINUTES);
    let mut keep = Vec::with_capacity(batch.findings.len());
    for finding in &batch.findings {
        let observed = DateTime::from_timestamp_millis(finding.observed_at_unix_ms)
            .ok_or(ApiError::BadRequest)?;
        if observed > latest {
            return Err(ApiError::BadRequest);
        }
        if observed >= oldest {
            keep.push(stored(finding, observed)?);
        }
    }
    let mut client = state.pool.get().await.map_err(|_| ApiError::Unavailable)?;
    if let Err(error) = ingest::store_findings(&mut client, &agent_id, &keep, now).await {
        tracing::warn!(
            endpoint = "/v1/findings",
            agent_id,
            "findings not stored (database error or missing partition)"
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
    }))
}
