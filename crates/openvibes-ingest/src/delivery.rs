use axum::{
    Json,
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
};

use chrono::{Duration, Utc};
use openvibes_core::{
    DeliveryAcknowledgement, FindingBatch, Heartbeat, Identifier, InventoryChanges,
    InventoryReport, RejectedFinding, SchemaVersion,
};
use platform_store::{ingest, inventory, wire};

use platform_agent_server::{ApiError, AuthenticatedAgent, parse};

use crate::server::AppState;

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
    let latest = now + Duration::minutes(wire::MAX_FUTURE_MINUTES);
    let mut client = state.pool.get().await.map_err(|_| ApiError::Unavailable)?;
    let partitions = platform_store::partition_days(&client).await?;
    let mut keep = Vec::with_capacity(batch.findings.len());
    let mut rejected = Vec::new();
    for finding in &batch.findings {
        match wire::finding(finding, oldest, latest, &partitions) {
            Ok(row) => keep.push(row),
            Err(reason) => rejected.push(RejectedFinding {
                finding_id: finding.finding_id.clone(),
                reason: Identifier::new(reason).map_err(|_| ApiError::Unavailable)?,
            }),
        }
    }
    if let Err(error) =
        ingest::store_findings(&mut client, &agent_id, &keep, ingest::Origin::Online, now).await
    {
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

/// `POST /v1/inventory` (protocol P8): replaces the authenticated agent's
/// package inventory, unless it is unchanged, for vulnerability matching.
/// The body may be gzip-compressed (P11).
pub(crate) async fn inventory(
    State(state): State<AppState>,
    AuthenticatedAgent(agent_id): AuthenticatedAgent,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, ApiError> {
    let body = platform_agent_server::decoded_body(
        &headers,
        &body,
        platform_agent_server::MAX_INVENTORY_BYTES,
    )?;
    let report: InventoryReport =
        platform_agent_server::parse_with_limit(&body, platform_agent_server::MAX_INVENTORY_BYTES)?;
    if report.agent_id.as_str() != agent_id {
        return Err(ApiError::BadRequest);
    }
    let (rows, digest) = wire::inventory(
        &report.os,
        report.running_kernel.as_deref(),
        &report.packages,
    )?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Unavailable)?;
    inventory::replace(
        &mut client,
        &agent_id,
        report.os.id.as_str(),
        report.os.version_id.as_str(),
        report.running_kernel.as_deref(),
        &rows,
        digest,
        Utc::now(),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /v1/inventory/changes` (protocol P11): applies a change set to the
/// authenticated agent's inventory, or answers 409 `inventory_resync`.
pub(crate) async fn inventory_changes(
    State(state): State<AppState>,
    AuthenticatedAgent(agent_id): AuthenticatedAgent,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, ApiError> {
    let body = platform_agent_server::decoded_body(
        &headers,
        &body,
        platform_agent_server::MAX_INVENTORY_BYTES,
    )?;
    let changes: InventoryChanges =
        platform_agent_server::parse_with_limit(&body, platform_agent_server::MAX_INVENTORY_BYTES)?;
    if changes.agent_id.as_str() != agent_id {
        return Err(ApiError::BadRequest);
    }
    let (Some(base), Some(expected)) = (
        openvibes_core::digest_from_hex(&changes.base_sha256),
        openvibes_core::digest_from_hex(&changes.sha256),
    ) else {
        return Err(ApiError::BadRequest);
    };
    let mut client = state.pool.get().await.map_err(|_| ApiError::Unavailable)?;
    match inventory::apply_changes(
        &mut client,
        &agent_id,
        &changes.os,
        changes.running_kernel.as_deref(),
        &wire::package_rows(&changes.added),
        &wire::package_rows(&changes.removed),
        base,
        expected,
        Utc::now(),
    )
    .await?
    {
        inventory::ChangesOutcome::Stored => Ok(StatusCode::NO_CONTENT),
        inventory::ChangesOutcome::Resync => Err(ApiError::Resync),
    }
}
