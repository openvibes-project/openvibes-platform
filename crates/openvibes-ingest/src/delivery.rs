use axum::{
    Json,
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
};

use chrono::{Duration, Utc};
use openvibes_core::{
    ALARM_BATCH_BYTES, AlarmBatch, DeliveryAcknowledgement, Finding, FindingBatch, FindingChanges,
    HOST_SERVICES_BYTES, Heartbeat, HostServices, Identifier, InventoryChanges, InventoryReport,
    ListenerProtocol, Owners, RejectedFinding, ResourceLimits, SchemaVersion, Validate, hex,
    services_digest,
};
use platform_store::{alarms, finding_changes, host_services, ingest, inventory, wire};

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
    let health = heartbeat
        .health
        .as_ref()
        .map(serde_json::to_value)
        .transpose()
        .map_err(|_| ApiError::BadRequest)?;
    let match_sha256 = heartbeat
        .match_sha256
        .as_deref()
        .map(|digest| openvibes_core::digest_from_hex(digest).ok_or(ApiError::BadRequest))
        .transpose()?;
    let now = Utc::now();
    let mut client = state.pool.get().await.map_err(|_| ApiError::Unavailable)?;
    ingest::heartbeat(
        &client,
        &agent_id,
        &heartbeat.scanner_version,
        heartbeat.hostname.as_deref(),
        &capabilities,
        health.as_ref(),
        now,
    )
    .await?;
    // P13: the heartbeat is stored; a digest that is not ours asks for the
    // whole match set.
    if let Some(digest) = match_sha256 {
        let last_scan_at = heartbeat
            .health
            .as_ref()
            .and_then(|health| health.last_scan.as_ref())
            .and_then(|scan| chrono::DateTime::from_timestamp_millis(scan.finished_at_unix_ms));
        if finding_changes::heartbeat(&mut client, &agent_id, digest, last_scan_at, now).await? {
            return Err(ApiError::FindingsResync);
        }
    }
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

/// `POST /v1/findings/changes` (protocol P13): applies a change set to the
/// authenticated agent's matches, or answers 409 `findings_resync`. Entries
/// are never refused one by one: a start the store cannot date (outside
/// retention, in the future, a day without a partition) is stored at
/// receipt; only a value it cannot hold, or an invalid document, is 400.
pub(crate) async fn finding_changes(
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
    let changes: FindingChanges =
        platform_agent_server::parse_with_limit(&body, platform_agent_server::MAX_INVENTORY_BYTES)?;
    if changes.agent_id.as_str() != agent_id || changes.validate(ResourceLimits::V1).is_err() {
        return Err(ApiError::BadRequest);
    }
    let now = Utc::now();
    let oldest = now - Duration::days(i64::from(state.finding_retention_days));
    let latest = now + Duration::minutes(wire::MAX_FUTURE_MINUTES);
    let mut client = state.pool.get().await.map_err(|_| ApiError::Unavailable)?;
    let partitions = platform_store::partition_days(&client).await?;
    let row = |finding: &Finding| -> Result<ingest::StoredFinding, ApiError> {
        match wire::finding(finding, oldest, latest, &partitions) {
            Ok(row) => Ok(row),
            Err("out_of_range") => Err(ApiError::BadRequest),
            // Stored at receipt; the match keeps its reported start.
            Err(_) => {
                let mut at_receipt = finding.clone();
                at_receipt.observed_at_unix_ms = now.timestamp_millis();
                wire::finding(&at_receipt, oldest, latest, &partitions)
                    .map_err(|_| ApiError::Unavailable)
            }
        }
    };
    let rows = finding_changes::Rows {
        started: changes.started.iter().map(row).collect::<Result<_, _>>()?,
        changed: changes.changed.iter().map(row).collect::<Result<_, _>>()?,
        transient: changes
            .transient
            .iter()
            .map(|transient| {
                let ended = chrono::DateTime::from_timestamp_millis(transient.ended_at_unix_ms)
                    .ok_or(ApiError::BadRequest)?;
                Ok((row(&transient.finding)?, ended))
            })
            .collect::<Result<_, ApiError>>()?,
    };
    match finding_changes::apply(&mut client, &agent_id, &changes, &rows, now).await? {
        finding_changes::Outcome::Stored => Ok(StatusCode::NO_CONTENT),
        finding_changes::Outcome::Resync => Err(ApiError::FindingsResync),
    }
}

/// `POST /v1/alarms` (protocol P14): stores the authenticated agent's
/// alarms. The answer carries nothing per alarm, so an alarm the store
/// cannot hold (outside retention, in the future, a day without a
/// partition) is skipped, logged and counted, and the rest stored: a
/// batch queued through a long outage must never stall the agent's queue.
/// 400 for an invalid document or another agent's id, 413 over 256 KiB.
pub(crate) async fn alarms(
    State(state): State<AppState>,
    AuthenticatedAgent(agent_id): AuthenticatedAgent,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, ApiError> {
    let body = platform_agent_server::decoded_body(
        &headers,
        &body,
        platform_agent_server::MAX_BODY_BYTES,
    )?;
    if body.len() > ALARM_BATCH_BYTES {
        return Err(ApiError::TooLarge);
    }
    let batch: AlarmBatch = parse(&body)?;
    if batch.agent_id.as_str() != agent_id {
        return Err(ApiError::BadRequest);
    }
    let now = Utc::now();
    let oldest = now - Duration::days(i64::from(state.finding_retention_days));
    let latest = now + Duration::minutes(wire::MAX_FUTURE_MINUTES);
    let mut client = state.pool.get().await.map_err(|_| ApiError::Unavailable)?;
    let partitions = platform_store::partition_days_of(&client, "alarms").await?;
    let mut rows = Vec::with_capacity(batch.alarms.len());
    let mut skipped: std::collections::BTreeMap<&str, u32> = Default::default();
    for alarm in &batch.alarms {
        match alarms::row(alarm, oldest, latest, &partitions) {
            Ok(row) => rows.push(row),
            Err(reason) => *skipped.entry(reason).or_default() += 1,
        }
    }
    if !skipped.is_empty() {
        tracing::warn!(?skipped, "alarms skipped: the store cannot hold them");
    }
    let done =
        alarms::insert_batch(&mut client, &agent_id, batch.dropped_total, &rows, now).await?;
    tracing::debug!(
        stored = done.stored,
        raised = done.raised,
        suppressed = done.suppressed,
        "alarms stored"
    );
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /v1/services` (P15): the host's listeners and services replace
/// its stored ones. Over 512 KiB is 413; an invalid report or another
/// agent's id is 400. A refusal is recorded on the host, so the console
/// says the lists are stale instead of showing them silently.
pub(crate) async fn services(
    State(state): State<AppState>,
    AuthenticatedAgent(agent_id): AuthenticatedAgent,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, ApiError> {
    let checked = (|| {
        // A gzip body whose output passes the limit is too large, like a
        // plain one; a broken stream is invalid.
        let body = platform_agent_server::decoded_body(&headers, &body, HOST_SERVICES_BYTES)
            .map_err(|error| match error {
                ApiError::TooLarge => (error, host_services::Refusal::TooLarge),
                error => (error, host_services::Refusal::Invalid),
            })?;
        if body.len() > HOST_SERVICES_BYTES {
            return Err((ApiError::TooLarge, host_services::Refusal::TooLarge));
        }
        let report: HostServices =
            parse(&body).map_err(|error| (error, host_services::Refusal::Invalid))?;
        if report.agent_id.as_str() != agent_id {
            return Err((ApiError::BadRequest, host_services::Refusal::WrongAgent));
        }
        // The digest is what later reports are compared with: recompute it
        // rather than trust the agent's (reviewer, #145).
        if hex(&services_digest(&report.listeners, &report.services)) != report.sha256 {
            return Err((ApiError::BadRequest, host_services::Refusal::Invalid));
        }
        Ok(report)
    })();
    let now = Utc::now();
    let mut client = state.pool.get().await.map_err(|_| ApiError::Unavailable)?;
    let report = match checked {
        Ok(report) => report,
        Err((error, refusal)) => {
            tracing::warn!(reason = refusal.code(), "services report refused");
            host_services::refused(&client, &agent_id, refusal, now).await?;
            return Err(error);
        }
    };
    let stored = host_services::Report {
        sha256: report.sha256,
        owners: match report.owners {
            Owners::Complete => "complete",
            Owners::Partial => "partial",
        }
        .into(),
        truncated: report.truncated,
        listeners: report
            .listeners
            .into_iter()
            .map(|l| host_services::Listener {
                protocol: match l.protocol {
                    ListenerProtocol::Tcp => "tcp",
                    ListenerProtocol::Udp => "udp",
                }
                .into(),
                address: l.address,
                port: i32::from(l.port),
                exposed: l.exposed,
                service: l.service,
                program: l.program,
            })
            .collect(),
        services: report
            .services
            .into_iter()
            .map(|s| host_services::Service {
                unit: s.unit,
                programs: s.programs,
                // Validated: at most 2^31-1.
                processes: i32::try_from(s.processes).unwrap_or(i32::MAX),
                run_as: s.user,
            })
            .collect(),
    };
    host_services::replace(&mut client, &agent_id, &stored, now).await?;
    Ok(StatusCode::NO_CONTENT)
}
