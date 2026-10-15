//! The demo's finding summary, list, groups and group endpoints, and one
//! finding.

use std::{collections::BTreeMap, sync::Arc};

use axum::{
    Json,
    extract::{Path, Query, State, rejection::QueryRejection},
    http::HeaderMap,
    response::{IntoResponse, Response},
};

use super::{
    filters::{FindingFilters, RawFindingFilters, parse_query},
    persona::{context, read_error},
    repository::{ConsoleRepository, GENERATED_AT},
    responses::not_found,
};
use crate::{
    FindingView, Permission, Severity,
    http::problem::{ProblemDetails, problem_response},
};

pub(super) async fn finding_summary(
    State(repository): State<Arc<dyn ConsoleRepository>>,
    headers: HeaderMap,
) -> Response {
    let (persona, mode) = match context(&headers, Permission::ComplianceRead) {
        Ok(context) => context,
        Err(response) => return *response,
    };
    if let Some(response) = read_error(mode) {
        return response;
    }
    (Json(repository.finding_summary(persona, mode))).into_response()
}

pub(super) async fn findings(
    State(repository): State<Arc<dyn ConsoleRepository>>,
    headers: HeaderMap,
    query: Result<Query<RawFindingFilters>, QueryRejection>,
) -> Response {
    let (persona, mode) = match context(&headers, Permission::ComplianceRead) {
        Ok(context) => context,
        Err(response) => return *response,
    };
    if let Some(response) = read_error(mode) {
        return response;
    }
    let filters = match parse_query(query).and_then(FindingFilters::try_from) {
        Ok(filters) => filters,
        Err(response) => return *response,
    };
    (Json(repository.findings(&filters, persona, mode))).into_response()
}

pub(super) async fn finding_groups(
    State(repository): State<Arc<dyn ConsoleRepository>>,
    headers: HeaderMap,
) -> Response {
    let (persona, mode) = match context(&headers, Permission::ComplianceRead) {
        Ok(v) => v,
        Err(r) => return *r,
    };
    if let Some(error) = read_error(mode) {
        return error;
    }
    let rows = repository.all_findings(persona, mode);
    let mut groups: BTreeMap<(String, String), Vec<FindingView>> = BTreeMap::new();
    for row in rows {
        groups
            .entry((row.rule_set_id.clone(), row.rule_id.clone()))
            .or_default()
            .push(row);
    }
    let items = groups
        .into_iter()
        .map(|((rule_set_id, rule_id), rows)| {
            let latest = rows
                .iter()
                .max_by(|a, b| a.last_observed_at.cmp(&b.last_observed_at))
                .expect("group has a member");
            let rank = |severity: Severity| match severity {
                Severity::Critical => 0,
                Severity::High => 1,
                Severity::Medium => 2,
                Severity::Low => 3,
            };
            let severity = rows
                .iter()
                .map(|item| item.severity)
                .min_by_key(|v| rank(*v))
                .unwrap_or(Severity::Low);
            crate::FindingGroupView {
                rule_set_id,
                rule_id,
                endpoint_count: rows.len() as u64,
                severity,
                latest_message: latest.message.clone(),
                rule_versions: rows.iter().map(|item| item.rule_version).collect(),
                first_observed_at: rows
                    .iter()
                    .map(|item| item.first_observed_at.as_str())
                    .min()
                    .unwrap_or(latest.first_observed_at.as_str())
                    .to_owned(),
                last_observed_at: latest.last_observed_at.clone(),
                older_endpoint_count: 0,
                triage_counts: crate::FindingTriageCounts {
                    open: rows.len() as u64,
                    ..Default::default()
                },
            }
        })
        .collect();
    Json(crate::FindingGroupPage {
        items,
        next_cursor: None,
        generated_at: GENERATED_AT.into(),
        since: "2026-09-23T12:00:00Z".into(),
    })
    .into_response()
}

pub(super) async fn finding_group_endpoints(
    State(repository): State<Arc<dyn ConsoleRepository>>,
    headers: HeaderMap,
    Path((rule_set, rule)): Path<(String, String)>,
) -> Response {
    let (persona, mode) = match context(&headers, Permission::ComplianceRead) {
        Ok(v) => v,
        Err(r) => return *r,
    };
    if let Some(error) = read_error(mode) {
        return error;
    }
    let rows = repository
        .all_findings(persona, mode)
        .into_iter()
        .filter(|item| item.rule_set_id == rule_set && item.rule_id == rule)
        .collect::<Vec<_>>();
    if rows.is_empty() {
        return problem_response(ProblemDetails::not_found(
            "compliance_finding_not_found",
            "Compliance finding group not found",
        ));
    }
    let items = rows
        .into_iter()
        .map(|item| crate::FindingGroupEndpointView {
            agent_id: item.agent_id,
            hostname: item.hostname,
            first_observed_at: item.first_observed_at,
            last_observed_at: item.last_observed_at,
            rule_version: item.rule_version,
            triage_state: "open".into(),
            triage_version: 0,
            assigned_to: None,
            accepted_until: None,
            ended_at: None,
            end_approximate: false,
            outside_window: false,
            origin: item.origin,
            authenticated: item.authenticated,
        })
        .collect();
    Json(crate::FindingGroupEndpointPage {
        items,
        next_cursor: None,
        generated_at: GENERATED_AT.into(),
        since: "2026-09-23T12:00:00Z".into(),
    })
    .into_response()
}

pub(super) async fn finding(
    State(repository): State<Arc<dyn ConsoleRepository>>,
    headers: HeaderMap,
    Path((agent, rule_set, rule)): Path<(String, String, String)>,
) -> Response {
    let (persona, mode) = match context(&headers, Permission::ComplianceRead) {
        Ok(context) => context,
        Err(response) => return *response,
    };
    if let Some(response) = read_error(mode) {
        return response;
    }
    repository
        .finding(&agent, &rule_set, &rule, persona, mode)
        .map_or_else(not_found, |finding| Json(finding).into_response())
}
