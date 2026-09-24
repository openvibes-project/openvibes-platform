//! Deterministic, permission-aware C1 read models for the loopback demo.

use std::{collections::BTreeMap, sync::Arc};

use axum::{
    Json, Router,
    extract::{Path, Query, State, rejection::QueryRejection},
    http::{HeaderMap, StatusCode},
    middleware,
    response::{IntoResponse, Response},
    routing::get,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Deserialize;

use crate::{
    AgentDetail, AgentPage, AgentStatus, AgentSummary, AgentView, BuiltInRole, CertificateView,
    CursorPage, CursorPagination, FindingOrigin, FindingPage, FindingSummary, FindingView,
    Permission, RoleBinding, Severity,
    problem::{ProblemDetails, problem_response},
    resolve_capabilities,
};

const GENERATED_AT: &str = "2026-09-24T12:00:00Z";
const DEFAULT_LIMIT: u16 = 50;
const MAX_SEARCH_LENGTH: usize = 128;
const MAX_AGENTS: usize = 50_000;
type SeedError = Box<Response>;

impl AgentStatus {
    fn label(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Stale => "stale",
            Self::Revoked => "revoked",
        }
    }
}

impl Severity {
    fn label(self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SeedMode {
    #[default]
    Mixed,
    Empty,
    Large,
    Stale,
    PartialFailure,
    ExpiredSession,
    PermissionRemoved,
}

impl SeedMode {
    fn parse(headers: &HeaderMap) -> Result<Self, SeedError> {
        let Some(value) = headers.get("x-openvibes-dev-mode") else {
            return Ok(Self::Mixed);
        };
        value
            .to_str()
            .ok()
            .and_then(|value| {
                serde_json::from_value(serde_json::Value::String(value.to_owned())).ok()
            })
            .ok_or_else(|| invalid_header("x-openvibes-dev-mode"))
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Persona {
    Viewer,
    #[default]
    Analyst,
    Operator,
    ScopedOperator,
    Admin,
}

impl Persona {
    fn parse(headers: &HeaderMap) -> Result<Self, SeedError> {
        let Some(value) = headers.get("x-openvibes-dev-persona") else {
            return Ok(Self::Analyst);
        };
        value
            .to_str()
            .ok()
            .and_then(|value| {
                serde_json::from_value(serde_json::Value::String(value.to_owned())).ok()
            })
            .ok_or_else(|| invalid_header("x-openvibes-dev-persona"))
    }

    fn permits(self, permission: Permission, mode: SeedMode) -> bool {
        if matches!(mode, SeedMode::PermissionRemoved) && permission == Permission::AgentsRead {
            return false;
        }
        resolve_capabilities(&[self.binding()])
            .iter()
            .any(|capability| capability.permission == permission)
    }

    fn global_scope(self) -> bool {
        !matches!(self, Self::ScopedOperator)
    }

    fn binding(self) -> RoleBinding {
        let role = match self {
            Self::Viewer => BuiltInRole::Viewer,
            Self::Analyst => BuiltInRole::Analyst,
            Self::Operator | Self::ScopedOperator => BuiltInRole::Operator,
            Self::Admin => BuiltInRole::Admin,
        };
        if self.global_scope() {
            RoleBinding::global(role)
        } else {
            RoleBinding::scoped(role, ["seeded-asset-group".to_owned()])
                .expect("the seeded asset-group ID is nonempty")
        }
    }
}

#[derive(Clone, Debug)]
struct AgentRecord {
    view: AgentView,
    certificates: Vec<CertificateView>,
    scope_member: bool,
}

#[derive(Clone, Debug)]
struct AgentFilters {
    page: CursorPagination,
    query: Option<String>,
    status: Option<AgentStatus>,
}

#[derive(Clone, Debug)]
struct FindingFilters {
    page: CursorPagination,
    query: Option<String>,
    severity: Option<Severity>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAgentFilters {
    #[serde(default)]
    cursor: Option<String>,
    #[serde(default = "default_limit")]
    limit: u16,
    #[serde(default)]
    q: Option<String>,
    #[serde(default)]
    status: Option<AgentStatus>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFindingFilters {
    #[serde(default)]
    cursor: Option<String>,
    #[serde(default = "default_limit")]
    limit: u16,
    #[serde(default)]
    q: Option<String>,
    #[serde(default)]
    severity: Option<Severity>,
}

impl TryFrom<RawAgentFilters> for AgentFilters {
    type Error = SeedError;

    fn try_from(raw: RawAgentFilters) -> Result<Self, Self::Error> {
        Ok(Self {
            page: pagination(raw.cursor, raw.limit, "agents")?,
            query: bounded_query(raw.q)?,
            status: raw.status,
        })
    }
}

impl TryFrom<RawFindingFilters> for FindingFilters {
    type Error = SeedError;

    fn try_from(raw: RawFindingFilters) -> Result<Self, Self::Error> {
        Ok(Self {
            page: pagination(raw.cursor, raw.limit, "findings")?,
            query: bounded_query(raw.q)?,
            severity: raw.severity,
        })
    }
}

fn default_limit() -> u16 {
    DEFAULT_LIMIT
}

trait ConsoleRepository: Send + Sync {
    fn agent_summary(&self, persona: Persona, mode: SeedMode) -> AgentSummary;
    fn agents(&self, filters: &AgentFilters, persona: Persona, mode: SeedMode) -> AgentPage;
    fn agent(&self, id: &str, persona: Persona, mode: SeedMode) -> Option<AgentDetail>;
    fn finding_summary(&self, persona: Persona, mode: SeedMode) -> FindingSummary;
    fn findings(&self, filters: &FindingFilters, persona: Persona, mode: SeedMode) -> FindingPage;
    fn finding(
        &self,
        agent: &str,
        rule_set: &str,
        rule: &str,
        persona: Persona,
        mode: SeedMode,
    ) -> Option<FindingView>;
}

struct SeededRepository {
    agents: Vec<AgentRecord>,
    findings: Vec<FindingView>,
}

impl Default for SeededRepository {
    fn default() -> Self {
        let agents = (1..=MAX_AGENTS)
            .map(|number| {
                let id = format!("agent-{number:05}");
                let hostname = (number % 11 != 0).then(|| format!("host-{number:05}.example.test"));
                let never_seen = number % 199 == 0;
                let status = if number % 97 == 0 {
                    AgentStatus::Revoked
                } else if number % 6 == 0 || never_seen {
                    AgentStatus::Stale
                } else {
                    AgentStatus::Active
                };
                let last_seen_at = if never_seen {
                    None
                } else if matches!(status, AgentStatus::Stale) {
                    Some("2026-09-22T08:00:00Z")
                } else {
                    Some("2026-09-24T11:58:00Z")
                };
                let certificate = CertificateView {
                    serial: format!("{number:016X}"),
                    not_before: "2026-09-01T00:00:00Z".to_owned(),
                    not_after: if number % 89 == 0 {
                        "2026-09-20T00:00:00Z"
                    } else {
                        "2027-09-24T00:00:00Z"
                    }
                    .to_owned(),
                    issued_at: "2026-09-01T00:00:00Z".to_owned(),
                };
                AgentRecord {
                    view: AgentView {
                        id,
                        hostname,
                        status,
                        enrolled_at: "2026-09-01T00:00:00Z".to_owned(),
                        revoked_at: matches!(status, AgentStatus::Revoked)
                            .then(|| "2026-09-23T08:00:00Z".to_owned()),
                        last_seen_at: last_seen_at.map(str::to_owned),
                        scanner_version: Some("0.4.0".to_owned()),
                        capabilities: vec!["findings".to_owned(), "heartbeat".to_owned()],
                    },
                    certificates: vec![certificate],
                    scope_member: number % 5 == 0,
                }
            })
            .collect::<Vec<_>>();
        let findings = (1u32..=120)
            .map(|number| {
                let agent_number = (number * 7 % 400) + 1;
                FindingView {
                    id: format!("finding-{number:05}"),
                    agent_id: format!("agent-{agent_number:05}"),
                    hostname: (agent_number % 11 != 0)
                        .then(|| format!("host-{agent_number:05}.example.test")),
                    rule_set_id: if number == 120 {
                        "~unknown".to_owned()
                    } else {
                        "baseline-linux".to_owned()
                    },
                    rule_id: format!("OV-{number:04}"),
                    rule_version: 3 + u64::from(number % 4),
                    severity: match number % 4 {
                        0 => Severity::Critical,
                        1 => Severity::High,
                        2 => Severity::Medium,
                        _ => Severity::Low,
                    },
                    confidence: if number == 120 { 82 } else { 95 },
                    message: format!("Synthetic security observation {number:04}"),
                    evidence: vec![format!("synthetic.observation={number:04}")],
                    scan_id: format!("scan-{number:05}"),
                    authenticated: number != 120,
                    origin: if number == 120 {
                        FindingOrigin::Import
                    } else {
                        FindingOrigin::Online
                    },
                    first_observed_at: "2026-09-20T12:00:00Z".to_owned(),
                    last_observed_at: format!("2026-09-24T11:{:02}:00Z", 59 - number % 60),
                    received_at: format!("2026-09-24T12:{:02}:00Z", number % 60),
                }
            })
            .collect();
        Self { agents, findings }
    }
}

impl SeededRepository {
    fn visible(&self, agent: &AgentRecord, persona: Persona, mode: SeedMode) -> bool {
        if matches!(mode, SeedMode::Empty) {
            return false;
        }
        let status_ok =
            !matches!(mode, SeedMode::Stale) || matches!(agent.view.status, AgentStatus::Stale);
        status_ok && (persona.global_scope() || agent.scope_member)
    }

    fn matching_findings(&self, persona: Persona, mode: SeedMode) -> Vec<FindingView> {
        if matches!(mode, SeedMode::Empty) {
            return Vec::new();
        }
        self.findings
            .iter()
            .filter(|finding| {
                // ponytail: scan at most 50,000 agent IDs for each of 120 seeded findings;
                // build an ID index if either fixture grows materially.
                self.agents
                    .iter()
                    .take(agent_count(mode))
                    .find(|agent| agent.view.id == finding.agent_id)
                    .is_some_and(|agent| self.visible(agent, persona, mode))
            })
            .cloned()
            .collect()
    }
}

impl ConsoleRepository for SeededRepository {
    fn agent_summary(&self, persona: Persona, mode: SeedMode) -> AgentSummary {
        self.agents
            .iter()
            .take(agent_count(mode))
            .filter(|agent| self.visible(agent, persona, mode))
            .fold(
                AgentSummary {
                    total: 0,
                    active: 0,
                    stale: 0,
                    revoked: 0,
                },
                |mut summary, agent| {
                    summary.total += 1;
                    match agent.view.status {
                        AgentStatus::Active => summary.active += 1,
                        AgentStatus::Stale => summary.stale += 1,
                        AgentStatus::Revoked => summary.revoked += 1,
                    }
                    summary
                },
            )
    }

    fn agents(&self, filters: &AgentFilters, persona: Persona, mode: SeedMode) -> AgentPage {
        let query = filters
            .query
            .as_deref()
            .unwrap_or_default()
            .to_ascii_lowercase();
        let matched =
            self.agents
                .iter()
                .take(agent_count(mode))
                .filter(|agent| {
                    self.visible(agent, persona, mode)
                        && filters
                            .status
                            .is_none_or(|status| agent.view.status.label() == status.label())
                        && (query.is_empty()
                            || agent.view.hostname.as_deref().is_some_and(|hostname| {
                                hostname.to_ascii_lowercase().contains(&query)
                            })
                            || agent.view.id.contains(&query))
                })
                .collect::<Vec<_>>();
        let offset = cursor_offset(filters.page.cursor(), "agents").unwrap_or(0);
        let page = page(
            matched
                .into_iter()
                .map(|agent| agent.view.clone())
                .collect(),
            offset,
            filters.page.limit(),
            "agents",
        );
        AgentPage {
            items: page.items,
            next_cursor: page.next_cursor,
            generated_at: page.generated_at,
        }
    }

    fn agent(&self, id: &str, persona: Persona, mode: SeedMode) -> Option<AgentDetail> {
        let agent = self
            .agents
            .iter()
            .take(agent_count(mode))
            .find(|agent| agent.view.id == id && self.visible(agent, persona, mode))?;
        Some(AgentDetail {
            agent: agent.view.clone(),
            certificates: agent.certificates.clone(),
        })
    }

    fn finding_summary(&self, persona: Persona, mode: SeedMode) -> FindingSummary {
        let findings = self.matching_findings(persona, mode);
        let mut summary = FindingSummary {
            total: findings.len() as u64,
            impacted_agents: 0,
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
        };
        let mut agents = BTreeMap::new();
        for finding in findings {
            agents.insert(finding.agent_id, ());
            match finding.severity {
                Severity::Critical => summary.critical += 1,
                Severity::High => summary.high += 1,
                Severity::Medium => summary.medium += 1,
                Severity::Low => summary.low += 1,
            }
        }
        summary.impacted_agents = agents.len() as u64;
        summary
    }

    fn findings(&self, filters: &FindingFilters, persona: Persona, mode: SeedMode) -> FindingPage {
        let query = filters
            .query
            .as_deref()
            .unwrap_or_default()
            .to_ascii_lowercase();
        let mut matched =
            self.matching_findings(persona, mode)
                .into_iter()
                .filter(|finding| {
                    filters
                        .severity
                        .is_none_or(|severity| finding.severity.label() == severity.label())
                        && (query.is_empty()
                            || finding.hostname.as_deref().is_some_and(|hostname| {
                                hostname.to_ascii_lowercase().contains(&query)
                            })
                            || finding.rule_id.to_ascii_lowercase().contains(&query)
                            || finding.message.to_ascii_lowercase().contains(&query))
                })
                .collect::<Vec<_>>();
        matched.sort_by(|left, right| {
            right
                .last_observed_at
                .cmp(&left.last_observed_at)
                .then_with(|| left.id.cmp(&right.id))
        });
        let offset = cursor_offset(filters.page.cursor(), "findings").unwrap_or(0);
        let page = page(matched, offset, filters.page.limit(), "findings");
        FindingPage {
            items: page.items,
            next_cursor: page.next_cursor,
            generated_at: page.generated_at,
        }
    }

    fn finding(
        &self,
        agent: &str,
        rule_set: &str,
        rule: &str,
        persona: Persona,
        mode: SeedMode,
    ) -> Option<FindingView> {
        self.matching_findings(persona, mode)
            .into_iter()
            .find(|finding| {
                finding.agent_id == agent
                    && finding.rule_set_id == rule_set
                    && finding.rule_id == rule
            })
    }
}

fn page<T>(items: Vec<T>, offset: usize, limit: u16, collection: &str) -> CursorPage<T> {
    let total = items.len();
    let start = offset.min(items.len());
    let end = start.saturating_add(usize::from(limit)).min(items.len());
    CursorPage {
        items: items.into_iter().skip(start).take(end - start).collect(),
        next_cursor: (end < total).then(|| make_cursor(collection, end)),
        generated_at: GENERATED_AT.to_owned(),
    }
}

fn agent_count(mode: SeedMode) -> usize {
    if matches!(mode, SeedMode::Large) {
        MAX_AGENTS
    } else {
        500
    }
}

fn make_cursor(collection: &str, offset: usize) -> String {
    URL_SAFE_NO_PAD.encode(format!("{collection}:{offset}"))
}

fn cursor_offset(cursor: Option<&str>, collection: &str) -> Option<usize> {
    let cursor = cursor?;
    let decoded = URL_SAFE_NO_PAD.decode(cursor).ok()?;
    let decoded = std::str::from_utf8(&decoded).ok()?;
    let (kind, offset) = decoded.split_once(':')?;
    (kind == collection).then(|| offset.parse().ok()).flatten()
}

fn pagination(
    cursor: Option<String>,
    limit: u16,
    collection: &'static str,
) -> Result<CursorPagination, SeedError> {
    let pagination = CursorPagination::new(cursor, limit).map_err(|_| {
        Box::new(bad_request(
            "invalid_pagination",
            "Invalid page cursor or limit",
        ))
    })?;
    let max_offset = if collection == "agents" {
        MAX_AGENTS
    } else {
        120
    };
    if pagination.cursor().is_some_and(|cursor| {
        cursor_offset(Some(cursor), collection).is_none_or(|offset| offset > max_offset)
    }) {
        return Err(Box::new(bad_request(
            "invalid_pagination",
            "Invalid page cursor or limit",
        )));
    }
    Ok(pagination)
}

fn bounded_query(query: Option<String>) -> Result<Option<String>, SeedError> {
    if query
        .as_ref()
        .is_some_and(|query| query.len() > MAX_SEARCH_LENGTH)
    {
        return Err(Box::new(bad_request(
            "invalid_filter",
            "Search filter exceeds its limit",
        )));
    }
    Ok(query.filter(|query| !query.is_empty()))
}

fn invalid_header(name: &'static str) -> SeedError {
    Box::new(bad_request("invalid_demo_selection", name))
}

fn bad_request(code: &'static str, title: &'static str) -> Response {
    problem_response(ProblemDetails::new(StatusCode::BAD_REQUEST, code, title))
}

fn denied() -> Response {
    problem_response(ProblemDetails::new(
        StatusCode::FORBIDDEN,
        "permission_denied",
        "Access is not available",
    ))
}

fn not_found() -> Response {
    problem_response(ProblemDetails::not_found(
        "resource_not_found",
        "Resource not found",
    ))
}

fn unavailable() -> Response {
    problem_response(ProblemDetails::new(
        StatusCode::SERVICE_UNAVAILABLE,
        "seeded_read_unavailable",
        "Synthetic read source is unavailable",
    ))
}

fn expired() -> Response {
    problem_response(ProblemDetails::new(
        StatusCode::UNAUTHORIZED,
        "session_expired",
        "The demonstration session has expired",
    ))
}

fn context(headers: &HeaderMap, permission: Permission) -> Result<(Persona, SeedMode), SeedError> {
    let persona = Persona::parse(headers)?;
    let mode = SeedMode::parse(headers)?;
    if matches!(mode, SeedMode::ExpiredSession) {
        return Err(Box::new(expired()));
    }
    if !persona.permits(permission, mode) {
        return Err(Box::new(denied()));
    }
    Ok((persona, mode))
}

fn read_error(mode: SeedMode) -> Option<Response> {
    matches!(mode, SeedMode::PartialFailure).then(unavailable)
}

fn parse_query<T: for<'de> Deserialize<'de>>(
    query: Result<Query<T>, QueryRejection>,
) -> Result<T, SeedError> {
    query
        .map(|Query(query)| query)
        .map_err(|_| Box::new(bad_request("invalid_query", "Query parameters are invalid")))
}

async fn agent_summary(
    State(repository): State<Arc<dyn ConsoleRepository>>,
    headers: HeaderMap,
) -> Response {
    let (persona, mode) = match context(&headers, Permission::AgentsRead) {
        Ok(context) => context,
        Err(response) => return *response,
    };
    (Json(repository.agent_summary(persona, mode))).into_response()
}

async fn agents(
    State(repository): State<Arc<dyn ConsoleRepository>>,
    headers: HeaderMap,
    query: Result<Query<RawAgentFilters>, QueryRejection>,
) -> Response {
    let (persona, mode) = match context(&headers, Permission::AgentsRead) {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let filters = match parse_query(query).and_then(AgentFilters::try_from) {
        Ok(filters) => filters,
        Err(response) => return *response,
    };
    (Json(repository.agents(&filters, persona, mode))).into_response()
}

async fn agent(
    State(repository): State<Arc<dyn ConsoleRepository>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let (persona, mode) = match context(&headers, Permission::AgentsRead) {
        Ok(context) => context,
        Err(response) => return *response,
    };
    repository
        .agent(&id, persona, mode)
        .map_or_else(not_found, |agent| Json(agent).into_response())
}

async fn finding_summary(
    State(repository): State<Arc<dyn ConsoleRepository>>,
    headers: HeaderMap,
) -> Response {
    let (persona, mode) = match context(&headers, Permission::FindingsRead) {
        Ok(context) => context,
        Err(response) => return *response,
    };
    if let Some(response) = read_error(mode) {
        return response;
    }
    (Json(repository.finding_summary(persona, mode))).into_response()
}

async fn findings(
    State(repository): State<Arc<dyn ConsoleRepository>>,
    headers: HeaderMap,
    query: Result<Query<RawFindingFilters>, QueryRejection>,
) -> Response {
    let (persona, mode) = match context(&headers, Permission::FindingsRead) {
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

async fn finding(
    State(repository): State<Arc<dyn ConsoleRepository>>,
    headers: HeaderMap,
    Path((agent, rule_set, rule)): Path<(String, String, String)>,
) -> Response {
    let (persona, mode) = match context(&headers, Permission::FindingsRead) {
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

async fn audit_events(headers: HeaderMap) -> Response {
    let (persona, mode) = match context(&headers, Permission::AuditRead) {
        Ok(context) => context,
        Err(response) => return *response,
    };
    if let Some(response) = read_error(mode) {
        return response;
    }
    let events = if matches!(persona, Persona::Admin) {
        vec![serde_json::json!({
            "id": "1", "at": GENERATED_AT, "actor": "admin@example.test",
            "action": "user.login", "target": "console", "result": "success",
            "request_id": null, "actor_kind": "user", "actor_id": "admin",
            "authentication_method": "local_password", "target_kind": null,
            "target_id": null, "reason_code": null
        })]
    } else {
        Vec::new()
    };
    Json(serde_json::json!({ "items": events, "next_cursor": null })).into_response()
}

async fn access_inventory(headers: HeaderMap) -> Response {
    let (persona, mode) = match context(&headers, Permission::RbacRead) {
        Ok(context) => context,
        Err(response) => return *response,
    };
    if let Some(response) = read_error(mode) {
        return response;
    }
    let role = |role_id: &str, name: &str, permissions: &[&str]| {
        serde_json::json!({
            "role_id": role_id, "display_name": name, "builtin": true, "permissions": permissions
        })
    };
    let roles = vec![
        role(
            "viewer",
            "Viewer",
            &["agents.read", "findings.read", "rules.read"],
        ),
        role(
            "analyst",
            "Analyst",
            &[
                "agents.read",
                "findings.read",
                "findings.triage",
                "rules.read",
            ],
        ),
        role(
            "operator",
            "Operator",
            &[
                "agents.read",
                "agents.revoke",
                "findings.read",
                "rules.read",
                "rules.upload",
                "tokens.read",
                "tokens.create",
                "tokens.revoke",
            ],
        ),
        role(
            "admin",
            "Admin",
            &[
                "agents.read",
                "agents.revoke",
                "findings.read",
                "findings.triage",
                "tokens.read",
                "tokens.create",
                "tokens.revoke",
                "rules.read",
                "rules.upload",
                "audit.read",
                "audit.export",
                "audit.retention.manage",
                "rbac.read",
                "rbac.manage",
                "asset_groups.manage",
                "service_accounts.read",
                "service_accounts.manage",
            ],
        ),
    ];
    let bindings = if matches!(persona, Persona::Admin) {
        vec![serde_json::json!({
            "binding_id": "seeded-admin-binding", "user_id": "seeded-admin", "username": "admin",
            "display_name": "Seeded administrator", "role_id": "admin", "asset_group_id": null,
            "asset_group_name": null, "created_at": GENERATED_AT, "created_by": "bootstrap"
        })]
    } else {
        Vec::new()
    };
    Json(serde_json::json!({ "roles": roles, "bindings": bindings, "asset_groups": [] }))
        .into_response()
}

pub(crate) fn router() -> Router {
    let repository: Arc<dyn ConsoleRepository> = Arc::new(SeededRepository::default());
    Router::new()
        .route("/api/v1/agents/summary", get(agent_summary))
        .route("/api/v1/agents", get(agents))
        .route("/api/v1/agents/{id}", get(agent))
        .route("/api/v1/findings/summary", get(finding_summary))
        .route("/api/v1/audit-events", get(audit_events))
        .route("/api/v1/access-control", get(access_inventory))
        .route("/api/v1/findings/latest", get(findings))
        .route(
            "/api/v1/findings/latest/{agent}/{rule_set}/{rule}",
            get(finding),
        )
        .with_state(repository)
        .layer(middleware::map_response(no_store))
}

async fn no_store(mut response: Response) -> Response {
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::{Persona, SeedMode};
    use crate::Permission;

    #[test]
    fn seeded_personas_use_the_approved_builtin_role_permissions() {
        assert!(Persona::Operator.permits(Permission::RulesUpload, SeedMode::Mixed));
        assert!(Persona::Operator.permits(Permission::TokensCreate, SeedMode::Mixed));
        assert!(!Persona::Operator.permits(Permission::FindingsTriage, SeedMode::Mixed));
        assert!(Persona::ScopedOperator.permits(Permission::AgentsRevoke, SeedMode::Mixed));
        assert!(!Persona::ScopedOperator.permits(Permission::TokensCreate, SeedMode::Mixed));
        assert!(!Persona::ScopedOperator.permits(Permission::FindingsTriage, SeedMode::Mixed));
        assert!(Persona::Admin.permits(Permission::AuditRetentionManage, SeedMode::Mixed));
    }
}
