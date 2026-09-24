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
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{
    CursorPage, CursorPagination, Permission,
    problem::{ProblemDetails, problem_response},
};

const GENERATED_AT: &str = "2026-09-24T12:00:00Z";
const DEFAULT_LIMIT: u16 = 50;
const MAX_SEARCH_LENGTH: usize = 128;
const MAX_AGENTS: usize = 50_000;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AgentStatus {
    Active,
    Stale,
    Revoked,
}

impl AgentStatus {
    fn label(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Stale => "stale",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Severity {
    Critical,
    High,
    Medium,
    Low,
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

#[derive(Clone, Debug, Serialize, ToSchema)]
pub(crate) struct AgentView {
    pub id: String,
    pub hostname: String,
    pub status: AgentStatus,
    pub last_seen_at: String,
    pub certificate_expires_at: String,
    pub environment: String,
    pub platform: String,
}

#[derive(Clone, Debug, Serialize, ToSchema)]
pub(crate) struct CertificateView {
    pub serial: String,
    pub not_after: String,
    pub revoked: bool,
}

#[derive(Clone, Debug, Serialize, ToSchema)]
pub(crate) struct AgentDetail {
    #[serde(flatten)]
    pub agent: AgentView,
    pub certificate: CertificateView,
}

#[derive(Clone, Debug, Serialize, ToSchema)]
pub(crate) struct AgentSummary {
    pub total: u64,
    pub active: u64,
    pub stale: u64,
    pub revoked: u64,
}

#[derive(Clone, Debug, Serialize, ToSchema)]
pub(crate) struct FindingView {
    pub id: String,
    pub agent_id: String,
    pub hostname: String,
    pub rule_set_id: String,
    pub rule_id: String,
    pub rule_version: u64,
    pub severity: Severity,
    pub message: String,
    pub first_observed_at: String,
    pub last_observed_at: String,
    pub occurrence_count: u64,
}

#[derive(Clone, Debug, Serialize, ToSchema)]
pub(crate) struct FindingSummary {
    pub total: u64,
    pub impacted_agents: u64,
    pub critical: u64,
    pub high: u64,
    pub medium: u64,
    pub low: u64,
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
    fn parse(headers: &HeaderMap) -> Result<Self, Response> {
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
    fn parse(headers: &HeaderMap) -> Result<Self, Response> {
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
        match self {
            Self::Viewer => matches!(
                permission,
                Permission::AgentsRead | Permission::FindingsRead
            ),
            Self::Analyst => matches!(
                permission,
                Permission::AgentsRead | Permission::FindingsRead | Permission::FindingsTriage
            ),
            Self::Operator => matches!(
                permission,
                Permission::AgentsRead
                    | Permission::AgentsRevoke
                    | Permission::FindingsRead
                    | Permission::FindingsTriage
                    | Permission::TokensRead
                    | Permission::TokensCreate
                    | Permission::TokensRevoke
            ),
            Self::ScopedOperator => matches!(
                permission,
                Permission::AgentsRead | Permission::FindingsRead | Permission::FindingsTriage
            ),
            Self::Admin => true,
        }
    }

    fn global_scope(self) -> bool {
        !matches!(self, Self::ScopedOperator)
    }
}

#[derive(Clone, Debug)]
struct AgentRecord {
    view: AgentView,
    certificate: CertificateView,
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
    type Error = Response;

    fn try_from(raw: RawAgentFilters) -> Result<Self, Self::Error> {
        Ok(Self {
            page: pagination(raw.cursor, raw.limit, "agents")?,
            query: bounded_query(raw.q)?,
            status: raw.status,
        })
    }
}

impl TryFrom<RawFindingFilters> for FindingFilters {
    type Error = Response;

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
    fn agents(
        &self,
        filters: &AgentFilters,
        persona: Persona,
        mode: SeedMode,
    ) -> CursorPage<AgentView>;
    fn agent(&self, id: &str, persona: Persona, mode: SeedMode) -> Option<AgentDetail>;
    fn finding_summary(&self, persona: Persona, mode: SeedMode) -> FindingSummary;
    fn findings(
        &self,
        filters: &FindingFilters,
        persona: Persona,
        mode: SeedMode,
    ) -> CursorPage<FindingView>;
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
                let hostname = format!("host-{number:05}.example.test");
                let environment = if number % 5 == 0 {
                    "production"
                } else if number % 5 == 1 {
                    "staging"
                } else {
                    "development"
                };
                let status = if number % 97 == 0 {
                    AgentStatus::Revoked
                } else if number % 6 == 0 {
                    AgentStatus::Stale
                } else {
                    AgentStatus::Active
                };
                let last_seen_at = if matches!(status, AgentStatus::Stale) {
                    "2026-09-22T08:00:00Z"
                } else {
                    "2026-09-24T11:58:00Z"
                };
                let certificate = CertificateView {
                    serial: format!("{number:016X}"),
                    not_after: if number % 89 == 0 {
                        "2026-09-20T00:00:00Z"
                    } else {
                        "2027-09-24T00:00:00Z"
                    }
                    .to_owned(),
                    revoked: matches!(status, AgentStatus::Revoked),
                };
                AgentRecord {
                    view: AgentView {
                        id,
                        hostname,
                        status,
                        last_seen_at: last_seen_at.to_owned(),
                        certificate_expires_at: certificate.not_after.clone(),
                        environment: environment.to_owned(),
                        platform: match number % 3 {
                            0 => "Fedora Linux",
                            1 => "Windows",
                            _ => "macOS",
                        }
                        .to_owned(),
                    },
                    certificate,
                }
            })
            .collect::<Vec<_>>();
        let findings = (1u32..=120)
            .map(|number| {
                let agent_number = (number * 7 % 400) + 1;
                FindingView {
                    id: format!("finding-{number:05}"),
                    agent_id: format!("agent-{agent_number:05}"),
                    hostname: format!("host-{agent_number:05}.example.test"),
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
                    message: format!("Synthetic security observation {number:04}"),
                    first_observed_at: "2026-09-20T12:00:00Z".to_owned(),
                    last_observed_at: format!("2026-09-24T11:{:02}:00Z", 59 - number % 60),
                    occurrence_count: 1 + u64::from(number % 40),
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
        status_ok && (persona.global_scope() || agent.view.environment == "production")
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

    fn agents(
        &self,
        filters: &AgentFilters,
        persona: Persona,
        mode: SeedMode,
    ) -> CursorPage<AgentView> {
        let query = filters
            .query
            .as_deref()
            .unwrap_or_default()
            .to_ascii_lowercase();
        let matched = self
            .agents
            .iter()
            .take(agent_count(mode))
            .filter(|agent| {
                self.visible(agent, persona, mode)
                    && filters
                        .status
                        .is_none_or(|status| agent.view.status.label() == status.label())
                    && (query.is_empty()
                        || agent.view.hostname.to_ascii_lowercase().contains(&query)
                        || agent.view.id.contains(&query))
            })
            .collect::<Vec<_>>();
        let offset = cursor_offset(filters.page.cursor(), "agents").unwrap_or(0);
        page(
            matched
                .into_iter()
                .map(|agent| agent.view.clone())
                .collect(),
            offset,
            filters.page.limit(),
            "agents",
        )
    }

    fn agent(&self, id: &str, persona: Persona, mode: SeedMode) -> Option<AgentDetail> {
        let agent = self
            .agents
            .iter()
            .take(agent_count(mode))
            .find(|agent| agent.view.id == id && self.visible(agent, persona, mode))?;
        Some(AgentDetail {
            agent: agent.view.clone(),
            certificate: agent.certificate.clone(),
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

    fn findings(
        &self,
        filters: &FindingFilters,
        persona: Persona,
        mode: SeedMode,
    ) -> CursorPage<FindingView> {
        let query = filters
            .query
            .as_deref()
            .unwrap_or_default()
            .to_ascii_lowercase();
        let mut matched = self
            .matching_findings(persona, mode)
            .into_iter()
            .filter(|finding| {
                filters
                    .severity
                    .is_none_or(|severity| finding.severity.label() == severity.label())
                    && (query.is_empty()
                        || finding.hostname.to_ascii_lowercase().contains(&query)
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
        page(matched, offset, filters.page.limit(), "findings")
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
) -> Result<CursorPagination, Response> {
    let pagination = CursorPagination::new(cursor, limit)
        .map_err(|_| bad_request("invalid_pagination", "Invalid page cursor or limit"))?;
    let max_offset = if collection == "agents" {
        MAX_AGENTS
    } else {
        120
    };
    if pagination.cursor().is_some_and(|cursor| {
        cursor_offset(Some(cursor), collection).is_none_or(|offset| offset > max_offset)
    }) {
        return Err(bad_request(
            "invalid_pagination",
            "Invalid page cursor or limit",
        ));
    }
    Ok(pagination)
}

fn bounded_query(query: Option<String>) -> Result<Option<String>, Response> {
    if query
        .as_ref()
        .is_some_and(|query| query.len() > MAX_SEARCH_LENGTH)
    {
        return Err(bad_request(
            "invalid_filter",
            "Search filter exceeds its limit",
        ));
    }
    Ok(query.filter(|query| !query.is_empty()))
}

fn invalid_header(name: &'static str) -> Response {
    bad_request("invalid_demo_selection", name)
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

fn context(headers: &HeaderMap, permission: Permission) -> Result<(Persona, SeedMode), Response> {
    let persona = Persona::parse(headers)?;
    let mode = SeedMode::parse(headers)?;
    if matches!(mode, SeedMode::ExpiredSession) {
        return Err(expired());
    }
    if !persona.permits(permission, mode) {
        return Err(denied());
    }
    Ok((persona, mode))
}

fn read_error(mode: SeedMode) -> Option<Response> {
    matches!(mode, SeedMode::PartialFailure).then(unavailable)
}

fn parse_query<T: for<'de> Deserialize<'de>>(
    query: Result<Query<T>, QueryRejection>,
) -> Result<T, Response> {
    query
        .map(|Query(query)| query)
        .map_err(|_| bad_request("invalid_query", "Query parameters are invalid"))
}

async fn agent_summary(
    State(repository): State<Arc<dyn ConsoleRepository>>,
    headers: HeaderMap,
) -> Response {
    let (persona, mode) = match context(&headers, Permission::AgentsRead) {
        Ok(context) => context,
        Err(response) => return response,
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
        Err(response) => return response,
    };
    let filters = match parse_query(query).and_then(AgentFilters::try_from) {
        Ok(filters) => filters,
        Err(response) => return response,
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
        Err(response) => return response,
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
        Err(response) => return response,
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
        Err(response) => return response,
    };
    if let Some(response) = read_error(mode) {
        return response;
    }
    let filters = match parse_query(query).and_then(FindingFilters::try_from) {
        Ok(filters) => filters,
        Err(response) => return response,
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
        Err(response) => return response,
    };
    if let Some(response) = read_error(mode) {
        return response;
    }
    repository
        .finding(&agent, &rule_set, &rule, persona, mode)
        .map_or_else(not_found, |finding| Json(finding).into_response())
}

pub(crate) fn router() -> Router {
    let repository: Arc<dyn ConsoleRepository> = Arc::new(SeededRepository::default());
    Router::new()
        .route("/api/v1/agents/summary", get(agent_summary))
        .route("/api/v1/agents", get(agents))
        .route("/api/v1/agents/{id}", get(agent))
        .route("/api/v1/findings/summary", get(finding_summary))
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
