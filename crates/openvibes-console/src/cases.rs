//! Cases over `/api/v1`: where one investigation happens (design in
//! `docs/specs/2026-10-04-console-cases-design.md`). Reads need
//! `cases.read`, changes `cases.manage`; both are scoped to the caller's
//! agents, and a case the caller cannot see reads as absent. Browser
//! sessions only: a bearer token is refused, as for dashboards.

use axum::{
    Json,
    extract::{Path, Query, State, rejection::JsonRejection, rejection::QueryRejection},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, SecondsFormat, Utc};
use platform_store::{
    console_cases::{
        self as store, AssigneeFilter, CaseChange, CaseDetail, CaseEvent, CaseFilters, CaseItem,
        CaseSummary, ItemCase, NewCase, OutcomeChange, Refusal, UserRef,
    },
    console_read::AgentScope,
};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use crate::{
    FieldError, Permission, PermissionScope, ProblemDetails,
    problem::problem_response,
    router::{AuthHttpState, parse_if_match_version, session_user, unavailable_auth},
};

/// A console user as a case shows them.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct CaseUserView {
    /// Stable UUID.
    pub user_id: String,
    /// Login name.
    pub username: String,
    /// Name to show.
    pub display_name: String,
}

/// One case as listed. Counts include only items the viewer can see.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct CaseSummaryView {
    /// Stable UUID.
    pub case_id: String,
    /// Shown as `C-<number>`; unique, never reused.
    pub number: i64,
    /// 1 to 120 characters.
    pub title: String,
    /// `open`, `investigating` or `closed`.
    pub status: String,
    /// `mitigated`, `false_positive` or `accepted_risk`, once closed.
    pub resolution: Option<String>,
    /// When accepted risk runs out and the case reopens (RFC 3339).
    pub accepted_until: Option<String>,
    /// `critical`, `high`, `medium` or `low`.
    pub severity: String,
    /// Who works on it.
    pub assignee: Option<CaseUserView>,
    /// Who opened it.
    pub opened_by: CaseUserView,
    /// RFC 3339.
    pub created_at: String,
    /// Last change of any kind (RFC 3339).
    pub updated_at: String,
    /// RFC 3339, once closed.
    pub closed_at: Option<String>,
    /// Version for `If-Match` (also the ETag of the detail).
    pub version: u64,
    /// Items the viewer can see.
    pub item_count: i64,
    /// Visible alarms, findings and vulnerabilities that have no outcome.
    pub pending_item_count: i64,
}

/// A page of cases, newest change first.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct CasePage {
    /// The cases the viewer can see.
    pub items: Vec<CaseSummaryView>,
    /// Pass as `cursor` for the next page; absent on the last page.
    pub next_cursor: Option<String>,
}

/// One item of a case that the viewer can see.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct CaseItemView {
    /// Stable UUID.
    pub item_id: String,
    /// `alarm`, `finding`, `vulnerability`, `host` or `software`.
    pub kind: String,
    /// The object's id as the console's panels write it: the alarm id;
    /// `agent/rule_set/rule` for a finding; `agent/advisory` for a
    /// vulnerability on a host; the agent id for a host; `manager/name`
    /// for software.
    #[serde(rename = "ref")]
    pub reference: String,
    /// The host that decides who sees the item; absent for software.
    pub agent_id: Option<String>,
    /// That host's name, when known.
    pub hostname: Option<String>,
    /// True while the case is not closed.
    pub active: bool,
    /// `resolved`, `false_positive` or `accepted_risk`.
    pub outcome: Option<String>,
    /// Why, for the last two.
    pub outcome_note: Option<String>,
    /// Who added it.
    pub added_by: CaseUserView,
    /// RFC 3339.
    pub added_at: String,
    /// What to show for it, when it still exists.
    pub title: Option<String>,
    /// Its own severity as its page states it (alarm and finding:
    /// `critical` to `info`; vulnerability: the advisory's), when it has one.
    pub severity: Option<String>,
    /// True when the evidence is gone, so that `resolved` is accepted: the
    /// finding is no longer reported, the vulnerability no longer matches
    /// the host, the alarm is closed as mitigated or no longer exists.
    /// Always false for hosts and software.
    pub evidence_gone: bool,
}

/// One timeline entry.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct CaseEventView {
    /// Position on the timeline.
    pub event_id: i64,
    /// RFC 3339.
    pub at: String,
    /// Who; absent for the platform itself.
    pub actor: Option<CaseUserView>,
    /// `created`, `note`, `status`, `assigned`, `severity`, `item_added`,
    /// `item_removed`, `item_outcome`, `resolved` or `reopened`.
    pub kind: String,
    /// The note's text; for `resolved` the resolution note; for
    /// `item_outcome` the outcome note.
    pub body: Option<String>,
    /// Structured facts: `from`/`to` for `status`, `assigned` (usernames)
    /// and `severity`; `item_id`, `item_kind`, `item_ref` and
    /// `item_agent_id` for item entries; `resolution` and `accepted_until`
    /// for `resolved`; `reason` for `reopened`.
    #[schema(value_type = Object)]
    pub detail: serde_json::Value,
}

/// A case with the items and timeline the viewer can see.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct CaseDetailView {
    /// The list fields.
    #[serde(flatten)]
    pub case: CaseSummaryView,
    /// Why it was closed.
    pub resolution_note: Option<String>,
    /// Visible items, oldest first.
    pub items: Vec<CaseItemView>,
    /// The timeline, oldest first, without entries about hidden items.
    pub events: Vec<CaseEventView>,
}

/// A case that holds an item.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct ItemCaseView {
    /// The case.
    pub case: CaseSummaryView,
    /// The item's id in that case.
    pub item_id: String,
    /// The item's outcome there.
    pub outcome: Option<String>,
}

/// The visible cases that hold an item.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct ItemCasesView {
    /// For an alarm, finding or vulnerability at most one: the open case.
    /// For a host or software, up to 50, newest change first, open or closed.
    pub items: Vec<ItemCaseView>,
}

/// Users a case can be assigned to.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct CaseAssigneesView {
    /// Enabled users who hold `cases.read`.
    pub items: Vec<CaseUserView>,
}

/// An item to add: what it is and its id.
#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CaseItemRef {
    /// `alarm`, `finding`, `vulnerability`, `host` or `software`.
    pub kind: String,
    /// The object's id as the console's panels write it (see
    /// `CaseItemView.ref`).
    #[serde(rename = "ref")]
    pub reference: String,
}

/// Opens a case.
#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateCaseRequest {
    /// 1 to 120 characters.
    pub title: String,
    /// `critical`, `high`, `medium` or `low`; the highest item severity
    /// (medium without one) when absent.
    pub severity: Option<String>,
    /// A user with `cases.read` (see the assignees route).
    pub assignee_user_id: Option<String>,
    /// Items to start with, at most 50.
    #[serde(default)]
    pub items: Vec<CaseItemRef>,
}

/// Replaces a case's editable fields; send every field.
#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct UpdateCaseRequest {
    /// 1 to 120 characters.
    pub title: String,
    /// `critical`, `high`, `medium` or `low`.
    pub severity: String,
    /// `open`, `investigating` or `closed`. `closed` closes the case; any
    /// other status on a closed case reopens it.
    pub status: String,
    /// A user with `cases.read`; absent or `null` means nobody.
    pub assignee_user_id: Option<String>,
    /// How it ended, required with `closed`: `mitigated`, `false_positive`
    /// or `accepted_risk`. Absent otherwise.
    pub resolution: Option<String>,
    /// Why, required with a resolution (at most 4000 characters).
    pub resolution_note: Option<String>,
    /// Required for `accepted_risk` (RFC 3339, in the future): the case
    /// reopens when it passes.
    pub accepted_until: Option<String>,
}

/// A note for the timeline.
#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct AddCaseNoteRequest {
    /// Plain text, 1 to 4000 characters.
    pub body: String,
}

/// Sets or clears an item's outcome.
#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SetCaseItemOutcomeRequest {
    /// `resolved` (only when the evidence is gone), `false_positive` or
    /// `accepted_risk`; absent or `null` clears it.
    pub outcome: Option<String>,
    /// Required for `false_positive` and `accepted_risk`.
    pub note: Option<String>,
}

/// Filters and paging for the case list.
#[derive(Debug, Deserialize, IntoParams)]
#[serde(deny_unknown_fields)]
pub(crate) struct CaseListParams {
    /// `open`, `investigating`, `closed` or `all`; open and investigating
    /// when absent.
    status: Option<String>,
    /// Exact severity.
    severity: Option<String>,
    /// A user id, `me`, or `none` for unassigned.
    assignee: Option<String>,
    /// Text in the title, or a case number such as `C-104`.
    q: Option<String>,
    /// Opaque continuation cursor.
    cursor: Option<String>,
    /// Page size from 1 to 100 (default 50).
    limit: Option<u16>,
}

/// Which cases hold an item.
#[derive(Debug, Deserialize, IntoParams)]
#[serde(deny_unknown_fields)]
pub(crate) struct ForItemParams {
    /// `alarm`, `finding`, `vulnerability`, `host` or `software`.
    kind: String,
    /// The object's id (see `CaseItemView.ref`).
    #[serde(rename = "ref")]
    #[param(rename = "ref")]
    reference: String,
}

fn time(at: DateTime<Utc>) -> String {
    at.to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn user_view(user: UserRef) -> CaseUserView {
    CaseUserView {
        user_id: user.user_id,
        username: user.username,
        display_name: user.display_name,
    }
}

fn summary_view(case: CaseSummary) -> CaseSummaryView {
    CaseSummaryView {
        case_id: case.case_id,
        number: case.number,
        title: case.title,
        status: case.status,
        resolution: case.resolution,
        accepted_until: case.accepted_until.map(time),
        severity: case.severity,
        assignee: case.assignee.map(user_view),
        opened_by: user_view(case.opened_by),
        created_at: time(case.created_at),
        updated_at: time(case.updated_at),
        closed_at: case.closed_at.map(time),
        version: case.version.try_into().unwrap_or_default(),
        item_count: case.items,
        pending_item_count: case.pending_items,
    }
}

fn item_view(item: CaseItem) -> CaseItemView {
    CaseItemView {
        item_id: item.item_id,
        kind: item.kind,
        reference: item.reference,
        agent_id: item.agent_id,
        hostname: item.hostname,
        active: item.active,
        outcome: item.outcome,
        outcome_note: item.outcome_note,
        added_by: user_view(item.added_by),
        added_at: time(item.added_at),
        title: item.title,
        severity: item.severity,
        evidence_gone: item.evidence_gone,
    }
}

fn event_view(event: CaseEvent) -> CaseEventView {
    CaseEventView {
        event_id: event.event_id,
        at: time(event.at),
        actor: event.actor.map(user_view),
        kind: event.kind,
        body: event.body,
        detail: event.detail,
    }
}

fn detail_view(detail: CaseDetail) -> CaseDetailView {
    CaseDetailView {
        case: summary_view(detail.summary),
        resolution_note: detail.resolution_note,
        items: detail.items.into_iter().map(item_view).collect(),
        events: detail.events.into_iter().map(event_view).collect(),
    }
}

fn item_case_view(found: ItemCase) -> ItemCaseView {
    ItemCaseView {
        case: summary_view(found.case),
        item_id: found.item_id,
        outcome: found.outcome,
    }
}

/// A JSON answer that is never cached; `version` adds the ETag.
fn answer(status: StatusCode, version: Option<u64>, body: impl Serialize) -> Response {
    let mut response = (status, Json(body)).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if let Some(version) = version
        && let Ok(value) = HeaderValue::from_str(&format!("\"{version}\""))
    {
        response.headers_mut().insert(header::ETAG, value);
    }
    response
}

fn detail_answer(status: StatusCode, detail: CaseDetail) -> Response {
    let view = detail_view(detail);
    answer(status, Some(view.case.version), view)
}

fn bad_request(code: &'static str, title: &'static str) -> Response {
    problem_response(ProblemDetails::new(StatusCode::BAD_REQUEST, code, title))
}

fn permission_denied() -> Response {
    problem_response(ProblemDetails::new(
        StatusCode::FORBIDDEN,
        "permission_denied",
        "Access is not available",
    ))
}

fn invalid(field: &str, code: &str, message: &str) -> Response {
    let mut problem = ProblemDetails::new(
        StatusCode::UNPROCESSABLE_ENTITY,
        "invalid_case",
        "The request is invalid",
    );
    problem.field_errors = Some(vec![FieldError {
        field: field.to_owned(),
        code: code.to_owned(),
        message: message.to_owned(),
    }]);
    problem_response(problem)
}

/// What a store validation code means, for the field error's message.
fn invalid_message(code: &str) -> &'static str {
    match code {
        "invalid_title" => "Use 1 to 120 characters, without control characters",
        "invalid_severity" => "Use critical, high, medium or low",
        "invalid_status" => "Use open, investigating or closed",
        "invalid_kind" => "Use alarm, compliance_finding, vulnerability, host or software",
        "invalid_ref" => "The id does not have the shape of this kind of item",
        "too_many_items" => "A case is created with at most 50 items",
        "resolution_required" => "A resolution is required to close a case",
        "invalid_resolution" => "Use mitigated, false_positive or accepted_risk",
        "resolution_note_required" => "A note is required to close a case",
        "invalid_note" => "Use 1 to 4000 characters of plain text",
        "note_required" => "A note is required for this outcome",
        "invalid_outcome" => "Use resolved, false_positive or accepted_risk",
        "outcome_not_applicable" => "Hosts and software need no outcome",
        "accepted_until_required" => "Accepted risk needs a date in the future",
        "accepted_until_past" => "The date must be in the future",
        "accepted_until_not_allowed" => "Only accepted risk has an end date",
        "resolution_not_allowed" => "Only a closed case has a resolution",
        _ => "The value is not valid",
    }
}

fn refused(refusal: Refusal) -> Response {
    let plain = |status: StatusCode, code: &'static str, title: &'static str| {
        problem_response(ProblemDetails::new(status, code, title))
    };
    match refusal {
        Refusal::NotFound => problem_response(ProblemDetails::not_found(
            "case_not_found",
            "Case not found",
        )),
        Refusal::ItemNotFound => problem_response(ProblemDetails::not_found(
            "item_not_found",
            "Item not found",
        )),
        Refusal::Stale => plain(
            StatusCode::PRECONDITION_FAILED,
            "stale_case",
            "The case changed since you loaded it",
        ),
        Refusal::Closed => plain(
            StatusCode::CONFLICT,
            "case_closed",
            "The case is closed; reopen it first",
        ),
        Refusal::Invalid(field, code) => invalid(field, code, invalid_message(code)),
        Refusal::AssigneeUnavailable => invalid(
            "assignee_user_id",
            "assignee_unavailable",
            "The assignee must be an enabled user who can read cases",
        ),
        Refusal::ItemInCase(number) => {
            let mut problem = ProblemDetails::new(
                StatusCode::CONFLICT,
                "item_in_case",
                "The item is already in another open case",
            );
            problem.case_number = number;
            problem_response(problem)
        }
        Refusal::AlreadyInCase => plain(
            StatusCode::CONFLICT,
            "item_already_in_case",
            "The item is already in this case",
        ),
        Refusal::TooManyItems => plain(
            StatusCode::UNPROCESSABLE_ENTITY,
            "too_many_items",
            "A case holds at most 500 items",
        ),
        Refusal::TimelineFull => plain(
            StatusCode::UNPROCESSABLE_ENTITY,
            "timeline_full",
            "The timeline holds at most 2000 entries",
        ),
        Refusal::ItemsUnresolved(_) => plain(
            StatusCode::CONFLICT,
            "items_unresolved",
            "Every alarm, finding and vulnerability needs an outcome before the case closes",
        ),
        Refusal::HiddenItemsUnresolved => plain(
            StatusCode::CONFLICT,
            "hidden_items_unresolved",
            "Items you cannot see still need an outcome; ask someone with access to them",
        ),
        Refusal::EvidencePresent => plain(
            StatusCode::CONFLICT,
            "evidence_present",
            "The evidence is still there; mark it false positive or accepted risk instead",
        ),
    }
}

/// A signed-in browser user holding `permissions`: their scope for the
/// first, and their id. Bearer tokens are refused. For changes, CSRF and
/// origin are checked first; the scope is that of the first permission.
async fn authorize(
    state: &AuthHttpState,
    headers: &HeaderMap,
    permissions: &[Permission],
    csrf_required: bool,
) -> Result<(AgentScope, String), Response> {
    let user = session_user(state, headers, csrf_required).await?;
    let mut scope = None;
    for permission in permissions {
        let Some(capability) = user
            .capabilities
            .iter()
            .find(|capability| capability.permission == *permission)
        else {
            return Err(permission_denied());
        };
        scope.get_or_insert_with(|| match &capability.scope {
            PermissionScope::Global => AgentScope::Global,
            PermissionScope::AssetGroups { asset_group_ids } => {
                AgentScope::AssetGroups(asset_group_ids.clone())
            }
        });
    }
    scope
        .map(|scope| (scope, user.user_id.to_ascii_lowercase()))
        .ok_or_else(permission_denied)
}

/// Reading: `cases.read`.
async fn reader(
    state: &AuthHttpState,
    headers: &HeaderMap,
) -> Result<(AgentScope, String), Response> {
    authorize(state, headers, &[Permission::CasesRead], false).await
}

/// Changing: `cases.manage` (with `cases.read`, which the built-in roles
/// grant together); items are checked against its scope.
async fn manager(
    state: &AuthHttpState,
    headers: &HeaderMap,
) -> Result<(AgentScope, String), Response> {
    authorize(
        state,
        headers,
        &[Permission::CasesManage, Permission::CasesRead],
        true,
    )
    .await
}

fn encode_cursor(case: &CaseSummary) -> String {
    URL_SAFE_NO_PAD.encode(format!(
        "{}.{}",
        case.updated_at.timestamp_micros(),
        case.case_id
    ))
}

fn decode_cursor(text: &str) -> Option<store::CaseCursor> {
    let bytes = URL_SAFE_NO_PAD.decode(text).ok()?;
    let (micros, id) = std::str::from_utf8(&bytes).ok()?.split_once('.')?;
    Some((
        DateTime::from_timestamp_micros(micros.parse().ok()?)?,
        id.to_owned(),
    ))
}

/// A title without the spaces around it; the store checks the rest.
fn title(raw: &str) -> &str {
    raw.trim()
}

/// A resolution or outcome note without the spaces around it; a blank one
/// is as good as none.
fn blank_is_absent(note: Option<&str>) -> Option<&str> {
    note.map(str::trim).filter(|note| !note.is_empty())
}

/// An RFC 3339 time, if it is one.
fn parse_time(text: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(text)
        .ok()
        .map(|at| at.with_timezone(&Utc))
}

/// The answer to a change that states no usable `If-Match`, or its version.
fn precondition(headers: &HeaderMap) -> Result<i64, ProblemDetails> {
    match parse_if_match_version(headers) {
        Ok(Some(version)) => Ok(version),
        Ok(None) => Err(ProblemDetails::new(
            StatusCode::PRECONDITION_REQUIRED,
            "precondition_required",
            "If-Match is required",
        )),
        Err(()) => Err(ProblemDetails::new(
            StatusCode::BAD_REQUEST,
            "invalid_precondition",
            "If-Match must contain one quoted version",
        )),
    }
}

#[utoipa::path(get, path = "/api/v1/cases", tag = "cases", params(CaseListParams),
    responses((status = 200, description = "The cases the caller can see, newest change first", body = crate::cases::CasePage),
        (status = 400, description = "Invalid query or cursor", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "Authentication required", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Bearer tokens and missing permissions are refused", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Unavailable", body = ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn list_cases(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    query: Result<Query<CaseListParams>, QueryRejection>,
) -> Response {
    let (scope, user_id) = match reader(&state, &headers).await {
        Ok(context) => context,
        Err(response) => return response,
    };
    let Ok(Query(params)) = query else {
        return bad_request("invalid_query", "Case query is invalid");
    };
    let limit = params.limit.unwrap_or(50);
    if !(1..=100).contains(&limit) {
        return bad_request("invalid_query", "limit must be 1 to 100");
    }
    if params
        .status
        .as_deref()
        .is_some_and(|status| !matches!(status, "open" | "investigating" | "closed" | "all"))
    {
        return bad_request(
            "invalid_query",
            "status must be open, investigating, closed or all",
        );
    }
    if params
        .severity
        .as_deref()
        .is_some_and(|severity| !matches!(severity, "critical" | "high" | "medium" | "low"))
    {
        return bad_request(
            "invalid_query",
            "severity must be critical, high, medium or low",
        );
    }
    if params.q.as_deref().is_some_and(|q| q.chars().count() > 120) {
        return bad_request("invalid_query", "q is at most 120 characters");
    }
    let assignee = match params.assignee.as_deref() {
        None => AssigneeFilter::Anyone,
        Some("none") => AssigneeFilter::Nobody,
        Some("me") => AssigneeFilter::User(user_id.clone()),
        Some(id) => AssigneeFilter::User(id.to_ascii_lowercase()),
    };
    let after = match params.cursor.as_deref().map(decode_cursor) {
        Some(None) => return bad_request("invalid_cursor", "cursor is invalid"),
        Some(cursor) => cursor,
        None => None,
    };
    let filters = CaseFilters {
        status: params.status,
        severity: params.severity,
        assignee,
        q: params.q,
    };
    let Ok(mut client) = state.pool.get().await else {
        return unavailable_auth();
    };
    // Accepted risk that has run out, and resolved evidence that has come
    // back, reopen their case before anyone looks.
    if store::reopen_due(&mut client, Utc::now()).await.is_err() {
        return unavailable_auth();
    }
    // One extra row says whether another page follows.
    let Ok(mut rows) = store::list(
        &client,
        &scope,
        &user_id,
        &filters,
        after.as_ref(),
        i64::from(limit) + 1,
    )
    .await
    else {
        return unavailable_auth();
    };
    let more = rows.len() > usize::from(limit);
    rows.truncate(usize::from(limit));
    let next_cursor = more.then(|| rows.last().map(encode_cursor)).flatten();
    answer(
        StatusCode::OK,
        None,
        CasePage {
            items: rows.into_iter().map(summary_view).collect(),
            next_cursor,
        },
    )
}

#[utoipa::path(post, path = "/api/v1/cases", tag = "cases", request_body = crate::cases::CreateCaseRequest,
    responses((status = 201, description = "Opened", body = crate::cases::CaseDetailView, headers(("ETag" = String, description = "Case version"))),
        (status = 400, description = "Invalid body", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "An item does not exist or is outside the caller's scope", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "An item is already in another open case", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "Invalid field", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "Authentication required", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Bearer tokens and missing permissions are refused", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Unavailable", body = ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn create_case(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    payload: Result<Json<CreateCaseRequest>, JsonRejection>,
) -> Response {
    let (scope, user_id) = match manager(&state, &headers).await {
        Ok(context) => context,
        Err(response) => return response,
    };
    let Ok(Json(request)) = payload else {
        return bad_request("invalid_request", "The request body is invalid");
    };
    let items: Vec<(&str, &str)> = request
        .items
        .iter()
        .map(|item| (item.kind.as_str(), item.reference.as_str()))
        .collect();
    let assignee = request.assignee_user_id.map(|id| id.to_ascii_lowercase());
    let new = NewCase {
        title: title(&request.title),
        severity: request.severity.as_deref(),
        assignee_user_id: assignee.as_deref(),
        items: &items,
    };
    let Ok(mut client) = state.pool.get().await else {
        return unavailable_auth();
    };
    match store::create(&mut client, &scope, &user_id, &new, Utc::now()).await {
        Ok(Ok(created)) => detail_answer(StatusCode::CREATED, created),
        Ok(Err(refusal)) => refused(refusal),
        Err(_) => unavailable_auth(),
    }
}

#[utoipa::path(get, path = "/api/v1/cases/{case_id}", tag = "cases", params(("case_id" = String, Path)),
    responses((status = 200, description = "The case, its visible items and timeline", body = crate::cases::CaseDetailView, headers(("ETag" = String, description = "Case version"))),
        (status = 404, description = "Absent or not visible", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "Authentication required", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Bearer tokens and missing permissions are refused", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Unavailable", body = ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn get_case(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let (scope, user_id) = match reader(&state, &headers).await {
        Ok(context) => context,
        Err(response) => return response,
    };
    let Ok(mut client) = state.pool.get().await else {
        return unavailable_auth();
    };
    if store::reopen_due(&mut client, Utc::now()).await.is_err() {
        return unavailable_auth();
    }
    match store::get(&client, &scope, &user_id, &id).await {
        Ok(Some(detail)) => detail_answer(StatusCode::OK, detail),
        Ok(None) => refused(Refusal::NotFound),
        Err(_) => unavailable_auth(),
    }
}

#[utoipa::path(put, path = "/api/v1/cases/{case_id}", tag = "cases", params(("case_id" = String, Path), ("If-Match" = String, Header, description = "Quoted version from ETag")),
    request_body = crate::cases::UpdateCaseRequest,
    responses((status = 200, description = "Saved", body = crate::cases::CaseDetailView, headers(("ETag" = String, description = "New case version"))),
        (status = 400, description = "Invalid body or If-Match", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "Absent or not visible", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "Items still need an outcome, an item is in another open case, or the case is closed", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 412, description = "Stale version", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "Invalid field", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 428, description = "If-Match is required", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "Authentication required", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Bearer tokens and missing permissions are refused", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Unavailable", body = ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn update_case(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    payload: Result<Json<UpdateCaseRequest>, JsonRejection>,
) -> Response {
    let (scope, user_id) = match manager(&state, &headers).await {
        Ok(context) => context,
        Err(response) => return response,
    };
    let expected = match precondition(&headers) {
        Ok(version) => version,
        Err(problem) => return problem_response(problem),
    };
    let Ok(Json(request)) = payload else {
        return bad_request("invalid_request", "The request body is invalid");
    };
    let accepted_until = match request.accepted_until.as_deref().map(parse_time) {
        Some(Some(at)) => Some(at),
        Some(None) => {
            return invalid(
                "accepted_until",
                "invalid_timestamp",
                "Use an RFC 3339 time",
            );
        }
        None => None,
    };
    let assignee = request.assignee_user_id.map(|id| id.to_ascii_lowercase());
    let note = blank_is_absent(request.resolution_note.as_deref());
    let change = CaseChange {
        expected_version: expected,
        title: title(&request.title),
        severity: &request.severity,
        status: &request.status,
        assignee_user_id: assignee.as_deref(),
        resolution: request.resolution.as_deref(),
        resolution_note: note,
        accepted_until,
    };
    let Ok(mut client) = state.pool.get().await else {
        return unavailable_auth();
    };
    match store::update(&mut client, &scope, &user_id, &id, &change, Utc::now()).await {
        Ok(Ok(saved)) => detail_answer(StatusCode::OK, saved),
        Ok(Err(refusal)) => refused(refusal),
        Err(_) => unavailable_auth(),
    }
}

#[utoipa::path(post, path = "/api/v1/cases/{case_id}/notes", tag = "cases", params(("case_id" = String, Path)), request_body = crate::cases::AddCaseNoteRequest,
    responses((status = 201, description = "Added to the timeline", body = crate::cases::CaseEventView),
        (status = 400, description = "Invalid body", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "Absent or not visible", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "Invalid note, or the timeline is full", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "Authentication required", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Bearer tokens and missing permissions are refused", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Unavailable", body = ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn add_note(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    payload: Result<Json<AddCaseNoteRequest>, JsonRejection>,
) -> Response {
    let (scope, user_id) = match manager(&state, &headers).await {
        Ok(context) => context,
        Err(response) => return response,
    };
    let Ok(Json(request)) = payload else {
        return bad_request("invalid_request", "The request body is invalid");
    };
    let Ok(mut client) = state.pool.get().await else {
        return unavailable_auth();
    };
    match store::add_note(
        &mut client,
        &scope,
        &user_id,
        &id,
        &request.body,
        Utc::now(),
    )
    .await
    {
        Ok(Ok(event)) => answer(StatusCode::CREATED, None, event_view(event)),
        Ok(Err(refusal)) => refused(refusal),
        Err(_) => unavailable_auth(),
    }
}

#[utoipa::path(post, path = "/api/v1/cases/{case_id}/items", tag = "cases", params(("case_id" = String, Path)), request_body = crate::cases::CaseItemRef,
    responses((status = 201, description = "Added", body = crate::cases::CaseItemView),
        (status = 400, description = "Invalid body", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "The case or the item does not exist or is outside the caller's scope", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "In another open case, already in this one, or the case is closed", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "Invalid kind or ref, or the case is full", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "Authentication required", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Bearer tokens and missing permissions are refused", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Unavailable", body = ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn add_item(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    payload: Result<Json<CaseItemRef>, JsonRejection>,
) -> Response {
    let (scope, user_id) = match manager(&state, &headers).await {
        Ok(context) => context,
        Err(response) => return response,
    };
    let Ok(Json(request)) = payload else {
        return bad_request("invalid_request", "The request body is invalid");
    };
    let Ok(mut client) = state.pool.get().await else {
        return unavailable_auth();
    };
    match store::add_item(
        &mut client,
        &scope,
        &user_id,
        &id,
        &request.kind,
        &request.reference,
        Utc::now(),
    )
    .await
    {
        Ok(Ok(item)) => answer(StatusCode::CREATED, None, item_view(item)),
        Ok(Err(refusal)) => refused(refusal),
        Err(_) => unavailable_auth(),
    }
}

#[utoipa::path(delete, path = "/api/v1/cases/{case_id}/items/{item_id}", tag = "cases", params(("case_id" = String, Path), ("item_id" = String, Path)),
    responses((status = 204, description = "Removed"),
        (status = 404, description = "The case or the item is absent or not visible", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The case is closed", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "Authentication required", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Bearer tokens and missing permissions are refused", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Unavailable", body = ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn remove_item(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path((id, item_id)): Path<(String, String)>,
) -> Response {
    let (scope, user_id) = match manager(&state, &headers).await {
        Ok(context) => context,
        Err(response) => return response,
    };
    let Ok(mut client) = state.pool.get().await else {
        return unavailable_auth();
    };
    match store::remove_item(&mut client, &scope, &user_id, &id, &item_id, Utc::now()).await {
        Ok(Ok(())) => StatusCode::NO_CONTENT.into_response(),
        Ok(Err(refusal)) => refused(refusal),
        Err(_) => unavailable_auth(),
    }
}

#[utoipa::path(put, path = "/api/v1/cases/{case_id}/items/{item_id}/outcome", tag = "cases", params(("case_id" = String, Path), ("item_id" = String, Path)), request_body = crate::cases::SetCaseItemOutcomeRequest,
    responses((status = 200, description = "Set or cleared", body = crate::cases::CaseItemView),
        (status = 400, description = "Invalid body", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "The case or the item is absent or not visible", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The case is closed, or resolved was asked for while the evidence is still there", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "Invalid outcome or note, or a kind that takes no outcome", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "Authentication required", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Bearer tokens and missing permissions are refused", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Unavailable", body = ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn set_item_outcome(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path((id, item_id)): Path<(String, String)>,
    payload: Result<Json<SetCaseItemOutcomeRequest>, JsonRejection>,
) -> Response {
    let (scope, user_id) = match manager(&state, &headers).await {
        Ok(context) => context,
        Err(response) => return response,
    };
    let Ok(Json(request)) = payload else {
        return bad_request("invalid_request", "The request body is invalid");
    };
    let note = blank_is_absent(request.note.as_deref());
    let change = request
        .outcome
        .as_deref()
        .map(|outcome| OutcomeChange { outcome, note });
    let Ok(mut client) = state.pool.get().await else {
        return unavailable_auth();
    };
    match store::set_outcome(
        &mut client,
        &scope,
        &user_id,
        &id,
        &item_id,
        change.as_ref(),
        Utc::now(),
    )
    .await
    {
        Ok(Ok(item)) => answer(StatusCode::OK, None, item_view(item)),
        Ok(Err(refusal)) => refused(refusal),
        Err(_) => unavailable_auth(),
    }
}

#[utoipa::path(get, path = "/api/v1/cases/for-item", tag = "cases", params(ForItemParams),
    responses((status = 200, description = "The visible cases that hold the item", body = crate::cases::ItemCasesView),
        (status = 400, description = "Invalid query", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "Invalid kind or ref", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "Authentication required", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Bearer tokens and missing permissions are refused", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Unavailable", body = ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn cases_for_item(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    query: Result<Query<ForItemParams>, QueryRejection>,
) -> Response {
    let (scope, user_id) = match reader(&state, &headers).await {
        Ok(context) => context,
        Err(response) => return response,
    };
    let Ok(Query(params)) = query else {
        return bad_request("invalid_query", "kind and ref are required");
    };
    let Ok(client) = state.pool.get().await else {
        return unavailable_auth();
    };
    match store::for_item(&client, &scope, &user_id, &params.kind, &params.reference).await {
        Ok(Ok(found)) => answer(
            StatusCode::OK,
            None,
            ItemCasesView {
                items: found.into_iter().map(item_case_view).collect(),
            },
        ),
        Ok(Err(refusal)) => refused(refusal),
        Err(_) => unavailable_auth(),
    }
}

#[utoipa::path(get, path = "/api/v1/cases/assignees", tag = "cases",
    responses((status = 200, description = "Users a case can be assigned to", body = crate::cases::CaseAssigneesView),
        (status = 401, description = "Authentication required", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Bearer tokens and missing permissions are refused", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Unavailable", body = ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn list_assignees(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = authorize(&state, &headers, &[Permission::CasesManage], false).await {
        return response;
    }
    let Ok(client) = state.pool.get().await else {
        return unavailable_auth();
    };
    match store::assignees(&client).await {
        Ok(users) => answer(
            StatusCode::OK,
            None,
            CaseAssigneesView {
                items: users.into_iter().map(user_view).collect(),
            },
        ),
        Err(_) => unavailable_auth(),
    }
}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone, Utc};

    use super::{decode_cursor, invalid_message};

    #[test]
    fn a_cursor_round_trips_and_garbage_is_refused() {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        let at = Utc.with_ymd_and_hms(2026, 10, 4, 12, 0, 0).unwrap();
        let text = URL_SAFE_NO_PAD.encode(format!(
            "{}.{}",
            at.timestamp_micros(),
            "11111111-1111-4111-8111-111111111111"
        ));
        assert_eq!(
            decode_cursor(&text),
            Some((at, "11111111-1111-4111-8111-111111111111".to_owned()))
        );
        for bad in [
            "",
            "!!",
            &URL_SAFE_NO_PAD.encode("no-dot"),
            &URL_SAFE_NO_PAD.encode("x.y"),
        ] {
            assert_eq!(decode_cursor(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn every_validation_code_the_store_emits_has_a_message() {
        for code in [
            "invalid_title",
            "invalid_severity",
            "invalid_status",
            "invalid_kind",
            "invalid_ref",
            "too_many_items",
            "resolution_required",
            "invalid_resolution",
            "resolution_note_required",
            "invalid_note",
            "note_required",
            "invalid_outcome",
            "outcome_not_applicable",
            "accepted_until_required",
            "accepted_until_past",
            "accepted_until_not_allowed",
            "resolution_not_allowed",
        ] {
            assert_ne!(invalid_message(code), "The value is not valid", "{code}");
        }
    }
}
