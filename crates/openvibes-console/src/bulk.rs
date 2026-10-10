//! Bulk triage over `/api/v1` (triage v2, spec
//! `2026-10-10-bulk-triage-design.md`, #237/#239/#240): one action on up to
//! 10,000 selected alarms, compliance findings or vulnerabilities. The
//! browser sends exactly the rows it shows; each item goes through its
//! single-item rules, and skipped items come back with a reason.

use std::collections::HashSet;

use axum::{
    Json,
    extract::{State, rejection::JsonRejection},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use chrono::{DateTime, Utc};
use platform_store::{
    alarm_suppressions::{self, Change},
    bulk_triage::{self as store, BulkChange, BulkRefusal, BulkResult, MAX_ITEMS},
    console_cases::{self, NewCase, Refusal},
    console_read::AgentScope,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{
    Permission, ProblemDetails,
    cases::authorize,
    problem::problem_response,
    router::{AuthHttpState, unavailable_auth},
};

/// One selected row. Alarms: `id`. Compliance: `rule_set_id` and `rule_id`
/// (every host in scope), with `agent_id` for one host. Vulnerabilities:
/// `advisory_id` (every host where it is open), with `agent_id` for one.
#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct BulkItem {
    /// The platform's alarm id.
    pub id: Option<String>,
    /// Rule set of a compliance finding.
    pub rule_set_id: Option<String>,
    /// Rule of a compliance finding.
    pub rule_id: Option<String>,
    /// Advisory of a vulnerability.
    pub advisory_id: Option<String>,
    /// One host only.
    pub agent_id: Option<String>,
}

/// One action on many items.
#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct BulkRequest {
    /// `state`, `assign`, `case`, or (alarms) `suppress`.
    pub action: String,
    /// For `state`: `open`, `mitigated`, `accepted_risk` or `false_positive`.
    pub state: Option<String>,
    /// Required to close, and for `suppress`; goes on every item.
    pub note: Option<String>,
    /// For `accepted_risk`: RFC 3339, in the future.
    pub accepted_until: Option<String>,
    /// For `assign`: a username, or absent to unassign.
    pub assignee: Option<String>,
    /// For `case`: an open case, or `new_case_title` to create one.
    pub case_id: Option<String>,
    /// For `case`: the title of a new case.
    pub new_case_title: Option<String>,
    /// For a new case: the selection's highest item severity (`important`
    /// counts as high, as for case items).
    pub new_case_severity: Option<String>,
    /// The selected rows, at most 10,000.
    pub items: Vec<BulkItem>,
}

/// An item left alone.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct BulkSkip {
    /// The item (alarm id, `agent/rule_set/rule`, `agent/advisory`, ...).
    pub id: String,
    /// Why.
    pub reason: String,
}

/// What a bulk action did.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct BulkResponse {
    /// Items changed (or already so).
    pub changed: usize,
    /// Items left alone, with the reason.
    pub skipped: Vec<BulkSkip>,
    /// For `case`: the case the items went into.
    pub case_id: Option<String>,
    /// For `case`: its number (`C-<number>`).
    pub case_number: Option<i64>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Alarms,
    Compliance,
    Vulnerabilities,
}

impl Kind {
    fn triage(self) -> Permission {
        match self {
            Kind::Alarms => Permission::AlarmsTriage,
            Kind::Compliance => Permission::ComplianceTriage,
            Kind::Vulnerabilities => Permission::VulnerabilitiesTriage,
        }
    }
}

fn bad(code: &'static str, title: &'static str) -> Response {
    problem_response(ProblemDetails::new(StatusCode::BAD_REQUEST, code, title))
}

#[utoipa::path(post, path = "/api/v1/alarms/bulk", tag = "alarms", request_body = crate::bulk::BulkRequest,
    responses((status = 200, description = "What the action did", body = crate::bulk::BulkResponse),
        (status = 400, description = "Invalid action, items, note or expiry", body = crate::ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn bulk_alarms(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    payload: Result<Json<BulkRequest>, JsonRejection>,
) -> Response {
    run(Kind::Alarms, &state, &headers, payload).await
}

#[utoipa::path(post, path = "/api/v1/compliance/bulk", tag = "compliance", request_body = crate::bulk::BulkRequest,
    responses((status = 200, description = "What the action did", body = crate::bulk::BulkResponse),
        (status = 400, description = "Invalid action, items, note or expiry", body = crate::ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn bulk_compliance(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    payload: Result<Json<BulkRequest>, JsonRejection>,
) -> Response {
    run(Kind::Compliance, &state, &headers, payload).await
}

#[utoipa::path(post, path = "/api/v1/vulnerabilities/bulk", tag = "vulnerabilities", request_body = crate::bulk::BulkRequest,
    responses((status = 200, description = "What the action did", body = crate::bulk::BulkResponse),
        (status = 400, description = "Invalid action, items, note or expiry", body = crate::ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn bulk_vulnerabilities(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    payload: Result<Json<BulkRequest>, JsonRejection>,
) -> Response {
    run(Kind::Vulnerabilities, &state, &headers, payload).await
}

/// Parsed items: alarm ids, compliance (set, rule, host?), vulnerability
/// (advisory, host?). `None` if an item does not fit the kind.
enum Items {
    Alarms(Vec<i64>),
    Compliance(Vec<(String, String, Option<String>)>),
    Vulnerabilities(Vec<(String, Option<String>)>),
}

fn parse_items(kind: Kind, items: &[BulkItem]) -> Option<Items> {
    let only = |item: &BulkItem, a: bool, b: bool, c: bool, d: bool| {
        item.id.is_some() == a
            && item.rule_set_id.is_some() == b
            && item.rule_id.is_some() == b
            && item.advisory_id.is_some() == c
            && (d || item.agent_id.is_none())
    };
    match kind {
        Kind::Alarms => items
            .iter()
            .map(|i| {
                only(i, true, false, false, false)
                    .then(|| i.id.as_deref()?.parse::<i64>().ok().filter(|id| *id > 0))
                    .flatten()
            })
            .collect::<Option<Vec<_>>>()
            .map(Items::Alarms),
        Kind::Compliance => items
            .iter()
            .map(|i| {
                only(i, false, true, false, true).then(|| {
                    (
                        i.rule_set_id.clone().unwrap_or_default(),
                        i.rule_id.clone().unwrap_or_default(),
                        i.agent_id.clone(),
                    )
                })
            })
            .collect::<Option<Vec<_>>>()
            .map(Items::Compliance),
        Kind::Vulnerabilities => items
            .iter()
            .map(|i| {
                only(i, false, false, true, true).then(|| {
                    (
                        i.advisory_id.clone().unwrap_or_default(),
                        i.agent_id.clone(),
                    )
                })
            })
            .collect::<Option<Vec<_>>>()
            .map(Items::Vulnerabilities),
    }
}

async fn run(
    kind: Kind,
    state: &AuthHttpState,
    headers: &HeaderMap,
    payload: Result<Json<BulkRequest>, JsonRejection>,
) -> Response {
    let Ok(Json(request)) = payload else {
        return bad("invalid_request", "Bulk request is invalid");
    };
    let mut needed = vec![kind.triage()];
    match request.action.as_str() {
        "state" | "assign" => {}
        "case" => needed.extend([Permission::CasesManage, Permission::CasesRead]),
        "suppress" if kind == Kind::Alarms => needed.push(Permission::AlarmsSuppress),
        _ => {
            return bad(
                "invalid_action",
                "Use state, assign, case or (alarms) suppress",
            );
        }
    }
    let (scope, user_id) = match authorize(state, headers, &needed, true).await {
        Ok(context) => context,
        Err(response) => return response,
    };
    if request.items.is_empty() || request.items.len() > MAX_ITEMS {
        return bad("invalid_items", "Select 1 to 10,000 items");
    }
    let Some(items) = parse_items(kind, &request.items) else {
        return bad("invalid_items", "An item does not fit this list");
    };
    let accepted_until = match request
        .accepted_until
        .as_deref()
        .map(DateTime::parse_from_rfc3339)
    {
        Some(Ok(at)) => Some(at.with_timezone(&Utc)),
        Some(Err(_)) => return bad("invalid_expiry", "accepted_until must be RFC 3339"),
        None => None,
    };
    let Ok(mut client) = state.pool.get().await else {
        return unavailable_auth();
    };
    let now = Utc::now();
    let note = request
        .note
        .as_deref()
        .map(str::trim)
        .filter(|n| !n.is_empty());
    let outcome = match request.action.as_str() {
        "state" => {
            let Some(new_state) = request.state.as_deref() else {
                return bad("invalid_state", "state is required");
            };
            let change = BulkChange::State {
                state: new_state,
                note,
                accepted_until,
            };
            apply(&mut client, &scope, &items, change, &user_id, now).await
        }
        "assign" => {
            let change = BulkChange::Assign(request.assignee.as_deref());
            apply(&mut client, &scope, &items, change, &user_id, now).await
        }
        "case" => return add_to_case(&mut client, &scope, &user_id, &items, &request, now).await,
        _ => {
            let (Items::Alarms(ids), Some(note)) = (&items, note) else {
                return bad("invalid_note", "A suppression needs a note");
            };
            return suppress(&mut client, &scope, &user_id, ids, note, now).await;
        }
    };
    match outcome {
        Ok(Ok(result)) => respond(result, None),
        Ok(Err(BulkRefusal::Count)) => bad("invalid_items", "Select 1 to 10,000 items"),
        Ok(Err(BulkRefusal::Fields)) => bad(
            "invalid_triage",
            "Triage state, note, or expiry is invalid (closing needs a note)",
        ),
        Err(_) => unavailable_auth(),
    }
}

async fn apply(
    client: &mut platform_store::Client,
    scope: &AgentScope,
    items: &Items,
    change: BulkChange<'_>,
    actor: &str,
    now: DateTime<Utc>,
) -> Result<Result<BulkResult, BulkRefusal>, platform_store::StoreError> {
    match items {
        Items::Alarms(ids) => store::alarms(client, scope, ids, change, actor, now).await,
        Items::Compliance(items) => {
            store::compliance(client, scope, items, change, actor, now).await
        }
        Items::Vulnerabilities(items) => {
            store::vulnerabilities(client, scope, items, change, actor, now).await
        }
    }
}

fn respond(result: BulkResult, case: Option<(String, i64)>) -> Response {
    let (case_id, case_number) = case.map_or((None, None), |(id, n)| (Some(id), Some(n)));
    Json(BulkResponse {
        changed: result.changed,
        skipped: result
            .skipped
            .into_iter()
            .map(|(id, reason)| BulkSkip {
                id,
                reason: reason.to_owned(),
            })
            .collect(),
        case_id,
        case_number,
    })
    .into_response()
}

/// Adds the items (hosts expanded in scope) to an open case, or to a new
/// one; items already in another open case are skipped.
async fn add_to_case(
    client: &mut platform_store::Client,
    scope: &AgentScope,
    user_id: &str,
    items: &Items,
    request: &BulkRequest,
    now: DateTime<Utc>,
) -> Response {
    let refs: Vec<(&'static str, String)> = match items {
        Items::Alarms(ids) => ids.iter().map(|id| ("alarm", id.to_string())).collect(),
        Items::Compliance(items) => match store::expand_compliance(client, scope, items).await {
            Ok(Some(found)) => found
                .into_iter()
                .map(|(a, s, r)| ("compliance_finding", format!("{a}/{s}/{r}")))
                .collect(),
            Ok(None) => return bad("invalid_items", "Select 1 to 10,000 items"),
            Err(_) => return unavailable_auth(),
        },
        Items::Vulnerabilities(items) => {
            match store::expand_vulnerabilities(client, scope, items).await {
                Ok(Some(found)) => found
                    .into_iter()
                    .map(|(a, adv)| ("vulnerability", format!("{a}/{adv}")))
                    .collect(),
                Ok(None) => return bad("invalid_items", "Select 1 to 10,000 items"),
                Err(_) => return unavailable_auth(),
            }
        }
    };
    let case = match (&request.case_id, &request.new_case_title) {
        (Some(id), None) => id.clone(),
        (None, Some(title)) => {
            let new = NewCase {
                title: title.trim(),
                severity: request
                    .new_case_severity
                    .as_deref()
                    .and_then(console_cases::case_severity_of),
                assignee_user_id: None,
                items: &[],
            };
            match console_cases::create(client, scope, user_id, &new, now).await {
                Ok(Ok(detail)) => detail.summary.case_id,
                Ok(Err(_)) => {
                    return bad(
                        "invalid_case",
                        "The new case's title or severity is invalid",
                    );
                }
                Err(_) => return unavailable_auth(),
            }
        }
        _ => return bad("invalid_case", "Give case_id or new_case_title"),
    };
    let mut result = BulkResult::default();
    let mut number = None;
    for (kind, reference) in &refs {
        match console_cases::add_item(client, scope, user_id, &case, kind, reference, now).await {
            Ok(Ok(_)) => result.changed += 1,
            Ok(Err(Refusal::NotFound | Refusal::Closed)) => {
                return problem_response(ProblemDetails::not_found(
                    "case_not_found",
                    "No such open case",
                ));
            }
            Ok(Err(Refusal::AlreadyInCase)) => result.changed += 1,
            Ok(Err(Refusal::ItemInCase(_))) => result
                .skipped
                .push((reference.clone(), "in another open case")),
            Ok(Err(Refusal::TooManyItems)) => result
                .skipped
                .push((reference.clone(), "the case is full (500 items)")),
            Ok(Err(_)) => result
                .skipped
                .push((reference.clone(), "not found or out of scope")),
            Err(_) => return unavailable_auth(),
        }
    }
    if let Ok(Some(detail)) = console_cases::get(client, scope, user_id, &case).await {
        number = Some(detail.summary.number);
    }
    respond(result, number.map(|n| (case.clone(), n)))
}

/// One `program` suppression per distinct rule and program among the
/// selected alarms (which closes every matching alarm, these included).
async fn suppress(
    client: &mut platform_store::Client,
    scope: &AgentScope,
    user_id: &str,
    ids: &[i64],
    note: &str,
    now: DateTime<Utc>,
) -> Response {
    let Ok(rows) = client
        .query(
            "SELECT DISTINCT ON (rule_set_id, rule_id, process->>'exe') id
             FROM alarms WHERE id = ANY($1) ORDER BY rule_set_id, rule_id, process->>'exe', id",
            &[&ids],
        )
        .await
    else {
        return unavailable_auth();
    };
    let representatives: HashSet<i64> = rows.iter().map(|r| r.get(0)).collect();
    let mut result = BulkResult::default();
    for id in ids {
        if !representatives.contains(id) {
            continue;
        }
        match alarm_suppressions::create(client, scope, *id, "program", note, user_id, now).await {
            Ok(Change::Done(_)) => result.changed += 1,
            Ok(Change::NeedsGlobalScope) => {
                result
                    .skipped
                    .push((id.to_string(), "program suppressions need global scope"));
            }
            Ok(_) => result
                .skipped
                .push((id.to_string(), "not found or out of scope")),
            Err(_) => return unavailable_auth(),
        }
    }
    respond(result, None)
}
