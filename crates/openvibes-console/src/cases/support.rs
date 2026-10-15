use axum::{
    Json,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use platform_store::{
    console_cases::{self as store, CaseDetail, CaseSummary, Refusal},
    console_read::AgentScope,
};
use serde::Serialize;

use crate::{
    FieldError, Permission, PermissionScope, ProblemDetails, access::guard::session_user,
    http::AuthHttpState, http::problem::problem_response, router::parse_if_match_version,
};

use super::views::*;
/// A JSON answer that is never cached; `version` adds the ETag.
pub(super) fn answer(status: StatusCode, version: Option<u64>, body: impl Serialize) -> Response {
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

pub(super) fn detail_answer(status: StatusCode, detail: CaseDetail) -> Response {
    let view = detail_view(detail);
    answer(status, Some(view.case.version), view)
}

pub(super) fn bad_request(code: &'static str, title: &'static str) -> Response {
    problem_response(ProblemDetails::new(StatusCode::BAD_REQUEST, code, title))
}

pub(super) fn permission_denied() -> Response {
    problem_response(ProblemDetails::new(
        StatusCode::FORBIDDEN,
        "permission_denied",
        "Access is not available",
    ))
}

pub(super) fn invalid(field: &str, code: &str, message: &str) -> Response {
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
pub(super) fn invalid_message(code: &str) -> &'static str {
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

pub(super) fn refused(refusal: Refusal) -> Response {
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
pub(crate) async fn authorize(
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
pub(super) async fn reader(
    state: &AuthHttpState,
    headers: &HeaderMap,
) -> Result<(AgentScope, String), Response> {
    authorize(state, headers, &[Permission::CasesRead], false).await
}

/// Changing: `cases.manage` (with `cases.read`, which the built-in roles
/// grant together); items are checked against its scope.
pub(super) async fn manager(
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

pub(super) fn encode_cursor(case: &CaseSummary) -> String {
    URL_SAFE_NO_PAD.encode(format!(
        "{}.{}",
        case.updated_at.timestamp_micros(),
        case.case_id
    ))
}

pub(super) fn decode_cursor(text: &str) -> Option<store::CaseCursor> {
    let bytes = URL_SAFE_NO_PAD.decode(text).ok()?;
    let (micros, id) = std::str::from_utf8(&bytes).ok()?.split_once('.')?;
    Some((
        DateTime::from_timestamp_micros(micros.parse().ok()?)?,
        id.to_owned(),
    ))
}

/// A title without the spaces around it; the store checks the rest.
pub(super) fn title(raw: &str) -> &str {
    raw.trim()
}

/// A resolution or outcome note without the spaces around it; a blank one
/// is as good as none.
pub(super) fn blank_is_absent(note: Option<&str>) -> Option<&str> {
    note.map(str::trim).filter(|note| !note.is_empty())
}

/// An RFC 3339 time, if it is one.
pub(super) fn parse_time(text: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(text)
        .ok()
        .map(|at| at.with_timezone(&Utc))
}

/// The answer to a change that states no usable `If-Match`, or its version.
pub(super) fn precondition(headers: &HeaderMap) -> Result<i64, ProblemDetails> {
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
