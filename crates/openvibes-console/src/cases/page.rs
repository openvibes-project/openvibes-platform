//! `GET /v1/cases/{id}/summary`: everything above the fold on a case's
//! page (roles plan 2026-10-25 step 5d, rulings 12–14). A case the caller
//! cannot see answers 404 `case_not_found`, as a missing one does.

use axum::{
    extract::{Path, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use chrono::Utc;
use platform_store::{
    case_summary::{case_summary, case_visible_to},
    console_cases as store,
    host_list::HostScopes,
};

use super::{
    page_types::{CasePageActionsView, CasePageSummaryView},
    permissions::both,
    responses::{permission_denied, refused},
};
use crate::{
    Permission,
    access::guard::{scope_of, session_user, unavailable_auth},
    http::{AuthHttpState, problem::ProblemDetails},
};

/// A case's page above the fold.
#[utoipa::path(get, path = "/api/v1/cases/{case_id}/summary", tag = "cases",
    params(("case_id" = String, Path, description = "Case UUID")),
    responses((status = 200, description = "The case as the caller may see it", body = CasePageSummaryView),
        (status = 401, description = "Authentication required", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Bearer tokens and callers without cases.read are refused", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "case_not_found: missing or not visible", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Read unavailable", body = ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn case_summary_page(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path(case_id): Path<String>,
) -> Response {
    let user = match session_user(&state, &headers, false).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let scope = |p| scope_of(&user.capabilities, p);
    let holds = |p| user.capabilities.iter().any(|c| c.permission == p);
    let Some(read) = scope(Permission::CasesRead) else {
        return permission_denied();
    };
    let user_id = user.user_id.to_ascii_lowercase();
    let (alarms, vulns, compliance) = (
        scope(Permission::AlarmsRead),
        scope(Permission::VulnerabilitiesRead),
        scope(Permission::ComplianceRead),
    );
    let scopes = HostScopes {
        hosts: &read,
        alarms: alarms.as_ref(),
        vulnerabilities: vulns.as_ref(),
        compliance: compliance.as_ref(),
    };
    let Ok(mut client) = state.pool.get().await else {
        return unavailable_auth();
    };
    let now = Utc::now();
    // Run-out acceptances and returned evidence reopen their case first.
    if store::reopen_due(&mut client, now).await.is_err() {
        return unavailable_auth();
    }
    let s = match case_summary(&client, &case_id, &scopes, &user_id, now).await {
        Ok(Some(s)) => s,
        Ok(None) => return refused(store::Refusal::NotFound),
        Err(_) => return unavailable_auth(),
    };
    // Changes use the scope cases.write and cases.read share (permissions.rs).
    let write = match scope(Permission::CasesWrite) {
        Some(w) => match case_visible_to(&client, &both(w, read.clone()), &user_id, &case_id).await
        {
            Ok(v) => v,
            Err(_) => return unavailable_auth(),
        },
        None => false,
    };
    let closed = s.case.status == "closed";
    let can = CasePageActionsView {
        edit: write,
        assign: write && holds(Permission::CasesAssign),
        close: write && !closed,
        reopen: write && closed,
        note: write,
        outcome: write && !closed,
        // The assistant takes no case reference (assistant/: agents,
        // findings and advisories only), so there is nothing to ask with.
        ask: false,
        export: true,
    };
    axum::Json(CasePageSummaryView::new(
        s,
        holds(Permission::AccessRead),
        can,
    ))
    .into_response()
}
