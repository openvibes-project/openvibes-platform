use axum::{
    extract::{Query, State, rejection::QueryRejection},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use platform_store::console_cases::{self as store};

use super::permissions::{authorize, reader};
use super::responses::{answer, bad_request};
use super::types::{ActiveCaseItem, ActiveCaseItemsView, ActiveItemsParams, CaseAssigneesView};
use super::views::user_view;
use crate::{Permission, ProblemDetails, access::guard::unavailable_auth, http::AuthHttpState};

#[utoipa::path(get, path = "/api/v1/cases/active-items", tag = "cases", params(ActiveItemsParams),
    responses((status = 200, description = "Items of this kind in open cases the caller can see", body = crate::cases::ActiveCaseItemsView),
        (status = 400, description = "Invalid kind", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "Authentication required", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Bearer tokens and missing permissions are refused", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Unavailable", body = ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn active_items(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    query: Result<Query<ActiveItemsParams>, QueryRejection>,
) -> Response {
    let (scope, user_id) = match reader(&state, &headers).await {
        Ok(context) => context,
        Err(response) => return response,
    };
    let Ok(Query(params)) = query else {
        return bad_request("invalid_query", "kind is required");
    };
    let Ok(client) = state.pool.get().await else {
        return unavailable_auth();
    };
    match store::active_items(&client, &scope, &user_id, &params.kind).await {
        Ok(Some(found)) => answer(
            StatusCode::OK,
            None,
            ActiveCaseItemsView {
                items: found
                    .into_iter()
                    .map(|(reference, case_number)| ActiveCaseItem {
                        reference,
                        case_number,
                    })
                    .collect(),
            },
        ),
        Ok(None) => bad_request(
            "invalid_kind",
            "kind must be alarm, compliance_finding or vulnerability",
        ),
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
    if let Err(response) = authorize(&state, &headers, &[Permission::CasesAssign], false).await {
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
