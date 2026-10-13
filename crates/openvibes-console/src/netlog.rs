//! Console API for registered network device connections.

use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use platform_store::console_read::AgentScope;

use crate::{
    NetlogDevicePage, NetlogDeviceView, Permission, ProblemDetails,
    problem::problem_response,
    router::{AuthHttpState, authenticated_permission, no_store, unavailable_auth},
};

/// Lists registered device connections.
#[utoipa::path(
    get,
    path = "/api/v1/netlog/devices",
    tag = "netlog",
    responses(
        (status = 200, description = "Registered devices", body = NetlogDevicePage),
        (status = 401, description = "Authentication required", body = ProblemDetails),
        (status = 403, description = "Permission denied", body = ProblemDetails),
        (status = 503, description = "Device list unavailable", body = ProblemDetails)
    )
)]
pub(crate) async fn list_devices(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
) -> Response {
    let (scope, actor) =
        match authenticated_permission(&state, &headers, Permission::NetlogRead, false).await {
            Ok(value) => value,
            Err(response) => return response,
        };

    if !matches!(scope, AgentScope::Global) {
        return problem_response(ProblemDetails::new(
            StatusCode::FORBIDDEN,
            "permission_denied",
            "Access is not available",
        ));
    }

    let client = match state.pool.get().await {
        Ok(client) => client,
        Err(_) => return unavailable_auth(),
    };

    let devices = match platform_store::devices::list(&client).await {
        Ok(devices) => devices,
        Err(_) => return unavailable_auth(),
    };

    if platform_store::audit::record(
        &client,
        &actor,
        "netlog.devices.viewed",
        Some("devices"),
        "success",
    )
    .await
    .is_err()
    {
        return unavailable_auth();
    }

    no_store(
        Json(NetlogDevicePage {
            items: devices
                .into_iter()
                .map(|device| NetlogDeviceView {
                    id: device.id,
                    name: device.name,
                    kind: device.kind,
                    address: device.address.to_string(),
                })
                .collect(),
        })
        .into_response(),
    )
}
