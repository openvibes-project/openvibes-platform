//! Open ports and running services over `/api/v1` (Assets v2, P15): one
//! host's listeners and services, and the fleet's ports and services.
//! Reads need `agents.read` and are scoped to the caller's agents; fleet
//! counts leave revoked hosts out.

use axum::{
    Json,
    extract::{Path, Query, State, rejection::QueryRejection},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use chrono::SecondsFormat;
use platform_store::host_services as store;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use crate::{
    Permission, ProblemDetails,
    problem::problem_response,
    router::{AuthHttpState, authenticated_permission, unavailable_auth},
};

/// One listening socket on a host.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct ListenerView {
    /// `tcp` or `udp`.
    pub protocol: String,
    /// The bound address (`0.0.0.0` or `::` for any).
    pub address: String,
    /// The port.
    pub port: i32,
    /// Bound to a non-loopback address: reachable from the network.
    pub exposed: bool,
    /// The owning systemd unit, when the agent could see it.
    pub service: Option<String>,
    /// The owning program, when the agent could see it.
    pub program: Option<String>,
}

/// One running service on a host.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct ServiceView {
    /// The systemd unit.
    pub unit: String,
    /// Its programs, sorted.
    pub programs: Vec<String>,
    /// How many processes it runs.
    pub processes: i32,
    /// The user it runs as (a name, or the uid when unknown).
    pub run_as: Option<String>,
}

/// One host's open ports and running services.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct HostServicesView {
    /// RFC 3339 time of the last report; absent if the host never sent one.
    pub reported_at: Option<String>,
    /// `complete` (every owner is named) or `partial` (some owners are
    /// not visible to the agent).
    pub owners: Option<String>,
    /// Listeners, exposed first, then by port.
    pub listeners: Vec<ListenerView>,
    /// Services, by unit.
    pub services: Vec<ServiceView>,
}

/// One port across the caller's hosts.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct PortView {
    /// `tcp` or `udp`.
    pub protocol: String,
    /// The port.
    pub port: i32,
    /// Hosts listening on it.
    pub hosts: i64,
    /// Of those, hosts where it is exposed.
    pub exposed_hosts: i64,
    /// Owning services seen for it, sorted, at most 8.
    pub services: Vec<String>,
}

/// One service unit across the caller's hosts.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct UnitView {
    /// The systemd unit.
    pub unit: String,
    /// Hosts running it.
    pub hosts: i64,
}

/// Filter for the fleet's ports.
#[derive(Debug, Deserialize, IntoParams)]
#[serde(deny_unknown_fields)]
pub(crate) struct PortParams {
    /// Only ports exposed on at least one host.
    exposed: Option<bool>,
}

fn listener_view(l: store::Listener) -> ListenerView {
    ListenerView {
        protocol: l.protocol,
        address: l.address.to_string(),
        port: l.port,
        exposed: l.exposed,
        service: l.service,
        program: l.program,
    }
}

fn service_view(s: store::Service) -> ServiceView {
    ServiceView {
        unit: s.unit,
        programs: s.programs,
        processes: s.processes,
        run_as: s.run_as,
    }
}

#[utoipa::path(get, path = "/api/v1/agents/{agent_id}/services", tag = "assets",
    params(("agent_id" = String, Path)),
    responses((status = 200, description = "The host's open ports and running services", body = crate::ports::HostServicesView),
        (status = 401, description = "Authentication required", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Permission denied", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "Absent or outside the caller's scope", body = crate::ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn get_host_services(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path(agent_id): Path<String>,
) -> Response {
    let (scope, _) =
        match authenticated_permission(&state, &headers, Permission::AgentsRead, false).await {
            Ok(context) => context,
            Err(response) => return response,
        };
    let Ok(client) = state.pool.get().await else {
        return unavailable_auth();
    };
    match store::for_host(&client, &scope, &agent_id).await {
        Ok(Some(host)) => Json(HostServicesView {
            reported_at: host
                .reported_at
                .map(|at| at.to_rfc3339_opts(SecondsFormat::Millis, true)),
            owners: host.owners,
            listeners: host.listeners.into_iter().map(listener_view).collect(),
            services: host.services.into_iter().map(service_view).collect(),
        })
        .into_response(),
        Ok(None) => problem_response(ProblemDetails::not_found(
            "agent_not_found",
            "Agent not found",
        )),
        Err(_) => unavailable_auth(),
    }
}

#[utoipa::path(get, path = "/api/v1/ports", tag = "assets", params(PortParams),
    responses((status = 200, description = "Ports across the caller's hosts, by port", body = Vec<crate::ports::PortView>),
        (status = 400, description = "Invalid query", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "Authentication required", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Permission denied", body = crate::ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn list_ports(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    params: Result<Query<PortParams>, QueryRejection>,
) -> Response {
    let (scope, _) =
        match authenticated_permission(&state, &headers, Permission::AgentsRead, false).await {
            Ok(context) => context,
            Err(response) => return response,
        };
    let Ok(Query(params)) = params else {
        return problem_response(ProblemDetails::new(
            StatusCode::BAD_REQUEST,
            "invalid_query",
            "Port query is invalid",
        ));
    };
    let Ok(client) = state.pool.get().await else {
        return unavailable_auth();
    };
    match store::fleet_ports(&client, &scope, params.exposed.unwrap_or(false)).await {
        Ok(rows) => Json(
            rows.into_iter()
                .map(|p| PortView {
                    protocol: p.protocol,
                    port: p.port,
                    hosts: p.hosts,
                    exposed_hosts: p.exposed_hosts,
                    services: p.services,
                })
                .collect::<Vec<_>>(),
        )
        .into_response(),
        Err(_) => unavailable_auth(),
    }
}

#[utoipa::path(get, path = "/api/v1/services", tag = "assets",
    responses((status = 200, description = "Running services across the caller's hosts, by unit", body = Vec<crate::ports::UnitView>),
        (status = 401, description = "Authentication required", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Permission denied", body = crate::ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn list_services(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
) -> Response {
    let (scope, _) =
        match authenticated_permission(&state, &headers, Permission::AgentsRead, false).await {
            Ok(context) => context,
            Err(response) => return response,
        };
    let Ok(client) = state.pool.get().await else {
        return unavailable_auth();
    };
    match store::fleet_services(&client, &scope).await {
        Ok(rows) => Json(
            rows.into_iter()
                .map(|u| UnitView {
                    unit: u.unit,
                    hosts: u.hosts,
                })
                .collect::<Vec<_>>(),
        )
        .into_response(),
        Err(_) => unavailable_auth(),
    }
}
