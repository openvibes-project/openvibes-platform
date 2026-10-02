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
    /// The agent cut a list to the protocol limits: the lists are
    /// incomplete.
    pub truncated: bool,
    /// RFC 3339 time ingest refused the host's last report, if it did since
    /// the last good one; the lists are then from that older report.
    pub refused_at: Option<String>,
    /// Why: `too_large` (over 512 KiB), `invalid`, or `wrong_agent`.
    pub refused: Option<String>,
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
            truncated: host.truncated,
            refused_at: host
                .refused
                .as_ref()
                .map(|(at, _)| at.to_rfc3339_opts(SecondsFormat::Millis, true)),
            refused: host.refused.map(|(_, code)| code),
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

/// One host listening on a port (once per bound address).
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct PortHostView {
    /// Agent id.
    pub agent_id: String,
    /// Hostname, when known.
    pub hostname: Option<String>,
    /// The bound address.
    pub address: String,
    /// Bound to a non-loopback address.
    pub exposed: bool,
    /// The owning unit, when the agent saw it.
    pub service: Option<String>,
    /// The owning program, when the agent saw it.
    pub program: Option<String>,
    /// Last contact (RFC 3339).
    pub last_seen_at: Option<String>,
}

/// One port across the caller's hosts: a page of the hosts listening on it.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct PortDetail {
    /// `tcp` or `udp`.
    pub protocol: String,
    /// The port.
    pub port: i32,
    /// Hosts on this page, by hostname.
    pub hosts: Vec<PortHostView>,
    /// Opaque cursor for the next page of hosts.
    pub next_cursor: Option<String>,
}

/// One host running a unit.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct UnitHostView {
    /// Agent id.
    pub agent_id: String,
    /// Hostname, when known.
    pub hostname: Option<String>,
    /// The unit's programs there, sorted.
    pub programs: Vec<String>,
    /// How many processes it runs there.
    pub processes: i32,
    /// The user it runs as there.
    pub run_as: Option<String>,
    /// Last contact (RFC 3339).
    pub last_seen_at: Option<String>,
}

/// One service unit across the caller's hosts: a page of the hosts
/// running it.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct UnitDetail {
    /// The systemd unit.
    pub unit: String,
    /// Hosts on this page, by hostname.
    pub hosts: Vec<UnitHostView>,
    /// Opaque cursor for the next page of hosts.
    pub next_cursor: Option<String>,
}

/// Paging for the hosts of one port or unit.
#[derive(Debug, Deserialize, IntoParams)]
#[serde(deny_unknown_fields)]
pub(crate) struct HostsParams {
    /// Opaque continuation cursor.
    cursor: Option<String>,
    /// Page size from 1 to 100 (default 50).
    limit: Option<u16>,
}

fn invalid((code, title): crate::software::Invalid) -> Response {
    problem_response(ProblemDetails::new(StatusCode::BAD_REQUEST, code, title))
}

fn rfc3339(at: Option<chrono::DateTime<chrono::Utc>>) -> Option<String> {
    at.map(|at| at.to_rfc3339_opts(SecondsFormat::Millis, true))
}

/// The page size and the decoded cursor, or why the query is refused.
fn paging<T: for<'de> Deserialize<'de>>(
    params: Result<Query<HostsParams>, QueryRejection>,
) -> Result<(i64, Option<T>), crate::software::Invalid> {
    let Ok(Query(params)) = params else {
        return Err(("invalid_query", "Query is invalid"));
    };
    let limit = crate::software::limit(params.limit)?;
    let after = crate::software::decode::<T>(params.cursor.as_deref())?;
    Ok((limit, after))
}

/// The page, cut to `limit`, and whether more follow.
fn page<T>(mut rows: Vec<T>, limit: i64) -> (Vec<T>, bool) {
    let limit = usize::try_from(limit).unwrap_or(usize::MAX);
    let more = rows.len() > limit;
    rows.truncate(limit);
    (rows, more)
}

#[utoipa::path(get, path = "/api/v1/ports/{protocol}/{port}", tag = "assets",
    params(("protocol" = String, Path, description = "`tcp` or `udp`"), ("port" = u16, Path), HostsParams),
    responses((status = 200, description = "A page of the caller's hosts listening on the port", body = crate::ports::PortDetail),
        (status = 400, description = "Invalid protocol, port, query or cursor", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "Authentication required", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Permission denied", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No visible host listens on it", body = crate::ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn get_port(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path((protocol, port)): Path<(String, String)>,
    params: Result<Query<HostsParams>, QueryRejection>,
) -> Response {
    let (scope, _) =
        match authenticated_permission(&state, &headers, Permission::AgentsRead, false).await {
            Ok(context) => context,
            Err(response) => return response,
        };
    let port = match port.parse::<u16>() {
        Ok(port) if port > 0 && (protocol == "tcp" || protocol == "udp") => i32::from(port),
        _ => {
            return invalid((
                "invalid_port",
                "protocol must be tcp or udp, port 1 to 65535",
            ));
        }
    };
    let (limit, after) = match paging::<(String, String, String)>(params) {
        Ok(paging) => paging,
        Err(refused) => return invalid(refused),
    };
    let Ok(client) = state.pool.get().await else {
        return unavailable_auth();
    };
    let after = after
        .as_ref()
        .map(|(host, agent, address)| (host.as_str(), agent.as_str(), address.as_str()));
    match store::port_hosts(&client, &scope, &protocol, port, after, limit + 1).await {
        Ok(rows) if rows.is_empty() && after.is_none() => problem_response(
            ProblemDetails::not_found("port_not_found", "No host listens on this port"),
        ),
        Ok(rows) => {
            let (rows, more) = page(rows, limit);
            let next_cursor = more
                .then(|| {
                    rows.last().map(|h| {
                        crate::software::encode(&(
                            h.hostname.as_deref().unwrap_or(""),
                            &h.agent_id,
                            h.address.to_string(),
                        ))
                    })
                })
                .flatten();
            Json(PortDetail {
                protocol,
                port,
                hosts: rows
                    .into_iter()
                    .map(|h| PortHostView {
                        agent_id: h.agent_id,
                        hostname: h.hostname,
                        address: h.address.to_string(),
                        exposed: h.exposed,
                        service: h.service,
                        program: h.program,
                        last_seen_at: rfc3339(h.last_seen_at),
                    })
                    .collect(),
                next_cursor,
            })
            .into_response()
        }
        Err(_) => unavailable_auth(),
    }
}

#[utoipa::path(get, path = "/api/v1/services/{unit}", tag = "assets",
    params(("unit" = String, Path), HostsParams),
    responses((status = 200, description = "A page of the caller's hosts running the unit", body = crate::ports::UnitDetail),
        (status = 400, description = "Invalid query or cursor", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "Authentication required", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Permission denied", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No visible host runs it", body = crate::ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn get_unit(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path(unit): Path<String>,
    params: Result<Query<HostsParams>, QueryRejection>,
) -> Response {
    let (scope, _) =
        match authenticated_permission(&state, &headers, Permission::AgentsRead, false).await {
            Ok(context) => context,
            Err(response) => return response,
        };
    let (limit, after) = match paging::<(String, String)>(params) {
        Ok(paging) => paging,
        Err(refused) => return invalid(refused),
    };
    let Ok(client) = state.pool.get().await else {
        return unavailable_auth();
    };
    let after = after
        .as_ref()
        .map(|(host, agent)| (host.as_str(), agent.as_str()));
    match store::unit_hosts(&client, &scope, &unit, after, limit + 1).await {
        Ok(rows) if rows.is_empty() && after.is_none() => problem_response(
            ProblemDetails::not_found("service_not_found", "No host runs this service"),
        ),
        Ok(rows) => {
            let (rows, more) = page(rows, limit);
            let next_cursor = more
                .then(|| {
                    rows.last().map(|h| {
                        crate::software::encode(&(h.hostname.as_deref().unwrap_or(""), &h.agent_id))
                    })
                })
                .flatten();
            Json(UnitDetail {
                unit,
                hosts: rows
                    .into_iter()
                    .map(|h| UnitHostView {
                        agent_id: h.agent_id,
                        hostname: h.hostname,
                        programs: h.programs,
                        processes: h.processes,
                        run_as: h.run_as,
                        last_seen_at: rfc3339(h.last_seen_at),
                    })
                    .collect(),
                next_cursor,
            })
            .into_response()
        }
        Err(_) => unavailable_auth(),
    }
}
