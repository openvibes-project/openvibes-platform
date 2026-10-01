//! Installed software over `/api/v1` (assets v1): one host's packages,
//! the fleet's software, and one package's versions and hosts. Reads need
//! `agents.read` and are scoped to the caller's agents: counts include only
//! visible hosts, and a host or package no visible host has is a 404.

use axum::{
    Json,
    extract::{Path, Query, State, rejection::QueryRejection},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::SecondsFormat;
use platform_store::console_inventory::{
    self as store, HostPackage, Software, SoftwareFilters, SoftwareHost, SoftwareVersion,
};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use crate::{
    Permission, ProblemDetails,
    problem::problem_response,
    router::{AuthHttpState, authenticated_permission, unavailable_auth},
};

/// Longest name filter, in bytes.
const MAX_QUERY: usize = 128;

/// One installed package version on a host.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct HostPackageView {
    /// Package manager (`rpm`, `dpkg`).
    pub manager: String,
    /// Package name.
    pub name: String,
    /// Epoch (0 when none).
    pub epoch: i32,
    /// Version.
    pub version: String,
    /// Release (empty for dpkg).
    pub release: String,
    /// Architecture.
    pub arch: String,
    /// The host has an open vulnerability with a fix on this package.
    pub fixable_vulnerable: bool,
}

/// A page of a host's packages, by name.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct HostPackagePage {
    /// Packages on this page.
    pub items: Vec<HostPackageView>,
    /// Opaque cursor for the next page.
    pub next_cursor: Option<String>,
}

/// One package across the caller's visible hosts.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct SoftwareView {
    /// Package manager.
    pub manager: String,
    /// Package name.
    pub name: String,
    /// Visible hosts with any version of it.
    pub hosts: i64,
    /// Distinct versions in use.
    pub versions: i64,
    /// Visible hosts where it has an open vulnerability with a fix.
    pub fixable_vulnerable_hosts: i64,
}

/// A page of the fleet's software, by name.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct SoftwarePage {
    /// Packages on this page.
    pub items: Vec<SoftwareView>,
    /// Opaque cursor for the next page.
    pub next_cursor: Option<String>,
}

/// One version of a package in use.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct SoftwareVersionView {
    /// Epoch.
    pub epoch: i32,
    /// Version.
    pub version: String,
    /// Release.
    pub release: String,
    /// Architecture.
    pub arch: String,
    /// Visible hosts with it.
    pub hosts: i64,
    /// Of those, hosts where it has an open vulnerability with a fix.
    pub fixable_vulnerable_hosts: i64,
}

/// One host that has the package.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct SoftwareHostView {
    /// Agent id.
    pub agent_id: String,
    /// Hostname, when known.
    pub hostname: Option<String>,
    /// The version it has (`epoch:version-release`).
    pub version: String,
    /// Architecture.
    pub arch: String,
    /// Last contact (RFC 3339).
    pub last_seen_at: Option<String>,
    /// It has an open vulnerability with a fix there.
    pub fixable_vulnerable: bool,
}

/// One package: its versions in use and, paged, its hosts.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct SoftwareDetail {
    /// Package manager.
    pub manager: String,
    /// Package name.
    pub name: String,
    /// Versions in use on visible hosts, most hosts first.
    pub versions: Vec<SoftwareVersionView>,
    /// Hosts on this page, by hostname.
    pub hosts: Vec<SoftwareHostView>,
    /// Opaque cursor for the next page of hosts.
    pub next_cursor: Option<String>,
}

/// Name filter and paging for a host's packages.
#[derive(Debug, Deserialize, IntoParams)]
#[serde(deny_unknown_fields)]
pub(crate) struct HostPackageParams {
    /// Case-insensitive substring of the name (at most 128 bytes).
    q: Option<String>,
    /// Opaque continuation cursor.
    cursor: Option<String>,
    /// Page size from 1 to 100 (default 50).
    limit: Option<u16>,
}

/// Filters and paging for the fleet's software.
#[derive(Debug, Deserialize, IntoParams)]
#[serde(deny_unknown_fields)]
pub(crate) struct SoftwareParams {
    /// Case-insensitive substring of the name (at most 128 bytes).
    q: Option<String>,
    /// Only packages with an open vulnerability with a fix on at least
    /// one visible host.
    fixable: Option<bool>,
    /// Opaque continuation cursor.
    cursor: Option<String>,
    /// Page size from 1 to 100 (default 50).
    limit: Option<u16>,
}

/// Paging for one package's hosts.
#[derive(Debug, Deserialize, IntoParams)]
#[serde(deny_unknown_fields)]
pub(crate) struct SoftwareDetailParams {
    /// Opaque continuation cursor.
    cursor: Option<String>,
    /// Page size from 1 to 100 (default 50).
    limit: Option<u16>,
}

fn bad(code: &'static str, title: &'static str) -> Response {
    problem_response(ProblemDetails::new(StatusCode::BAD_REQUEST, code, title))
}

fn limit(limit: Option<u16>) -> Result<i64, Response> {
    match limit.unwrap_or(50) {
        limit @ 1..=100 => Ok(i64::from(limit)),
        _ => Err(bad("invalid_query", "limit must be 1 to 100")),
    }
}

fn query(q: Option<String>) -> Result<Option<String>, Response> {
    match q {
        Some(q) if q.len() > MAX_QUERY || q.contains('\0') => {
            Err(bad("invalid_query", "q must be at most 128 bytes"))
        }
        Some(q) if q.is_empty() => Ok(None),
        q => Ok(q),
    }
}

/// Cursors are base64url JSON arrays of the keyset values.
fn encode<T: Serialize>(key: &T) -> String {
    URL_SAFE_NO_PAD.encode(serde_json::to_vec(key).unwrap_or_default())
}

fn decode<T: for<'de> Deserialize<'de>>(cursor: Option<&str>) -> Result<Option<T>, Response> {
    cursor
        .map(|text| {
            URL_SAFE_NO_PAD
                .decode(text)
                .ok()
                .and_then(|bytes| serde_json::from_slice(&bytes).ok())
                .ok_or_else(|| bad("invalid_cursor", "cursor is invalid"))
        })
        .transpose()
}

fn package_view(package: HostPackage) -> HostPackageView {
    HostPackageView {
        manager: package.manager,
        name: package.name,
        epoch: package.epoch,
        version: package.version,
        release: package.release,
        arch: package.arch,
        fixable_vulnerable: package.fixable_vulnerable,
    }
}

fn software_view(software: Software) -> SoftwareView {
    SoftwareView {
        manager: software.manager,
        name: software.name,
        hosts: software.hosts,
        versions: software.versions,
        fixable_vulnerable_hosts: software.fixable_vulnerable_hosts,
    }
}

fn version_view(version: SoftwareVersion) -> SoftwareVersionView {
    SoftwareVersionView {
        epoch: version.epoch,
        version: version.version,
        release: version.release,
        arch: version.arch,
        hosts: version.hosts,
        fixable_vulnerable_hosts: version.fixable_vulnerable_hosts,
    }
}

fn host_view(host: SoftwareHost) -> SoftwareHostView {
    SoftwareHostView {
        agent_id: host.agent_id,
        hostname: host.hostname,
        version: host.version,
        arch: host.arch,
        last_seen_at: host
            .last_seen_at
            .map(|at| at.to_rfc3339_opts(SecondsFormat::Millis, true)),
        fixable_vulnerable: host.fixable_vulnerable,
    }
}

#[utoipa::path(get, path = "/api/v1/agents/{agent_id}/packages", tag = "software",
    params(("agent_id" = String, Path), HostPackageParams),
    responses((status = 200, description = "The host's installed packages, by name", body = crate::software::HostPackagePage),
        (status = 400, description = "Invalid query or cursor", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "Authentication required", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Permission denied", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "Absent or outside the caller's scope", body = crate::ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn list_host_packages(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path(agent_id): Path<String>,
    params: Result<Query<HostPackageParams>, QueryRejection>,
) -> Response {
    let (scope, _) =
        match authenticated_permission(&state, &headers, Permission::AgentsRead, false).await {
            Ok(context) => context,
            Err(response) => return response,
        };
    let Ok(Query(params)) = params else {
        return bad("invalid_query", "Package query is invalid");
    };
    let (q, limit, after) = match (
        query(params.q),
        limit(params.limit),
        decode::<(String, i64)>(params.cursor.as_deref()),
    ) {
        (Ok(q), Ok(limit), Ok(after)) => (q, limit, after),
        (Err(response), _, _) | (_, Err(response), _) | (_, _, Err(response)) => return response,
    };
    let Ok(client) = state.pool.get().await else {
        return unavailable_auth();
    };
    let after = after.as_ref().map(|(name, id)| (name.as_str(), *id));
    match store::host_packages(&client, &scope, &agent_id, q.as_deref(), after, limit + 1).await {
        Ok(Some(mut rows)) => {
            let more = rows.len() > usize::try_from(limit).unwrap_or(usize::MAX);
            rows.truncate(usize::try_from(limit).unwrap_or(usize::MAX));
            let next_cursor = more
                .then(|| rows.last().map(|(id, p)| encode(&(&p.name, id))))
                .flatten();
            Json(HostPackagePage {
                items: rows.into_iter().map(|(_, p)| package_view(p)).collect(),
                next_cursor,
            })
            .into_response()
        }
        Ok(None) => problem_response(ProblemDetails::not_found(
            "agent_not_found",
            "Agent not found",
        )),
        Err(_) => unavailable_auth(),
    }
}

#[utoipa::path(get, path = "/api/v1/software", tag = "software", params(SoftwareParams),
    responses((status = 200, description = "Packages across the caller's visible hosts, by name", body = crate::software::SoftwarePage),
        (status = 400, description = "Invalid query or cursor", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "Authentication required", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Permission denied", body = crate::ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn list_software(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    params: Result<Query<SoftwareParams>, QueryRejection>,
) -> Response {
    let (scope, _) =
        match authenticated_permission(&state, &headers, Permission::AgentsRead, false).await {
            Ok(context) => context,
            Err(response) => return response,
        };
    let Ok(Query(params)) = params else {
        return bad("invalid_query", "Software query is invalid");
    };
    let (q, limit, after) = match (
        query(params.q),
        limit(params.limit),
        decode::<(String, String)>(params.cursor.as_deref()),
    ) {
        (Ok(q), Ok(limit), Ok(after)) => (q, limit, after),
        (Err(response), _, _) | (_, Err(response), _) | (_, _, Err(response)) => return response,
    };
    let filters = SoftwareFilters {
        q,
        fixable: params.fixable.unwrap_or(false),
    };
    let Ok(client) = state.pool.get().await else {
        return unavailable_auth();
    };
    let after = after
        .as_ref()
        .map(|(name, manager)| (name.as_str(), manager.as_str()));
    match store::software(&client, &scope, &filters, after, limit + 1).await {
        Ok(mut rows) => {
            let more = rows.len() > usize::try_from(limit).unwrap_or(usize::MAX);
            rows.truncate(usize::try_from(limit).unwrap_or(usize::MAX));
            let next_cursor = more
                .then(|| rows.last().map(|s| encode(&(&s.name, &s.manager))))
                .flatten();
            Json(SoftwarePage {
                items: rows.into_iter().map(software_view).collect(),
                next_cursor,
            })
            .into_response()
        }
        Err(_) => unavailable_auth(),
    }
}

#[utoipa::path(get, path = "/api/v1/software/{manager}/{name}", tag = "software",
    params(("manager" = String, Path), ("name" = String, Path), SoftwareDetailParams),
    responses((status = 200, description = "The package's versions in use and a page of its hosts", body = crate::software::SoftwareDetail),
        (status = 400, description = "Invalid cursor", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "Authentication required", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Permission denied", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No visible host has it", body = crate::ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn get_software(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path((manager, name)): Path<(String, String)>,
    params: Result<Query<SoftwareDetailParams>, QueryRejection>,
) -> Response {
    let (scope, _) =
        match authenticated_permission(&state, &headers, Permission::AgentsRead, false).await {
            Ok(context) => context,
            Err(response) => return response,
        };
    let Ok(Query(params)) = params else {
        return bad("invalid_query", "Software query is invalid");
    };
    let (limit, after) = match (
        limit(params.limit),
        decode::<(String, String, i64)>(params.cursor.as_deref()),
    ) {
        (Ok(limit), Ok(after)) => (limit, after),
        (Err(response), _) | (_, Err(response)) => return response,
    };
    let not_found = || {
        problem_response(ProblemDetails::not_found(
            "software_not_found",
            "Software not found",
        ))
    };
    let Ok(client) = state.pool.get().await else {
        return unavailable_auth();
    };
    let versions = match store::software_versions(&client, &scope, &manager, &name).await {
        Ok(versions) if versions.is_empty() => return not_found(),
        Ok(versions) => versions,
        Err(_) => return unavailable_auth(),
    };
    let after = after
        .as_ref()
        .map(|(host, agent, id)| (host.as_str(), agent.as_str(), *id));
    match store::software_hosts(&client, &scope, &manager, &name, after, limit + 1).await {
        Ok(mut rows) => {
            let more = rows.len() > usize::try_from(limit).unwrap_or(usize::MAX);
            rows.truncate(usize::try_from(limit).unwrap_or(usize::MAX));
            let next_cursor = more
                .then(|| {
                    rows.last().map(|(id, h)| {
                        encode(&(h.hostname.as_deref().unwrap_or(""), &h.agent_id, id))
                    })
                })
                .flatten();
            Json(SoftwareDetail {
                manager,
                name,
                versions: versions.into_iter().map(version_view).collect(),
                hosts: rows.into_iter().map(|(_, h)| host_view(h)).collect(),
                next_cursor,
            })
            .into_response()
        }
        Err(_) => unavailable_auth(),
    }
}
