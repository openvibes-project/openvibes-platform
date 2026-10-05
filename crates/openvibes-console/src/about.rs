//! The About page: what is running, and whether a newer release exists.
//!
//! `GET /api/v1/about` reports versions the platform already knows and is
//! readable by every signed-in user. `GET /api/v1/about/update` asks the
//! project's latest GitHub release (from the server: the browser's CSP
//! allows only same-origin requests) and never fails the page: any problem
//! is reported as `unavailable`. It is a separate route so the page does not
//! wait on the network.

use std::time::{Duration, Instant};

use axum::{
    Json,
    extract::State,
    http::{HeaderMap, HeaderValue, header},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use utoipa::ToSchema;

use crate::{
    ProblemDetails,
    router::{AuthHttpState, session_user, unavailable_auth},
};

const LATEST_RELEASE_URL: &str =
    "https://api.github.com/repos/openvibes-project/openvibes-platform/releases/latest";
const RELEASE_PAGE_PREFIX: &str = "https://github.com/openvibes-project/openvibes-platform/";
const FETCH_TIMEOUT: Duration = Duration::from_secs(4);
const MAX_RESPONSE_BYTES: u64 = 1024 * 1024;
const FOUND_TTL: Duration = Duration::from_secs(6 * 60 * 60);
const FAILED_TTL: Duration = Duration::from_secs(15 * 60);

/// Versions of the running platform.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub(crate) struct AboutResponse {
    /// Platform release this console belongs to.
    pub platform_version: String,
    /// Database schema version the platform requires.
    pub schema_version: i32,
    /// Database schema version actually applied.
    pub applied_schema_version: Option<i32>,
    /// PostgreSQL server version, when the database reports one.
    pub database_version: Option<String>,
    /// Whether this console serves its web UI from the same build.
    pub web_ui_embedded: bool,
}

/// Outcome of comparing against the latest published release.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum UpdateState {
    /// The check is turned off in the console configuration.
    Disabled,
    /// The latest release could not be determined (offline or unexpected reply).
    Unavailable,
    /// This platform is at or ahead of the latest release.
    UpToDate,
    /// A newer release is published.
    Available,
}

/// Result of the newer-version check.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub(crate) struct UpdateResponse {
    /// Outcome of the check.
    pub state: UpdateState,
    /// Latest published release, without a leading `v`.
    pub latest_version: Option<String>,
    /// Page of the latest release.
    pub release_url: Option<String>,
}

#[derive(Clone, Debug)]
struct Latest {
    version: String,
    url: String,
}

#[derive(Deserialize)]
struct ReleaseJson {
    tag_name: String,
    html_url: String,
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    prerelease: bool,
}

/// Looks up the latest release at most once every few hours.
pub(crate) struct UpdateChecker {
    url: String,
    agent: ureq::Agent,
    cache: Mutex<Option<(Instant, Option<Latest>)>>,
}

impl UpdateChecker {
    pub(crate) fn new() -> Self {
        Self::with_url(LATEST_RELEASE_URL)
    }

    fn with_url(url: &str) -> Self {
        let config = ureq::Agent::config_builder()
            .timeout_global(Some(FETCH_TIMEOUT))
            .max_redirects(0)
            .build();
        Self {
            url: url.to_owned(),
            agent: config.into(),
            cache: Mutex::new(None),
        }
    }

    async fn check(&self, current: &str) -> UpdateResponse {
        // Held across the fetch so concurrent page loads share one request.
        let mut cache = self.cache.lock().await;
        let fresh = cache.as_ref().is_some_and(|(at, latest)| {
            at.elapsed()
                < if latest.is_some() {
                    FOUND_TTL
                } else {
                    FAILED_TTL
                }
        });
        if !fresh {
            let agent = self.agent.clone();
            let url = self.url.clone();
            let latest = tokio::task::spawn_blocking(move || fetch_latest(&agent, &url))
                .await
                .ok()
                .flatten();
            *cache = Some((Instant::now(), latest));
        }
        let latest = cache.as_ref().and_then(|(_, latest)| latest.clone());
        classify(current, latest)
    }
}

fn fetch_latest(agent: &ureq::Agent, url: &str) -> Option<Latest> {
    let mut response = agent
        .get(url)
        .header("Accept", "application/vnd.github+json")
        .header(
            "User-Agent",
            concat!("openvibes-console/", env!("CARGO_PKG_VERSION")),
        )
        .call()
        .ok()?;
    let bytes = response
        .body_mut()
        .with_config()
        .limit(MAX_RESPONSE_BYTES)
        .read_to_vec()
        .ok()?;
    parse_release(&bytes)
}

fn parse_release(bytes: &[u8]) -> Option<Latest> {
    let release: ReleaseJson = serde_json::from_slice(bytes).ok()?;
    if release.draft || release.prerelease {
        return None;
    }
    let version = release
        .tag_name
        .strip_prefix('v')
        .unwrap_or(&release.tag_name);
    parse_version(version)?;
    // Only ever link into this project's own repository.
    release
        .html_url
        .starts_with(RELEASE_PAGE_PREFIX)
        .then(|| Latest {
            version: version.to_owned(),
            url: release.html_url,
        })
}

/// `major.minor.patch` of plain numbers; anything else is not comparable.
fn parse_version(raw: &str) -> Option<[u64; 3]> {
    let mut parts = raw.split('.');
    let mut out = [0u64; 3];
    for slot in &mut out {
        let part = parts.next()?;
        if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        *slot = part.parse().ok()?;
    }
    parts.next().is_none().then_some(out)
}

fn classify(current: &str, latest: Option<Latest>) -> UpdateResponse {
    let unavailable = UpdateResponse {
        state: UpdateState::Unavailable,
        latest_version: None,
        release_url: None,
    };
    let Some(latest) = latest else {
        return unavailable;
    };
    let (Some(running), Some(published)) = (parse_version(current), parse_version(&latest.version))
    else {
        return unavailable;
    };
    UpdateResponse {
        state: if published > running {
            UpdateState::Available
        } else {
            UpdateState::UpToDate
        },
        latest_version: Some(latest.version),
        release_url: Some(latest.url),
    }
}

fn no_store(response: impl IntoResponse) -> Response {
    let mut response = response.into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

#[utoipa::path(get, path = "/api/v1/about", tag = "about",
    responses(
        (status = 200, description = "Versions of the running platform", body = AboutResponse),
        (status = 401, description = "Authentication required", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Bearer tokens are refused", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Unavailable", body = ProblemDetails, content_type = "application/problem+json")
    ))]
pub(crate) async fn about(State(state): State<AuthHttpState>, headers: HeaderMap) -> Response {
    if let Err(response) = session_user(&state, &headers, false).await {
        return response;
    }
    let Ok(client) = state.pool.get().await else {
        return unavailable_auth();
    };
    let applied_schema_version = platform_store::schema_version(&client).await.ok().flatten();
    let database_version = client
        .query_one("SHOW server_version", &[])
        .await
        .ok()
        .and_then(|row| row.try_get::<_, String>(0).ok());
    no_store(Json(AboutResponse {
        platform_version: env!("CARGO_PKG_VERSION").to_owned(),
        schema_version: platform_store::SCHEMA_VERSION,
        applied_schema_version,
        database_version,
        web_ui_embedded: cfg!(feature = "embedded-ui"),
    }))
}

#[utoipa::path(get, path = "/api/v1/about/update", tag = "about",
    responses(
        (status = 200, description = "Whether a newer release is published; never an error for network problems", body = UpdateResponse),
        (status = 401, description = "Authentication required", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Bearer tokens are refused", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Unavailable", body = ProblemDetails, content_type = "application/problem+json")
    ))]
pub(crate) async fn about_update(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = session_user(&state, &headers, false).await {
        return response;
    }
    let body = match state.update_checker.as_ref() {
        Some(checker) => checker.check(env!("CARGO_PKG_VERSION")).await,
        None => UpdateResponse {
            state: UpdateState::Disabled,
            latest_version: None,
            release_url: None,
        },
    };
    no_store(Json(body))
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Read, Write},
        net::TcpListener,
    };

    use super::*;

    fn release(tag: &str) -> Vec<u8> {
        format!(
            r#"{{"tag_name":"{tag}","html_url":"{RELEASE_PAGE_PREFIX}releases/tag/{tag}","draft":false,"prerelease":false,"assets":[]}}"#
        )
        .into_bytes()
    }

    #[test]
    fn parses_plain_versions_only() {
        assert_eq!(parse_version("0.2.4"), Some([0, 2, 4]));
        for bad in ["", "1.2", "1.2.3.4", "1.2.x", "1.2.3-rc1", "v1.2.3", "1..3"] {
            assert_eq!(parse_version(bad), None, "{bad}");
        }
    }

    #[test]
    fn compares_numerically() {
        let latest = |v: &str| parse_release(&release(v)).unwrap();
        assert_eq!(
            classify("0.2.4", Some(latest("v0.2.10"))).state,
            UpdateState::Available
        );
        assert_eq!(
            classify("0.2.4", Some(latest("v0.2.4"))).state,
            UpdateState::UpToDate
        );
        assert_eq!(
            classify("0.3.0", Some(latest("v0.2.9"))).state,
            UpdateState::UpToDate
        );
        assert_eq!(classify("0.2.4", None).state, UpdateState::Unavailable);
    }

    #[test]
    fn ignores_prereleases_foreign_links_and_junk() {
        let pre = br#"{"tag_name":"v9.9.9","html_url":"https://github.com/openvibes-project/openvibes-platform/x","prerelease":true}"#;
        assert!(parse_release(pre).is_none());
        let foreign = br#"{"tag_name":"v9.9.9","html_url":"https://evil.example/x"}"#;
        assert!(parse_release(foreign).is_none());
        assert!(parse_release(b"not json").is_none());
        assert!(parse_release(br#"{"tag_name":"nightly","html_url":"https://github.com/openvibes-project/openvibes-platform/x"}"#).is_none());
    }

    fn serve_once(body: Vec<u8>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/latest", listener.local_addr().unwrap());
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut request = [0u8; 2048];
                let _ = stream.read(&mut request);
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(head.as_bytes());
                let _ = stream.write_all(&body);
            }
        });
        url
    }

    #[tokio::test]
    async fn fetches_once_then_serves_from_cache() {
        let checker = UpdateChecker::with_url(&serve_once(release("v0.9.0")));
        let first = checker.check("0.2.4").await;
        assert_eq!(first.state, UpdateState::Available);
        assert_eq!(first.latest_version.as_deref(), Some("0.9.0"));
        // The server above answered once and is gone; this must be cached.
        assert_eq!(checker.check("0.2.4").await.state, UpdateState::Available);
    }

    #[tokio::test]
    async fn offline_is_unavailable_not_an_error() {
        let unused = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/latest", unused.local_addr().unwrap());
        drop(unused);
        let checker = UpdateChecker::with_url(&url);
        let result = checker.check("0.2.4").await;
        assert_eq!(result.state, UpdateState::Unavailable);
        assert!(result.latest_version.is_none());
    }
}
