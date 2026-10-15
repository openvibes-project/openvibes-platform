//! The About page: what is running, and whether a newer release exists.
//!
//! `GET /api/v1/about` reports versions the platform already knows and is
//! readable by every signed-in user. `GET /api/v1/about/update` asks the
//! project's latest GitHub release (from the server: the browser's CSP
//! allows only same-origin requests) and never fails the page: any problem
//! is reported as `unavailable`. It is a separate route so the page does not
//! wait on the network.

use std::{
    sync::OnceLock,
    time::{Duration, Instant},
};

use axum::{
    Json,
    extract::State,
    http::{HeaderMap, HeaderValue, header},
    response::{IntoResponse, Response},
};
use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use utoipa::ToSchema;

use crate::{
    ProblemDetails,
    access::guard::{session_user, unavailable_auth},
    http::AuthHttpState,
};

const LATEST_RELEASE_URL: &str =
    "https://api.github.com/repos/openvibes-project/openvibes-platform/releases/latest";
const RELEASE_PAGE_PREFIX: &str = "https://github.com/openvibes-project/openvibes-platform/";
// The agent is released on its own: a platform and an agent may both be
// the latest of their kind at different versions.
const AGENT_RELEASE_URL: &str =
    "https://api.github.com/repos/openvibes-project/openvibes-agent/releases/latest";
const AGENT_RELEASE_PAGE_PREFIX: &str = "https://github.com/openvibes-project/openvibes-agent/";
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
    /// Operating system and CPU architecture the console runs on.
    pub platform: String,
    /// When this console process started.
    pub started_at: String,
    /// Agents by state.
    pub fleet: AboutFleet,
    /// The CA certificates the platform issues under.
    pub certificates: Vec<AboutCertificate>,
    /// Vulnerability feeds and when they last updated.
    pub feeds: Vec<AboutFeed>,
}

/// Agent counts for the About page.
#[derive(Clone, Debug, Default, Serialize, ToSchema)]
pub(crate) struct AboutFleet {
    /// Active agents (enrolled and not revoked).
    pub active: i64,
    /// Active agents that reported recently.
    pub online: i64,
    /// Revoked agents.
    pub revoked: i64,
    /// Newest agent version any active agent reports.
    pub newest_agent_version: Option<String>,
}

/// One CA certificate.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub(crate) struct AboutCertificate {
    /// `root` or `intermediate`.
    pub role: String,
    /// End of validity.
    pub not_after: String,
}

/// One vulnerability feed.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub(crate) struct AboutFeed {
    /// Feed name, e.g. `fedora-44-x86_64`.
    pub source: String,
    /// Advisories in the last good content.
    pub advisories: i32,
    /// Last check.
    pub last_checked_at: Option<String>,
    /// Last time the content changed.
    pub last_changed_at: Option<String>,
    /// Whether the last check failed.
    pub failing: bool,
}

fn time(at: DateTime<Utc>) -> String {
    at.to_rfc3339_opts(SecondsFormat::Secs, true)
}

static STARTED_AT: OnceLock<DateTime<Utc>> = OnceLock::new();

/// Records the process start; call once when the server is built.
pub(crate) fn mark_started() {
    STARTED_AT.get_or_init(Utc::now);
}

fn newest_version(versions: impl Iterator<Item = String>) -> Option<String> {
    versions.max_by_key(|v| parse_version(v).unwrap_or([0; 3]))
}

async fn fleet(client: &platform_store::Client, now: DateTime<Utc>) -> AboutFleet {
    let Ok(agents) =
        platform_store::agents::list(client, platform_store::agents::Filter::All, now).await
    else {
        return AboutFleet::default();
    };
    let window = chrono::Duration::minutes(platform_store::OFFLINE_AFTER_MINUTES);
    let active: Vec<_> = agents.iter().filter(|a| a.status == "active").collect();
    AboutFleet {
        active: i64::try_from(active.len()).unwrap_or(i64::MAX),
        online: i64::try_from(
            active
                .iter()
                .filter(|a| a.last_seen_at.is_some_and(|seen| seen >= now - window))
                .count(),
        )
        .unwrap_or(i64::MAX),
        revoked: i64::try_from(agents.iter().filter(|a| a.status == "revoked").count())
            .unwrap_or(i64::MAX),
        newest_agent_version: newest_version(
            active.iter().filter_map(|a| a.scanner_version.clone()),
        ),
    }
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
    /// Latest published agent release, without a leading `v`; agents older
    /// than it are behind.
    pub latest_agent_version: Option<String>,
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

/// Looks up the latest platform and agent releases at most once every few hours.
pub(crate) struct UpdateChecker {
    platform: ReleaseFeed,
    agent: ReleaseFeed,
}

impl UpdateChecker {
    pub(crate) fn new() -> Self {
        Self::with_urls(LATEST_RELEASE_URL, AGENT_RELEASE_URL)
    }

    fn with_urls(platform: &str, agent: &str) -> Self {
        Self {
            platform: ReleaseFeed::new(platform, RELEASE_PAGE_PREFIX),
            agent: ReleaseFeed::new(agent, AGENT_RELEASE_PAGE_PREFIX),
        }
    }

    async fn check(&self, current: &str) -> UpdateResponse {
        let (platform, agent) = tokio::join!(self.platform.latest(), self.agent.latest());
        UpdateResponse {
            latest_agent_version: agent.map(|latest| latest.version),
            ..classify(current, platform)
        }
    }
}

/// One repository's latest release, cached.
struct ReleaseFeed {
    url: String,
    prefix: &'static str,
    agent: ureq::Agent,
    cache: Mutex<Option<(Instant, Option<Latest>)>>,
}

impl ReleaseFeed {
    fn new(url: &str, prefix: &'static str) -> Self {
        let config = ureq::Agent::config_builder()
            .timeout_global(Some(FETCH_TIMEOUT))
            .max_redirects(0)
            .build();
        Self {
            url: url.to_owned(),
            prefix,
            agent: config.into(),
            cache: Mutex::new(None),
        }
    }

    async fn latest(&self) -> Option<Latest> {
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
            let prefix = self.prefix;
            let latest = tokio::task::spawn_blocking(move || fetch_latest(&agent, &url, prefix))
                .await
                .ok()
                .flatten();
            *cache = Some((Instant::now(), latest));
        }
        cache.as_ref().and_then(|(_, latest)| latest.clone())
    }
}

fn fetch_latest(agent: &ureq::Agent, url: &str, prefix: &str) -> Option<Latest> {
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
    parse_release(&bytes, prefix)
}

fn parse_release(bytes: &[u8], prefix: &str) -> Option<Latest> {
    let release: ReleaseJson = serde_json::from_slice(bytes).ok()?;
    if release.draft || release.prerelease {
        return None;
    }
    let version = release
        .tag_name
        .strip_prefix('v')
        .unwrap_or(&release.tag_name);
    parse_version(version)?;
    // Only ever link into the expected repository.
    release.html_url.starts_with(prefix).then(|| Latest {
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
        latest_agent_version: None,
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
        latest_agent_version: None,
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
    let now = Utc::now();
    let fleet = fleet(&client, now).await;
    let certificates = platform_store::ca::list(&client)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|c| AboutCertificate {
            role: c.role,
            not_after: time(c.not_after),
        })
        .collect();
    let feeds = platform_store::vulns::feeds(&client)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|f| AboutFeed {
            source: f.source,
            advisories: f.advisories,
            last_checked_at: f.last_checked_at.map(time),
            last_changed_at: f.last_changed_at.map(time),
            failing: f.last_error.is_some(),
        })
        .collect();
    no_store(Json(AboutResponse {
        platform_version: env!("CARGO_PKG_VERSION").to_owned(),
        schema_version: platform_store::SCHEMA_VERSION,
        applied_schema_version,
        database_version,
        web_ui_embedded: cfg!(feature = "embedded-ui"),
        platform: format!("{} {}", std::env::consts::OS, std::env::consts::ARCH),
        started_at: time(*STARTED_AT.get_or_init(Utc::now)),
        fleet,
        certificates,
        feeds,
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
            latest_agent_version: None,
        },
    };
    no_store(Json(body))
}

#[cfg(test)]
#[path = "about_tests.rs"]
mod tests;
