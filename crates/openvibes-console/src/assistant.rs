use std::{collections::HashMap, sync::Arc, time::Duration};

use platform_assistant::{
    Area, Assistant, BackendClient, BackendError, Location, Lookup, LookupError, LookupOutput,
    LookupRunner, ResolvedMode, Segment, StoreLookups,
};
use platform_store::{Pool, StoreError, assistant::AgentScope, console_read};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::{Mutex, OwnedSemaphorePermit, RwLock, Semaphore};
use utoipa::ToSchema;

use crate::ConsoleError;

#[derive(Clone)]
pub(crate) struct AssistantRuntime {
    pub(crate) assistant: Arc<Assistant>,
    pub(crate) backend: Arc<BackendClient>,
    pub(crate) mode: Arc<RwLock<Option<ResolvedMode>>>,
    pub(crate) available: Arc<RwLock<bool>>,
    pub(crate) concurrency: Arc<Semaphore>,
    principal_slots: Arc<Mutex<HashMap<String, Arc<Semaphore>>>>,
}

impl AssistantRuntime {
    pub(crate) fn new(mut assistant: Assistant) -> Result<Option<Self>, ConsoleError> {
        if !assistant.enabled {
            return Ok(None);
        }
        assistant.max_lookups = assistant.max_lookups.min(6);
        let backend = assistant
            .backend
            .clone()
            .filter(|backend| backend.location != Location::External)
            .ok_or(ConsoleError::Config)?;
        let backend = Arc::new(BackendClient::new(&backend).map_err(|_| ConsoleError::Config)?);
        let capacity = assistant
            .backend
            .as_ref()
            .map_or(1, |backend| semaphore_capacity(backend.concurrency));
        let runtime = Self {
            assistant: Arc::new(assistant),
            backend,
            mode: Arc::new(RwLock::new(None)),
            available: Arc::new(RwLock::new(false)),
            concurrency: Arc::new(Semaphore::new(capacity)),
            principal_slots: Arc::new(Mutex::new(HashMap::new())),
        };
        runtime.start_probe_loop();
        Ok(Some(runtime))
    }

    fn start_probe_loop(&self) {
        let backend = self.backend.clone();
        let mode = self.mode.clone();
        let available = self.available.clone();
        let configured = self.assistant.lookup_mode;
        tokio::spawn(async move {
            for attempt in 0u32.. {
                let client = backend.clone();
                let report = tokio::task::spawn_blocking(move || {
                    platform_assistant::probe(&client, configured)
                })
                .await
                .ok();
                if let Some(report) = report {
                    let ready = report.models.is_ok() && !report.configured_mode_failed;
                    *mode.write().await = Some(report.selected);
                    *available.write().await = ready;
                    if ready {
                        return;
                    }
                    let error = report.models.as_ref().err().copied();
                    tokio::time::sleep(probe_retry(error, attempt)).await;
                } else {
                    *available.write().await = false;
                    tokio::time::sleep(probe_retry(None, attempt)).await;
                }
            }
        });
    }

    pub(crate) async fn principal_slot(&self, principal_id: &str) -> Arc<Semaphore> {
        let mut slots = self.principal_slots.lock().await;
        slots
            .entry(principal_id.to_owned())
            .or_insert_with(|| Arc::new(Semaphore::new(1)))
            .clone()
    }
}

/// When to probe again. Not reachable or timed out (still starting or
/// loading its model, as after `assistant-setup`): every 10 s for the
/// first minute. Otherwise, and
/// after that: a probe is costly and, through openvibes-llm's socket, loads
/// the model (or retries a model that cannot start), so wait longer than
/// its idle time (5 min by default): the probe alone never keeps it loaded.
fn probe_retry(models_error: Option<BackendError>, attempt: u32) -> Duration {
    let starting = matches!(
        models_error,
        Some(BackendError::Connect | BackendError::Timeout)
    );
    if starting && attempt < 6 {
        Duration::from_secs(10)
    } else {
        Duration::from_secs(15 * 60)
    }
}

fn semaphore_capacity(configured: u32) -> usize {
    configured.max(1) as usize
}

#[cfg(test)]
mod tests {
    use super::{probe_retry, semaphore_capacity};

    #[test]
    fn a_failed_probe_waits_longer_than_the_model_servers_idle_time() {
        // openvibes-llm unloads after 5 min idle by default: retrying a
        // probe that reaches the model sooner would keep it loaded.
        use platform_assistant::BackendError as E;
        let idle = std::time::Duration::from_secs(300);
        let fast = std::time::Duration::from_secs(10);
        // Unreachable, or timed out during a long cold load: fast for a minute.
        for error in [E::Connect, E::Timeout] {
            assert_eq!(probe_retry(Some(error), 0), fast, "{error:?}");
            assert_eq!(probe_retry(Some(error), 5), fast, "{error:?}");
            assert!(probe_retry(Some(error), 6) > idle, "{error:?}");
        }
        // Answered but failed (models listed, or another error): slow.
        for error in [None, Some(E::Unauthorized), Some(E::Unavailable)] {
            assert!(probe_retry(error, 0) > idle, "{error:?}");
        }
    }

    #[test]
    fn assistant_capacity_never_disables_all_requests() {
        assert_eq!(semaphore_capacity(0), 1);
        assert_eq!(semaphore_capacity(4), 4);
    }
}

/// Keeps request capacity held if the HTTP future is dropped while a
/// `spawn_blocking` model request is still draining.
pub(crate) struct LeasedChatBackend {
    backend: Arc<BackendClient>,
    _user_permit: OwnedSemaphorePermit,
    _capacity_permit: OwnedSemaphorePermit,
}

impl LeasedChatBackend {
    pub(crate) fn new(
        backend: Arc<BackendClient>,
        user_permit: OwnedSemaphorePermit,
        capacity_permit: OwnedSemaphorePermit,
    ) -> Self {
        Self {
            backend,
            _user_permit: user_permit,
            _capacity_permit: capacity_permit,
        }
    }
}

impl platform_assistant::ChatBackend for LeasedChatBackend {
    fn chat(
        &self,
        request: &platform_assistant::ChatRequest,
        on_text: &mut dyn FnMut(&str),
    ) -> Result<platform_assistant::ChatResponse, platform_assistant::BackendError> {
        self.backend.chat(request, on_text)
    }
}

/// What the asking user may read, by console permission: the assistant
/// shows no more than the matching console pages would.
pub(crate) struct Access {
    /// `agents.read`, equal to `compliance.read` (the endpoint checks).
    pub(crate) agents: console_read::AgentScope,
    /// `vulnerabilities.read`; `None` without it.
    pub(crate) vulnerabilities: Option<console_read::AgentScope>,
    /// `rules.read` (global only, as on the Rules page): every published
    /// rule. Without it, only rules with a finding in the agent scope.
    pub(crate) rules: bool,
    /// Internet lookups; `None` when the user may not use them.
    pub(crate) internet: Option<crate::fetch_client::Internet>,
}

/// Runs every lookup offered to the model (`platform_assistant::lookups::specs`)
/// within the user's console permissions. A lookup the user may not run is
/// still offered and answers [`LookupError::Forbidden`], so the model says
/// "you have no access" instead of "no data".
pub(crate) struct ConsoleReadLookups {
    /// Agent and finding scope.
    lookups: StoreLookups,
    /// Vulnerability scope; `None` without `vulnerabilities.read`.
    vulnerabilities: Option<StoreLookups>,
    /// `fleet_overview` mixes agents, findings and vulnerabilities, so it
    /// needs `vulnerabilities.read` with the agent scope.
    overview: bool,
    rules: bool,
    internet: Option<crate::fetch_client::Internet>,
    /// An internet lookup was attempted and did not succeed (not "off",
    /// not blocked).
    internet_failed: std::sync::atomic::AtomicBool,
    pool: Pool,
    scope: console_read::AgentScope,
    now: chrono::DateTime<chrono::Utc>,
}

/// The store's form of a console scope: asset groups become agent IDs.
async fn store_scope(
    pool: &Pool,
    scope: &console_read::AgentScope,
) -> Result<AgentScope, StoreError> {
    Ok(match scope {
        console_read::AgentScope::Global => AgentScope::All,
        console_read::AgentScope::AssetGroups(_) => {
            let client = pool.get().await.map_err(|_| StoreError::Unavailable)?;
            AgentScope::Only(console_read::agent_ids_in_scope(&client, scope).await?)
        }
    })
}

impl ConsoleReadLookups {
    pub(crate) async fn for_user(
        pool: Pool,
        access: Access,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<Self, StoreError> {
        let agent_scope = store_scope(&pool, &access.agents).await?;
        let overview = access.vulnerabilities.as_ref() == Some(&access.agents);
        let vulnerabilities = match &access.vulnerabilities {
            None => None,
            Some(_) if overview => Some(agent_scope.clone()),
            Some(scope) => Some(store_scope(&pool, scope).await?),
        }
        .map(|scope| StoreLookups::new(pool.clone(), scope, now));
        Ok(Self {
            lookups: StoreLookups::new(pool.clone(), agent_scope, now),
            vulnerabilities,
            overview,
            rules: access.rules,
            internet: access.internet,
            internet_failed: std::sync::atomic::AtomicBool::new(false),
            pool,
            scope: access.agents,
            now,
        })
    }
}

impl ConsoleReadLookups {
    /// An internet lookup was attempted for this answer and failed
    /// (unreachable, too large, rate-limited; a blocked query is no failure).
    pub(crate) fn internet_failed(&self) -> bool {
        self.internet_failed
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// The internet lookups that went out for this answer.
    pub(crate) fn internet_sent(&self) -> Vec<crate::fetch_client::Sent> {
        self.internet.as_ref().map_or_else(Vec::new, |internet| {
            internet
                .sent
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        })
    }
}

impl LookupRunner for ConsoleReadLookups {
    async fn run(&self, lookup: &Lookup, items: u32) -> Result<LookupOutput, LookupError> {
        let forbidden = |area| Err(LookupError::Forbidden(area));
        match lookup {
            // Host services and software read host data, guarded by
            // agents.read like agent_summary (and the Assets and Software
            // pages), with the agent scope.
            Lookup::SearchFindings { .. }
            | Lookup::FindingEndpoints { .. }
            | Lookup::HostServices { .. }
            | Lookup::Software { .. } => self.lookups.run(lookup, items).await,
            Lookup::HostVulnerabilities { .. } | Lookup::VulnerabilityHosts { .. } => {
                match &self.vulnerabilities {
                    Some(lookups) => lookups.run(lookup, items).await,
                    None => forbidden(Area::Vulnerabilities),
                }
            }
            Lookup::FleetOverview { .. } if self.overview => self.lookups.run(lookup, items).await,
            Lookup::FleetOverview { .. } => forbidden(Area::Vulnerabilities),
            Lookup::RuleDescription { rule, .. } => {
                // Without rules.read: the latest published definition of a
                // rule the user has findings for (same rule id, never another
                // host's data; the Compliance page shows the version each
                // finding was evaluated against). Such a rule is only read
                // from a set it was found in (`rule_set_for_description`).
                if !self.rules && self.lookups.rule_sets_for(rule).await?.is_empty() {
                    return forbidden(Area::Rules);
                }
                self.lookups.run(lookup, items).await
            }
            Lookup::Reference { .. } | Lookup::WebSearch { .. } => match &self.internet {
                Some(internet) => {
                    let result = internet.run(&self.pool, lookup).await;
                    if match &result {
                        Ok(output) => crate::fetch_client::is_failure(output),
                        Err(_) => true,
                    } {
                        self.internet_failed
                            .store(true, std::sync::atomic::Ordering::Relaxed);
                    }
                    result
                }
                None => Err(crate::fetch_client::forbidden()),
            },
            Lookup::AgentSummary { agent } => {
                let client = self.pool.get().await.map_err(|_| LookupError::Store)?;
                let mut matches =
                    console_read::agent_matches_in_scope(&client, agent, self.now, &self.scope)
                        .await
                        .map_err(|_| LookupError::Store)?;
                if matches.len() > 1 {
                    return Err(LookupError::Ambiguous);
                }
                let records = matches
                    .drain(..)
                    .map(|record| {
                        let state = match record.state {
                            console_read::AgentState::Active => "seen recently",
                            console_read::AgentState::Stale => {
                                if record.last_seen_at.is_some() {
                                    "offline"
                                } else {
                                    "never seen"
                                }
                            }
                            console_read::AgentState::Revoked => "revoked",
                            console_read::AgentState::Imported => "imported",
                        };
                        json!({
                            "cite": format!("[agent:{}]", record.agent_id),
                            "hostname": record.hostname,
                            "state": state,
                            "last_seen": record.last_seen_at.map(|value| value.to_rfc3339()),
                        })
                    })
                    .collect::<Vec<_>>();
                Ok(LookupOutput {
                    data: json!({ "items": records, "omitted": 0 }),
                })
            }
        }
    }
}

#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct ClientTurn {
    pub(crate) question: String,
    pub(crate) answer: String,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct AssistantMessageRequest {
    pub(crate) question: String,
    #[serde(default)]
    pub(crate) history: Vec<ClientTurn>,
}

#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum AssistantSegment {
    Text {
        text: String,
    },
    Citation {
        target_kind: String,
        id: String,
        path: String,
    },
}

#[derive(Clone, Debug, Serialize, ToSchema)]
pub(crate) struct AssistantLookup {
    pub(crate) name: Option<String>,
    pub(crate) objects: usize,
    pub(crate) error: Option<String>,
}

/// One line under an answer that used the internet. A reference's link is
/// built from its ID; a result's text is its link's host, never fetched text.
#[derive(Clone, Debug, PartialEq, Serialize, ToSchema)]
pub(crate) struct AssistantInternetSource {
    /// `reference`, `search`, `result`, `blocked` (a query kept on the
    /// host) or `unavailable` (a lookup failed).
    pub(crate) kind: &'static str,
    pub(crate) text: String,
    pub(crate) url: Option<String>,
    /// A result's `[web:N]` number, as the model saw it.
    pub(crate) number: Option<u32>,
}

#[derive(Clone, Debug, Serialize, ToSchema)]
pub(crate) struct AssistantMessageResponse {
    pub(crate) segments: Vec<AssistantSegment>,
    pub(crate) lookups: Vec<AssistantLookup>,
    pub(crate) internet: Vec<AssistantInternetSource>,
}

pub(crate) use crate::fetch_client::internet_sources;

#[derive(Clone, Debug, Serialize, ToSchema)]
pub(crate) struct AssistantStatusResponse {
    pub(crate) available: bool,
    pub(crate) location: &'static str,
    pub(crate) model: String,
}

impl From<&Segment> for AssistantSegment {
    fn from(segment: &Segment) -> Self {
        match segment {
            Segment::Text(text) => Self::Text { text: text.clone() },
            Segment::Cite(citation) => {
                use platform_assistant::Citation;
                let (kind, id, path) = match citation {
                    Citation::Agent(id) => (
                        "agent",
                        id.clone(),
                        format!("/agents?agent={}", encode_component(id)),
                    ),
                    Citation::Finding { rule_set, rule } => {
                        let id = format!("{rule_set}/{rule}");
                        ("finding", id, "/compliance".to_owned())
                    }
                    Citation::Advisory(id) => {
                        ("advisory", id.clone(), "/vulnerabilities".to_owned())
                    }
                };
                Self::Citation {
                    target_kind: kind.into(),
                    id,
                    path,
                }
            }
        }
    }
}

pub(crate) fn encode_component(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            output.push(char::from(byte));
        } else {
            use std::fmt::Write as _;
            let _ = write!(output, "%{byte:02X}");
        }
    }
    output
}

#[cfg(test)]
mod internet_tests;
#[cfg(test)]
mod lookup_tests;
