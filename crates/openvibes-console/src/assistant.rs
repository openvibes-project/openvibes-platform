use std::{collections::HashMap, sync::Arc, time::Duration};

use platform_assistant::{
    Assistant, BackendClient, Location, Lookup, LookupError, LookupOutput, LookupRunner,
    ResolvedMode, Segment, StoreLookups,
};
use platform_store::{Pool, console_read};
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
        let mut backend = assistant
            .backend
            .clone()
            .filter(|backend| backend.location != Location::External)
            .ok_or(ConsoleError::Config)?;
        // The HTTP turn is capped at 30 seconds. Keep any blocking backend
        // call within the same bound after the request future is cancelled.
        backend.deadline = backend.deadline.min(Duration::from_secs(30));
        let backend = Arc::new(BackendClient::new(&backend).map_err(|_| ConsoleError::Config)?);
        let capacity = assistant
            .backend
            .as_ref()
            .map_or(1, |backend| backend.concurrency as usize);
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
            loop {
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
                } else {
                    *available.write().await = false;
                }
                tokio::time::sleep(Duration::from_secs(300)).await;
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

/// Only the agent and finding queries currently exposed by the console.
pub(crate) struct ConsoleReadLookups {
    lookups: StoreLookups,
    pool: Pool,
    scope: console_read::AgentScope,
    now: chrono::DateTime<chrono::Utc>,
}

impl ConsoleReadLookups {
    pub(crate) fn new(
        lookups: StoreLookups,
        pool: Pool,
        scope: console_read::AgentScope,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Self {
        Self {
            lookups,
            pool,
            scope,
            now,
        }
    }
}

impl LookupRunner for ConsoleReadLookups {
    async fn run(&self, lookup: &Lookup, items: u32) -> Result<LookupOutput, LookupError> {
        match lookup {
            Lookup::SearchFindings { .. } | Lookup::FindingEndpoints { .. } => {
                self.lookups.run(lookup, items).await
            }
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
            _ => Err(LookupError::Unknown),
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

#[derive(Clone, Debug, Serialize, ToSchema)]
pub(crate) struct AssistantMessageResponse {
    pub(crate) segments: Vec<AssistantSegment>,
    pub(crate) lookups: Vec<AssistantLookup>,
}

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
                        ("finding", id, "/findings".to_owned())
                    }
                    Citation::Advisory(id) => ("advisory", id.clone(), "/findings".to_owned()),
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

fn encode_component(value: &str) -> String {
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
