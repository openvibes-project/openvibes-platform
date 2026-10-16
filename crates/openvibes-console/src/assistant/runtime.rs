use std::{collections::HashMap, sync::Arc, time::Duration};

use platform_assistant::{Assistant, BackendClient, BackendError, Location, ResolvedMode};
use tokio::sync::{Mutex, OwnedSemaphorePermit, RwLock, Semaphore};

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
