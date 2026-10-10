//! The assistant's internet lookups, from the console's side: one request
//! to the `openvibes-fetch` socket per lookup, a per-user rate limit, an
//! audit row for every outbound request, and fixed notes when anything
//! goes wrong (the model then answers from local data).

use std::{
    collections::HashMap,
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};

use openvibes_fetch::protocol::{Kind, Refusal, Request, Response};
use platform_assistant::{Area, Lookup, LookupError, LookupOutput};
use platform_store::Pool;
use serde_json::{Value, json};

/// Where `openvibes-fetch.socket` listens.
pub(crate) const DEFAULT_FETCH_SOCKET: &str = "/run/openvibes-fetch/fetch.sock";
const TIMEOUT: Duration = Duration::from_secs(15);
const MAX_REPLY: u64 = 64 * 1024;
/// Lookups per user and hour.
const PER_HOUR: u32 = 20;

const NOTE_OFF: &str = "internet lookups are off";
const NOTE_BLOCKED: &str = "blocked: the query contained internal data";
const NOTE_LIMIT: &str = "the internet lookup limit is reached; try again later";
const NOTE_REFERENCE_DOWN: &str = "OSV could not be reached; this answer uses local data only";
const NOTE_SEARCH_DOWN: &str =
    "the web search could not be reached; this answer uses local data only";

/// Lookups used per user in the current hour.
#[derive(Default)]
pub(crate) struct Limits(Mutex<HashMap<String, (i64, u32)>>);

impl Limits {
    /// Counts one lookup for `user` in `hour`; false when over the limit.
    fn allow(&self, user: &str, hour: i64) -> bool {
        let Ok(mut map) = self.0.lock() else {
            return false;
        };
        map.retain(|_, (h, _)| *h == hour);
        let count = &mut map.entry(user.to_owned()).or_insert((hour, 0)).1;
        *count += 1;
        *count <= PER_HOUR
    }
}

/// What a runner needs to make internet lookups for one user.
pub(crate) struct Internet {
    pub(crate) user: String,
    pub(crate) socket: Arc<Path>,
    pub(crate) limits: Arc<Limits>,
}

fn note(text: &str) -> LookupOutput {
    LookupOutput {
        data: json!({ "note": text }),
    }
}

/// Whether `output` is a note for a lookup that was attempted and failed
/// (not the off note, which is no failure).
pub(crate) fn is_failure(output: &LookupOutput) -> bool {
    output
        .data
        .get("note")
        .and_then(Value::as_str)
        .is_some_and(|text| text != NOTE_OFF)
}

/// One exchange with the fetch service; `None` when it cannot be reached
/// or answers anything but a response.
async fn ask(socket: &Path, request: &Request) -> Option<Response> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let body = serde_json::to_vec(request).ok()?;
    let exchange = async {
        let mut stream = tokio::net::UnixStream::connect(socket).await?;
        stream.write_all(&body).await?;
        stream.shutdown().await?;
        let mut reply = Vec::new();
        stream.take(MAX_REPLY).read_to_end(&mut reply).await?;
        Ok::<_, std::io::Error>(reply)
    };
    let reply = tokio::time::timeout(TIMEOUT, exchange).await.ok()?.ok()?;
    serde_json::from_slice(&reply).ok()
}

impl Internet {
    /// Runs `lookup` (a `Reference` or `WebSearch`).
    pub(crate) async fn run(
        &self,
        pool: &Pool,
        lookup: &Lookup,
    ) -> Result<LookupOutput, LookupError> {
        let (kind, subject, wire, down, fallback) = match lookup {
            Lookup::Reference { id } => (
                "reference",
                id,
                Kind::Reference { id: id.clone() },
                NOTE_REFERENCE_DOWN,
                "osv.dev",
            ),
            Lookup::WebSearch { query } => (
                "search",
                query,
                Kind::Search {
                    query: query.clone(),
                },
                NOTE_SEARCH_DOWN,
                "web search",
            ),
            _ => return Err(LookupError::Unknown),
        };
        let level = crate::assistant_internet::current_level(pool).await;
        if level == 0 || (kind == "search" && level < 2) {
            return Ok(note(NOTE_OFF));
        }
        if !self
            .limits
            .allow(&self.user, chrono::Utc::now().timestamp() / 3600)
        {
            return Ok(note(NOTE_LIMIT));
        }
        let request = Request {
            user: self.user.clone(),
            kind: wire,
        };
        let response = ask(&self.socket, &request).await;
        let (destination, result) = match &response {
            Some(Response::Ok { source, .. }) => (source.as_str(), "success".to_owned()),
            Some(Response::Refused { code }) => (fallback, format!("refused:{}", code_name(*code))),
            None => (fallback, "unreachable".to_owned()),
        };
        let detail = json!({ "kind": kind, "subject": subject, "destination": destination });
        let client = pool.get().await.map_err(|_| LookupError::Store)?;
        platform_store::audit::record_with_detail(
            &client,
            &self.user,
            "assistant.internet.lookup",
            "assistant",
            &result,
            &crate::problem::next_request_id(),
            &detail,
        )
        .await
        .map_err(|_| LookupError::Store)?;
        Ok(match response {
            Some(Response::Ok { source, items }) => outside(&source, items),
            Some(Response::Refused { code: Refusal::Off }) => note(NOTE_OFF),
            Some(Response::Refused {
                code: Refusal::Blocked,
            }) => note(NOTE_BLOCKED),
            _ => note(down),
        })
    }
}

fn code_name(code: Refusal) -> &'static str {
    match code {
        Refusal::Off => "off",
        Refusal::Blocked => "blocked",
        Refusal::Invalid => "invalid",
        Refusal::Unavailable => "unavailable",
        Refusal::TooLarge => "too_large",
    }
}

/// Outside text as data for the model. Each item has a plain-text `ref`
/// label and its URL as text; no key here is a citation key, so nothing
/// outside can become a link in the answer.
fn outside(source: &str, items: Vec<openvibes_fetch::protocol::Item>) -> LookupOutput {
    let items: Vec<Value> = items
        .into_iter()
        .enumerate()
        .map(|(n, item)| {
            json!({ "ref": format!("[web:{}]", n + 1), "title": item.title,
                    "snippet": item.snippet, "url": item.url })
        })
        .collect();
    LookupOutput {
        data: json!({ "source": source, "outside_data": true, "items": items, "omitted": 0 }),
    }
}

/// The forbidden answer for a user without internet access.
pub(crate) const fn forbidden() -> LookupError {
    LookupError::Forbidden(Area::Internet)
}
