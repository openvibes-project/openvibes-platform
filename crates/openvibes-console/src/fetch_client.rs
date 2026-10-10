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

use openvibes_fetch::{
    filter::upper_prefix,
    outside::{
        self, NOTE_BLOCKED, NOTE_INVALID, NOTE_LIMIT, NOTE_OFF, NOTE_REFERENCE_DOWN,
        NOTE_SEARCH_DOWN,
    },
    protocol::{Kind, Refusal, Request, Response},
};
use platform_assistant::{Area, Lookup, LookupError, LookupOutput};
use platform_store::Pool;
use serde_json::{Value, json};

use crate::assistant::{AssistantInternetSource, encode_component};

/// Where `openvibes-fetch.socket` listens.
pub(crate) const DEFAULT_FETCH_SOCKET: &str = "/run/openvibes-fetch/fetch.sock";
const TIMEOUT: Duration = Duration::from_secs(25);
// The fetcher's own deadline is the bound; its answer must still arrive.
const _: () = assert!(TIMEOUT.as_secs() > openvibes_fetch::DEADLINE.as_secs());
const MAX_REPLY: u64 = 64 * 1024;
/// Lookups per user and hour.
const PER_HOUR: u32 = 20;

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
    /// What went out so far for this answer.
    pub(crate) sent: Mutex<Vec<Sent>>,
}

/// One lookup that went out, for the sources line under the answer.
#[derive(Clone, Debug)]
pub(crate) struct Sent {
    /// `reference` (answered) or `search` (sent, whatever came back).
    pub(crate) kind: &'static str,
    /// The ID or query as sent.
    pub(crate) subject: String,
    /// The `[web:N]` number of the first result.
    pub(crate) first: usize,
    /// Every result's URL, in order.
    pub(crate) links: Vec<String>,
}

fn note(text: &str) -> LookupOutput {
    LookupOutput {
        data: outside::note(text),
    }
}

/// Whether `output` is a note for a lookup that was attempted and failed
/// (not the off note, which is no failure).
pub(crate) fn is_failure(output: &LookupOutput) -> bool {
    output
        .data
        .get("note")
        .and_then(Value::as_str)
        .is_some_and(|text| text != NOTE_OFF && text != NOTE_INVALID)
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
                upper_prefix(id),
                Kind::Reference {
                    id: upper_prefix(id),
                },
                NOTE_REFERENCE_DOWN,
                "osv.dev",
            ),
            Lookup::WebSearch { query } => (
                "search",
                query.clone(),
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
        let first = self.record(kind, subject, response.as_ref());
        Ok(match response {
            Some(Response::Ok { source, items }) => LookupOutput {
                data: outside::data(&source, &items, first),
            },
            Some(Response::Refused { code: Refusal::Off }) => note(NOTE_OFF),
            Some(Response::Refused {
                code: Refusal::Blocked,
            }) => note(NOTE_BLOCKED),
            Some(Response::Refused {
                code: Refusal::Invalid,
            }) if kind == "reference" => note(NOTE_INVALID),
            _ => note(down),
        })
    }

    /// Keeps an answered reference, or a search that went out (answered,
    /// or failed at the source), for the sources line. Returns the first
    /// `[web:N]` number for this lookup's results.
    fn record(&self, kind: &'static str, subject: String, response: Option<&Response>) -> usize {
        let mut sent = self
            .sent
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let first = sent.last().map_or(1, |s| s.first + s.links.len());
        let links = match response {
            Some(Response::Ok { items, .. }) => Some(items.iter().map(|i| i.url.clone()).collect()),
            Some(Response::Refused {
                code: Refusal::Unavailable | Refusal::TooLarge,
            }) if kind == "search" => Some(Vec::new()),
            _ => None,
        };
        if let Some(links) = links {
            sent.push(Sent {
                kind,
                subject,
                first,
                links,
            });
        }
        first
    }
}

/// Test connection: the fixed word `openvibes` through the same path as the
/// assistant's web search (filter, level check, rate limit, audit row).
pub(crate) async fn test_search(
    pool: &Pool,
    socket: &Arc<Path>,
    limits: &Arc<Limits>,
    user: String,
) -> Result<(bool, String), LookupError> {
    let internet = Internet {
        user,
        socket: socket.clone(),
        limits: limits.clone(),
        sent: Mutex::default(),
    };
    let lookup = Lookup::WebSearch {
        query: "openvibes".into(),
    };
    let output = internet.run(pool, &lookup).await?;
    Ok(match output.data.get("note").and_then(Value::as_str) {
        Some(NOTE_OFF) => (false, "web search is off".to_owned()),
        Some(note) => (false, note.to_owned()),
        None => {
            let n = output.data["items"].as_array().map_or(0, Vec::len);
            (true, format!("{n} results"))
        }
    })
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

/// The sources line under an answer: each reference looked up (its link
/// built here from the ID), each search that went out, each result link
/// shown by host only (never its outside title) with its `[web:N]` number,
/// each link once; then one line if any lookup failed.
pub(crate) fn internet_sources(failed: bool, sent: &[Sent]) -> Vec<AssistantInternetSource> {
    let unavailable = failed.then(|| AssistantInternetSource {
        kind: "unavailable",
        text: "Internet lookup unavailable; this answer uses local data only".to_owned(),
        url: None,
        number: None,
    });
    let mut out: Vec<AssistantInternetSource> = Vec::new();
    for s in sent {
        let head = if s.kind == "reference" {
            let id = &s.subject;
            let (source, url) = if id.starts_with("FEDORA-") {
                (
                    "bodhi.fedoraproject.org",
                    format!(
                        "https://bodhi.fedoraproject.org/updates/{}",
                        encode_component(id)
                    ),
                )
            } else {
                (
                    "osv.dev",
                    format!("https://osv.dev/vulnerability/{}", encode_component(id)),
                )
            };
            AssistantInternetSource {
                kind: "reference",
                text: format!("Looked up {id} on {source}"),
                url: Some(url),
                number: None,
            }
        } else {
            AssistantInternetSource {
                kind: "search",
                text: format!("Searched the web for: {}", s.subject),
                url: None,
                number: None,
            }
        };
        let results = s.links.iter().enumerate().filter_map(|(n, url)| {
            Some(AssistantInternetSource {
                kind: "result",
                text: outside::link_host(url)?,
                url: Some(url.clone()),
                number: u32::try_from(s.first + n).ok(),
            })
        });
        for entry in std::iter::once(head).chain(results) {
            let seen = out.iter().any(|o| match (&o.url, &entry.url) {
                (Some(a), Some(b)) => a == b,
                (None, None) => o.text == entry.text,
                _ => false,
            });
            if !seen {
                out.push(entry);
            }
        }
    }
    out.extend(unavailable);
    out
}

/// The forbidden answer for a user without internet access.
pub(crate) const fn forbidden() -> LookupError {
    LookupError::Forbidden(Area::Internet)
}
