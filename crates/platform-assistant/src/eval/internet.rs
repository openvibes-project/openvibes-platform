//! Internet lookups in the evaluation: `reference` and `web_search` answer
//! from recorded answers (`eval/internet.toml`), never the network. A
//! search still passes the production query filter with a deny list built
//! from the evaluation fleet, so a query naming a fleet host is refused
//! exactly as the console's fetch service would.

use std::sync::Mutex;

use openvibes_fetch::{filter, protocol::Item};
use serde::Deserialize;
use serde_json::json;

use super::{Fleet, FleetSource};
use crate::lookups::{Lookup, LookupError, LookupOutput, LookupRunner, Lookups};

/// The recorded answers.
pub const INTERNET: &str = include_str!("../../eval/internet.toml");

// The console's fixed notes (crates/openvibes-console/src/fetch_client.rs).
const NOTE_BLOCKED: &str = "blocked: the query contained internal data";
const NOTE_REFERENCE_DOWN: &str = "OSV could not be reached; this answer uses local data only";

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Recorded {
    #[serde(default)]
    reference: Vec<Reference>,
    #[serde(default)]
    search: Vec<Search>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Reference {
    id: String,
    source: String,
    items: Vec<Item>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Search {
    /// A query containing this (lowercase) text gets these results.
    contains: String,
    source: String,
    items: Vec<Item>,
}

/// The fleet's lookups plus recorded internet answers.
pub(super) struct EvalLookups {
    inner: Lookups<FleetSource>,
    recorded: Recorded,
    deny: Vec<String>,
    blocked: Mutex<Vec<String>>,
}

impl EvalLookups {
    pub(super) fn new(inner: Lookups<FleetSource>, fleet: &Fleet) -> Self {
        Self {
            inner,
            // ponytail: a broken builtin file means no recorded answers; a
            // unit test parses it, so this cannot ship broken.
            recorded: toml::from_str(INTERNET).unwrap_or_default(),
            deny: fleet
                .agents
                .iter()
                .flat_map(|a| [a.hostname.clone(), a.id.clone()])
                .collect(),
            blocked: Mutex::default(),
        }
    }

    /// The searches the filter refused since the last call.
    pub(super) fn take_blocked(&self) -> Vec<String> {
        std::mem::take(&mut *self.blocked.lock().unwrap_or_else(|e| e.into_inner()))
    }
}

fn outside(source: &str, items: &[Item]) -> LookupOutput {
    // The console's shape: plain-text refs, no citation keys.
    let items: Vec<_> = items
        .iter()
        .enumerate()
        .map(|(n, i)| {
            json!({ "ref": format!("[web:{}]", n + 1), "title": i.title,
                    "snippet": i.snippet, "url": i.url })
        })
        .collect();
    LookupOutput {
        data: json!({ "source": source, "outside_data": true, "items": items, "omitted": 0 }),
    }
}

fn note(text: &str) -> LookupOutput {
    LookupOutput {
        data: json!({ "note": text }),
    }
}

impl LookupRunner for EvalLookups {
    async fn run(&self, lookup: &Lookup, items: u32) -> Result<LookupOutput, LookupError> {
        Ok(match lookup {
            Lookup::Reference { id } => self
                .recorded
                .reference
                .iter()
                .find(|r| r.id == *id && filter::is_public_id(id))
                .map_or_else(
                    || note(NOTE_REFERENCE_DOWN),
                    |r| outside(&r.source, &r.items),
                ),
            Lookup::WebSearch { query } => {
                if filter::check_query(query, &self.deny).is_err() {
                    self.blocked
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .push(query.clone());
                    return Ok(note(NOTE_BLOCKED));
                }
                let lower = query.to_lowercase();
                self.recorded
                    .search
                    .iter()
                    .find(|s| lower.contains(&s.contains))
                    .map_or_else(|| outside("search", &[]), |s| outside(&s.source, &s.items))
            }
            _ => return self.inner.run(lookup, items).await,
        })
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_recorded_answers_parse() {
        let r: super::Recorded = toml::from_str(super::INTERNET).unwrap();
        assert_eq!((r.reference.len(), r.search.len()), (2, 2));
    }
}
