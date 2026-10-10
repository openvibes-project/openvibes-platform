//! The internet lookups (spec 2026-10-10): `reference` (level 1) and
//! `web_search` (level 2). Offered only when the console allows them; the
//! console runner does the fetching, so nothing here touches the network.

use serde::Deserialize;
use serde_json::json;

use super::{Lookup, LookupError, args, object, required, text_schema};
use crate::client::ToolSpec;

/// The internet lookup names.
pub const INTERNET_NAMES: [&str; 2] = ["reference", "web_search"];

/// The internet lookups offered at `level` (0 off, 1 reference, 2 both).
#[must_use]
pub fn internet_specs(level: u8) -> Vec<ToolSpec> {
    let mut specs = Vec::new();
    if level >= 1 {
        specs.push(ToolSpec {
            name: INTERNET_NAMES[0].into(),
            description: "Public advisory text for a CVE or advisory ID (OSV). Outside data.".into(),
            parameters: object(
                json!({ "id": text_schema("A public ID such as CVE-2026-1234 or GHSA-xxxx-xxxx-xxxx.") }),
                &["id"],
            ),
        });
    }
    if level >= 2 {
        specs.push(ToolSpec {
            name: INTERNET_NAMES[1].into(),
            description: "Web search for public security information. Outside data.".into(),
            parameters: object(
                json!({ "query": text_schema("Public terms only: never host names, IPs or users.") }),
                &["query"],
            ),
        });
    }
    specs
}

pub(super) fn parse(name: &str, arguments: &str) -> Result<Lookup, LookupError> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Reference {
        id: String,
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Search {
        query: String,
    }
    match name {
        "reference" => Ok(Lookup::Reference {
            id: required(args::<Reference>(arguments)?.id)?,
        }),
        "web_search" => Ok(Lookup::WebSearch {
            query: required(args::<Search>(arguments)?.query)?,
        }),
        _ => Err(LookupError::Unknown),
    }
}
