//! One JSON request in, one JSON response out, one process per request.

use serde::{Deserialize, Serialize};

/// A lookup request, e.g. `{"user":"alex","kind":"reference","id":"CVE-2026-1234"}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Request {
    /// Console user the lookup is made for (permission and audit).
    pub user: String,
    /// What to look up; its tag is the `kind` field of the request object.
    #[serde(flatten)]
    pub kind: Kind,
}

/// The two kinds of lookup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Kind {
    /// Level 1: fetch a public advisory or CVE page by its identifier.
    Reference {
        /// The public identifier, checked by `filter::is_public_id`.
        id: String,
    },
    /// Level 2: a web search, checked by `filter::check_query`.
    Search {
        /// The search text.
        query: String,
    },
}

/// One result: a title, a short snippet and the page it came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Item {
    /// Page title.
    pub title: String,
    /// Short extract of the page.
    pub snippet: String,
    /// Source URL.
    pub url: String,
}

/// The response, tagged by `result`: `{"result":"ok","source":..,"items":[..]}`
/// or `{"result":"refused","code":"blocked"}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum Response {
    /// The lookup ran.
    Ok {
        /// Which source answered.
        source: String,
        /// The results, already bounded.
        items: Vec<Item>,
    },
    /// The lookup did not run.
    Refused {
        /// Why.
        code: Refusal,
    },
}

/// Why a lookup was refused (snake_case on the wire).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Refusal {
    /// Internet lookups are switched off.
    Off,
    /// The query filter refused it.
    Blocked,
    /// The request is malformed.
    Invalid,
    /// The source could not be reached or answered badly.
    Unavailable,
    /// The answer exceeded the size limit.
    TooLarge,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_format() {
        let r: Request =
            serde_json::from_str(r#"{"user":"alex","kind":"reference","id":"CVE-2026-1234"}"#)
                .unwrap();
        assert_eq!(
            r.kind,
            Kind::Reference {
                id: "CVE-2026-1234".into()
            }
        );
        let s: Request =
            serde_json::from_str(r#"{"user":"a","kind":"search","query":"x"}"#).unwrap();
        assert_eq!(s.kind, Kind::Search { query: "x".into() });
        let out = serde_json::to_string(&Response::Refused {
            code: Refusal::TooLarge,
        })
        .unwrap();
        assert_eq!(out, r#"{"result":"refused","code":"too_large"}"#);
        let ok = Response::Ok {
            source: "s".into(),
            items: vec![],
        };
        assert_eq!(
            serde_json::to_string(&ok).unwrap(),
            r#"{"result":"ok","source":"s","items":[]}"#
        );
    }
}
