use platform_assistant::Segment;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

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

pub(crate) use crate::assistant::fetch_client::internet_sources;

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
                        format!("/hosts/{}", encode_component(id)),
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
mod tests {
    use super::*;

    #[test]
    fn host_citations_link_to_the_host_page() {
        let segment = Segment::Cite(platform_assistant::Citation::Agent("web 01/a".into()));
        match AssistantSegment::from(&segment) {
            AssistantSegment::Citation {
                target_kind, path, ..
            } => {
                assert_eq!(target_kind, "agent");
                assert_eq!(path, "/hosts/web%2001%2Fa");
            }
            AssistantSegment::Text { .. } => panic!("a citation"),
        }
    }
}
