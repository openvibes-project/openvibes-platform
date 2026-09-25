//! What the console shows: model text made inert, and citations verified
//! against the objects this question's lookups returned (spec §6).
//!
//! The console renders [`Segment::Text`] as plain text and
//! [`Segment::Cite`] as its own link, so model output can never become
//! markup, a link, or a citation of an object the user was not shown.

use std::{collections::BTreeSet, fmt};

/// Longest answer shown, in characters.
pub const MAX_ANSWER_CHARS: usize = 8_000;
/// Longest ID inside a citation.
const MAX_CITATION_ID: usize = 200;

/// An object the console can link to.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Citation {
    /// An agent, `[agent:agent.<uuid>]`.
    Agent(String),
    /// A finding group, `[finding:<rule set>/<rule>]`; the rule set is
    /// empty for findings from before protocol P6, written `~unknown`.
    Finding {
        /// Rule set (`""` when unknown).
        rule_set: String,
        /// Rule.
        rule: String,
    },
    /// An advisory, `[advisory:<id>]`.
    Advisory(String),
}

impl fmt::Display for Citation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Agent(id) => write!(f, "[agent:{id}]"),
            Self::Finding { rule_set, rule } if rule_set.is_empty() => {
                write!(f, "[finding:~unknown/{rule}]")
            }
            Self::Finding { rule_set, rule } => write!(f, "[finding:{rule_set}/{rule}]"),
            Self::Advisory(id) => write!(f, "[advisory:{id}]"),
        }
    }
}

fn id_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':')
}

impl Citation {
    /// Parses `[kind:id]` exactly as [`Display`](fmt::Display) writes it.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let inner = text.strip_prefix('[')?.strip_suffix(']')?;
        let (kind, id) = inner.split_once(':')?;
        let valid = |part: &str| {
            !part.is_empty() && part.len() <= MAX_CITATION_ID && part.chars().all(id_char)
        };
        match kind {
            "agent" if valid(id) => Some(Self::Agent(id.to_owned())),
            "advisory" if valid(id) => Some(Self::Advisory(id.to_owned())),
            "finding" => {
                let (rule_set, rule) = id.split_once('/')?;
                let rule_set = if rule_set == "~unknown" {
                    ""
                } else if valid(rule_set) {
                    rule_set
                } else {
                    return None;
                };
                valid(rule).then(|| Self::Finding {
                    rule_set: rule_set.to_owned(),
                    rule: rule.to_owned(),
                })
            }
            _ => None,
        }
    }
}

/// One piece of a shown answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Segment {
    /// Plain text; the console never interprets it as markup or links.
    Text(String),
    /// A verified citation; the console renders its own link.
    Cite(Citation),
}

/// Whether `c` could reorder or hide text (bidirectional controls and
/// invisible formatting), as in "Trojan Source" spoofing.
fn hidden_control(c: char) -> bool {
    matches!(
        c,
        '\u{061C}' | '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{2069}'
            | '\u{FEFF}'
    )
}

/// Cleans model text and splits out citations:
///
/// - control characters other than newline and tab, bidirectional controls,
///   and invisible formatting are removed;
/// - `scheme://` becomes `scheme[:]//`, so nothing can turn it into a link;
/// - the text is cut to [`MAX_ANSWER_CHARS`];
/// - `[kind:id]` becomes a [`Segment::Cite`] only when `allowed` holds it;
///   any other bracketed text stays plain text.
#[must_use]
pub fn sanitize(text: &str, allowed: &BTreeSet<Citation>) -> Vec<Segment> {
    let clean: String = text
        .chars()
        .filter(|c| (!c.is_control() || matches!(c, '\n' | '\t')) && !hidden_control(*c))
        .take(MAX_ANSWER_CHARS)
        .collect::<String>()
        .replace("://", "[:]//");
    let mut segments: Vec<Segment> = Vec::new();
    let push_text = |segments: &mut Vec<Segment>, piece: &str| {
        if piece.is_empty() {
            return;
        }
        match segments.last_mut() {
            Some(Segment::Text(text)) => text.push_str(piece),
            _ => segments.push(Segment::Text(piece.to_owned())),
        }
    };
    let mut rest = clean.as_str();
    while let Some(start) = rest.find('[') {
        push_text(&mut segments, &rest[..start]);
        let candidate = &rest[start..];
        let citation = candidate
            .find(']')
            .filter(|end| *end <= MAX_CITATION_ID * 2 + 16)
            .and_then(|end| Some((end, Citation::parse(&candidate[..=end])?)))
            .filter(|(_, citation)| allowed.contains(citation));
        match citation {
            Some((end, citation)) => {
                segments.push(Segment::Cite(citation));
                rest = &candidate[end + 1..];
            }
            None => {
                push_text(&mut segments, "[");
                rest = &candidate[1..];
            }
        }
    }
    push_text(&mut segments, rest);
    let trimmed_end = match segments.last_mut() {
        Some(Segment::Text(text)) => {
            let kept = text.trim_end().len();
            text.truncate(kept);
            text.is_empty()
        }
        _ => false,
    };
    if trimmed_end {
        segments.pop();
    }
    segments
}

/// The answer as plain text, citations written as `[kind:id]` (for the
/// conversation history sent back to the model, and for storage).
#[must_use]
pub fn plain_text(segments: &[Segment]) -> String {
    segments
        .iter()
        .map(|segment| match segment {
            Segment::Text(text) => text.clone(),
            Segment::Cite(citation) => citation.to_string(),
        })
        .collect()
}
