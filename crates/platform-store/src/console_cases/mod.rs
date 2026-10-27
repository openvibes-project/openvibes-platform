//! Cases: where one investigation happens (schema 35, design in
//! `docs/specs/2026-10-04-console-cases-design.md`).
//!
//! A case holds a title, a status, items that link to existing objects
//! (never copies of them) and an append-only timeline. Visibility is the
//! caller's asset-group scope, applied in SQL through each item's agent: a
//! case is seen by someone who can see at least one of its items, who
//! opened it or to whom it is assigned, and its items, counts and timeline
//! entries about items are limited to what the caller can see. A case the
//! caller cannot see reads as absent. Every change and its audit row
//! commit together; the audit log never holds a note's text.

use chrono::{DateTime, Utc};
use serde_json::Value;
use tokio_postgres::error::SqlState;

use crate::{StoreError, console_read::AgentScope};

/// Items one case may hold.
pub const MAX_ITEMS_PER_CASE: i64 = 500;
/// Items a case may be created with.
pub const MAX_ITEMS_ON_CREATE: usize = 50;
/// Timeline entries one case may hold; past it notes are refused.
pub const MAX_EVENTS_PER_CASE: i64 = 2000;
/// Longest title, in characters.
pub const MAX_TITLE_CHARS: usize = 120;
/// Longest note, resolution note or outcome note, in characters.
pub const MAX_NOTE_CHARS: usize = 4000;
/// How long after closing a case is watched for the evidence of its
/// `resolved` items coming back, in days.
pub const EVIDENCE_WATCH_DAYS: i64 = 30;
/// How far ahead an item's accepted risk may run, in days.
pub const MAX_ACCEPT_DAYS: i64 = 365;
/// The outcomes an alarm, finding or vulnerability can take; each needs a
/// note except `resolved`.
pub const OUTCOMES: [&str; 5] = [
    "resolved",
    "false_positive",
    "accepted_risk",
    "confirmed_malicious",
    "expected",
];
/// Cases looked at per call of the lazy reopen checks.
const REOPEN_BATCH: i64 = 100;
/// Cases returned for one host or software item.
const FOR_ITEM_LIMIT: i64 = 50;

/// What an item points at.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ItemKind {
    /// A threat alarm; the ref is the platform's alarm id.
    Alarm,
    /// One finding on one host; the ref is `agent/rule_set/rule`.
    Finding,
    /// One vulnerability on one host; the ref is `agent/advisory`.
    Vulnerability,
    /// A host; the ref is the agent id.
    Host,
    /// A package across the fleet; the ref is `manager/name`.
    Software,
    /// A port across the fleet; the ref is `tcp/22` or `udp/53`.
    Port,
    /// A service across the fleet; the ref is the unit, e.g. `sshd.service`.
    Service,
}

impl ItemKind {
    /// The kind as stored and sent.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Alarm => "alarm",
            Self::Finding => "compliance_finding",
            Self::Vulnerability => "vulnerability",
            Self::Host => "host",
            Self::Software => "software",
            Self::Port => "port",
            Self::Service => "service",
        }
    }

    /// The kind for its stored name.
    pub fn parse(text: &str) -> Option<Self> {
        Some(match text {
            "alarm" => Self::Alarm,
            "compliance_finding" => Self::Finding,
            "vulnerability" => Self::Vulnerability,
            "host" => Self::Host,
            "software" => Self::Software,
            "port" => Self::Port,
            "service" => Self::Service,
            _ => return None,
        })
    }

    /// True for the kinds that can be in only one open case at a time and
    /// that need an outcome before a case closes.
    pub const fn exclusive(self) -> bool {
        matches!(self, Self::Alarm | Self::Finding | Self::Vulnerability)
    }
}

/// A console user as the cases show them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UserRef {
    /// Stable UUID.
    pub user_id: String,
    /// Login name.
    pub username: String,
    /// Name to show.
    pub display_name: String,
}

/// One case as listed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaseSummary {
    /// Stable UUID.
    pub case_id: String,
    /// The number shown as `C-<number>`.
    pub number: i64,
    /// 1 to 120 characters.
    pub title: String,
    /// `open`, `investigating` or `closed`.
    pub status: String,
    /// `mitigated`, `false_positive` or `accepted_risk` on a case closed
    /// before step 5d; new closes set none.
    pub resolution: Option<String>,
    /// When a pre-5d case's accepted risk runs out.
    pub accepted_until: Option<DateTime<Utc>>,
    /// `critical`, `high`, `medium` or `low`.
    pub severity: String,
    /// Who works on it.
    pub assignee: Option<UserRef>,
    /// Who opened it.
    pub opened_by: UserRef,
    /// Creation time.
    pub created_at: DateTime<Utc>,
    /// Last change of any kind.
    pub updated_at: DateTime<Utc>,
    /// When it was closed.
    pub closed_at: Option<DateTime<Utc>>,
    /// Version for conditional updates.
    pub version: i64,
    /// Items the caller can see.
    pub items: i64,
    /// Visible alarm, finding and vulnerability items without an outcome.
    pub pending_items: i64,
}

/// One item of a case that the caller can see.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaseItem {
    /// Stable UUID.
    pub item_id: String,
    /// What it points at.
    pub kind: String,
    /// Its id, as the console's panels write it.
    pub reference: String,
    /// The host that decides who sees it (none for software).
    pub agent_id: Option<String>,
    /// That host's name, when known.
    pub hostname: Option<String>,
    /// True while the case is not closed.
    pub active: bool,
    /// One of [`OUTCOMES`].
    pub outcome: Option<String>,
    /// Why, for every outcome but `resolved`.
    pub outcome_note: Option<String>,
    /// When an `accepted_risk` outcome runs out and the case reopens.
    pub outcome_until: Option<DateTime<Utc>>,
    /// Who added it.
    pub added_by: UserRef,
    /// When.
    pub added_at: DateTime<Utc>,
    /// What to show for it, when it still exists.
    pub title: Option<String>,
    /// Its severity as its own page states it, when it has one.
    pub severity: Option<String>,
    /// True when the evidence is gone: the finding is no longer reported,
    /// the vulnerability no longer matches the host, the alarm is closed
    /// as mitigated or no longer exists. Always false for hosts and software.
    pub evidence_gone: bool,
}

/// One timeline entry.
#[derive(Clone, Debug, PartialEq)]
pub struct CaseEvent {
    /// Position on the timeline.
    pub event_id: i64,
    /// When.
    pub at: DateTime<Utc>,
    /// Who; none for the platform itself.
    pub actor: Option<UserRef>,
    /// `created`, `note`, `status`, `assigned`, `severity`, `item_added`,
    /// `item_removed`, `item_outcome`, `resolved` or `reopened`.
    pub kind: String,
    /// The note's text, or the resolution note for `resolved`.
    pub body: Option<String>,
    /// Structured facts about the change.
    pub detail: Value,
}

/// A case with what the caller can see of it.
#[derive(Clone, Debug, PartialEq)]
pub struct CaseDetail {
    /// The list fields.
    pub summary: CaseSummary,
    /// The closing note.
    pub resolution_note: Option<String>,
    /// Visible items, oldest first.
    pub items: Vec<CaseItem>,
    /// The timeline, oldest first, without entries about hidden items.
    pub events: Vec<CaseEvent>,
}

/// A case that holds an item.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ItemCase {
    /// The case.
    pub case: CaseSummary,
    /// The item's id in that case.
    pub item_id: String,
    /// The item's outcome there.
    pub outcome: Option<String>,
}

/// Why a request was refused (not a database failure).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Refusal {
    /// No such case, or the caller cannot see it.
    NotFound,
    /// No such item: it does not exist, is not in the case, or is outside
    /// the caller's scope; the answer is the same for all three.
    ItemNotFound,
    /// `expected_version` is not the current version.
    Stale,
    /// The case is closed; reopen it first.
    Closed,
    /// A field is wrong: its name and a stable code.
    Invalid(&'static str, &'static str),
    /// The assignee is not an enabled user who can read cases.
    AssigneeUnavailable,
    /// The item is in another open case; its number only when the caller
    /// can see that case.
    ItemInCase(Option<i64>),
    /// The item is already in this case.
    AlreadyInCase,
    /// The case holds [`MAX_ITEMS_PER_CASE`] items.
    TooManyItems,
    /// The timeline holds [`MAX_EVENTS_PER_CASE`] entries.
    TimelineFull,
    /// Closing needs an outcome (and evidence for resolved ones) on this
    /// many visible items.
    ItemsUnresolved(i64),
    /// Closing is blocked by items the caller cannot see.
    HiddenItemsUnresolved,
    /// `resolved` needs the evidence to be gone, and it is not.
    EvidencePresent,
}

/// A request to change a case; every editable field is stated.
#[derive(Clone, Copy, Debug)]
pub struct CaseChange<'a> {
    /// The version the caller read.
    pub expected_version: i64,
    /// New title.
    pub title: &'a str,
    /// New severity.
    pub severity: &'a str,
    /// New status; `closed` closes the case, and anything else on a closed
    /// case reopens it.
    pub status: &'a str,
    /// Assignee's user id, or nobody.
    pub assignee_user_id: Option<&'a str>,
    /// The closing note, stored as `resolution_note`: required when
    /// `status` is `closed` (the current one while a closed case stays
    /// closed), and absent otherwise.
    pub closing_note: Option<&'a str>,
}

/// A new case.
#[derive(Clone, Copy, Debug)]
pub struct NewCase<'a> {
    /// Title.
    pub title: &'a str,
    /// Severity; the highest item severity when absent.
    pub severity: Option<&'a str>,
    /// Assignee's user id.
    pub assignee_user_id: Option<&'a str>,
    /// Items to start with: (kind, ref).
    pub items: &'a [(&'a str, &'a str)],
}

/// An item's outcome.
#[derive(Clone, Copy, Debug)]
pub struct OutcomeChange<'a> {
    /// One of [`OUTCOMES`].
    pub outcome: &'a str,
    /// Required for all but `resolved`.
    pub note: Option<&'a str>,
    /// Required for `accepted_risk`, and only there: a time in the next
    /// [`MAX_ACCEPT_DAYS`] days.
    pub outcome_until: Option<DateTime<Utc>>,
}

/// Who is asking about a case and what they can see.
struct Viewer<'a> {
    global: bool,
    groups: Vec<String>,
    user_id: &'a str,
}

impl<'a> Viewer<'a> {
    fn new(scope: &AgentScope, user_id: &'a str) -> Self {
        Self {
            global: scope.is_global(),
            groups: scope.group_ids(),
            user_id,
        }
    }
}

/// The first three query parameters: scope and user.
macro_rules! viewer_params {
    ($v:expr $(, $rest:expr)* $(,)?) => {
        &[&$v.global, &$v.groups, &$v.user_id $(, $rest)*]
    };
}

mod close;
mod events;
mod items;
mod list;
mod outcomes;
mod reopen;
mod visibility;

pub use close::update;
pub use events::add_note;
use items::free_text_ok;
pub use items::{add_item, create, remove_item};
pub(crate) use list::case_number;
pub use list::{
    ACTIVE_ITEMS_LIMIT, AssigneeFilter, CaseCursor, CaseFilters, active_items, assignees, for_item,
    get, list,
};
pub use outcomes::set_outcome;
pub use reopen::{reopen_due, reopen_evidence_returned, reopen_expired};
pub(crate) use visibility::{
    CASE_COLUMNS, CASE_JOINS, blocking_item, case_counts, case_visible, case_visible_with,
    item_in_scope, item_visible, summary_from_row,
};

/// True for a canonical UUID (8-4-4-4-12 hex, any case). Other ids are simply
/// not found, before any query, so a cast can never fail.
pub(crate) fn is_uuid(id: &str) -> bool {
    id.len() == 36
        && id.char_indices().all(|(index, c)| match index {
            8 | 13 | 18 | 23 => c == '-',
            _ => c.is_ascii_hexdigit(),
        })
}

/// The case severity an item severity counts as.
pub fn case_severity_of(item_severity: &str) -> Option<&'static str> {
    Some(match item_severity {
        "critical" => "critical",
        "high" | "important" => "high",
        "medium" | "moderate" => "medium",
        "low" | "info" | "unrated" => "low",
        _ => return None,
    })
}

fn severity_rank(severity: &str) -> u8 {
    match severity {
        "critical" => 3,
        "high" => 2,
        "medium" => 1,
        _ => 0,
    }
}

/// The highest of the items' severities; medium when none has one.
fn default_severity<'a>(items: impl IntoIterator<Item = Option<&'a str>>) -> &'static str {
    items
        .into_iter()
        .flatten()
        .filter_map(case_severity_of)
        .max_by_key(|severity| severity_rank(severity))
        .unwrap_or("medium")
}

fn title_ok(title: &str) -> bool {
    free_text_ok(title, MAX_TITLE_CHARS) && title.trim() == title
}

fn severity_ok(severity: &str) -> bool {
    matches!(severity, "critical" | "high" | "medium" | "low")
}

/// A note's text: bounded, not blank, plain text (line breaks and tabs
/// allowed).
fn note_ok(text: &str) -> bool {
    !text.trim().is_empty()
        && text.chars().count() <= MAX_NOTE_CHARS
        && !text
            .chars()
            .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
}

async fn refuse<T>(
    tx: deadpool_postgres::Transaction<'_>,
    refusal: Refusal,
) -> Result<Result<T, Refusal>, StoreError> {
    tx.rollback().await?;
    Ok(Err(refusal))
}

fn unique_violation(error: &tokio_postgres::Error) -> bool {
    error.code() == Some(&SqlState::UNIQUE_VIOLATION)
}

#[cfg(test)]
mod tests;
