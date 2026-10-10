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
use deadpool_postgres::GenericClient;
use serde_json::{Value, json};
use tokio_postgres::{Row, error::SqlState};

use crate::{
    Client, StoreError,
    console_read::{AgentScope, agent_visibility},
};

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
    /// `mitigated`, `false_positive` or `accepted_risk` once closed.
    pub resolution: Option<String>,
    /// When accepted risk runs out.
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
    /// `resolved`, `false_positive` or `accepted_risk`.
    pub outcome: Option<String>,
    /// Why, for the last two.
    pub outcome_note: Option<String>,
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
    /// Why it was closed.
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
    /// How the case ended; only when `status` is `closed`.
    pub resolution: Option<&'a str>,
    /// Why; required with a resolution.
    pub resolution_note: Option<&'a str>,
    /// When accepted risk runs out; required for `accepted_risk` and a
    /// future time.
    pub accepted_until: Option<DateTime<Utc>>,
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
    /// `resolved`, `false_positive` or `accepted_risk`.
    pub outcome: &'a str,
    /// Required for the last two.
    pub note: Option<&'a str>,
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

/// Items an item row may be seen through: software always, the rest when
/// their agent is in the caller's scope. Uses `$1` and `$2`.
fn item_visible(item: &str) -> String {
    format!(
        "({item}.agent_id IS NULL OR EXISTS (SELECT 1 FROM agents a
            WHERE a.agent_id = {item}.agent_id AND {}))",
        agent_visibility("a.agent_id", "$1", "$2")
    )
}

/// A case the caller can see: they opened it, it is assigned to them, or
/// one of its items is visible to them. Uses `$1`, `$2` and `$3`.
fn case_visible(case: &str) -> String {
    format!(
        "({case}.opened_by_user_id = $3::text::uuid
          OR {case}.assignee_user_id IS NOT DISTINCT FROM $3::text::uuid
          OR EXISTS (SELECT 1 FROM case_items vi WHERE vi.case_id = {case}.case_id AND {}))",
        item_visible("vi")
    )
}

const CASE_COLUMNS: &str = "c.case_id::text, c.number, c.title, c.status, c.resolution,
    c.accepted_until, c.severity, c.assignee_user_id::text, au.username, au.display_name,
    c.opened_by_user_id::text, ou.username, ou.display_name, c.created_at, c.updated_at,
    c.closed_at, c.version::bigint, c.resolution_note";

const CASE_JOINS: &str = "JOIN console_users ou ON ou.user_id = c.opened_by_user_id
    LEFT JOIN console_users au ON au.user_id = c.assignee_user_id";

/// Counts of the case's items the caller can see (columns 18 and 19).
fn case_counts() -> String {
    let visible = item_visible("ci");
    format!(
        "(SELECT count(*) FROM case_items ci WHERE ci.case_id = c.case_id AND {visible}),
         (SELECT count(*) FROM case_items ci WHERE ci.case_id = c.case_id
            AND ci.kind IN ('alarm', 'compliance_finding', 'vulnerability') AND ci.outcome IS NULL
            AND {visible})"
    )
}

/// The agent of a finding or vulnerability item, or its other parts.
const REF_PART_2: &str = "split_part(i.ref, '/', 2)";
const REF_PART_3: &str = "split_part(i.ref, '/', 3)";
/// Everything after the first `/`: an advisory id, a package name.
const REF_TAIL: &str = "substr(i.ref, strpos(i.ref, '/') + 1)";

/// What to show for an item (alias `i`, hosts joined as `ha`).
fn item_title() -> String {
    format!(
        "CASE i.kind
            WHEN 'alarm' THEN (SELECT al.message FROM alarms al WHERE al.id = i.ref::bigint)
            WHEN 'compliance_finding' THEN (SELECT f.message FROM current_findings f
                WHERE f.agent_id = i.agent_id AND f.rule_set_id = {REF_PART_2}
                  AND f.rule_id = {REF_PART_3})
            WHEN 'vulnerability' THEN (SELECT ad.title FROM advisories ad
                WHERE ad.advisory_id = {REF_TAIL})
            WHEN 'host' THEN ha.hostname
            ELSE {REF_TAIL}
        END"
    )
}

/// An item's own severity.
fn item_severity() -> String {
    format!(
        "CASE i.kind
            WHEN 'alarm' THEN (SELECT al.severity FROM alarms al WHERE al.id = i.ref::bigint)
            WHEN 'compliance_finding' THEN (SELECT f.severity FROM current_findings f
                WHERE f.agent_id = i.agent_id AND f.rule_set_id = {REF_PART_2}
                  AND f.rule_id = {REF_PART_3})
            WHEN 'vulnerability' THEN (SELECT ad.severity FROM advisories ad
                WHERE ad.advisory_id = {REF_TAIL})
        END"
    )
}

/// True when the evidence an item stands for is gone (alias `i`).
fn item_gone() -> String {
    format!(
        "CASE i.kind
            WHEN 'alarm' THEN NOT EXISTS (SELECT 1 FROM alarms al
                WHERE al.id = i.ref::bigint AND al.state <> 'mitigated')
            WHEN 'compliance_finding' THEN NOT EXISTS (SELECT 1 FROM current_findings f
                WHERE f.agent_id = i.agent_id AND f.rule_set_id = {REF_PART_2}
                  AND f.rule_id = {REF_PART_3} AND f.ended_at IS NULL)
            WHEN 'vulnerability' THEN
                NOT EXISTS (SELECT 1 FROM vulnerabilities v
                    WHERE v.agent_id = i.agent_id AND v.advisory_id = {REF_TAIL}
                      AND v.fixed_at IS NULL)
                AND NOT EXISTS (SELECT 1 FROM version_vulnerabilities vv
                    JOIN host_packages hp ON hp.package_version_id = vv.package_version_id
                    WHERE hp.agent_id = i.agent_id AND vv.advisory_id = {REF_TAIL})
            ELSE false
        END"
    )
}

fn user_ref(id: String, username: String, display_name: String) -> UserRef {
    UserRef {
        user_id: id,
        username,
        display_name,
    }
}

fn summary_from_row(row: &Row) -> CaseSummary {
    CaseSummary {
        case_id: row.get(0),
        number: row.get(1),
        title: row.get(2),
        status: row.get(3),
        resolution: row.get(4),
        accepted_until: row.get(5),
        severity: row.get(6),
        assignee: row
            .get::<_, Option<String>>(7)
            .map(|id| user_ref(id, row.get(8), row.get(9))),
        opened_by: user_ref(row.get(10), row.get(11), row.get(12)),
        created_at: row.get(13),
        updated_at: row.get(14),
        closed_at: row.get(15),
        version: row.get(16),
        items: row.get(18),
        pending_items: row.get(19),
    }
}

fn item_from_row(row: &Row) -> CaseItem {
    CaseItem {
        item_id: row.get(0),
        kind: row.get(1),
        reference: row.get(2),
        agent_id: row.get(3),
        hostname: row.get(4),
        active: row.get(5),
        outcome: row.get(6),
        outcome_note: row.get(7),
        added_by: user_ref(row.get(8), row.get(9), row.get(10)),
        added_at: row.get(11),
        title: row.get(12),
        severity: row.get(13),
        evidence_gone: row.get(14),
    }
}

fn event_from_row(row: &Row) -> CaseEvent {
    CaseEvent {
        event_id: row.get(0),
        at: row.get(1),
        actor: row
            .get::<_, Option<String>>(2)
            .map(|id| user_ref(id, row.get(3), row.get(4))),
        kind: row.get(5),
        body: row.get(6),
        detail: row.get(7),
    }
}

/// True for a canonical UUID (8-4-4-4-12 hex, any case). Other ids are simply
/// not found, before any query, so a cast can never fail.
fn is_uuid(id: &str) -> bool {
    id.len() == 36
        && id.char_indices().all(|(index, c)| match index {
            8 | 13 | 18 | 23 => c == '-',
            _ => c.is_ascii_hexdigit(),
        })
}

fn identifier_ok(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 128
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
}

fn free_text_ok(text: &str, longest: usize) -> bool {
    !text.is_empty() && text.chars().count() <= longest && !text.chars().any(char::is_control)
}

/// The parts of an item's ref, checked for its kind.
#[derive(Clone, Debug, Eq, PartialEq)]
enum Parsed<'a> {
    Alarm(i64),
    Finding(&'a str, &'a str, &'a str),
    Vulnerability(&'a str, &'a str),
    Host(&'a str),
    Software(&'a str, &'a str),
}

/// Checks `reference` against the shape its kind has in the console, so
/// that what is stored is exactly what the panels would write.
fn parse_ref(kind: ItemKind, reference: &str) -> Option<Parsed<'_>> {
    match kind {
        ItemKind::Alarm => {
            let id: i64 = reference.parse().ok()?;
            (id > 0 && id.to_string() == reference).then_some(Parsed::Alarm(id))
        }
        ItemKind::Finding => {
            let mut parts = reference.split('/');
            let (agent, set, rule) = (parts.next()?, parts.next()?, parts.next()?);
            // A rule set may be empty (findings from before rule sets).
            (parts.next().is_none()
                && identifier_ok(agent)
                && (set.is_empty() || identifier_ok(set))
                && identifier_ok(rule))
            .then_some(Parsed::Finding(agent, set, rule))
        }
        ItemKind::Vulnerability => {
            let (agent, advisory) = reference.split_once('/')?;
            (identifier_ok(agent) && free_text_ok(advisory, 256))
                .then_some(Parsed::Vulnerability(agent, advisory))
        }
        ItemKind::Host => identifier_ok(reference).then_some(Parsed::Host(reference)),
        ItemKind::Software => {
            let (manager, name) = reference.split_once('/')?;
            (identifier_ok(manager) && free_text_ok(name, 256))
                .then_some(Parsed::Software(manager, name))
        }
    }
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

/// The `C-104`, `c104` or `104` a search text may be.
fn case_number(text: &str) -> Option<i64> {
    let digits = text
        .strip_prefix("C-")
        .or_else(|| text.strip_prefix("c-"))
        .or_else(|| text.strip_prefix(['C', 'c']))
        .unwrap_or(text);
    digits.parse().ok().filter(|number: &i64| *number > 0)
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

async fn audit(
    tx: &impl GenericClient,
    actor: Option<&str>,
    action: &str,
    case_id: &str,
    detail: Value,
) -> Result<(), StoreError> {
    match actor {
        Some(user_id) => {
            tx.execute(
                "INSERT INTO audit_log (actor, action, target, result, detail,
                     actor_kind, actor_id, actor_display, target_kind, target_id)
                 SELECT $1, $2, $3, 'success', $4, 'user', $1, u.display_name, 'case', $3
                 FROM console_users u WHERE u.user_id = $1::text::uuid",
                &[&user_id, &action, &case_id, &detail],
            )
            .await?;
        }
        None => {
            tx.execute(
                "INSERT INTO audit_log (actor, action, target, result, detail,
                     actor_kind, actor_display, target_kind, target_id)
                 VALUES ('system', $1, $2, 'success', $3, 'system', 'system', 'case', $2)",
                &[&action, &case_id, &detail],
            )
            .await?;
        }
    }
    Ok(())
}

async fn push_event(
    tx: &impl GenericClient,
    case_id: &str,
    at: DateTime<Utc>,
    actor: Option<&str>,
    kind: &str,
    body: Option<&str>,
    detail: Value,
) -> Result<(), StoreError> {
    tx.execute(
        "INSERT INTO case_events (case_id, at, actor_user_id, kind, body, detail)
         VALUES ($1::text::uuid, $2, $3::text::uuid, $4, $5, $6)",
        &[&case_id, &at, &actor, &kind, &body, &detail],
    )
    .await?;
    Ok(())
}

async fn touch(
    tx: &impl GenericClient,
    case_id: &str,
    now: DateTime<Utc>,
) -> Result<(), StoreError> {
    tx.execute(
        "UPDATE cases SET updated_at = GREATEST(updated_at, $2) WHERE case_id = $1::text::uuid",
        &[&case_id, &now],
    )
    .await?;
    Ok(())
}

/// The case, if the viewer can see it.
async fn read_summary(
    db: &impl GenericClient,
    viewer: &Viewer<'_>,
    case_id: &str,
) -> Result<Option<(CaseSummary, Option<String>)>, StoreError> {
    if !is_uuid(case_id) {
        return Ok(None);
    }
    let counts = case_counts();
    let visible = case_visible("c");
    let row = db
        .query_opt(
            &format!(
                "SELECT {CASE_COLUMNS}, {counts} FROM cases c {CASE_JOINS}
                 WHERE c.case_id = $4::text::uuid AND {visible}"
            ),
            viewer_params!(viewer, &case_id),
        )
        .await?;
    Ok(row.map(|row| (summary_from_row(&row), row.get(17))))
}

/// The viewer's visible items, oldest first; one when `item_id` is given.
async fn read_items(
    db: &impl GenericClient,
    viewer: &Viewer<'_>,
    case_id: &str,
    item_id: Option<&str>,
) -> Result<Vec<CaseItem>, StoreError> {
    let (title, severity, gone, visible) = (
        item_title(),
        item_severity(),
        item_gone(),
        item_visible("i"),
    );
    let rows = db
        .query(
            &format!(
                "SELECT i.item_id::text, i.kind, i.ref, i.agent_id, ha.hostname, i.active,
                    i.outcome, i.outcome_note, i.added_by_user_id::text, ub.username,
                    ub.display_name, i.added_at, {title}, {severity}, {gone}
                 FROM case_items i
                 JOIN console_users ub ON ub.user_id = i.added_by_user_id
                 LEFT JOIN agents ha ON ha.agent_id = i.agent_id
                 WHERE i.case_id = $4::text::uuid AND {visible} AND $3::text IS NOT NULL
                   AND ($5::text IS NULL OR i.item_id = $5::text::uuid)
                 ORDER BY i.added_at, i.seq"
            ),
            viewer_params!(viewer, &case_id, &item_id),
        )
        .await?;
    Ok(rows.iter().map(item_from_row).collect())
}

/// The timeline without entries about items the viewer cannot see.
async fn read_events(
    db: &impl GenericClient,
    viewer: &Viewer<'_>,
    case_id: &str,
) -> Result<Vec<CaseEvent>, StoreError> {
    let visible = agent_visibility("a.agent_id", "$1", "$2");
    let rows = db
        .query(
            &format!(
                "SELECT e.event_id, e.at, e.actor_user_id::text, u.username, u.display_name,
                    e.kind, e.body, e.detail
                 FROM case_events e LEFT JOIN console_users u ON u.user_id = e.actor_user_id
                 WHERE e.case_id = $4::text::uuid AND $3::text IS NOT NULL
                   AND (e.detail->>'item_agent_id' IS NULL OR EXISTS (
                        SELECT 1 FROM agents a
                        WHERE a.agent_id = e.detail->>'item_agent_id' AND {visible}))
                 ORDER BY e.event_id"
            ),
            viewer_params!(viewer, &case_id),
        )
        .await?;
    Ok(rows.iter().map(event_from_row).collect())
}

async fn read_detail(
    db: &impl GenericClient,
    viewer: &Viewer<'_>,
    case_id: &str,
) -> Result<Option<CaseDetail>, StoreError> {
    let Some((summary, resolution_note)) = read_summary(db, viewer, case_id).await? else {
        return Ok(None);
    };
    Ok(Some(CaseDetail {
        summary,
        resolution_note,
        items: read_items(db, viewer, case_id, None).await?,
        events: read_events(db, viewer, case_id).await?,
    }))
}

/// Filters for [`list`].
#[derive(Clone, Debug, Default)]
pub struct CaseFilters {
    /// `open`, `investigating`, `closed`, `all`, or `None` for open and
    /// investigating.
    pub status: Option<String>,
    /// Exact severity.
    pub severity: Option<String>,
    /// Who the case is assigned to.
    pub assignee: AssigneeFilter,
    /// Text in the title, or a case number (`C-104`, `104`).
    pub q: Option<String>,
}

/// Who a case is assigned to, for [`CaseFilters`].
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum AssigneeFilter {
    /// Anyone, or nobody.
    #[default]
    Anyone,
    /// Nobody.
    Nobody,
    /// This user id.
    User(String),
}

/// Where the next page starts: after this `(updated_at, case_id)`.
pub type CaseCursor = (DateTime<Utc>, String);

/// The cases the caller can see, newest change first.
pub async fn list(
    client: &Client,
    scope: &AgentScope,
    user_id: &str,
    filters: &CaseFilters,
    after: Option<&CaseCursor>,
    limit: i64,
) -> Result<Vec<CaseSummary>, StoreError> {
    let viewer = Viewer::new(scope, user_id);
    let status = filters.status.as_deref().unwrap_or("active");
    let (mode, who): (&str, Option<&str>) = match &filters.assignee {
        AssigneeFilter::Anyone => ("any", None),
        AssigneeFilter::Nobody => ("none", None),
        AssigneeFilter::User(id) if is_uuid(id) => ("user", Some(id.as_str())),
        // Not a user id: matches nobody.
        AssigneeFilter::User(_) => ("user", Some("00000000-0000-0000-0000-000000000000")),
    };
    let q = filters
        .q
        .as_deref()
        .map(str::trim)
        .filter(|q| !q.is_empty());
    let number = q.and_then(case_number);
    let (cursor_at, cursor_id) = after.map_or((None, None), |(at, id)| {
        (Some(*at), is_uuid(id).then_some(id.as_str()))
    });
    let (counts, visible) = (case_counts(), case_visible("c"));
    let rows = client
        .query(
            &format!(
                "SELECT {CASE_COLUMNS}, {counts} FROM cases c {CASE_JOINS}
                 WHERE {visible}
                   AND ($4::text = 'all' OR ($4 = 'active' AND c.status <> 'closed')
                        OR c.status = $4)
                   AND ($5::text IS NULL OR c.severity = $5)
                   AND ($6::text = 'any' OR ($6 = 'none' AND c.assignee_user_id IS NULL)
                        OR ($6 = 'user' AND c.assignee_user_id = $7::text::uuid))
                   AND ($8::text IS NULL OR c.number = $9::bigint
                        OR strpos(lower(c.title), lower($8)) > 0)
                   AND ($10::timestamptz IS NULL
                        OR (c.updated_at, c.case_id) < ($10, $11::text::uuid))
                 ORDER BY c.updated_at DESC, c.case_id DESC LIMIT $12"
            ),
            viewer_params!(
                viewer,
                &status,
                &filters.severity,
                &mode,
                &who,
                &q,
                &number,
                &cursor_at,
                &cursor_id,
                &limit
            ),
        )
        .await?;
    Ok(rows.iter().map(summary_from_row).collect())
}

/// One case with its visible items and timeline, if the caller can see it.
pub async fn get(
    client: &Client,
    scope: &AgentScope,
    user_id: &str,
    case_id: &str,
) -> Result<Option<CaseDetail>, StoreError> {
    read_detail(client, &Viewer::new(scope, user_id), case_id).await
}

/// An enabled user who holds `cases.read` through a live role binding.
const READS_CASES: &str = "u.enabled AND EXISTS (
    SELECT 1 FROM console_role_bindings b
    JOIN console_role_permissions rp ON rp.role_id = b.role_id
    WHERE b.user_id = u.user_id AND b.revoked_at IS NULL AND rp.permission_id = 'cases.read')";

/// Users a case can be assigned to: enabled users with `cases.read`.
pub async fn assignees(client: &Client) -> Result<Vec<UserRef>, StoreError> {
    let rows = client
        .query(
            &format!(
                "SELECT u.user_id::text, u.username, u.display_name FROM console_users u
                 WHERE {READS_CASES} ORDER BY lower(u.display_name), u.username"
            ),
            &[],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|row| user_ref(row.get(0), row.get(1), row.get(2)))
        .collect())
}

async fn assignee_available(db: &impl GenericClient, user_id: &str) -> Result<bool, StoreError> {
    if !is_uuid(user_id) {
        return Ok(false);
    }
    Ok(db
        .query_opt(
            &format!(
                "SELECT 1 FROM console_users u WHERE u.user_id = $1::text::uuid AND {READS_CASES}"
            ),
            &[&user_id],
        )
        .await?
        .is_some())
}

async fn username(db: &impl GenericClient, user_id: Option<&str>) -> Result<Value, StoreError> {
    let Some(user_id) = user_id else {
        return Ok(Value::Null);
    };
    Ok(db
        .query_opt(
            "SELECT username FROM console_users WHERE user_id = $1::text::uuid",
            &[&user_id],
        )
        .await?
        .map_or(Value::Null, |row| json!(row.get::<_, String>(0))))
}

/// What an item resolves to when it is added.
struct Resolved<'a> {
    kind: ItemKind,
    reference: &'a str,
    agent_id: Option<String>,
    severity: Option<String>,
}

/// Checks the item's shape and that the viewer can see the object it
/// points at; a missing and a hidden object are the same answer.
async fn resolve_item<'a>(
    db: &impl GenericClient,
    viewer: &Viewer<'_>,
    kind: &str,
    reference: &'a str,
) -> Result<Result<Resolved<'a>, Refusal>, StoreError> {
    let Some(kind) = ItemKind::parse(kind) else {
        return Ok(Err(Refusal::Invalid("kind", "invalid_kind")));
    };
    let Some(parsed) = parse_ref(kind, reference) else {
        return Ok(Err(Refusal::Invalid("ref", "invalid_ref")));
    };
    let visible = agent_visibility("a.agent_id", "$1", "$2");
    let found = match parsed {
        Parsed::Alarm(id) => {
            db.query_opt(
                &format!(
                    "SELECT al.agent_id, al.severity FROM alarms al
                     JOIN agents a ON a.agent_id = al.agent_id WHERE al.id = $3 AND {visible}"
                ),
                &[&viewer.global, &viewer.groups, &id],
            )
            .await?
        }
        Parsed::Finding(agent, set, rule) => {
            db.query_opt(
                &format!(
                    "SELECT f.agent_id, f.severity FROM current_findings f
                     JOIN agents a ON a.agent_id = f.agent_id
                     WHERE f.agent_id = $3 AND f.rule_set_id = $4 AND f.rule_id = $5
                       AND {visible}"
                ),
                &[&viewer.global, &viewer.groups, &agent, &set, &rule],
            )
            .await?
        }
        Parsed::Vulnerability(agent, advisory) => {
            db.query_opt(
                &format!(
                    "SELECT a.agent_id, (SELECT ad.severity FROM advisories ad
                                         WHERE ad.advisory_id = $4)
                     FROM agents a WHERE a.agent_id = $3 AND {visible}
                       AND (EXISTS (SELECT 1 FROM vulnerabilities v
                                    WHERE v.agent_id = a.agent_id AND v.advisory_id = $4)
                            OR EXISTS (SELECT 1 FROM version_vulnerabilities vv
                                JOIN host_packages hp
                                  ON hp.package_version_id = vv.package_version_id
                                WHERE hp.agent_id = a.agent_id AND vv.advisory_id = $4))"
                ),
                &[&viewer.global, &viewer.groups, &agent, &advisory],
            )
            .await?
        }
        Parsed::Host(agent) => {
            db.query_opt(
                &format!(
                    "SELECT a.agent_id, NULL::text FROM agents a
                     WHERE a.agent_id = $3 AND {visible}"
                ),
                &[&viewer.global, &viewer.groups, &agent],
            )
            .await?
        }
        // Software is visible to a reader, but only if a host they can see
        // has it, so that adding it never says whether other hosts do.
        Parsed::Software(manager, name) => {
            db.query_opt(
                &format!(
                    "SELECT NULL::text, NULL::text WHERE EXISTS (
                        SELECT 1 FROM package_versions pv
                        JOIN host_packages hp ON hp.package_version_id = pv.id
                        JOIN agents a ON a.agent_id = hp.agent_id
                        WHERE pv.manager = $3 AND pv.name = $4 AND {visible})"
                ),
                &[&viewer.global, &viewer.groups, &manager, &name],
            )
            .await?
        }
    };
    Ok(match found {
        Some(row) => Ok(Resolved {
            kind,
            reference,
            agent_id: row.get(0),
            severity: row.get(1),
        }),
        None => Err(Refusal::ItemNotFound),
    })
}

/// Adds a resolved item to an open case (locked by the caller).
async fn insert_item(
    tx: &impl GenericClient,
    viewer: &Viewer<'_>,
    case_id: &str,
    item: &Resolved<'_>,
    now: DateTime<Utc>,
) -> Result<Result<String, Refusal>, StoreError> {
    let kind = item.kind.as_str();
    let held: i64 = tx
        .query_one(
            "SELECT count(*) FROM case_items WHERE case_id = $1::text::uuid",
            &[&case_id],
        )
        .await?
        .get(0);
    if held >= MAX_ITEMS_PER_CASE {
        return Ok(Err(Refusal::TooManyItems));
    }
    let same = tx
        .query_opt(
            "SELECT 1 FROM case_items WHERE case_id = $1::text::uuid AND kind = $2 AND ref = $3",
            &[&case_id, &kind, &item.reference],
        )
        .await?;
    if same.is_some() {
        return Ok(Err(Refusal::AlreadyInCase));
    }
    if item.kind.exclusive() {
        let visible = case_visible("oc");
        let other = tx
            .query_opt(
                &format!(
                    "SELECT oc.number, {visible} FROM case_items o
                     JOIN cases oc ON oc.case_id = o.case_id
                     WHERE o.kind = $5 AND o.ref = $6 AND o.active
                       AND o.case_id <> $4::text::uuid"
                ),
                viewer_params!(viewer, &case_id, &kind, &item.reference),
            )
            .await?;
        if let Some(row) = other {
            let number: i64 = row.get(0);
            let seen: bool = row.get(1);
            return Ok(Err(Refusal::ItemInCase(seen.then_some(number))));
        }
    }
    let inserted = tx
        .query_one(
            "INSERT INTO case_items (item_id, case_id, kind, ref, agent_id, active,
                 added_by_user_id, added_at)
             VALUES (gen_random_uuid(), $1::text::uuid, $2, $3, $4, true, $5::text::uuid, $6)
             RETURNING item_id::text",
            &[
                &case_id,
                &kind,
                &item.reference,
                &item.agent_id,
                &viewer.user_id,
                &now,
            ],
        )
        .await;
    match inserted {
        Ok(row) => Ok(Ok(row.get(0))),
        // Two requests raced past the checks above.
        Err(error) if unique_violation(&error) => Ok(Err(Refusal::ItemInCase(None))),
        Err(error) => Err(error.into()),
    }
}

/// The item's timeline entry and audit row. The agent goes into the
/// detail so that the timeline can be filtered by scope.
async fn record_item_added(
    tx: &impl GenericClient,
    viewer: &Viewer<'_>,
    case_id: &str,
    number: i64,
    item: &Resolved<'_>,
    item_id: &str,
    now: DateTime<Utc>,
) -> Result<(), StoreError> {
    let kind = item.kind.as_str();
    push_event(
        tx,
        case_id,
        now,
        Some(viewer.user_id),
        "item_added",
        None,
        json!({ "item_id": item_id, "item_kind": kind, "item_ref": item.reference,
                "item_agent_id": item.agent_id }),
    )
    .await?;
    audit(
        tx,
        Some(viewer.user_id),
        "case.item.add",
        case_id,
        json!({ "number": number, "kind": kind, "ref": item.reference }),
    )
    .await
}

/// Opens a case. The caller sees it afterwards because they opened it.
pub async fn create(
    client: &mut Client,
    scope: &AgentScope,
    user_id: &str,
    new: &NewCase<'_>,
    now: DateTime<Utc>,
) -> Result<Result<CaseDetail, Refusal>, StoreError> {
    if !title_ok(new.title) {
        return Ok(Err(Refusal::Invalid("title", "invalid_title")));
    }
    if new.severity.is_some_and(|severity| !severity_ok(severity)) {
        return Ok(Err(Refusal::Invalid("severity", "invalid_severity")));
    }
    if new.items.len() > MAX_ITEMS_ON_CREATE {
        return Ok(Err(Refusal::Invalid("items", "too_many_items")));
    }
    let viewer = Viewer::new(scope, user_id);
    let tx = client.transaction().await?;
    if let Some(assignee) = new.assignee_user_id
        && !assignee_available(&tx, assignee).await?
    {
        return refuse(tx, Refusal::AssigneeUnavailable).await;
    }
    let mut resolved = Vec::with_capacity(new.items.len());
    for (kind, reference) in new.items {
        match resolve_item(&tx, &viewer, kind, reference).await? {
            Ok(item) => resolved.push(item),
            Err(refusal) => return refuse(tx, refusal).await,
        }
    }
    let severity = new
        .severity
        .unwrap_or_else(|| default_severity(resolved.iter().map(|item| item.severity.as_deref())));
    let row = tx
        .query_one(
            "INSERT INTO cases (case_id, title, status, severity, assignee_user_id,
                 opened_by_user_id, created_at, updated_at)
             VALUES (gen_random_uuid(), $1, 'open', $2, $3::text::uuid, $4::text::uuid, $5, $5)
             RETURNING case_id::text, number",
            &[&new.title, &severity, &new.assignee_user_id, &user_id, &now],
        )
        .await?;
    let (case_id, number): (String, i64) = (row.get(0), row.get(1));
    push_event(
        &tx,
        &case_id,
        now,
        Some(user_id),
        "created",
        None,
        json!({ "severity": severity }),
    )
    .await?;
    if let Some(assignee) = new.assignee_user_id {
        let name = username(&tx, Some(assignee)).await?;
        push_event(
            &tx,
            &case_id,
            now,
            Some(user_id),
            "assigned",
            None,
            json!({ "from": null, "to": name }),
        )
        .await?;
    }
    audit(
        &tx,
        Some(user_id),
        "case.create",
        &case_id,
        json!({ "number": number, "severity": severity, "items": resolved.len() }),
    )
    .await?;
    for item in &resolved {
        match insert_item(&tx, &viewer, &case_id, item, now).await? {
            Ok(item_id) => {
                record_item_added(&tx, &viewer, &case_id, number, item, &item_id, now).await?;
            }
            Err(refusal) => return refuse(tx, refusal).await,
        }
    }
    let Some(created) = read_detail(&tx, &viewer, &case_id).await? else {
        return Err(StoreError::Query);
    };
    tx.commit().await?;
    Ok(Ok(created))
}

/// A case row as locked for a change.
struct Locked {
    number: i64,
    title: String,
    status: String,
    severity: String,
    assignee: Option<String>,
    resolution: Option<String>,
    resolution_note: Option<String>,
    accepted_until: Option<DateTime<Utc>>,
    version: i64,
}

/// Locks the case if the viewer can see it.
async fn lock_case(
    tx: &impl GenericClient,
    viewer: &Viewer<'_>,
    case_id: &str,
) -> Result<Option<Locked>, StoreError> {
    if !is_uuid(case_id) {
        return Ok(None);
    }
    let visible = case_visible("c");
    let row = tx
        .query_opt(
            &format!(
                "SELECT c.number, c.title, c.status, c.severity, c.assignee_user_id::text,
                    c.resolution, c.resolution_note, c.accepted_until, c.version::bigint
                 FROM cases c WHERE c.case_id = $4::text::uuid AND {visible} FOR UPDATE OF c"
            ),
            viewer_params!(viewer, &case_id),
        )
        .await?;
    Ok(row.map(|row| Locked {
        number: row.get(0),
        title: row.get(1),
        status: row.get(2),
        severity: row.get(3),
        assignee: row.get(4),
        resolution: row.get(5),
        resolution_note: row.get(6),
        accepted_until: row.get(7),
        version: row.get(8),
    }))
}

/// Checks the resolution fields a request states for its new status.
fn resolution_valid(
    change: &CaseChange<'_>,
    now: DateTime<Utc>,
) -> Result<(), (&'static str, &'static str)> {
    if change.status != "closed" {
        return if change.resolution.is_some()
            || change.resolution_note.is_some()
            || change.accepted_until.is_some()
        {
            Err(("resolution", "resolution_not_allowed"))
        } else {
            Ok(())
        };
    }
    let Some(resolution) = change.resolution else {
        return Err(("resolution", "resolution_required"));
    };
    if !matches!(resolution, "mitigated" | "false_positive" | "accepted_risk") {
        return Err(("resolution", "invalid_resolution"));
    }
    match change.resolution_note {
        None => return Err(("resolution_note", "resolution_note_required")),
        Some(note) if !note_ok(note) => return Err(("resolution_note", "invalid_note")),
        Some(_) => {}
    }
    match (resolution == "accepted_risk", change.accepted_until) {
        (true, None) => Err(("accepted_until", "accepted_until_required")),
        (true, Some(until)) if until <= now => Err(("accepted_until", "accepted_until_past")),
        (false, Some(_)) => Err(("accepted_until", "accepted_until_not_allowed")),
        _ => Ok(()),
    }
}

/// Alarm, finding and vulnerability items that still stand in the way of
/// closing: without an outcome, or resolved while the evidence is back.
/// Returns (visible, hidden) counts.
async fn blocking_items(
    tx: &impl GenericClient,
    viewer: &Viewer<'_>,
    case_id: &str,
) -> Result<(i64, i64), StoreError> {
    let (gone, visible) = (item_gone(), item_visible("i"));
    let rows = tx
        .query(
            &format!(
                "SELECT s.seen, count(*) FROM (
                    SELECT {visible} AS seen FROM case_items i
                    WHERE i.case_id = $4::text::uuid AND $3::text IS NOT NULL
                      AND i.kind IN ('alarm', 'compliance_finding', 'vulnerability')
                      AND (i.outcome IS NULL OR (i.outcome = 'resolved' AND NOT ({gone}))))
                 s GROUP BY s.seen"
            ),
            viewer_params!(viewer, &case_id),
        )
        .await?;
    let (mut seen, mut hidden) = (0, 0);
    for row in rows {
        if row.get::<_, bool>(0) {
            seen += row.get::<_, i64>(1);
        } else {
            hidden += row.get::<_, i64>(1);
        }
    }
    Ok((seen, hidden))
}

/// Looks for an exclusive item of the case that another open case holds.
async fn reopen_conflict(
    tx: &impl GenericClient,
    viewer: &Viewer<'_>,
    case_id: &str,
) -> Result<Option<Option<i64>>, StoreError> {
    // The other case is named only if the caller can see it and the
    // clashing item.
    let visible = format!("{} AND {}", case_visible("oc"), item_visible("mine"));
    let row = tx
        .query_opt(
            &format!(
                "SELECT oc.number, {visible} FROM case_items mine
                 JOIN case_items o ON o.kind = mine.kind AND o.ref = mine.ref AND o.active
                      AND o.case_id <> mine.case_id
                 JOIN cases oc ON oc.case_id = o.case_id
                 WHERE mine.case_id = $4::text::uuid
                   AND mine.kind IN ('alarm', 'compliance_finding', 'vulnerability')
                 ORDER BY oc.number LIMIT 1"
            ),
            viewer_params!(viewer, &case_id),
        )
        .await?;
    Ok(row.map(|row| row.get::<_, bool>(1).then(|| row.get::<_, i64>(0))))
}

/// Changes a case's title, severity, status, assignee and resolution with a
/// version check. Closing needs a resolution, a note, a future date for
/// accepted risk and an outcome on every alarm, finding and vulnerability;
/// reopening needs that none of its items has joined another open case.
/// Sending the current values changes nothing and writes nothing.
pub async fn update(
    client: &mut Client,
    scope: &AgentScope,
    user_id: &str,
    case_id: &str,
    change: &CaseChange<'_>,
    now: DateTime<Utc>,
) -> Result<Result<CaseDetail, Refusal>, StoreError> {
    if !title_ok(change.title) {
        return Ok(Err(Refusal::Invalid("title", "invalid_title")));
    }
    if !severity_ok(change.severity) {
        return Ok(Err(Refusal::Invalid("severity", "invalid_severity")));
    }
    if !matches!(change.status, "open" | "investigating" | "closed") {
        return Ok(Err(Refusal::Invalid("status", "invalid_status")));
    }
    if let Err((field, code)) = resolution_valid(change, now) {
        return Ok(Err(Refusal::Invalid(field, code)));
    }
    let viewer = Viewer::new(scope, user_id);
    let tx = client.transaction().await?;
    let Some(current) = lock_case(&tx, &viewer, case_id).await? else {
        return refuse(tx, Refusal::NotFound).await;
    };
    if current.version != change.expected_version {
        return refuse(tx, Refusal::Stale).await;
    }
    let (was_closed, will_close) = (current.status == "closed", change.status == "closed");
    // Nothing else about how a closed case ended changes while it stays closed.
    let same_resolution = current.resolution.as_deref() == change.resolution
        && current.resolution_note.as_deref() == change.resolution_note
        && current.accepted_until.map(|at| at.timestamp_micros())
            == change.accepted_until.map(|at| at.timestamp_micros());
    if was_closed && will_close && !same_resolution {
        return refuse(tx, Refusal::Closed).await;
    }
    let assignee_changed = current.assignee.as_deref() != change.assignee_user_id;
    if assignee_changed
        && let Some(assignee) = change.assignee_user_id
        && !assignee_available(&tx, assignee).await?
    {
        return refuse(tx, Refusal::AssigneeUnavailable).await;
    }
    let fields_changed =
        current.title != change.title || current.severity != change.severity || assignee_changed;
    if !fields_changed && current.status == change.status {
        let Some(unchanged) = read_detail(&tx, &viewer, case_id).await? else {
            return Err(StoreError::Query);
        };
        tx.rollback().await?;
        return Ok(Ok(unchanged));
    }
    if !was_closed && will_close {
        let (seen, hidden) = blocking_items(&tx, &viewer, case_id).await?;
        if seen > 0 {
            return refuse(tx, Refusal::ItemsUnresolved(seen)).await;
        }
        if hidden > 0 {
            return refuse(tx, Refusal::HiddenItemsUnresolved).await;
        }
    }
    if was_closed
        && !will_close
        && let Some(number) = reopen_conflict(&tx, &viewer, case_id).await?
    {
        return refuse(tx, Refusal::ItemInCase(number)).await;
    }
    tx.execute(
        "UPDATE cases SET title = $2, severity = $3, status = $4,
            assignee_user_id = $5::text::uuid, resolution = $6, resolution_note = $7,
            accepted_until = $8, closed_at = CASE WHEN $4 = 'closed'
                THEN COALESCE(closed_at, $9) END,
            version = version + 1, updated_at = $9
         WHERE case_id = $1::text::uuid",
        &[
            &case_id,
            &change.title,
            &change.severity,
            &change.status,
            &change.assignee_user_id,
            &change.resolution,
            &change.resolution_note,
            &change.accepted_until,
            &now,
        ],
    )
    .await?;
    if was_closed != will_close {
        let active = !will_close;
        let result = tx
            .execute(
                "UPDATE case_items SET active = $2 WHERE case_id = $1::text::uuid",
                &[&case_id, &active],
            )
            .await;
        match result {
            Ok(_) => {}
            // Another request put one of the items in a new open case.
            Err(error) if unique_violation(&error) => {
                return refuse(tx, Refusal::ItemInCase(None)).await;
            }
            Err(error) => return Err(error.into()),
        }
    }
    if assignee_changed {
        let (from, to) = (
            username(&tx, current.assignee.as_deref()).await?,
            username(&tx, change.assignee_user_id).await?,
        );
        push_event(
            &tx,
            case_id,
            now,
            Some(user_id),
            "assigned",
            None,
            json!({ "from": from, "to": to }),
        )
        .await?;
    }
    if current.severity != change.severity {
        push_event(
            &tx,
            case_id,
            now,
            Some(user_id),
            "severity",
            None,
            json!({ "from": current.severity, "to": change.severity }),
        )
        .await?;
    }
    if will_close && !was_closed {
        push_event(
            &tx,
            case_id,
            now,
            Some(user_id),
            "resolved",
            change.resolution_note,
            json!({ "resolution": change.resolution,
                    "accepted_until": change.accepted_until.map(|at| at.to_rfc3339()) }),
        )
        .await?;
        audit(
            &tx,
            Some(user_id),
            "case.close",
            case_id,
            json!({ "number": current.number, "resolution": change.resolution }),
        )
        .await?;
    } else if was_closed && !will_close {
        push_event(
            &tx,
            case_id,
            now,
            Some(user_id),
            "reopened",
            None,
            json!({ "reason": "manual", "status": change.status,
                    "previous_resolution": current.resolution }),
        )
        .await?;
        audit(
            &tx,
            Some(user_id),
            "case.reopen",
            case_id,
            json!({ "number": current.number, "reason": "manual" }),
        )
        .await?;
    } else if current.status != change.status {
        push_event(
            &tx,
            case_id,
            now,
            Some(user_id),
            "status",
            None,
            json!({ "from": current.status, "to": change.status }),
        )
        .await?;
    }
    if fields_changed || (current.status != change.status && !was_closed && !will_close) {
        audit(
            &tx,
            Some(user_id),
            "case.update",
            case_id,
            json!({ "number": current.number, "title": change.title,
                    "severity": change.severity, "status": change.status,
                    "assigned": assignee_changed }),
        )
        .await?;
    }
    let Some(saved) = read_detail(&tx, &viewer, case_id).await? else {
        return Err(StoreError::Query);
    };
    tx.commit().await?;
    Ok(Ok(saved))
}

/// Appends a note to the timeline. Notes can be added to a closed case.
pub async fn add_note(
    client: &mut Client,
    scope: &AgentScope,
    user_id: &str,
    case_id: &str,
    text: &str,
    now: DateTime<Utc>,
) -> Result<Result<CaseEvent, Refusal>, StoreError> {
    if !note_ok(text) {
        return Ok(Err(Refusal::Invalid("body", "invalid_note")));
    }
    let viewer = Viewer::new(scope, user_id);
    let tx = client.transaction().await?;
    let Some(current) = lock_case(&tx, &viewer, case_id).await? else {
        return refuse(tx, Refusal::NotFound).await;
    };
    let events: i64 = tx
        .query_one(
            "SELECT count(*) FROM case_events WHERE case_id = $1::text::uuid",
            &[&case_id],
        )
        .await?
        .get(0);
    if events >= MAX_EVENTS_PER_CASE {
        return refuse(tx, Refusal::TimelineFull).await;
    }
    let row = tx
        .query_one(
            "INSERT INTO case_events (case_id, at, actor_user_id, kind, body, detail)
             VALUES ($1::text::uuid, $2, $3::text::uuid, 'note', $4, '{}')
             RETURNING event_id",
            &[&case_id, &now, &user_id, &text],
        )
        .await?;
    let event_id: i64 = row.get(0);
    touch(&tx, case_id, now).await?;
    // Never the text: the audit log is read by more people than the case.
    audit(
        &tx,
        Some(user_id),
        "case.note",
        case_id,
        json!({ "number": current.number, "event_id": event_id, "length": text.chars().count() }),
    )
    .await?;
    let events = read_events(&tx, &viewer, case_id).await?;
    let Some(event) = events.into_iter().find(|event| event.event_id == event_id) else {
        return Err(StoreError::Query);
    };
    tx.commit().await?;
    Ok(Ok(event))
}

/// Adds one item to an open case. The viewer must see the object; a
/// missing and a hidden object are the same answer. An alarm, finding or
/// vulnerability that another open case holds is refused.
pub async fn add_item(
    client: &mut Client,
    scope: &AgentScope,
    user_id: &str,
    case_id: &str,
    kind: &str,
    reference: &str,
    now: DateTime<Utc>,
) -> Result<Result<CaseItem, Refusal>, StoreError> {
    let viewer = Viewer::new(scope, user_id);
    let tx = client.transaction().await?;
    let Some(current) = lock_case(&tx, &viewer, case_id).await? else {
        return refuse(tx, Refusal::NotFound).await;
    };
    if current.status == "closed" {
        return refuse(tx, Refusal::Closed).await;
    }
    let item = match resolve_item(&tx, &viewer, kind, reference).await? {
        Ok(item) => item,
        Err(refusal) => return refuse(tx, refusal).await,
    };
    let item_id = match insert_item(&tx, &viewer, case_id, &item, now).await? {
        Ok(item_id) => item_id,
        Err(refusal) => return refuse(tx, refusal).await,
    };
    record_item_added(&tx, &viewer, case_id, current.number, &item, &item_id, now).await?;
    touch(&tx, case_id, now).await?;
    let mut items = read_items(&tx, &viewer, case_id, Some(&item_id)).await?;
    let Some(added) = items.pop() else {
        return Err(StoreError::Query);
    };
    tx.commit().await?;
    Ok(Ok(added))
}

/// An item of the case the viewer can see, as stored.
struct StoredItem {
    kind: ItemKind,
    reference: String,
    agent_id: Option<String>,
    outcome: Option<String>,
    gone: bool,
}

async fn lock_item(
    tx: &impl GenericClient,
    viewer: &Viewer<'_>,
    case_id: &str,
    item_id: &str,
) -> Result<Option<StoredItem>, StoreError> {
    if !is_uuid(item_id) {
        return Ok(None);
    }
    let (gone, visible) = (item_gone(), item_visible("i"));
    let row = tx
        .query_opt(
            &format!(
                "SELECT i.kind, i.ref, i.agent_id, i.outcome, {gone} FROM case_items i
                 WHERE i.case_id = $4::text::uuid AND i.item_id = $5::text::uuid
                   AND {visible} AND $3::text IS NOT NULL
                 FOR UPDATE OF i"
            ),
            viewer_params!(viewer, &case_id, &item_id),
        )
        .await?;
    Ok(row.and_then(|row| {
        Some(StoredItem {
            kind: ItemKind::parse(&row.get::<_, String>(0))?,
            reference: row.get(1),
            agent_id: row.get(2),
            outcome: row.get(3),
            gone: row.get(4),
        })
    }))
}

/// Removes an item from an open case. The timeline keeps that it was there.
pub async fn remove_item(
    client: &mut Client,
    scope: &AgentScope,
    user_id: &str,
    case_id: &str,
    item_id: &str,
    now: DateTime<Utc>,
) -> Result<Result<(), Refusal>, StoreError> {
    let viewer = Viewer::new(scope, user_id);
    let tx = client.transaction().await?;
    let Some(current) = lock_case(&tx, &viewer, case_id).await? else {
        return refuse(tx, Refusal::NotFound).await;
    };
    if current.status == "closed" {
        return refuse(tx, Refusal::Closed).await;
    }
    let Some(item) = lock_item(&tx, &viewer, case_id, item_id).await? else {
        return refuse(tx, Refusal::ItemNotFound).await;
    };
    tx.execute(
        "DELETE FROM case_items WHERE item_id = $1::text::uuid",
        &[&item_id],
    )
    .await?;
    push_event(
        &tx,
        case_id,
        now,
        Some(user_id),
        "item_removed",
        None,
        json!({ "item_id": item_id, "item_kind": item.kind.as_str(),
                "item_ref": item.reference, "item_agent_id": item.agent_id }),
    )
    .await?;
    touch(&tx, case_id, now).await?;
    audit(
        &tx,
        Some(user_id),
        "case.item.remove",
        case_id,
        json!({ "number": current.number, "kind": item.kind.as_str(), "ref": item.reference }),
    )
    .await?;
    tx.commit().await?;
    Ok(Ok(()))
}

/// Sets, or with `None` clears, an item's outcome on an open case.
/// `resolved` needs the evidence to be gone; `false_positive` and
/// `accepted_risk` need a note. Hosts and software take no outcome.
pub async fn set_outcome(
    client: &mut Client,
    scope: &AgentScope,
    user_id: &str,
    case_id: &str,
    item_id: &str,
    change: Option<&OutcomeChange<'_>>,
    now: DateTime<Utc>,
) -> Result<Result<CaseItem, Refusal>, StoreError> {
    if let Some(change) = change {
        if !matches!(
            change.outcome,
            "resolved" | "false_positive" | "accepted_risk"
        ) {
            return Ok(Err(Refusal::Invalid("outcome", "invalid_outcome")));
        }
        let needs_note = change.outcome != "resolved";
        match change.note {
            None if needs_note => return Ok(Err(Refusal::Invalid("note", "note_required"))),
            Some(note) if !note_ok(note) => {
                return Ok(Err(Refusal::Invalid("note", "invalid_note")));
            }
            _ => {}
        }
    }
    let viewer = Viewer::new(scope, user_id);
    let tx = client.transaction().await?;
    let Some(current) = lock_case(&tx, &viewer, case_id).await? else {
        return refuse(tx, Refusal::NotFound).await;
    };
    if current.status == "closed" {
        return refuse(tx, Refusal::Closed).await;
    }
    let Some(item) = lock_item(&tx, &viewer, case_id, item_id).await? else {
        return refuse(tx, Refusal::ItemNotFound).await;
    };
    if !item.kind.exclusive() {
        return refuse(tx, Refusal::Invalid("outcome", "outcome_not_applicable")).await;
    }
    if change.is_some_and(|change| change.outcome == "resolved") && !item.gone {
        return refuse(tx, Refusal::EvidencePresent).await;
    }
    let outcome = change.map(|change| change.outcome);
    let note = change.and_then(|change| change.note);
    if item.outcome.as_deref() != outcome || change.is_some() {
        tx.execute(
            "UPDATE case_items SET outcome = $2, outcome_note = $3 WHERE item_id = $1::text::uuid",
            &[&item_id, &outcome, &note],
        )
        .await?;
        push_event(
            &tx,
            case_id,
            now,
            Some(user_id),
            "item_outcome",
            note,
            json!({ "item_id": item_id, "item_kind": item.kind.as_str(),
                    "item_ref": item.reference, "item_agent_id": item.agent_id,
                    "from": item.outcome, "to": outcome }),
        )
        .await?;
        touch(&tx, case_id, now).await?;
        audit(
            &tx,
            Some(user_id),
            "case.item.outcome",
            case_id,
            json!({ "number": current.number, "kind": item.kind.as_str(),
                    "ref": item.reference, "outcome": outcome }),
        )
        .await?;
    }
    let mut items = read_items(&tx, &viewer, case_id, Some(item_id)).await?;
    let Some(saved) = items.pop() else {
        return Err(StoreError::Query);
    };
    tx.commit().await?;
    Ok(Ok(saved))
}

/// The cases that hold an item, visible ones only. An alarm, finding or
/// vulnerability has at most one: the open case that holds it. A host or
/// software item can be in many, open or closed, newest change first.
pub async fn for_item(
    client: &Client,
    scope: &AgentScope,
    user_id: &str,
    kind: &str,
    reference: &str,
) -> Result<Result<Vec<ItemCase>, Refusal>, StoreError> {
    let Some(kind) = ItemKind::parse(kind) else {
        return Ok(Err(Refusal::Invalid("kind", "invalid_kind")));
    };
    if parse_ref(kind, reference).is_none() {
        return Ok(Err(Refusal::Invalid("ref", "invalid_ref")));
    }
    let viewer = Viewer::new(scope, user_id);
    // The item itself must be visible: a case that holds it is not
    // listed to someone who cannot see it, even if they see the case.
    let (counts, visible, item) = (case_counts(), case_visible("c"), item_visible("i"));
    let exclusive = kind.exclusive();
    let rows = client
        .query(
            &format!(
                "SELECT {CASE_COLUMNS}, {counts}, i.item_id::text, i.outcome
                 FROM case_items i JOIN cases c ON c.case_id = i.case_id {CASE_JOINS}
                 WHERE i.kind = $4 AND i.ref = $5 AND ($6 OR i.active) AND {visible}
                   AND {item}
                 ORDER BY c.updated_at DESC, c.case_id DESC LIMIT $7"
            ),
            viewer_params!(
                viewer,
                &kind.as_str(),
                &reference,
                &!exclusive,
                &FOR_ITEM_LIMIT
            ),
        )
        .await?;
    Ok(Ok(rows
        .iter()
        .map(|row| ItemCase {
            case: summary_from_row(row),
            item_id: row.get(20),
            outcome: row.get(21),
        })
        .collect()))
}

/// Most rows [`active_items`] returns.
pub const ACTIVE_ITEMS_LIMIT: i64 = 20_000;

/// Every alarm, finding or vulnerability (`kind`) active in an open case
/// the caller can see, with that case's number: the lists' case badges
/// (triage v2: "being worked on" means in a case). `None` for a kind that
/// is not one-case-only.
pub async fn active_items(
    client: &Client,
    scope: &AgentScope,
    user_id: &str,
    kind: &str,
) -> Result<Option<Vec<(String, i64)>>, StoreError> {
    let Some(kind) = ItemKind::parse(kind).filter(|k| k.exclusive()) else {
        return Ok(None);
    };
    let viewer = Viewer::new(scope, user_id);
    let (visible, item) = (case_visible("c"), item_visible("i"));
    let rows = client
        .query(
            &format!(
                "SELECT i.ref, c.number FROM case_items i JOIN cases c ON c.case_id = i.case_id
                 WHERE i.kind = $4 AND i.active AND {visible} AND {item}
                 ORDER BY c.number LIMIT $5"
            ),
            viewer_params!(viewer, &kind.as_str(), &ACTIVE_ITEMS_LIMIT),
        )
        .await?;
    Ok(Some(rows.iter().map(|r| (r.get(0), r.get(1))).collect()))
}

/// Reopens recently closed cases whose `resolved` evidence has come back,
/// as the platform (audit actor `system`).
///
/// Only cases closed within [`EVIDENCE_WATCH_DAYS`] are looked at, which
/// keeps the check bounded, and only items with the outcome `resolved`:
/// `false_positive` and `accepted_risk` are decisions, not evidence (accepted
/// risk reopens on its date, see [`reopen_expired`]). Each returning item
/// loses its outcome, so someone decides again; the other outcomes stay.
/// A case with an item that has since joined another open case is left
/// closed. The timeline gets one `reopened` entry that names no item, and
/// an `item_outcome` entry per returning item, which, like every item entry,
/// only those who can see the item are shown. Returns how many reopened.
pub async fn reopen_evidence_returned(
    client: &mut Client,
    now: DateTime<Utc>,
) -> Result<u32, StoreError> {
    let since = now - chrono::Duration::days(EVIDENCE_WATCH_DAYS);
    let gone = item_gone();
    let returned = format!(
        "i.outcome = 'resolved' AND i.kind IN ('alarm', 'compliance_finding', 'vulnerability')
         AND NOT ({gone})"
    );
    let due = client
        .query(
            &format!(
                "SELECT c.case_id::text FROM cases c
                 WHERE c.status = 'closed' AND c.closed_at >= $1
                   AND EXISTS (SELECT 1 FROM case_items i
                               WHERE i.case_id = c.case_id AND {returned})
                 ORDER BY c.closed_at DESC LIMIT $2"
            ),
            &[&since, &REOPEN_BATCH],
        )
        .await?;
    let mut reopened = 0;
    for row in due {
        let case_id: String = row.get(0);
        let tx = client.transaction().await?;
        let locked = tx
            .query_opt(
                "SELECT number FROM cases
                 WHERE case_id = $1::text::uuid AND status = 'closed' AND closed_at >= $2
                 FOR UPDATE SKIP LOCKED",
                &[&case_id, &since],
            )
            .await?;
        let Some(locked) = locked else {
            tx.rollback().await?;
            continue;
        };
        let number: i64 = locked.get(0);
        let items = tx
            .query(
                &format!(
                    "SELECT i.item_id::text, i.kind, i.ref, i.agent_id FROM case_items i
                     WHERE i.case_id = $1::text::uuid AND {returned}
                     ORDER BY i.seq"
                ),
                &[&case_id],
            )
            .await?;
        if items.is_empty() {
            tx.rollback().await?;
            continue;
        }
        let taken = tx
            .query_opt(
                "SELECT 1 FROM case_items mine
                 JOIN case_items o ON o.kind = mine.kind AND o.ref = mine.ref AND o.active
                      AND o.case_id <> mine.case_id
                 WHERE mine.case_id = $1::text::uuid
                   AND mine.kind IN ('alarm', 'compliance_finding', 'vulnerability')
                 LIMIT 1",
                &[&case_id],
            )
            .await?;
        if taken.is_some() {
            tx.rollback().await?;
            continue;
        }
        let ids: Vec<String> = items.iter().map(|item| item.get(0)).collect();
        let activated = tx
            .execute(
                "UPDATE case_items SET active = true,
                    outcome = CASE WHEN item_id::text = ANY($2) THEN NULL ELSE outcome END,
                    outcome_note = CASE WHEN item_id::text = ANY($2) THEN NULL
                                        ELSE outcome_note END
                 WHERE case_id = $1::text::uuid",
                &[&case_id, &ids],
            )
            .await;
        match activated {
            Ok(_) => {}
            // A concurrent request took one of the items: leave it closed.
            Err(error) if unique_violation(&error) => {
                tx.rollback().await?;
                continue;
            }
            Err(error) => return Err(error.into()),
        }
        let previous: Option<String> = tx
            .query_one(
                "SELECT resolution FROM cases WHERE case_id = $1::text::uuid",
                &[&case_id],
            )
            .await?
            .get(0);
        tx.execute(
            "UPDATE cases SET status = 'open', resolution = NULL, resolution_note = NULL,
                accepted_until = NULL, closed_at = NULL, version = version + 1,
                updated_at = $2
             WHERE case_id = $1::text::uuid",
            &[&case_id, &now],
        )
        .await?;
        push_event(
            &tx,
            &case_id,
            now,
            None,
            "reopened",
            None,
            json!({ "reason": "evidence_returned", "status": "open",
                    "previous_resolution": previous }),
        )
        .await?;
        let mut named = Vec::with_capacity(items.len());
        for item in &items {
            let (item_id, kind, reference, agent_id): (String, String, String, Option<String>) =
                (item.get(0), item.get(1), item.get(2), item.get(3));
            push_event(
                &tx,
                &case_id,
                now,
                None,
                "item_outcome",
                None,
                json!({ "item_id": item_id, "item_kind": kind, "item_ref": reference,
                        "item_agent_id": agent_id, "from": "resolved", "to": null,
                        "reason": "evidence_returned" }),
            )
            .await?;
            named.push(json!({ "kind": kind, "ref": reference }));
        }
        audit(
            &tx,
            None,
            "case.reopen",
            &case_id,
            json!({ "number": number, "reason": "evidence_returned", "items": named }),
        )
        .await?;
        tx.commit().await?;
        reopened += 1;
    }
    Ok(reopened)
}

/// Both lazy reopen checks, for the console to run before it lists or reads
/// cases: accepted risk that has run out, and evidence that has returned.
pub async fn reopen_due(client: &mut Client, now: DateTime<Utc>) -> Result<u32, StoreError> {
    Ok(reopen_expired(client, now).await? + reopen_evidence_returned(client, now).await?)
}

/// Reopens closed cases whose accepted risk has run out, as the platform
/// (audit actor `system`). Items whose acceptance expired lose that
/// outcome, so someone decides again. A case with an item that has since
/// joined another open case is left closed. Returns how many reopened.
pub async fn reopen_expired(client: &mut Client, now: DateTime<Utc>) -> Result<u32, StoreError> {
    let due = client
        .query(
            "SELECT case_id::text FROM cases
             WHERE status = 'closed' AND resolution = 'accepted_risk' AND accepted_until <= $1
             ORDER BY accepted_until LIMIT 100",
            &[&now],
        )
        .await?;
    let mut reopened = 0;
    for row in due {
        let case_id: String = row.get(0);
        let tx = client.transaction().await?;
        let locked = tx
            .query_opt(
                "SELECT number FROM cases
                 WHERE case_id = $1::text::uuid AND status = 'closed'
                   AND resolution = 'accepted_risk' AND accepted_until <= $2
                 FOR UPDATE SKIP LOCKED",
                &[&case_id, &now],
            )
            .await?;
        let Some(locked) = locked else {
            tx.rollback().await?;
            continue;
        };
        let number: i64 = locked.get(0);
        let taken = tx
            .query_opt(
                "SELECT 1 FROM case_items mine
                 JOIN case_items o ON o.kind = mine.kind AND o.ref = mine.ref AND o.active
                      AND o.case_id <> mine.case_id
                 WHERE mine.case_id = $1::text::uuid
                   AND mine.kind IN ('alarm', 'compliance_finding', 'vulnerability')
                 LIMIT 1",
                &[&case_id],
            )
            .await?;
        if taken.is_some() {
            tx.rollback().await?;
            continue;
        }
        let activated = tx
            .execute(
                "UPDATE case_items SET active = true,
                    outcome = CASE WHEN outcome = 'accepted_risk' THEN NULL ELSE outcome END,
                    outcome_note = CASE WHEN outcome = 'accepted_risk' THEN NULL ELSE outcome_note END
                 WHERE case_id = $1::text::uuid",
                &[&case_id],
            )
            .await;
        match activated {
            Ok(_) => {}
            // A concurrent request took one of the items: leave it closed.
            Err(error) if unique_violation(&error) => {
                tx.rollback().await?;
                continue;
            }
            Err(error) => return Err(error.into()),
        }
        tx.execute(
            "UPDATE cases SET status = 'open', resolution = NULL, resolution_note = NULL,
                accepted_until = NULL, closed_at = NULL, version = version + 1,
                updated_at = $2
             WHERE case_id = $1::text::uuid",
            &[&case_id, &now],
        )
        .await?;
        push_event(
            &tx,
            &case_id,
            now,
            None,
            "reopened",
            None,
            json!({ "reason": "accepted_risk_expired", "status": "open",
                    "previous_resolution": "accepted_risk" }),
        )
        .await?;
        audit(
            &tx,
            None,
            "case.reopen",
            &case_id,
            json!({ "number": number, "reason": "accepted_risk_expired" }),
        )
        .await?;
        tx.commit().await?;
        reopened += 1;
    }
    Ok(reopened)
}

#[cfg(test)]
mod tests {
    use super::{
        ItemKind, Parsed, case_number, case_severity_of, default_severity, note_ok, parse_ref,
        title_ok,
    };

    #[test]
    fn refs_are_checked_against_the_shape_the_panels_write() {
        let agent = "agent.00000000-0000-4000-8000-000000000001";
        assert_eq!(parse_ref(ItemKind::Alarm, "42"), Some(Parsed::Alarm(42)));
        for bad in ["", "0", "-1", "042", "4 2", "1e3", "99999999999999999999"] {
            assert_eq!(parse_ref(ItemKind::Alarm, bad), None, "{bad:?}");
        }
        let finding = format!("{agent}/baseline/ssh-root-login");
        assert_eq!(
            parse_ref(ItemKind::Finding, &finding),
            Some(Parsed::Finding(agent, "baseline", "ssh-root-login"))
        );
        // A finding from before rule sets has an empty rule set.
        assert!(parse_ref(ItemKind::Finding, &format!("{agent}//old-rule")).is_some());
        for bad in [
            agent.to_owned(),
            format!("{agent}/baseline"),
            format!("{agent}/baseline/rule/extra"),
            format!("{agent}/baseline/"),
            "/baseline/rule".to_owned(),
            format!("{agent}/base line/rule"),
        ] {
            assert_eq!(parse_ref(ItemKind::Finding, &bad), None, "{bad:?}");
        }
        assert_eq!(
            parse_ref(ItemKind::Vulnerability, &format!("{agent}/RHSA-2026:1234")),
            Some(Parsed::Vulnerability(agent, "RHSA-2026:1234"))
        );
        assert_eq!(parse_ref(ItemKind::Vulnerability, agent), None);
        assert_eq!(parse_ref(ItemKind::Host, agent), Some(Parsed::Host(agent)));
        assert_eq!(parse_ref(ItemKind::Host, "a/b"), None);
        // A package name may itself contain a slash.
        assert_eq!(
            parse_ref(ItemKind::Software, "npm/@scope/pkg"),
            Some(Parsed::Software("npm", "@scope/pkg"))
        );
        assert_eq!(parse_ref(ItemKind::Software, "rpm"), None);
        assert_eq!(parse_ref(ItemKind::Software, "rpm/"), None);
    }

    #[test]
    fn only_alarms_findings_and_vulnerabilities_are_exclusive() {
        for (name, exclusive) in [
            ("alarm", true),
            ("compliance_finding", true),
            ("vulnerability", true),
            ("host", false),
            ("software", false),
        ] {
            assert_eq!(ItemKind::parse(name).unwrap().exclusive(), exclusive);
        }
        assert_eq!(ItemKind::parse("port"), None);
    }

    #[test]
    fn the_default_severity_is_the_highest_item_severity() {
        assert_eq!(case_severity_of("important"), Some("high"));
        assert_eq!(case_severity_of("moderate"), Some("medium"));
        assert_eq!(case_severity_of("info"), Some("low"));
        assert_eq!(case_severity_of("weird"), None);
        assert_eq!(
            default_severity([Some("low"), None, Some("important"), Some("moderate")]),
            "high"
        );
        assert_eq!(
            default_severity([Some("critical"), Some("high")]),
            "critical"
        );
        assert_eq!(default_severity([None, Some("weird")]), "medium");
        assert_eq!(default_severity([]), "medium");
    }

    #[test]
    fn titles_and_notes_are_bounded_plain_text() {
        assert!(title_ok("SSH on web-01"));
        assert!(!title_ok(""));
        assert!(!title_ok(" padded "));
        assert!(!title_ok("tab\there"));
        assert!(title_ok(&"é".repeat(120)));
        assert!(!title_ok(&"é".repeat(121)));
        assert!(note_ok("line one\nline two\twith a tab"));
        assert!(!note_ok("   "));
        assert!(!note_ok("bell\u{7}"));
        assert!(note_ok(&"n".repeat(4000)));
        assert!(!note_ok(&"n".repeat(4001)));
    }

    #[test]
    fn case_numbers_are_found_in_search_text() {
        assert_eq!(case_number("C-104"), Some(104));
        assert_eq!(case_number("c-7"), Some(7));
        assert_eq!(case_number("c104"), Some(104));
        assert_eq!(case_number("104"), Some(104));
        assert_eq!(case_number("ssh"), None);
        assert_eq!(case_number("C-0"), None);
        assert_eq!(case_number("C--1"), None);
    }
}
