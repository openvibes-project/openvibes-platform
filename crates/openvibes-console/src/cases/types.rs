use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

/// A console user as a case shows them.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct CaseUserView {
    /// Stable UUID.
    pub user_id: String,
    /// Login name.
    pub username: String,
    /// Name to show.
    pub display_name: String,
}

/// One case as listed. Counts include only items the viewer can see.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct CaseSummaryView {
    /// Stable UUID.
    pub case_id: String,
    /// Shown as `C-<number>`; unique, never reused.
    pub number: i64,
    /// 1 to 120 characters.
    pub title: String,
    /// `open`, `investigating` or `closed`.
    pub status: String,
    /// `mitigated`, `false_positive` or `accepted_risk`, once closed.
    pub resolution: Option<String>,
    /// When accepted risk runs out and the case reopens (RFC 3339).
    pub accepted_until: Option<String>,
    /// `critical`, `high`, `medium` or `low`.
    pub severity: String,
    /// Who works on it.
    pub assignee: Option<CaseUserView>,
    /// Who opened it.
    pub opened_by: CaseUserView,
    /// RFC 3339.
    pub created_at: String,
    /// Last change of any kind (RFC 3339).
    pub updated_at: String,
    /// RFC 3339, once closed.
    pub closed_at: Option<String>,
    /// Version for `If-Match` (also the ETag of the detail).
    pub version: u64,
    /// Items the viewer can see.
    pub item_count: i64,
    /// Visible alarms, findings and vulnerabilities that have no outcome.
    pub pending_item_count: i64,
}

/// A page of cases, newest change first.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct CasePage {
    /// The cases the viewer can see.
    pub items: Vec<CaseSummaryView>,
    /// Pass as `cursor` for the next page; absent on the last page.
    pub next_cursor: Option<String>,
}

/// One item of a case that the viewer can see.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct CaseItemView {
    /// Stable UUID.
    pub item_id: String,
    /// `alarm`, `finding`, `vulnerability`, `host` or `software`.
    pub kind: String,
    /// The object's id as the console's panels write it: the alarm id;
    /// `agent/rule_set/rule` for a finding; `agent/advisory` for a
    /// vulnerability on a host; the agent id for a host; `manager/name`
    /// for software.
    #[serde(rename = "ref")]
    pub reference: String,
    /// The host that decides who sees the item; absent for software.
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
    pub added_by: CaseUserView,
    /// RFC 3339.
    pub added_at: String,
    /// What to show for it, when it still exists.
    pub title: Option<String>,
    /// Its own severity as its page states it (alarm and finding:
    /// `critical` to `info`; vulnerability: the advisory's), when it has one.
    pub severity: Option<String>,
    /// True when the evidence is gone, so that `resolved` is accepted: the
    /// finding is no longer reported, the vulnerability no longer matches
    /// the host, the alarm is closed as mitigated or no longer exists.
    /// Always false for hosts and software.
    pub evidence_gone: bool,
}

/// One timeline entry.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct CaseEventView {
    /// Position on the timeline.
    pub event_id: i64,
    /// RFC 3339.
    pub at: String,
    /// Who; absent for the platform itself.
    pub actor: Option<CaseUserView>,
    /// `created`, `note`, `status`, `assigned`, `severity`, `item_added`,
    /// `item_removed`, `item_outcome`, `resolved` or `reopened`.
    pub kind: String,
    /// The note's text; for `resolved` the resolution note; for
    /// `item_outcome` the outcome note.
    pub body: Option<String>,
    /// Structured facts: `from`/`to` for `status`, `assigned` (usernames)
    /// and `severity`; `item_id`, `item_kind`, `item_ref` and
    /// `item_agent_id` for item entries; `resolution` and `accepted_until`
    /// for `resolved`; `reason` for `reopened`.
    #[schema(value_type = Object)]
    pub detail: serde_json::Value,
}

/// A case with the items and timeline the viewer can see.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct CaseDetailView {
    /// The list fields.
    #[serde(flatten)]
    pub case: CaseSummaryView,
    /// Why it was closed.
    pub resolution_note: Option<String>,
    /// Visible items, oldest first.
    pub items: Vec<CaseItemView>,
    /// The timeline, oldest first, without entries about hidden items.
    pub events: Vec<CaseEventView>,
}

/// A case that holds an item.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct ItemCaseView {
    /// The case.
    pub case: CaseSummaryView,
    /// The item's id in that case.
    pub item_id: String,
    /// The item's outcome there.
    pub outcome: Option<String>,
}

/// The visible cases that hold an item.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct ItemCasesView {
    /// For an alarm, finding or vulnerability at most one: the open case.
    /// For a host or software, up to 50, newest change first, open or closed.
    pub items: Vec<ItemCaseView>,
}

/// Users a case can be assigned to.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct CaseAssigneesView {
    /// Enabled users who hold `cases.read`.
    pub items: Vec<CaseUserView>,
}

/// An item to add: what it is and its id.
#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CaseItemRef {
    /// `alarm`, `finding`, `vulnerability`, `host` or `software`.
    pub kind: String,
    /// The object's id as the console's panels write it (see
    /// `CaseItemView.ref`).
    #[serde(rename = "ref")]
    pub reference: String,
}

/// Opens a case.
#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateCaseRequest {
    /// 1 to 120 characters.
    pub title: String,
    /// `critical`, `high`, `medium` or `low`; the highest item severity
    /// (medium without one) when absent.
    pub severity: Option<String>,
    /// A user with `cases.read` (see the assignees route).
    pub assignee_user_id: Option<String>,
    /// Items to start with, at most 50.
    #[serde(default)]
    pub items: Vec<CaseItemRef>,
}

/// Replaces a case's editable fields; send every field.
#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct UpdateCaseRequest {
    /// 1 to 120 characters.
    pub title: String,
    /// `critical`, `high`, `medium` or `low`.
    pub severity: String,
    /// `open`, `investigating` or `closed`. `closed` closes the case; any
    /// other status on a closed case reopens it.
    pub status: String,
    /// A user with `cases.read`; absent or `null` means nobody.
    pub assignee_user_id: Option<String>,
    /// How it ended, required with `closed`: `mitigated`, `false_positive`
    /// or `accepted_risk`. Absent otherwise.
    #[expect(
        dead_code,
        reason = "ignored since step 5d; goes with the route change"
    )]
    pub resolution: Option<String>,
    /// Why, required with a resolution (at most 4000 characters).
    pub resolution_note: Option<String>,
    /// Required for `accepted_risk` (RFC 3339, in the future): the case
    /// reopens when it passes.
    #[expect(
        dead_code,
        reason = "ignored since step 5d; goes with the route change"
    )]
    pub accepted_until: Option<String>,
}

/// A note for the timeline.
#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct AddCaseNoteRequest {
    /// Plain text, 1 to 4000 characters.
    pub body: String,
}

/// Sets or clears an item's outcome.
#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SetCaseItemOutcomeRequest {
    /// `resolved` (only when the evidence is gone), `false_positive` or
    /// `accepted_risk`; absent or `null` clears it.
    pub outcome: Option<String>,
    /// Required for `false_positive` and `accepted_risk`.
    pub note: Option<String>,
}

/// Filters and paging for the case list.
#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(deny_unknown_fields)]
pub(crate) struct CaseListParams {
    /// `open`, `investigating`, `closed` or `all`; open and investigating
    /// when absent.
    pub(super) status: Option<String>,
    /// Exact severity.
    pub(super) severity: Option<String>,
    /// A user id, `me`, or `none` for unassigned.
    pub(super) assignee: Option<String>,
    /// Text in the title, or a case number such as `C-104`.
    pub(super) q: Option<String>,
    /// Opaque continuation cursor.
    pub(super) cursor: Option<String>,
    /// Page size from 1 to 100 (default 50).
    pub(super) limit: Option<u16>,
}

/// Which cases hold an item.
#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(deny_unknown_fields)]
pub(crate) struct ForItemParams {
    /// `alarm`, `finding`, `vulnerability`, `host` or `software`.
    pub(super) kind: String,
    /// The object's id (see `CaseItemView.ref`).
    #[serde(rename = "ref")]
    #[param(rename = "ref")]
    pub(super) reference: String,
}

/// Items in open cases, for the lists' case badges.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct ActiveCaseItemsView {
    /// Item ref (alarm id, `agent/rule_set/rule`, `agent/advisory`) and
    /// the number of the open case holding it.
    pub items: Vec<ActiveCaseItem>,
}

/// One item in an open case.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct ActiveCaseItem {
    /// The item's ref.
    #[serde(rename = "ref")]
    pub reference: String,
    /// The case's number (`C-<number>`).
    pub case_number: i64,
}

/// `kind`: `alarm`, `compliance_finding` or `vulnerability`.
#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(deny_unknown_fields)]
pub(crate) struct ActiveItemsParams {
    pub(super) kind: String,
}
