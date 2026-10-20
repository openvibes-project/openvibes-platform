//! An alarm's page answer (`GET /v1/alarms/{id}/summary`).

use serde::Serialize;
use utoipa::ToSchema;

use super::{AlarmTriageView, list_types::AlarmListCaseView, list_types::AlarmListRowView};
use crate::hosts::summary_types::{TopAlarmsView, TopVulnerabilitiesView};

/// The alarm: the list-row fields and its detail.
#[derive(Serialize, ToSchema)]
pub(crate) struct AlarmPageAlarmView {
    /// The list-row fields.
    #[serde(flatten)]
    pub row: AlarmListRowView,
    /// 0 to 100.
    pub confidence: i16,
    /// Rule set version.
    pub rule_set_version: i64,
    /// Rule version.
    pub rule_version: i64,
    /// The process (masked args) as the agent sent it.
    #[schema(value_type = Object)]
    pub process: serde_json::Value,
    /// Its ancestors, nearest first, as sent.
    #[schema(value_type = Vec<Object>)]
    pub ancestors: serde_json::Value,
    /// When ingest stored it, RFC 3339.
    pub received_at: String,
    /// Current triage.
    pub triage: AlarmTriageView,
}

/// The four tiles, over the alarm and its siblings.
#[derive(Serialize, ToSchema)]
pub(crate) struct AlarmTilesView {
    /// Starts matched.
    pub starts: i64,
    /// Distinct command lines (siblings).
    pub different_commands: i64,
    /// The earliest first start, RFC 3339.
    pub first_seen: String,
    /// The alarm's confidence, 0 to 100.
    pub confidence: i16,
}

/// What the "What happened" card says. Until the rule is indexed, the
/// title and message are the alarm's message (`GET /alarms/{id}/rule` still
/// resolves it).
#[derive(Serialize, ToSchema)]
pub(crate) struct AlarmRuleTextView {
    /// Rule title.
    pub title: String,
    /// Rule message.
    pub message: String,
    /// What a match means.
    pub explain: Option<String>,
    /// What a person should look at.
    pub check: Option<String>,
    /// ATT&CK technique ids.
    pub techniques: Vec<String>,
}

/// One command seen: a sibling alarm with its own command line.
#[derive(Serialize, ToSchema)]
pub(crate) struct AlarmCommandView {
    /// The sibling's alarm id.
    pub id: i64,
    /// The command line, masked as stored.
    pub args: Vec<String>,
    /// Starts matched.
    pub count: i64,
    /// RFC 3339.
    pub first_seen: String,
    /// RFC 3339.
    pub last_seen: String,
    /// Triage state.
    pub state: String,
    /// The suppression that closed it.
    pub suppressed_by: Option<i64>,
    /// The open case holding it.
    pub case: Option<AlarmListCaseView>,
}

/// Other hosts in reach with an open alarm from this rule.
#[derive(Serialize, ToSchema)]
pub(crate) struct SameRuleElsewhereView {
    /// Hosts.
    pub hosts: i64,
    /// Their open alarms from the rule.
    pub open: i64,
}

/// The Related card.
#[derive(Serialize, ToSchema)]
pub(crate) struct AlarmRelatedView {
    /// Up to five other open alarms on the host, and the total.
    pub host_alarms: TopAlarmsView,
    /// The host's top three open vulnerabilities and the total; absent
    /// without `vulnerabilities.read` on the host.
    pub host_vulnerabilities: Option<TopVulnerabilitiesView>,
    /// Same rule elsewhere.
    pub same_rule_elsewhere: SameRuleElsewhereView,
}

/// Actions allowed on this alarm, each by its permission on the host.
#[derive(Serialize, ToSchema)]
pub(crate) struct AlarmActionsView {
    /// Set state (`alarms.triage`).
    pub triage: bool,
    /// Assign (`alarms.triage` and `cases.assign`).
    pub assign: bool,
    /// Suppress (`alarms.suppress`).
    pub suppress: bool,
    /// Add to case (`cases.write`).
    pub add_to_case: bool,
    /// Ask about this (`assistant.use`, with the assistant on).
    pub ask: bool,
    /// Export (`alarms.export`).
    pub export: bool,
}

/// Everything above the fold on an alarm's page.
#[derive(Serialize, ToSchema)]
pub(crate) struct AlarmSummaryPageView {
    /// The alarm.
    pub alarm: AlarmPageAlarmView,
    /// The tiles.
    pub tiles: AlarmTilesView,
    /// The rule's text.
    pub rule: AlarmRuleTextView,
    /// Commands seen: the alarm and its siblings, most starts first.
    pub commands: Vec<AlarmCommandView>,
    /// Starts per hour of the alarm and its siblings, the 24 hours ending
    /// with the current one, oldest first.
    pub hourly: Vec<i64>,
    /// The Related card.
    pub related: AlarmRelatedView,
    /// Allowed actions.
    pub can: AlarmActionsView,
}
