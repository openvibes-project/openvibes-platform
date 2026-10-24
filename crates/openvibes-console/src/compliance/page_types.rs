//! A check's page answers (`GET /v1/compliance/checks/{rule_set_id}/{rule_id}/summary`
//! and `/hosts`).

use chrono::SecondsFormat;
use platform_store::check_summary::{CheckHostsPage, CheckPageSummary, Evidence};
use serde::Serialize;
use utoipa::ToSchema;

use super::evidence::fact_file;
use crate::{
    alarms::list_types::AlarmListPersonView, vulnerabilities::list_page_types::VulnAssigneeView,
};

fn rfc3339(at: chrono::DateTime<chrono::Utc>) -> String {
    at.to_rfc3339_opts(SecondsFormat::Secs, true)
}

/// The header.
#[derive(Serialize, ToSchema)]
pub(crate) struct CheckHeaderView {
    /// The rule's title (its newest indexed version), else the rule id.
    pub title: String,
    /// `critical`, `high`, `medium`, `low` or `info`: the newest finding's
    /// in reach, else the rule's indexed severity.
    pub severity: Option<String>,
    /// Rule set id.
    pub rule_set_id: String,
    /// The newest indexed version of the set holding the rule.
    pub rule_set_version: Option<i64>,
    /// Rule id.
    pub rule_id: String,
    /// The rule's version (indexed, else the newest finding's).
    pub rule_version: Option<i64>,
    /// What the check is about (derived from the rule id).
    pub area: String,
    /// Failing hosts in reach.
    pub failing: i64,
    /// Of those, open (an expired acceptance counts): what the header's Set
    /// state and Assign change.
    pub open: i64,
    /// Failing and passing hosts in reach.
    pub checked: i64,
    /// Who the open failing hosts are assigned to.
    pub assignee: VulnAssigneeView,
}

/// The earliest first-seen failing host.
#[derive(Serialize, ToSchema)]
pub(crate) struct CheckFirstSeenView {
    /// RFC 3339.
    pub at: String,
    /// Host name.
    pub hostname: Option<String>,
}

/// The tiles.
#[derive(Serialize, ToSchema)]
pub(crate) struct CheckTilesView {
    /// Failing hosts.
    pub failing: i64,
    /// Inferred passing hosts.
    pub passing: i64,
    /// The earliest first-seen failing host; absent with none failing.
    pub first_seen: Option<CheckFirstSeenView>,
    /// Failing hosts per UTC day, the last 14 days ending today, oldest first.
    pub days: Vec<u32>,
}

/// The rule's text.
#[derive(Serialize, ToSchema)]
pub(crate) struct CheckTextView {
    /// "Why it matters".
    pub explain: Option<String>,
    /// "How to fix".
    pub check: Option<String>,
    /// The finding message, shown when the others are absent.
    pub message: String,
}

/// The details card.
#[derive(Serialize, ToSchema)]
pub(crate) struct CheckDetailsView {
    /// "Linux hosts", "All hosts" or "Hosts with this rule set".
    pub applies_to: String,
    /// ATT&CK technique ids.
    pub techniques: Vec<String>,
}

/// One History event, newest first.
#[derive(Serialize, ToSchema)]
pub(crate) struct CheckEventView {
    /// RFC 3339.
    pub at: String,
    /// `triage`, `failing` (started failing), `passes_again` or
    /// `published` (a rule-set version).
    pub kind: String,
    /// Who changed triage, or published.
    pub actor: Option<String>,
    /// The host (absent for `published`).
    pub agent_id: Option<String>,
    /// Its name.
    pub hostname: Option<String>,
    /// Triage state before.
    pub from_state: Option<String>,
    /// Triage state after.
    pub to_state: Option<String>,
    /// Triage note.
    pub note: Option<String>,
    /// The published rule-set version.
    pub version: Option<i64>,
}

/// The exposed port of a `port.*` check.
#[derive(Serialize, ToSchema)]
pub(crate) struct CheckPortView {
    /// `tcp` or `udp`.
    pub protocol: String,
    /// The port, linking to `/ports/{port}`.
    pub port: u16,
    /// Hosts in reach where it is exposed.
    pub hosts: i64,
}

/// The unit of a `harden.services.*` check.
#[derive(Serialize, ToSchema)]
pub(crate) struct CheckServiceView {
    /// The systemd unit, linking to `/services/{unit}`.
    pub unit: String,
    /// Hosts in reach running it.
    pub hosts: i64,
}

/// Other failing checks in reach in the same area.
#[derive(Serialize, ToSchema)]
pub(crate) struct CheckSameAreaView {
    /// How many.
    pub checks: i64,
    /// Their worst severity.
    pub worst: Option<String>,
}

/// The Related card.
#[derive(Serialize, ToSchema)]
pub(crate) struct CheckRelatedView {
    /// For `port.*` checks whose rule names a port.
    pub port: Option<CheckPortView>,
    /// For `harden.services.*` checks whose rule names a unit.
    pub service: Option<CheckServiceView>,
    /// Same area.
    pub same_area: CheckSameAreaView,
}

/// Actions allowed, each when the viewer holds its permission on a host in
/// reach.
#[derive(Serialize, ToSchema)]
pub(crate) struct CheckActionsView {
    /// Set state (`compliance.triage`).
    pub triage: bool,
    /// Assign (`compliance.triage`).
    pub assign: bool,
    /// Add to case (`cases.write` and `cases.read`).
    pub add_to_case: bool,
    /// Ask about this (`assistant.use`, with the assistant on).
    pub ask: bool,
    /// Export (`compliance.export`).
    pub export: bool,
}

/// A check's page above the Hosts table.
#[derive(Serialize, ToSchema)]
pub(crate) struct CheckSummaryView {
    /// Header.
    pub header: CheckHeaderView,
    /// Tiles.
    pub tiles: CheckTilesView,
    /// Text.
    pub text: CheckTextView,
    /// Details.
    pub details: CheckDetailsView,
    /// Up to 50 events in reach, newest first.
    pub history: Vec<CheckEventView>,
    /// Related.
    pub related: CheckRelatedView,
    /// Allowed actions.
    pub can: CheckActionsView,
}

/// One input the failing evaluation read.
#[derive(Serialize, ToSchema)]
pub(crate) struct CheckEvidenceView {
    /// Fact key, for example `sshd.permitrootlogin`.
    pub fact: String,
    /// Its value, only when the agent sent it complete.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    /// `masked`, `summarized` or `truncated`, instead of a value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    /// The file the agent read it from.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
}

/// One row of the Hosts table.
#[derive(Serialize, ToSchema)]
pub(crate) struct CheckHostRowView {
    /// Agent id.
    pub agent_id: String,
    /// Host name.
    pub hostname: Option<String>,
    /// Distribution, as the Hosts list names it.
    pub os: Option<String>,
    /// Last address.
    pub address: Option<String>,
    /// open, mitigated, accepted_risk, false_positive or passing.
    pub state: String,
    /// What the failing evaluation read; empty for a passing host or a
    /// finding recorded without detection.
    pub evidence: Vec<CheckEvidenceView>,
    /// Assignee.
    pub assignee: Option<AlarmListPersonView>,
    /// RFC 3339: the last observation (failing) or heartbeat (passing).
    pub checked_at: Option<String>,
    /// The triage version for If-Match (0 without triage); null for a
    /// passing host.
    pub triage_version: Option<i64>,
    /// RFC 3339: until when the risk is accepted, kept after it expires
    /// (the state then reads open); null for a passing host.
    pub accepted_until: Option<String>,
    /// `online` or `import` (an agent export); null for a passing host.
    pub origin: Option<String>,
}

/// Hosts per segment.
#[derive(Serialize, ToSchema)]
pub(crate) struct CheckSegmentsView {
    /// Failing and passing.
    pub all: i64,
    /// Failing, in any triage state.
    pub failing: i64,
    /// Inferred passing.
    pub passing: i64,
}

/// Failing hosts per triage state.
#[derive(Serialize, ToSchema)]
pub(crate) struct CheckStatesView {
    /// Open (an expired acceptance counts).
    pub open: i64,
    /// Mitigated.
    pub mitigated: i64,
    /// Accepted risk.
    pub accepted_risk: i64,
    /// False positive.
    pub false_positive: i64,
}

/// One page of the Hosts table.
#[derive(Serialize, ToSchema)]
pub(crate) struct CheckHostsPageView {
    /// The page, by host name then agent id.
    pub rows: Vec<CheckHostRowView>,
    /// Hosts in the chosen segment.
    pub total: i64,
    /// Every segment's count.
    pub segments: CheckSegmentsView,
    /// The failing hosts per triage state, whatever `state` is chosen.
    pub states: CheckStatesView,
}

impl CheckSummaryView {
    pub(crate) fn new(s: CheckPageSummary, can: CheckActionsView) -> Self {
        let (h, t, r) = (s.header, s.tiles, s.related);
        Self {
            header: CheckHeaderView {
                title: h.title,
                severity: h.severity.map(|v| v.as_str().into()),
                rule_set_id: h.rule_set_id,
                rule_set_version: h.rule_set_version,
                rule_id: h.rule_id,
                rule_version: h.rule_version,
                area: h.area.into(),
                failing: h.failing,
                open: h.open,
                checked: h.checked,
                assignee: h.assignee.into(),
            },
            tiles: CheckTilesView {
                failing: t.failing,
                passing: t.passing,
                first_seen: t.first_seen.map(|f| CheckFirstSeenView {
                    at: rfc3339(f.at),
                    hostname: f.hostname,
                }),
                days: t.days.to_vec(),
            },
            text: CheckTextView {
                explain: s.text.explain,
                check: s.text.check,
                message: s.text.message,
            },
            details: CheckDetailsView {
                applies_to: s.details.applies_to.into(),
                techniques: s.details.techniques,
            },
            history: s
                .history
                .into_iter()
                .map(|e| CheckEventView {
                    at: rfc3339(e.at),
                    kind: e.kind,
                    actor: e.actor,
                    agent_id: e.agent_id,
                    hostname: e.hostname,
                    from_state: e.from_state,
                    to_state: e.to_state,
                    note: e.note,
                    version: e.version,
                })
                .collect(),
            related: CheckRelatedView {
                port: r.port.map(|p| CheckPortView {
                    protocol: p.protocol,
                    port: p.port,
                    hosts: p.hosts,
                }),
                service: r.service.map(|s| CheckServiceView {
                    unit: s.unit,
                    hosts: s.hosts,
                }),
                same_area: CheckSameAreaView {
                    checks: r.same_area.checks,
                    worst: r.same_area.worst,
                },
            },
            can,
        }
    }
}

fn evidence_view(e: Evidence) -> CheckEvidenceView {
    CheckEvidenceView {
        file: fact_file(&e.fact),
        fact: e.fact,
        value: e.value,
        status: e.status,
    }
}

impl From<CheckHostsPage> for CheckHostsPageView {
    fn from(p: CheckHostsPage) -> Self {
        let g = p.segments;
        Self {
            rows: p
                .rows
                .into_iter()
                .map(|r| CheckHostRowView {
                    agent_id: r.agent_id,
                    hostname: r.hostname,
                    os: r.os,
                    address: r.address,
                    state: r.state,
                    evidence: r.evidence.into_iter().map(evidence_view).collect(),
                    assignee: r
                        .assignee
                        .map(|(id, name)| AlarmListPersonView { id, name }),
                    checked_at: r.checked_at.map(rfc3339),
                    triage_version: r.triage_version,
                    accepted_until: r.accepted_until.map(rfc3339),
                    origin: r.origin,
                })
                .collect(),
            total: p.total,
            segments: CheckSegmentsView {
                all: g.all,
                failing: g.failing,
                passing: g.passing,
            },
            states: CheckStatesView {
                open: p.states.open,
                mitigated: p.states.mitigated,
                accepted_risk: p.states.accepted_risk,
                false_positive: p.states.false_positive,
            },
        }
    }
}
