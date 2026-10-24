//! A check's page (roles spec §10.3; step 5c rulings 2, 8, 11–15): one rule
//! of a rule set over its failing and inferred passing hosts in the
//! viewer's `compliance.read` scope — the header, tiles, text, details,
//! history, the Related card and the Hosts table. Pairs follow the
//! Compliance list (`check_list_sql`), so the page and its list row agree.
//! A check the list would not show in reach reads as missing.

use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::Value;

pub use crate::check_states::{CheckHostState, CheckStateCounts};
pub use crate::vuln_summary::Lookup;
use crate::{
    Client, StoreError,
    check_area::check_area,
    check_list::CheckSeverity,
    check_related::{CheckRelated, SameArea, port_and_service},
    check_summary_sql as sql,
    console_read::AgentScope,
    host_list::values,
    vuln_list::AssigneeSummary,
};

/// Most events the History card shows.
pub const HISTORY: usize = 50;

/// The header.
#[derive(Clone, Debug)]
pub struct CheckHeader {
    /// The newest indexed version's title, else the rule ID.
    pub title: String,
    /// The newest finding's in reach (failing first), else the indexed one.
    pub severity: Option<CheckSeverity>,
    /// Rule set.
    pub rule_set_id: String,
    /// The newest indexed version of the set holding the rule.
    pub rule_set_version: Option<i64>,
    /// Rule.
    pub rule_id: String,
    /// The rule's version there, else the newest finding's.
    pub rule_version: Option<i64>,
    /// [`check_area`].
    pub area: &'static str,
    /// Failing hosts.
    pub failing: i64,
    /// Of those, open (an expired acceptance counts): what the header's
    /// Set state and Assign change.
    pub open: i64,
    /// Failing and passing hosts.
    pub checked: i64,
    /// Who the open failing pairs are assigned to.
    pub assignee: AssigneeSummary,
}

/// The earliest first-seen failing pair.
#[derive(Clone, Debug, Deserialize)]
pub struct FirstSeen {
    /// When.
    #[serde(deserialize_with = "millis")]
    pub at: DateTime<Utc>,
    /// Its host's name.
    pub hostname: Option<String>,
}

/// The tiles.
#[derive(Clone, Debug)]
pub struct CheckTiles {
    /// Failing hosts.
    pub failing: i64,
    /// Inferred passing hosts.
    pub passing: i64,
    /// The earliest first-seen failing pair.
    pub first_seen: Option<FirstSeen>,
    /// Failing hosts per UTC day, the last 14 days, oldest first.
    pub days: [u32; 14],
}

/// The rule's text.
#[derive(Clone, Debug)]
pub struct CheckText {
    /// Why it matters.
    pub explain: Option<String>,
    /// How to fix.
    pub check: Option<String>,
    /// The finding message.
    pub message: String,
}

/// The details card.
#[derive(Clone, Debug)]
pub struct CheckDetails {
    /// "Linux hosts", "All hosts" or "Hosts with this rule set" (ruling 13).
    pub applies_to: &'static str,
    /// ATT&CK technique ids.
    pub techniques: Vec<String>,
}

/// One History event (ruling 14).
#[derive(Clone, Debug, Deserialize)]
pub struct CheckEvent {
    /// When.
    #[serde(deserialize_with = "millis")]
    pub at: DateTime<Utc>,
    /// `triage`, `failing` (an episode starts), `passes_again` (it ended)
    /// or `published` (a rule-set version).
    pub kind: String,
    /// Who: a display name, or the stored actor; the publisher.
    pub actor: Option<String>,
    /// The host.
    pub agent_id: Option<String>,
    /// Its name.
    pub hostname: Option<String>,
    /// Triage state before.
    pub from_state: Option<String>,
    /// Triage state after.
    pub to_state: Option<String>,
    /// Triage note.
    pub note: Option<String>,
    /// The published version.
    pub version: Option<i64>,
}

/// A check's page above the Hosts table.
#[derive(Clone, Debug)]
pub struct CheckPageSummary {
    /// Header.
    pub header: CheckHeader,
    /// Tiles.
    pub tiles: CheckTiles,
    /// Text.
    pub text: CheckText,
    /// Details.
    pub details: CheckDetails,
    /// The last [`HISTORY`] events in reach, newest first.
    pub history: Vec<CheckEvent>,
    /// Related.
    pub related: CheckRelated,
    /// The hosts in reach with a pair, for the actions' permissions.
    pub agents: Vec<String>,
    /// Of those, the failing ones, for triage and assign (a passing host
    /// has nothing to triage).
    pub failing_agents: Vec<String>,
}

fn millis<'de, D: serde::Deserializer<'de>>(d: D) -> Result<DateTime<Utc>, D::Error> {
    let ms = i64::deserialize(d)?;
    DateTime::from_timestamp_millis(ms).ok_or_else(|| serde::de::Error::custom("time"))
}

#[derive(Deserialize)]
struct RawMeta {
    title: String,
    message: String,
    explain: Option<String>,
    check: Option<String>,
    rule_version: i64,
    rule_set_version: i64,
    techniques: Vec<String>,
    expression: Option<String>,
}

#[derive(Deserialize)]
struct RawFinding {
    message: Option<String>,
    rule_version: i64,
}

#[derive(Deserialize)]
struct Raw {
    failing: i64,
    open: i64,
    passing: i64,
    agents: Vec<String>,
    failing_agents: Vec<String>,
    people: Vec<(String, String)>,
    first_seen: Option<FirstSeen>,
    severity: Option<String>,
    finding: Option<RawFinding>,
    meta: Option<RawMeta>,
    days: Vec<u32>,
    same_area: SameArea,
    history: Vec<CheckEvent>,
}

/// Ruling 13.
fn applies_to(rule_set_id: &str) -> &'static str {
    if rule_set_id.starts_with("hardening-linux-") {
        "Linux hosts"
    } else if rule_set_id == "baseline" {
        "All hosts"
    } else {
        "Hosts with this rule set"
    }
}

fn n32(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

/// The page of `rule_set_id`/`rule_id` within `scope` at `now`.
pub async fn check_summary(
    client: &Client,
    rule_set_id: &str,
    rule_id: &str,
    scope: &AgentScope,
    now: DateTime<Utc>,
) -> Result<Lookup<CheckPageSummary>, StoreError> {
    let row = client
        .query_one(
            &sql::summary(),
            &[
                &scope.is_global(),
                &scope.group_ids(),
                &rule_set_id,
                &rule_id,
                &now,
            ],
        )
        .await?;
    let raw: Raw = serde_json::from_value(row.get(0)).map_err(|_| StoreError::Query)?;
    if raw.failing + raw.passing == 0 {
        return Ok(Lookup::Missing);
    }
    let days: [u32; 14] = raw.days.try_into().map_err(|_| StoreError::Query)?;
    let mut people = raw.people;
    people.sort();
    let (port, service) = port_and_service(
        client,
        scope,
        rule_id,
        raw.meta.as_ref().and_then(|m| m.expression.as_deref()),
    )
    .await?;
    let meta = raw.meta;
    Ok(Lookup::Found(CheckPageSummary {
        header: CheckHeader {
            title: meta
                .as_ref()
                .map_or_else(|| rule_id.to_owned(), |m| m.title.clone()),
            severity: raw.severity.as_deref().and_then(CheckSeverity::parse),
            rule_set_id: rule_set_id.to_owned(),
            rule_set_version: meta.as_ref().map(|m| m.rule_set_version),
            rule_id: rule_id.to_owned(),
            rule_version: meta
                .as_ref()
                .map(|m| m.rule_version)
                .or(raw.finding.as_ref().map(|f| f.rule_version)),
            area: check_area(rule_id),
            failing: raw.failing,
            open: raw.open,
            checked: raw.failing + raw.passing,
            assignee: match people.len() {
                0 => AssigneeSummary::None,
                1 => {
                    let (id, name) = people.remove(0);
                    AssigneeSummary::One(id, name)
                }
                n => AssigneeSummary::Several(n32(n)),
            },
        },
        tiles: CheckTiles {
            failing: raw.failing,
            passing: raw.passing,
            first_seen: raw.first_seen,
            days,
        },
        text: CheckText {
            explain: meta.as_ref().and_then(|m| m.explain.clone()),
            check: meta.as_ref().and_then(|m| m.check.clone()),
            message: meta
                .as_ref()
                .map(|m| m.message.clone())
                .or(raw.finding.and_then(|f| f.message))
                .unwrap_or_default(),
        },
        details: CheckDetails {
            applies_to: applies_to(rule_set_id),
            techniques: meta.map(|m| m.techniques).unwrap_or_default(),
        },
        history: raw.history,
        related: CheckRelated {
            port,
            service,
            same_area: raw.same_area,
        },
        agents: raw.agents,
        failing_agents: raw.failing_agents,
    }))
}

values!(
    /// A Hosts card segment (ruling 11).
    CheckHostSegment {
        /// Failing and passing.
        All = "all",
        /// A failing pair, in any triage state.
        Failing = "failing",
        /// An inferred passing host.
        Passing = "passing",
    }
);

/// One input a finding's evaluation read (protocol P17).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Evidence {
    /// The fact key.
    pub fact: String,
    /// Its value, only when the agent sent it complete.
    pub value: Option<String>,
    /// `masked`, `summarized` or `truncated` instead of a value.
    pub status: Option<String>,
}

/// One row of the Hosts table.
#[derive(Clone, Debug)]
pub struct CheckHostRow {
    /// The host.
    pub agent_id: String,
    /// Its name.
    pub hostname: Option<String>,
    /// Its distribution, as the Hosts list names it.
    pub os: Option<String>,
    /// Its last address.
    pub address: Option<String>,
    /// open, mitigated, accepted_risk, false_positive or passing.
    pub state: String,
    /// What the failing evaluation read; empty for a passing host or a
    /// finding without detection.
    pub evidence: Vec<Evidence>,
    /// (user id, display name).
    pub assignee: Option<(String, String)>,
    /// The last observation (failing) or heartbeat health (passing).
    pub checked_at: Option<DateTime<Utc>>,
    /// The triage version for If-Match (0 without a triage row); none
    /// for a passing host.
    pub triage_version: Option<i64>,
    /// Until when the risk is accepted (kept after it expires, when the
    /// state reads open again); none for a passing host.
    pub accepted_until: Option<DateTime<Utc>>,
    /// The finding's origin (`online` or `import`); none for a passing host.
    pub origin: Option<String>,
}

/// Pairs per segment.
#[derive(Clone, Copy, Debug, Default, Deserialize)]
pub struct CheckSegments {
    /// Failing and passing.
    pub all: i64,
    /// Failing.
    pub failing: i64,
    /// Passing.
    pub passing: i64,
}

/// One page of the Hosts table.
#[derive(Clone, Debug)]
pub struct CheckHostsPage {
    /// The page, by host name then agent id.
    pub rows: Vec<CheckHostRow>,
    /// Pairs in the chosen segment.
    pub total: i64,
    /// Every segment's count.
    pub segments: CheckSegments,
    /// The failing pairs per triage state, whatever state is chosen.
    pub states: CheckStateCounts,
}

/// A finding's `detection -> 'inputs'` as evidence: a value only for a
/// complete input (P17 `status` `complete`, or none on older rows), else
/// the status alone, so a masked value is never shown.
#[must_use]
pub fn evidence(inputs: &Value) -> Vec<Evidence> {
    inputs
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|input| {
            let fact = input["key"].as_str()?.to_owned();
            let status = input["status"].as_str().filter(|s| *s != "complete");
            let value = match (status, &input["value"]) {
                (None, Value::String(s)) => Some(s.clone()),
                (None, v @ (Value::Bool(_) | Value::Number(_))) => Some(v.to_string()),
                _ => None,
            };
            Some(Evidence {
                fact,
                value,
                status: status.map(str::to_owned),
            })
        })
        .collect()
}

/// One page of the check's Hosts table within `scope`: `segment`, `state`
/// (narrows the Failing segment; ignored by the others), `offset`
/// (0–100000) and `limit` (1–100).
#[allow(clippy::too_many_arguments, reason = "the key, scope, page and clock")]
pub async fn check_hosts(
    client: &Client,
    rule_set_id: &str,
    rule_id: &str,
    scope: &AgentScope,
    segment: CheckHostSegment,
    state: Option<CheckHostState>,
    offset: i64,
    limit: i64,
    now: DateTime<Utc>,
) -> Result<Lookup<CheckHostsPage>, StoreError> {
    let state = state.filter(|_| segment == CheckHostSegment::Failing);
    let rows = client
        .query(
            &sql::hosts(),
            &[
                &scope.is_global(),
                &scope.group_ids(),
                &rule_set_id,
                &rule_id,
                &now,
                &segment.as_str(),
                &limit.clamp(1, 100),
                &offset.clamp(0, 100_000),
                &state.map_or("", CheckHostState::as_str),
            ],
        )
        .await?;
    let counts: Value = rows.first().map(|r| r.get(0)).unwrap_or_default();
    let states: CheckStateCounts =
        serde_json::from_value(counts["states"].clone()).map_err(|_| StoreError::Query)?;
    let segments: CheckSegments = serde_json::from_value(counts).map_err(|_| StoreError::Query)?;
    if segments.all == 0 {
        return Ok(Lookup::Missing);
    }
    Ok(Lookup::Found(CheckHostsPage {
        total: match (segment, state) {
            (CheckHostSegment::All, _) => segments.all,
            (CheckHostSegment::Failing, Some(s)) => states.of(s),
            (CheckHostSegment::Failing, None) => segments.failing,
            (CheckHostSegment::Passing, _) => segments.passing,
        },
        segments,
        states,
        rows: rows
            .iter()
            .filter_map(|r| {
                let agent_id: String = r.get::<_, Option<String>>(1)?;
                let assignee: Option<String> = r.get(7);
                Some(CheckHostRow {
                    agent_id,
                    hostname: r.get(2),
                    os: r.get(3),
                    address: r.get(4),
                    state: r.get(5),
                    evidence: r
                        .get::<_, Option<Value>>(6)
                        .map(|i| evidence(&i))
                        .unwrap_or_default(),
                    assignee: assignee.map(|id| (id, r.get(8))),
                    checked_at: r.get(9),
                    triage_version: r.get(10),
                    accepted_until: r.get(11),
                    origin: r.get(12),
                })
            })
            .collect(),
    }))
}
