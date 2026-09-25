//! The fixed list of read-only lookups (spec §5): their definitions for the
//! model, strict parsing of what the model asks for, and execution through
//! `platform-store` with the asking user's scope.
//!
//! Every result is JSON with bounded items, a `cite` value on each object
//! the model may cite, and how many items were left out, so the model never
//! claims completeness it did not see.

use std::{collections::BTreeSet, future::Future};

use chrono::{DateTime, Duration, SecondsFormat, Utc};
use openvibes_core::{PayloadEncoding, RuleSet, SignedRuleEnvelope};
use platform_store::{
    Pool,
    assistant::{
        self as store, ADVISORY_SEVERITIES, AgentScope, FINDING_SEVERITIES, GroupFilter, Page,
    },
    rules::{self, Served},
};
use serde::Deserialize;
use serde_json::{Map, Value, json};

use crate::{answer::Citation, client::ToolSpec};

/// Longest string argument.
const MAX_ARGUMENT: usize = 128;
/// Default and largest look-back window, in hours.
const DEFAULT_WINDOW_HOURS: u32 = 24;
const MAX_WINDOW_HOURS: u32 = 720;
/// Largest rule payload parsed for `rule_description`.
const MAX_RULE_PAYLOAD: usize = 1024 * 1024;
/// Longest rule expression shown.
const MAX_EXPRESSION: usize = 500;

/// A validated lookup request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Lookup {
    /// Finding groups (console decision 18).
    SearchFindings {
        /// Text in the rule set, rule, or message.
        text: Option<String>,
        /// Lowest severity.
        min_severity: Option<&'static str>,
        /// One rule set (`""` for unknown).
        rule_set: Option<String>,
        /// Look-back window.
        window_hours: u32,
    },
    /// Endpoints reporting one finding.
    FindingEndpoints {
        /// Rule set (`""` for unknown).
        rule_set: String,
        /// Rule.
        rule: String,
        /// Look-back window.
        window_hours: u32,
    },
    /// Agents by ID or host name.
    AgentSummary {
        /// Agent ID or host name.
        agent: String,
    },
    /// A host's open vulnerabilities.
    HostVulnerabilities {
        /// Agent ID or host name.
        agent: String,
        /// Lowest advisory severity.
        min_severity: Option<&'static str>,
    },
    /// Hosts affected by a CVE or advisory.
    VulnerabilityHosts {
        /// CVE ID or advisory ID.
        id: String,
    },
    /// The fleet at a glance.
    FleetOverview {
        /// Look-back window for findings.
        window_hours: u32,
    },
    /// A rule's published definition.
    RuleDescription {
        /// Rule set.
        rule_set: String,
        /// Rule.
        rule: String,
    },
}

/// Why a lookup request was refused or failed. Fed back to the model as a
/// fixed message and recorded for audit; never contains model text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LookupError {
    /// Not one of the lookups.
    Unknown,
    /// Arguments are not valid JSON for the lookup's schema.
    InvalidArguments,
    /// A host name matches several agents.
    Ambiguous,
    /// The database failed.
    Store,
}

impl LookupError {
    /// The message given to the model.
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            Self::Unknown => "error: no such lookup; use one of the listed lookups",
            Self::InvalidArguments => "error: invalid arguments for this lookup; check its schema",
            Self::Ambiguous => {
                "error: that host name matches several agents; use an agent ID from agent_summary"
            }
            Self::Store => "error: the lookup failed; try again later",
        }
    }
}

fn severity_schema(values: &[&str]) -> Value {
    json!({ "type": "string", "enum": values })
}

fn text_schema(description: &str) -> Value {
    json!({ "type": "string", "maxLength": MAX_ARGUMENT, "description": description })
}

fn window_schema() -> Value {
    json!({ "type": "integer", "minimum": 1, "maximum": MAX_WINDOW_HOURS,
            "description": "Look-back window in hours (default 24)." })
}

fn object(properties: Value, required: &[&str]) -> Value {
    json!({ "type": "object", "properties": properties, "required": required,
            "additionalProperties": false })
}

/// The lookups offered to the model.
#[must_use]
pub fn specs() -> Vec<ToolSpec> {
    let spec = |name: &str, description: &str, parameters: Value| ToolSpec {
        name: name.into(),
        description: description.into(),
        parameters,
    };
    vec![
        spec(
            "search_findings",
            "Findings (rule matches) across endpoints, one row per rule, most severe and widespread first.",
            object(
                json!({
                    "text": text_schema("Words in the rule or message, e.g. ssh."),
                    "min_severity": severity_schema(&FINDING_SEVERITIES),
                    "rule_set": text_schema("One rule set."),
                    "window_hours": window_schema(),
                }),
                &[],
            ),
        ),
        spec(
            "finding_endpoints",
            "Endpoints that reported one finding, most recent first.",
            object(
                json!({
                    "rule_set": text_schema("Rule set of the finding."),
                    "rule": text_schema("Rule of the finding."),
                    "window_hours": window_schema(),
                }),
                &["rule_set", "rule"],
            ),
        ),
        spec(
            "agent_summary",
            "One endpoint by agent ID or host name: status, last contact, OS, counts of findings and vulnerabilities.",
            object(
                json!({ "agent": text_schema("Agent ID or host name.") }),
                &["agent"],
            ),
        ),
        spec(
            "host_vulnerabilities",
            "Open vulnerabilities on one endpoint, highest priority first (exploited, then EPSS, then severity).",
            object(
                json!({
                    "agent": text_schema("Agent ID or host name."),
                    "min_severity": severity_schema(&ADVISORY_SEVERITIES),
                }),
                &["agent"],
            ),
        ),
        spec(
            "vulnerability_hosts",
            "Endpoints with an open vulnerability for a CVE or advisory.",
            object(
                json!({ "id": text_schema("CVE ID or advisory ID.") }),
                &["id"],
            ),
        ),
        spec(
            "fleet_overview",
            "Agent counts by state, open vulnerabilities, top findings, and top advisories.",
            object(json!({ "window_hours": window_schema() }), &[]),
        ),
        spec(
            "rule_description",
            "What a rule checks: title, severity, message, and expression.",
            object(
                json!({
                    "rule_set": text_schema("Rule set."),
                    "rule": text_schema("Rule."),
                }),
                &["rule_set", "rule"],
            ),
        ),
    ]
}

/// The lookup names, in [`specs`] order.
pub const NAMES: [&str; 7] = [
    "search_findings",
    "finding_endpoints",
    "agent_summary",
    "host_vulnerabilities",
    "vulnerability_hosts",
    "fleet_overview",
    "rule_description",
];

fn text_arg(value: Option<String>) -> Result<Option<String>, LookupError> {
    match value {
        None => Ok(None),
        Some(text) => {
            let text = text.trim();
            if text.is_empty() {
                return Ok(None);
            }
            let valid = text.chars().count() <= MAX_ARGUMENT && !text.chars().any(char::is_control);
            valid
                .then(|| Some(text.to_owned()))
                .ok_or(LookupError::InvalidArguments)
        }
    }
}

fn required(value: String) -> Result<String, LookupError> {
    text_arg(Some(value))?.ok_or(LookupError::InvalidArguments)
}

/// A rule set argument: `~unknown` or empty means findings from before P6.
fn rule_set_arg(value: String) -> Result<String, LookupError> {
    match text_arg(Some(value))? {
        None => Ok(String::new()),
        Some(set) if set == "~unknown" => Ok(String::new()),
        Some(set) => Ok(set),
    }
}

fn window(hours: Option<u32>) -> Result<u32, LookupError> {
    let hours = hours.unwrap_or(DEFAULT_WINDOW_HOURS);
    (1..=MAX_WINDOW_HOURS)
        .contains(&hours)
        .then_some(hours)
        .ok_or(LookupError::InvalidArguments)
}

fn severity(
    value: Option<String>,
    known: &'static [&'static str],
) -> Result<Option<&'static str>, LookupError> {
    value
        .map(|value| {
            known
                .iter()
                .find(|s| s.eq_ignore_ascii_case(value.trim()))
                .copied()
                .ok_or(LookupError::InvalidArguments)
        })
        .transpose()
}

impl Lookup {
    /// Parses a request by name with its JSON arguments; unknown fields,
    /// wrong types, and out-of-range values are refused.
    pub fn parse(name: &str, arguments: &str) -> Result<Self, LookupError> {
        fn args<T: for<'de> Deserialize<'de>>(arguments: &str) -> Result<T, LookupError> {
            let arguments = if arguments.trim().is_empty() {
                "{}"
            } else {
                arguments
            };
            serde_json::from_str(arguments).map_err(|_| LookupError::InvalidArguments)
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Search {
            text: Option<String>,
            min_severity: Option<String>,
            rule_set: Option<String>,
            window_hours: Option<u32>,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Endpoints {
            rule_set: String,
            rule: String,
            window_hours: Option<u32>,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Agent {
            agent: String,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct HostVulns {
            agent: String,
            min_severity: Option<String>,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Id {
            id: String,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Overview {
            window_hours: Option<u32>,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Rule {
            rule_set: String,
            rule: String,
        }
        match name {
            "search_findings" => {
                let a: Search = args(arguments)?;
                Ok(Self::SearchFindings {
                    text: text_arg(a.text)?,
                    min_severity: severity(a.min_severity, &FINDING_SEVERITIES)?,
                    rule_set: a.rule_set.map(rule_set_arg).transpose()?,
                    window_hours: window(a.window_hours)?,
                })
            }
            "finding_endpoints" => {
                let a: Endpoints = args(arguments)?;
                Ok(Self::FindingEndpoints {
                    rule_set: rule_set_arg(a.rule_set)?,
                    rule: required(a.rule)?,
                    window_hours: window(a.window_hours)?,
                })
            }
            "agent_summary" => {
                let a: Agent = args(arguments)?;
                Ok(Self::AgentSummary {
                    agent: required(a.agent)?,
                })
            }
            "host_vulnerabilities" => {
                let a: HostVulns = args(arguments)?;
                Ok(Self::HostVulnerabilities {
                    agent: required(a.agent)?,
                    min_severity: severity(a.min_severity, &ADVISORY_SEVERITIES)?,
                })
            }
            "vulnerability_hosts" => {
                let a: Id = args(arguments)?;
                Ok(Self::VulnerabilityHosts {
                    id: required(a.id)?,
                })
            }
            "fleet_overview" => {
                let a: Overview = args(arguments)?;
                Ok(Self::FleetOverview {
                    window_hours: window(a.window_hours)?,
                })
            }
            "rule_description" => {
                let a: Rule = args(arguments)?;
                Ok(Self::RuleDescription {
                    rule_set: rule_set_arg(a.rule_set)?,
                    rule: required(a.rule)?,
                })
            }
            _ => Err(LookupError::Unknown),
        }
    }

    /// The lookup's name.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::SearchFindings { .. } => NAMES[0],
            Self::FindingEndpoints { .. } => NAMES[1],
            Self::AgentSummary { .. } => NAMES[2],
            Self::HostVulnerabilities { .. } => NAMES[3],
            Self::VulnerabilityHosts { .. } => NAMES[4],
            Self::FleetOverview { .. } => NAMES[5],
            Self::RuleDescription { .. } => NAMES[6],
        }
    }

    /// The validated arguments, re-serialised (for audit: never the raw
    /// model text).
    #[must_use]
    pub fn arguments(&self) -> Value {
        match self {
            Self::SearchFindings {
                text,
                min_severity,
                rule_set,
                window_hours,
            } => json!({
                "text": text, "min_severity": min_severity, "rule_set": rule_set,
                "window_hours": window_hours,
            }),
            Self::FindingEndpoints {
                rule_set,
                rule,
                window_hours,
            } => {
                json!({ "rule_set": rule_set, "rule": rule, "window_hours": window_hours })
            }
            Self::AgentSummary { agent } => json!({ "agent": agent }),
            Self::HostVulnerabilities {
                agent,
                min_severity,
            } => {
                json!({ "agent": agent, "min_severity": min_severity })
            }
            Self::VulnerabilityHosts { id } => json!({ "id": id }),
            Self::FleetOverview { window_hours } => json!({ "window_hours": window_hours }),
            Self::RuleDescription { rule_set, rule } => {
                json!({ "rule_set": rule_set, "rule": rule })
            }
        }
    }
}

/// A lookup's result: JSON the model reads, with an `items` list that can
/// be shortened to fit the prompt.
#[derive(Clone, Debug, PartialEq)]
pub struct LookupOutput {
    /// The result object (`items`, `omitted`, and summary fields).
    pub data: Value,
}

impl LookupOutput {
    fn page(mut summary: Map<String, Value>, items: Vec<Value>, total: i64) -> Self {
        let shown = i64::try_from(items.len()).unwrap_or(i64::MAX);
        summary.insert("items".into(), Value::Array(items));
        summary.insert("omitted".into(), json!((total - shown).max(0)));
        Self {
            data: Value::Object(summary),
        }
    }

    /// The serialised result.
    #[must_use]
    pub fn text(&self) -> String {
        self.data.to_string()
    }

    /// Drops trailing items (counting them as omitted) until the result
    /// fits `max_chars`, or no items are left.
    pub fn shrink_to(&mut self, max_chars: usize) {
        while self.text().len() > max_chars {
            let Some(Value::Array(items)) = self.data.get_mut("items") else {
                return;
            };
            if items.pop().is_none() {
                return;
            }
            if let Some(omitted) = self.data.get_mut("omitted") {
                *omitted = json!(omitted.as_i64().unwrap_or(0) + 1);
            }
        }
    }

    /// Citations of the objects in this result (from their `cite` values).
    #[must_use]
    pub fn citations(&self) -> BTreeSet<Citation> {
        let mut found = BTreeSet::new();
        collect_citations(&self.data, &mut found);
        found
    }

    /// Objects shown (for audit).
    #[must_use]
    pub fn objects(&self) -> usize {
        self.citations().len()
    }
}

/// Keys whose values are platform-written citations.
const CITATION_KEYS: [&str; 4] = ["cite", "agent", "finding", "advisory"];

fn collect_citations(value: &Value, found: &mut BTreeSet<Citation>) {
    match value {
        Value::Object(map) => {
            // Only these keys carry citations the platform wrote. Strings
            // from hosts (host names, messages) never do, even when they
            // look like one.
            for key in CITATION_KEYS {
                if let Some(citation) = map
                    .get(key)
                    .and_then(Value::as_str)
                    .and_then(Citation::parse)
                {
                    found.insert(citation);
                }
            }
            map.values()
                .for_each(|value| collect_citations(value, found));
        }
        Value::Array(items) => items
            .iter()
            .for_each(|value| collect_citations(value, found)),
        _ => {}
    }
}

/// Runs lookups. The console's implementation is [`StoreLookups`]; tests
/// substitute their own.
pub trait LookupRunner: Send + Sync {
    /// Runs `lookup`, returning at most `items` items.
    fn run(
        &self,
        lookup: &Lookup,
        items: u32,
    ) -> impl Future<Output = Result<LookupOutput, LookupError>> + Send;
}

/// Lookups against `platform-store`, limited to one user's scope.
pub struct StoreLookups {
    pool: Pool,
    scope: AgentScope,
    now: DateTime<Utc>,
}

impl StoreLookups {
    /// Lookups for a user whose asset scope is `scope`, as of `now`.
    #[must_use]
    pub fn new(pool: Pool, scope: AgentScope, now: DateTime<Utc>) -> Self {
        Self { pool, scope, now }
    }
}

fn time(at: DateTime<Utc>) -> String {
    at.to_rfc3339_opts(SecondsFormat::Secs, true)
}

fn agent_cite(id: &str) -> String {
    Citation::Agent(id.to_owned()).to_string()
}

fn finding_cite(rule_set: &str, rule: &str) -> String {
    Citation::Finding {
        rule_set: rule_set.to_owned(),
        rule: rule.to_owned(),
    }
    .to_string()
}

fn advisory_cite(id: &str) -> String {
    Citation::Advisory(id.to_owned()).to_string()
}

fn groups_json(page: &Page<store::FindingGroup>) -> Vec<Value> {
    page.items
        .iter()
        .map(|g| {
            json!({
                "cite": finding_cite(&g.rule_set_id, &g.rule_id),
                "rule_set": if g.rule_set_id.is_empty() { "~unknown" } else { g.rule_set_id.as_str() },
                "rule": g.rule_id,
                "severity": g.severity,
                "endpoints": g.endpoints,
                "rule_versions": g.rule_versions,
                "first_observed": time(g.first_observed_at),
                "last_observed": time(g.last_observed_at),
                "message": g.message,
            })
        })
        .collect()
}

impl StoreLookups {
    async fn resolve_agent(
        &self,
        client: &platform_store::Client,
        key: &str,
    ) -> Result<Option<String>, LookupError> {
        let found = store::agent_summaries(client, &self.scope, key, self.now, 2)
            .await
            .map_err(|_| LookupError::Store)?;
        match found.items.as_slice() {
            [] => Ok(None),
            [one] => Ok(Some(one.agent_id.clone())),
            _ => Err(LookupError::Ambiguous),
        }
    }
}

impl LookupRunner for StoreLookups {
    async fn run(&self, lookup: &Lookup, items: u32) -> Result<LookupOutput, LookupError> {
        let client = self.pool.get().await.map_err(|_| LookupError::Store)?;
        let store_error = |_| LookupError::Store;
        let since = |hours: u32| self.now - Duration::hours(i64::from(hours));
        let mut summary = Map::new();
        Ok(match lookup {
            Lookup::SearchFindings {
                text,
                min_severity,
                rule_set,
                window_hours,
            } => {
                let filter = GroupFilter {
                    text: text.as_deref(),
                    min_severity: *min_severity,
                    rule_set_id: rule_set.as_deref(),
                };
                let page = store::finding_groups(
                    &client,
                    &self.scope,
                    &filter,
                    since(*window_hours),
                    items,
                )
                .await
                .map_err(store_error)?;
                summary.insert("window_hours".into(), json!(window_hours));
                LookupOutput::page(summary, groups_json(&page), page.total)
            }
            Lookup::FindingEndpoints {
                rule_set,
                rule,
                window_hours,
            } => {
                let page = store::finding_endpoints(
                    &client,
                    &self.scope,
                    rule_set,
                    rule,
                    since(*window_hours),
                    items,
                )
                .await
                .map_err(store_error)?;
                summary.insert("finding".into(), json!(finding_cite(rule_set, rule)));
                summary.insert("window_hours".into(), json!(window_hours));
                summary.insert("not_seen_in_window".into(), json!(page.older));
                let endpoints = page
                    .items
                    .iter()
                    .map(|e| {
                        json!({
                            "cite": agent_cite(&e.agent_id),
                            "hostname": e.hostname,
                            "first_observed": time(e.first_observed_at),
                            "last_observed": time(e.last_observed_at),
                            "rule_version": e.rule_version,
                            "severity": e.severity,
                        })
                    })
                    .collect();
                LookupOutput::page(summary, endpoints, page.total)
            }
            Lookup::AgentSummary { agent } => {
                let page = store::agent_summaries(
                    &client,
                    &self.scope,
                    agent,
                    since(DEFAULT_WINDOW_HOURS),
                    items.min(5),
                )
                .await
                .map_err(store_error)?;
                let offline_before =
                    self.now - Duration::minutes(platform_store::OFFLINE_AFTER_MINUTES);
                let agents = page
                    .items
                    .iter()
                    .map(|a| {
                        let state = match (a.status.as_str(), a.last_seen_at) {
                            ("revoked", _) => "revoked",
                            (_, None) => "never seen",
                            (_, Some(seen)) if seen < offline_before => "offline",
                            _ => "seen recently",
                        };
                        json!({
                            "cite": agent_cite(&a.agent_id),
                            "hostname": a.hostname,
                            "state": state,
                            "last_seen": a.last_seen_at.map(time),
                            "scanner_version": a.scanner_version,
                            "os": a.os.as_ref().map(|(id, version)| format!("{id} {version}")),
                            "running_kernel": a.running_kernel,
                            "capabilities": a.capabilities,
                            "findings_last_24h": a.findings,
                            "open_vulnerabilities": a.open_vulnerabilities,
                            "exploited_vulnerabilities": a.exploited_vulnerabilities,
                        })
                    })
                    .collect();
                LookupOutput::page(summary, agents, page.total)
            }
            Lookup::HostVulnerabilities {
                agent,
                min_severity,
            } => {
                let Some(agent_id) = self.resolve_agent(&client, agent).await? else {
                    summary.insert("agent".into(), Value::Null);
                    return Ok(LookupOutput::page(summary, Vec::new(), 0));
                };
                let page = store::host_vulnerabilities(
                    &client,
                    &self.scope,
                    &agent_id,
                    *min_severity,
                    items,
                )
                .await
                .map_err(store_error)?;
                summary.insert("agent".into(), json!(agent_cite(&agent_id)));
                let vulns = page
                    .items
                    .iter()
                    .map(|v| {
                        json!({
                            "cite": advisory_cite(&v.advisory_id),
                            "severity": v.severity,
                            "title": v.title,
                            "cves": v.cves,
                            "exploited": v.exploited,
                            "epss_percentile": v.epss_percentile,
                            "reboot_needed": v.reboot_needed,
                            "first_seen": time(v.first_seen_at),
                        })
                    })
                    .collect();
                LookupOutput::page(summary, vulns, page.total)
            }
            Lookup::VulnerabilityHosts { id } => {
                let page = store::vulnerable_hosts(&client, &self.scope, id, items)
                    .await
                    .map_err(store_error)?;
                let hosts = page
                    .items
                    .iter()
                    .map(|h| {
                        json!({
                            "cite": agent_cite(&h.agent_id),
                            "hostname": h.hostname,
                            "advisory": advisory_cite(&h.advisory_id),
                            "first_seen": time(h.first_seen_at),
                            "reboot_needed": h.reboot_needed,
                        })
                    })
                    .collect();
                LookupOutput::page(summary, hosts, page.total)
            }
            Lookup::FleetOverview { window_hours } => {
                let overview = store::overview(
                    &client,
                    &self.scope,
                    since(*window_hours),
                    self.now,
                    items.min(5),
                )
                .await
                .map_err(store_error)?;
                summary.insert("window_hours".into(), json!(window_hours));
                summary.insert(
                    "agents".into(),
                    json!({
                        "seen_recently": overview.agents.seen_recently,
                        "offline": overview.agents.offline,
                        "never_seen": overview.agents.never_seen,
                        "revoked": overview.agents.revoked,
                    }),
                );
                summary.insert(
                    "open_vulnerabilities".into(),
                    json!(overview.open_vulnerabilities),
                );
                summary.insert(
                    "hosts_with_exploited".into(),
                    json!(overview.hosts_with_exploited),
                );
                summary.insert(
                    "top_advisories".into(),
                    Value::Array(
                        overview
                            .top_advisories
                            .items
                            .iter()
                            .map(|a| {
                                json!({ "cite": advisory_cite(&a.advisory_id), "severity": a.severity,
                                        "title": a.title, "hosts": a.hosts })
                            })
                            .collect(),
                    ),
                );
                LookupOutput::page(
                    summary,
                    groups_json(&overview.top_findings),
                    overview.top_findings.total,
                )
            }
            Lookup::RuleDescription { rule_set, rule } => {
                let served = rules::serve(&client, rule_set, None)
                    .await
                    .map_err(store_error)?;
                summary.insert("rule".into(), rule_json(served, rule_set, rule));
                LookupOutput::page(summary, Vec::new(), 0)
            }
        })
    }
}

/// A rule from a published bundle, or `null` when the rule set, bundle, or
/// rule is unknown or the payload cannot be read (only JSON payloads are).
fn rule_json(served: Served, rule_set: &str, rule: &str) -> Value {
    let Served::Envelope(bytes) = served else {
        return Value::Null;
    };
    let Ok(envelope) = serde_json::from_slice::<SignedRuleEnvelope>(&bytes) else {
        return Value::Null;
    };
    if envelope.payload_encoding != PayloadEncoding::Json
        || envelope.payload.len() > MAX_RULE_PAYLOAD
    {
        return Value::Null;
    }
    let Ok(set) = serde_json::from_str::<RuleSet>(&envelope.payload) else {
        return Value::Null;
    };
    set.rules
        .iter()
        .find(|candidate| candidate.id.as_str() == rule)
        .map_or(Value::Null, |found| {
            json!({
                "cite": finding_cite(rule_set, rule),
                "bundle_version": envelope.rule_set_version,
                "version": found.version,
                "title": found.title,
                "severity": found.severity,
                "message": found.finding_message,
                "expression": found.expression.chars().take(MAX_EXPRESSION).collect::<String>(),
            })
        })
}
