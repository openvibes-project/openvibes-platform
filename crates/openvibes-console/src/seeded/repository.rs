//! The fixture behind the demo: 50,000 generated agents and their findings,
//! and the reads each handler makes of them.

use std::collections::BTreeMap;

use super::{
    filters::{AgentFilters, FindingFilters, cursor_offset, page},
    persona::{Persona, SeedMode},
};
use crate::{
    AgentDetail, AgentPage, AgentRuleSetView, AgentStatus, AgentSummary, AgentView,
    CertificateView, FindingOrigin, FindingPage, FindingSummary, FindingView, Severity,
};

pub(super) const GENERATED_AT: &str = "2026-09-24T12:00:00Z";

pub(super) const MAX_AGENTS: usize = 50_000;

impl AgentStatus {
    fn label(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Stale => "stale",
            Self::Revoked => "revoked",
            Self::Imported => "imported",
        }
    }
}

impl Severity {
    fn label(self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
        }
    }
}

#[derive(Clone, Debug)]
struct AgentRecord {
    view: AgentView,
    certificates: Vec<CertificateView>,
    scope_member: bool,
}

pub(super) trait ConsoleRepository: Send + Sync {
    fn agent_summary(&self, persona: Persona, mode: SeedMode) -> AgentSummary;
    fn agents(&self, filters: &AgentFilters, persona: Persona, mode: SeedMode) -> AgentPage;
    fn agent(&self, id: &str, persona: Persona, mode: SeedMode) -> Option<AgentDetail>;
    fn finding_summary(&self, persona: Persona, mode: SeedMode) -> FindingSummary;
    fn findings(&self, filters: &FindingFilters, persona: Persona, mode: SeedMode) -> FindingPage;
    fn finding(
        &self,
        agent: &str,
        rule_set: &str,
        rule: &str,
        persona: Persona,
        mode: SeedMode,
    ) -> Option<FindingView>;
    fn all_findings(&self, persona: Persona, mode: SeedMode) -> Vec<FindingView>;
}

pub(super) struct SeededRepository {
    agents: Vec<AgentRecord>,
    findings: Vec<FindingView>,
}

impl Default for SeededRepository {
    fn default() -> Self {
        let agents = (1..=MAX_AGENTS)
            .map(|number| {
                let id = format!("agent-{number:05}");
                let hostname = (number % 11 != 0).then(|| format!("host-{number:05}.example.test"));
                let never_seen = number % 199 == 0;
                let status = if number % 97 == 0 {
                    AgentStatus::Revoked
                } else if number % 6 == 0 || never_seen {
                    AgentStatus::Stale
                } else {
                    AgentStatus::Active
                };
                let last_seen_at = if never_seen {
                    None
                } else if matches!(status, AgentStatus::Stale) {
                    Some("2026-09-22T08:00:00Z")
                } else {
                    Some("2026-09-24T11:58:00Z")
                };
                let certificate = CertificateView {
                    serial: format!("{number:016X}"),
                    not_before: "2026-09-01T00:00:00Z".to_owned(),
                    not_after: if number % 89 == 0 {
                        "2026-09-20T00:00:00Z"
                    } else {
                        "2027-09-24T00:00:00Z"
                    }
                    .to_owned(),
                    issued_at: "2026-09-01T00:00:00Z".to_owned(),
                };
                AgentRecord {
                    view: AgentView {
                        id,
                        hostname,
                        status,
                        enrolled_at: "2026-09-01T00:00:00Z".to_owned(),
                        revoked_at: matches!(status, AgentStatus::Revoked)
                            .then(|| "2026-09-23T08:00:00Z".to_owned()),
                        last_seen_at: last_seen_at.map(str::to_owned),
                        scanner_version: Some("0.4.0".to_owned()),
                        capabilities: vec!["findings".to_owned(), "heartbeat".to_owned()],
                        os_id: Some("fedora".to_owned()),
                        os_version: Some("44".to_owned()),
                        running_kernel: Some("6.17.4-300.fc44.x86_64".to_owned()),
                        inventory_at: last_seen_at.map(str::to_owned),
                        rule_sets: vec![AgentRuleSetView {
                            id: "baseline".to_owned(),
                            version: Some(2),
                            expires_at_ms: Some(1_853_910_427_825),
                            refused: None,
                            state: None,
                        }],
                        rule_sets_at: last_seen_at.map(str::to_owned),
                        alarms: Some(if number % 41 == 0 {
                            crate::AgentAlarmsView {
                                state: "off".to_owned(),
                                source: None,
                                reason: Some("audit_not_set_up".to_owned()),
                                text: Some("this kernel has no BTF, and no program start seen through audit yet: the exec audit rule is probably not loaded, or auditd is not running".to_owned()),
                                fix: Some("make sure auditd is installed and running, then run the command below".to_owned()),
                                command: Some("sudo /usr/libexec/openvibes-agent/audit-fallback".to_owned()),
                                fault: true,
                            }
                        } else {
                            crate::AgentAlarmsView {
                                state: "on".to_owned(),
                                source: Some(if number % 7 == 0 { "audit" } else { "ebpf" }.to_owned()),
                                reason: None,
                                text: None,
                                fix: None,
                                command: None,
                                fault: false,
                            }
                        }),
                    },
                    certificates: vec![certificate],
                    scope_member: number % 5 == 0,
                }
            })
            .collect::<Vec<_>>();
        let findings = (1u32..=120)
            .map(|number| {
                let agent_number = (number * 7 % 400) + 1;
                FindingView {
                    detection: None,
                    id: format!("finding-{number:05}"),
                    agent_id: format!("agent-{agent_number:05}"),
                    hostname: (agent_number % 11 != 0)
                        .then(|| format!("host-{agent_number:05}.example.test")),
                    rule_set_id: if number == 120 {
                        "~unknown".to_owned()
                    } else {
                        "baseline-linux".to_owned()
                    },
                    rule_id: format!("OV-{number:04}"),
                    rule_version: 3 + u64::from(number % 4),
                    severity: match number % 4 {
                        0 => Severity::Critical,
                        1 => Severity::High,
                        2 => Severity::Medium,
                        _ => Severity::Low,
                    },
                    confidence: if number == 120 { 82 } else { 95 },
                    message: format!("Synthetic security observation {number:04}"),
                    evidence: vec![format!("synthetic.observation={number:04}")],
                    scan_id: format!("scan-{number:05}"),
                    authenticated: number != 120,
                    origin: if number == 120 {
                        FindingOrigin::Import
                    } else {
                        FindingOrigin::Online
                    },
                    first_observed_at: "2026-09-20T12:00:00Z".to_owned(),
                    last_observed_at: format!("2026-09-24T11:{:02}:00Z", 59 - number % 60),
                    received_at: format!("2026-09-24T12:{:02}:00Z", number % 60),
                }
            })
            .collect();
        Self { agents, findings }
    }
}

impl SeededRepository {
    fn visible(&self, agent: &AgentRecord, persona: Persona, mode: SeedMode) -> bool {
        if matches!(mode, SeedMode::Empty) {
            return false;
        }
        let status_ok =
            !matches!(mode, SeedMode::Stale) || matches!(agent.view.status, AgentStatus::Stale);
        status_ok && (persona.global_scope() || agent.scope_member)
    }

    fn matching_findings(&self, persona: Persona, mode: SeedMode) -> Vec<FindingView> {
        if matches!(mode, SeedMode::Empty) {
            return Vec::new();
        }
        self.findings
            .iter()
            .filter(|finding| {
                // ponytail: scan at most 50,000 agent IDs for each of 120 seeded findings;
                // build an ID index if either fixture grows materially.
                self.agents
                    .iter()
                    .take(agent_count(mode))
                    .find(|agent| agent.view.id == finding.agent_id)
                    .is_some_and(|agent| self.visible(agent, persona, mode))
            })
            .cloned()
            .collect()
    }
}

impl ConsoleRepository for SeededRepository {
    fn agent_summary(&self, persona: Persona, mode: SeedMode) -> AgentSummary {
        self.agents
            .iter()
            .take(agent_count(mode))
            .filter(|agent| self.visible(agent, persona, mode))
            .fold(
                AgentSummary {
                    total: 0,
                    active: 0,
                    stale: 0,
                    revoked: 0,
                    imported: 0,
                    platform_version: env!("CARGO_PKG_VERSION").to_owned(),
                },
                |mut summary, agent| {
                    summary.total += 1;
                    match agent.view.status {
                        AgentStatus::Active => summary.active += 1,
                        AgentStatus::Stale => summary.stale += 1,
                        AgentStatus::Revoked => summary.revoked += 1,
                        AgentStatus::Imported => summary.imported += 1,
                    }
                    summary
                },
            )
    }

    fn agents(&self, filters: &AgentFilters, persona: Persona, mode: SeedMode) -> AgentPage {
        let query = filters
            .query
            .as_deref()
            .unwrap_or_default()
            .to_ascii_lowercase();
        let matched =
            self.agents
                .iter()
                .take(agent_count(mode))
                .filter(|agent| {
                    self.visible(agent, persona, mode)
                        && filters
                            .status
                            .is_none_or(|status| agent.view.status.label() == status.label())
                        && (query.is_empty()
                            || agent.view.hostname.as_deref().is_some_and(|hostname| {
                                hostname.to_ascii_lowercase().contains(&query)
                            })
                            || agent.view.id.contains(&query))
                })
                .collect::<Vec<_>>();
        let offset = cursor_offset(filters.page.cursor(), "agents").unwrap_or(0);
        let page = page(
            matched
                .into_iter()
                .map(|agent| agent.view.clone())
                .collect(),
            offset,
            filters.page.limit(),
            "agents",
        );
        AgentPage {
            items: page.items,
            next_cursor: page.next_cursor,
            generated_at: page.generated_at,
        }
    }

    fn agent(&self, id: &str, persona: Persona, mode: SeedMode) -> Option<AgentDetail> {
        let agent = self
            .agents
            .iter()
            .take(agent_count(mode))
            .find(|agent| agent.view.id == id && self.visible(agent, persona, mode))?;
        Some(AgentDetail {
            agent: agent.view.clone(),
            certificates: agent.certificates.clone(),
            last_test: crate::hosts::LastTest::default(),
        })
    }

    fn finding_summary(&self, persona: Persona, mode: SeedMode) -> FindingSummary {
        let findings = self.matching_findings(persona, mode);
        let mut summary = FindingSummary {
            total: findings.len() as u64,
            impacted_agents: 0,
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
        };
        let mut agents = BTreeMap::new();
        for finding in findings {
            agents.insert(finding.agent_id, ());
            match finding.severity {
                Severity::Critical => summary.critical += 1,
                Severity::High => summary.high += 1,
                Severity::Medium => summary.medium += 1,
                Severity::Low => summary.low += 1,
            }
        }
        summary.impacted_agents = agents.len() as u64;
        summary
    }

    fn findings(&self, filters: &FindingFilters, persona: Persona, mode: SeedMode) -> FindingPage {
        let query = filters
            .query
            .as_deref()
            .unwrap_or_default()
            .to_ascii_lowercase();
        let mut matched =
            self.matching_findings(persona, mode)
                .into_iter()
                .filter(|finding| {
                    filters
                        .severity
                        .is_none_or(|severity| finding.severity.label() == severity.label())
                        && (query.is_empty()
                            || finding.hostname.as_deref().is_some_and(|hostname| {
                                hostname.to_ascii_lowercase().contains(&query)
                            })
                            || finding.rule_id.to_ascii_lowercase().contains(&query)
                            || finding.message.to_ascii_lowercase().contains(&query))
                })
                .collect::<Vec<_>>();
        matched.sort_by(|left, right| {
            right
                .last_observed_at
                .cmp(&left.last_observed_at)
                .then_with(|| left.id.cmp(&right.id))
        });
        let offset = cursor_offset(filters.page.cursor(), "findings").unwrap_or(0);
        let page = page(matched, offset, filters.page.limit(), "findings");
        FindingPage {
            items: page.items,
            next_cursor: page.next_cursor,
            generated_at: page.generated_at,
        }
    }

    fn finding(
        &self,
        agent: &str,
        rule_set: &str,
        rule: &str,
        persona: Persona,
        mode: SeedMode,
    ) -> Option<FindingView> {
        self.matching_findings(persona, mode)
            .into_iter()
            .find(|finding| {
                finding.agent_id == agent
                    && finding.rule_set_id == rule_set
                    && finding.rule_id == rule
            })
    }

    fn all_findings(&self, persona: Persona, mode: SeedMode) -> Vec<FindingView> {
        self.matching_findings(persona, mode)
    }
}

fn agent_count(mode: SeedMode) -> usize {
    if matches!(mode, SeedMode::Large) {
        MAX_AGENTS
    } else {
        500
    }
}
