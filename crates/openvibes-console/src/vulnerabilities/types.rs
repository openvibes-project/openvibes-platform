//! Request and response types of vulnerabilities and advisories.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Advisory severity used by the vulnerability matcher.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum VulnerabilitySeverity {
    /// Critical.
    Critical,
    /// Important.
    Important,
    /// Moderate.
    Moderate,
    /// Low.
    Low,
    /// No severity rating was supplied.
    Unrated,
}

/// One severity total in the visible vulnerability scope.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct VulnerabilitySeverityCount {
    /// Advisory severity.
    pub severity: VulnerabilitySeverity,
    /// Open host-advisory pairs.
    pub count: u64,
}

/// Operator-facing top vulnerable host.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct VulnerabilityTopHost {
    /// Agent or imported installation identifier.
    pub agent_id: String,
    /// Hostname label, when reported.
    pub hostname: Option<String>,
    /// Number of open advisories.
    pub open: u64,
    /// Critical and important advisories.
    pub serious: u64,
}

/// Scope-filtered fleet vulnerability summary.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct VulnerabilitySummary {
    /// Open host-advisory pairs by severity.
    pub by_severity: Vec<VulnerabilitySeverityCount>,
    /// Hosts with at least one open advisory.
    pub hosts: u64,
    /// Ten most affected hosts in scope.
    pub top_hosts: Vec<VulnerabilityTopHost>,
    /// Hosts only needing a reboot to activate the installed fix.
    pub reboot_hosts: u64,
    /// Host-advisory pairs without a known fixed package version.
    pub no_fix: u64,
    /// Open, non-reboot findings with KEV/EUVD exploitation evidence.
    pub exploited: u64,
    /// When an advisory feed last imported new content (RFC 3339); null
    /// until one has, so zero counts mean "nothing found" only when set.
    pub feed_last_imported_at: Option<String>,
}

/// One host-advisory match with package and exploitation details.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct VulnerabilityView {
    /// Agent or imported installation identifier.
    pub agent_id: String,
    /// Hostname label, when reported.
    pub hostname: Option<String>,
    /// Advisory identifier.
    pub advisory_id: String,
    /// Advisory severity.
    pub severity: VulnerabilitySeverity,
    /// Advisory title.
    pub title: String,
    /// Advisory URL.
    pub url: String,
    /// CVE identifiers named by the advisory.
    pub cves: Vec<String>,
    /// Affected package names and installed/fixed versions.
    pub packages: serde_json::Value,
    /// First time this host matched the advisory.
    pub first_seen_at: String,
    /// When the vulnerability was fixed; absent while still open.
    pub fixed_at: Option<String>,
    /// A kernel fix is installed but not running.
    pub reboot_needed: bool,
    /// At least one CVE is on KEV or EUVD exploited lists.
    pub exploited: bool,
    /// At least one CVE is on CISA KEV.
    pub kev: bool,
    /// At least one CVE is on EUVD's exploited list.
    pub euvd: bool,
    /// Earliest KEV due date.
    pub kev_due: Option<String>,
    /// One CVE is known to be used by ransomware.
    pub ransomware: bool,
    /// Highest EPSS score among advisory CVEs.
    pub epss: Option<f32>,
    /// Highest EPSS percentile among advisory CVEs.
    pub epss_percentile: Option<f32>,
    /// Highest NVD CVSS base score among advisory CVEs.
    pub cvss: Option<f32>,
    /// Feed the advisory came from, e.g. `fedora-44-x86_64`.
    pub source: String,
    /// How the host was matched to the advisory, e.g. `distribution-advisory`.
    pub match_method: String,
    /// Mapping confidence, 0 to 100.
    pub confidence: u8,
    /// A sentence saying how the host was matched.
    pub match_basis: String,
    /// This host's triage: `open`, `mitigated`, `accepted_risk` or
    /// `false_positive` (triage v2).
    pub triage_state: String,
    /// Triage write version (0 = never triaged), for If-Match.
    pub triage_version: i64,
    /// Assigned analyst's username.
    pub assigned_to: Option<String>,
}

/// Bounded prioritised vulnerability list for the current scope.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct VulnerabilityPage {
    /// Highest-priority rows returned by the query.
    pub items: Vec<VulnerabilityView>,
    /// True when more rows exist beyond this response's fixed page bound.
    pub more_available: bool,
    /// RFC 3339 instant when this page was generated.
    pub generated_at: String,
}

/// CVE enrichment visible through one advisory present in the caller's scope.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct CveDetailView {
    /// CVE identifier.
    pub cve_id: String,
    /// NVD CVSS base score.
    pub cvss_score: Option<f32>,
    /// CVSS version.
    pub cvss_version: Option<String>,
    /// CWE identifiers.
    pub cwe: Vec<String>,
    /// NVD description.
    pub description: Option<String>,
    /// On CISA KEV.
    pub kev: bool,
    /// EUVD identifier, if listed as exploited.
    pub euvd_exploited: Option<String>,
    /// EPSS score.
    pub epss: Option<f32>,
}

/// Advisory view and in-scope affected hosts.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct VulnerabilityAdvisoryDetail {
    /// Affected host-advisory matches in the current scope.
    pub hosts: VulnerabilityPage,
    /// CVE metadata for this visible advisory.
    pub cves: Vec<CveDetailView>,
}
