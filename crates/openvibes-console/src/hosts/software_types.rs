//! The software endpoints' response types.

use serde::Serialize;
use utoipa::ToSchema;

/// One installed package version on a host.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct HostPackageView {
    /// Package manager (`rpm`, `dpkg`).
    pub manager: String,
    /// Package name.
    pub name: String,
    /// Epoch (0 when none).
    pub epoch: i32,
    /// Version.
    pub version: String,
    /// Release (empty for dpkg).
    pub release: String,
    /// Architecture.
    pub arch: String,
    /// The host has an open vulnerability with a fix on this package.
    pub fixable_vulnerable: bool,
}

/// A page of a host's packages, by name.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct HostPackagePage {
    /// Packages on this page.
    pub items: Vec<HostPackageView>,
    /// Opaque cursor for the next page.
    pub next_cursor: Option<String>,
}

/// One package across the caller's visible hosts.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct SoftwareView {
    /// Package manager.
    pub manager: String,
    /// Package name.
    pub name: String,
    /// Visible hosts with any version of it.
    pub hosts: i64,
    /// Distinct versions in use.
    pub versions: i64,
    /// Visible hosts where it has an open vulnerability with a fix.
    pub fixable_vulnerable_hosts: i64,
    /// Distinct open advisories on it, with or without a fix.
    pub advisories: i64,
    /// Of those, advisories with no fix yet.
    pub no_fix_advisories: i64,
    /// Worst severity among them (`critical`, `important`, `moderate`,
    /// `low`, `unrated`); absent without advisories.
    pub worst_severity: Option<String>,
    /// One of them is on an exploited list (CISA KEV or EUVD).
    pub exploited: bool,
}

/// A page of the fleet's software, by name.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct SoftwarePage {
    /// Packages on this page.
    pub items: Vec<SoftwareView>,
    /// Opaque cursor for the next page.
    pub next_cursor: Option<String>,
}

/// One version of a package in use.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct SoftwareVersionView {
    /// Epoch.
    pub epoch: i32,
    /// Version.
    pub version: String,
    /// Release.
    pub release: String,
    /// Architecture.
    pub arch: String,
    /// Visible hosts with it.
    pub hosts: i64,
    /// Of those, hosts where it has an open vulnerability with a fix.
    pub fixable_vulnerable_hosts: i64,
    /// Distinct open advisories that apply to this version.
    pub advisories: i64,
}

/// An advisory open on the package.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct SoftwareAdvisoryView {
    /// Advisory id (opens the advisory view).
    pub advisory_id: String,
    /// Severity (`critical`, `important`, `moderate`, `low`, `unrated`).
    pub severity: String,
    /// Advisory title.
    pub title: String,
    /// Link to the advisory.
    pub url: String,
    /// CVE ids.
    pub cves: Vec<String>,
    /// Visible hosts it is open on.
    pub hosts: i64,
    /// The version that fixes the package; absent while there is no fix.
    pub fixed_in: Option<String>,
    /// On CISA KEV or EUVD's exploited list.
    pub exploited: bool,
    /// Highest EPSS score among its CVEs.
    pub epss: Option<f32>,
    /// Highest CVSS base score among its CVEs.
    pub cvss: Option<f32>,
}

/// One host that has the package.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct SoftwareHostView {
    /// Agent id.
    pub agent_id: String,
    /// Hostname, when known.
    pub hostname: Option<String>,
    /// The version it has (`epoch:version-release`).
    pub version: String,
    /// Architecture.
    pub arch: String,
    /// Last contact (RFC 3339).
    pub last_seen_at: Option<String>,
    /// It has an open vulnerability with a fix there.
    pub fixable_vulnerable: bool,
}

/// One package: its versions in use and, paged, its hosts.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct SoftwareDetail {
    /// Package manager.
    pub manager: String,
    /// Package name.
    pub name: String,
    /// Versions in use on visible hosts, most hosts first.
    pub versions: Vec<SoftwareVersionView>,
    /// Open advisories on the package, most urgent first (at most 200).
    pub advisories: Vec<SoftwareAdvisoryView>,
    /// Hosts on this page, by hostname.
    pub hosts: Vec<SoftwareHostView>,
    /// Opaque cursor for the next page of hosts.
    pub next_cursor: Option<String>,
}
