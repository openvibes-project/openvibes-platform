//! A vulnerability's page answers (`GET /v1/vulnerabilities/{key}/summary`
//! and `/{key}/hosts`).

use platform_store::{
    vuln_list::{AssigneeSummary, Fixed},
    vuln_summary::{Fix, VulnHostsPage, VulnPageSummary},
};
use serde::Serialize;
use utoipa::ToSchema;

use super::list_page_types::{VulnAssigneeView, VulnFixedView};
use crate::{
    alarms::list_types::AlarmListPersonView,
    hosts::{list_types::CountView, summary::top_alarms_view, summary_types::TopAlarmsView},
};

/// The header.
#[derive(Serialize, ToSchema)]
pub(crate) struct VulnHeaderView {
    /// Title of the covering advisory with the most hosts in reach.
    pub title: String,
    /// Worst severity among the covering advisories in reach.
    pub severity: String,
    /// Affected package names, sorted.
    pub packages: Vec<String>,
    /// The fixed version.
    pub fixed: VulnFixedView,
    /// Open pairs (triage open, not fixed).
    pub open: i64,
    /// Every pair, whatever its state.
    pub total: i64,
    /// Who the open pairs are assigned to.
    pub assignee: VulnAssigneeView,
    /// KEV due date, `YYYY-MM-DD`.
    pub kev_due: Option<String>,
    /// KEV lists known ransomware use.
    pub ransomware: bool,
}

/// Whether the distributions with pairs have a fix.
#[derive(Serialize, ToSchema)]
pub(crate) struct VulnFixTileView {
    /// `all`, `some` (`n` of `of`) or `none`.
    pub kind: String,
    /// Distributions with a fix, for `some`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n: Option<u32>,
    /// Distributions, for `some`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub of: Option<u32>,
}

/// The tiles.
#[derive(Serialize, ToSchema)]
pub(crate) struct VulnTilesView {
    /// Open pairs.
    pub open: i64,
    /// Every pair.
    pub total: i64,
    /// Distributions with a fix.
    pub fix: VulnFixTileView,
    /// EPSS score.
    pub epss: Option<f32>,
    /// EPSS percentile.
    pub epss_percentile: Option<f32>,
    /// CVSS base score.
    pub cvss: Option<f32>,
    /// CVSS version.
    pub cvss_version: Option<String>,
}

/// A package and its fixed version.
#[derive(Serialize, ToSchema)]
pub(crate) struct VulnPackageFixView {
    /// Package name.
    pub name: String,
    /// Fixed version; none without a fix.
    pub fixed: Option<String>,
}

/// What to do on one distribution.
#[derive(Serialize, ToSchema)]
pub(crate) struct VulnDistributionView {
    /// OS id.
    pub os_id: String,
    /// OS version.
    pub os_version: String,
    /// Its covering advisory with the most hosts.
    pub advisory_id: String,
    /// The advisory's link (none for a CPE match).
    pub url: Option<String>,
    /// Packages to update, sorted.
    pub packages: Vec<VulnPackageFixView>,
    /// Hosts in reach not yet fixed.
    pub hosts: i64,
    /// A fix waits for a reboot.
    pub reboot: bool,
}

/// A covering advisory.
#[derive(Serialize, ToSchema)]
pub(crate) struct VulnAdvisoryRefView {
    /// Id (`CPE:<cve>:<product>` for a CPE match).
    pub id: String,
    /// Link.
    pub url: Option<String>,
    /// Feed source (`cpe` for a CPE match).
    pub source: String,
}

/// How sure the matches are.
#[derive(Serialize, ToSchema)]
pub(crate) struct VulnConfidenceView {
    /// The least sure match, 0 to 100.
    pub min: u8,
    /// The surest, 0 to 100.
    pub max: u8,
    /// How the least sure one was made.
    pub basis: String,
}

/// The details card.
#[derive(Serialize, ToSchema)]
pub(crate) struct VulnDetailsView {
    /// The covering advisories in reach, by id.
    pub advisories: Vec<VulnAdvisoryRefView>,
    /// The earliest advisory issue date, RFC 3339.
    pub published: Option<String>,
    /// Confidence.
    pub confidence: VulnConfidenceView,
    /// CVSS vector.
    pub cvss_vector: Option<String>,
    /// CWE ids.
    pub cwe: Vec<String>,
    /// NVD's description.
    pub description: Option<String>,
}

/// One triage change.
#[derive(Serialize, ToSchema)]
pub(crate) struct VulnHistoryEventView {
    /// RFC 3339.
    pub at: String,
    /// Who: a display name.
    pub actor: String,
    /// The host.
    pub agent_id: String,
    /// Its name.
    pub hostname: Option<String>,
    /// The advisory changed.
    pub advisory_id: String,
    /// The state before.
    pub from_state: Option<String>,
    /// The state after.
    pub to_state: String,
    /// The note given.
    pub note: Option<String>,
}

/// A case holding a pair.
#[derive(Serialize, ToSchema)]
pub(crate) struct VulnCaseRefView {
    /// Case id.
    pub id: String,
    /// Case number.
    pub number: i64,
    /// Title.
    pub title: String,
}

/// Other CVEs in reach on the same packages.
#[derive(Serialize, ToSchema)]
pub(crate) struct VulnSamePackageView {
    /// How many.
    pub cves: i64,
    /// How many per severity, most severe first.
    pub severities: Vec<CountView>,
}

/// The Related card.
#[derive(Serialize, ToSchema)]
pub(crate) struct VulnRelatedView {
    /// Open alarms on the hosts, the top three and the total; absent
    /// without `alarms.read`.
    pub alarms: Option<TopAlarmsView>,
    /// Open cases holding a pair; absent without `cases.read`.
    pub cases: Option<Vec<VulnCaseRefView>>,
    /// Same package.
    pub same_package: VulnSamePackageView,
}

/// Actions allowed, each when the viewer holds its permission on a host in
/// reach.
#[derive(Serialize, ToSchema)]
pub(crate) struct VulnActionsView {
    /// Set state (`vulnerabilities.triage`).
    pub triage: bool,
    /// Assign (`vulnerabilities.triage`).
    pub assign: bool,
    /// Add to case (`cases.write` and `cases.read`).
    pub add_to_case: bool,
    /// Ask about this (`assistant.use`, with the assistant on).
    pub ask: bool,
    /// Export (`vulnerabilities.export`).
    pub export: bool,
}

/// A vulnerability's page above the Hosts table.
#[derive(Serialize, ToSchema)]
pub(crate) struct VulnerabilitySummaryView {
    /// The canonical key: the CVE, or the CVE-less advisory. The web
    /// replaces the URL when it differs from the one asked for.
    pub key: String,
    /// Header.
    pub header: VulnHeaderView,
    /// Tiles.
    pub tiles: VulnTilesView,
    /// What to do, per distribution.
    pub what_to_do: Vec<VulnDistributionView>,
    /// Details.
    pub details: VulnDetailsView,
    /// The last 50 triage changes of pairs in reach, newest first.
    pub history: Vec<VulnHistoryEventView>,
    /// Related.
    pub related: VulnRelatedView,
    /// Other CVEs the covering advisories in reach name, sorted.
    pub also_covers: Vec<String>,
    /// Allowed actions.
    pub can: VulnActionsView,
}

/// One row of the Hosts table: a host and covering advisory.
#[derive(Serialize, ToSchema)]
pub(crate) struct VulnHostRowView {
    /// Agent id.
    pub agent_id: String,
    /// Host name.
    pub hostname: Option<String>,
    /// Distribution, as the Hosts list names it.
    pub os: Option<String>,
    /// Last address.
    pub address: Option<String>,
    /// Installed versions, comma-separated.
    pub installed: String,
    /// open, mitigated, accepted_risk, false_positive or resolved.
    pub state: String,
    /// Assignee.
    pub assignee: Option<AlarmListPersonView>,
    /// The covering advisory.
    pub advisory_id: String,
    /// The triage version for If-Match; null where triage does not apply.
    pub triage_version: Option<i64>,
}

/// Pairs per segment.
#[derive(Serialize, ToSchema)]
pub(crate) struct VulnSegmentsView {
    /// Every pair.
    pub all: i64,
    /// Triage open, not fixed.
    pub open: i64,
    /// Mitigated.
    pub mitigated: i64,
    /// Fixed by an update, accepted risk or false positive.
    pub resolved: i64,
}

/// One page of the Hosts table.
#[derive(Serialize, ToSchema)]
pub(crate) struct VulnerabilityHostsPage {
    /// The page, by host name then agent id.
    pub rows: Vec<VulnHostRowView>,
    /// Pairs in the chosen segment.
    pub total: i64,
    /// Every segment's count.
    pub segments: VulnSegmentsView,
}

impl From<Fixed> for VulnFixedView {
    fn from(f: Fixed) -> Self {
        let (kind, version, count) = match f {
            Fixed::One(v) => ("one", Some(v), None),
            Fixed::Several(n) => ("several", None, Some(n)),
            Fixed::None => ("none", None, None),
        };
        Self {
            kind: kind.into(),
            version,
            count,
        }
    }
}

impl From<AssigneeSummary> for VulnAssigneeView {
    fn from(a: AssigneeSummary) -> Self {
        let (kind, id, name, count) = match a {
            AssigneeSummary::None => ("none", None, None, None),
            AssigneeSummary::One(id, name) => ("one", Some(id), Some(name), None),
            AssigneeSummary::Several(n) => ("several", None, None, Some(n)),
        };
        Self {
            kind: kind.into(),
            id,
            name,
            count,
        }
    }
}

impl VulnerabilitySummaryView {
    pub(crate) fn new(s: VulnPageSummary, can: VulnActionsView) -> Self {
        let (h, t, d, r) = (s.header, s.tiles, s.details, s.related);
        let (kind, n, of) = match t.fix {
            Fix::All => ("all", None, None),
            Fix::Some(n, of) => ("some", Some(n), Some(of)),
            Fix::None => ("none", None, None),
        };
        Self {
            key: s.key,
            header: VulnHeaderView {
                title: h.title,
                severity: h.severity.as_str().into(),
                packages: h.packages,
                fixed: h.fixed.into(),
                open: h.open,
                total: h.total,
                assignee: h.assignee.into(),
                kev_due: h.kev_due.map(|d| d.to_string()),
                ransomware: h.ransomware,
            },
            tiles: VulnTilesView {
                open: t.open,
                total: t.total,
                fix: VulnFixTileView {
                    kind: kind.into(),
                    n,
                    of,
                },
                epss: t.epss,
                epss_percentile: t.epss_percentile,
                cvss: t.cvss,
                cvss_version: t.cvss_version,
            },
            what_to_do: s
                .what_to_do
                .into_iter()
                .map(|w| VulnDistributionView {
                    os_id: w.os_id,
                    os_version: w.os_version,
                    advisory_id: w.advisory_id,
                    url: w.url,
                    packages: w
                        .packages
                        .into_iter()
                        .map(|(name, fixed)| VulnPackageFixView { name, fixed })
                        .collect(),
                    hosts: w.hosts,
                    reboot: w.reboot,
                })
                .collect(),
            details: VulnDetailsView {
                advisories: d
                    .advisories
                    .into_iter()
                    .map(|a| VulnAdvisoryRefView {
                        id: a.id,
                        url: a.url,
                        source: a.source,
                    })
                    .collect(),
                published: d.published.map(|p| p.to_rfc3339()),
                confidence: VulnConfidenceView {
                    min: d.confidence.min,
                    max: d.confidence.max,
                    basis: d.confidence.basis,
                },
                cvss_vector: d.cvss_vector,
                cwe: d.cwe,
                description: d.description,
            },
            history: s
                .history
                .into_iter()
                .map(|e| VulnHistoryEventView {
                    at: e.at.to_rfc3339(),
                    actor: e.actor,
                    agent_id: e.agent_id,
                    hostname: e.hostname,
                    advisory_id: e.advisory_id,
                    from_state: e.from_state,
                    to_state: e.to_state,
                    note: e.note,
                })
                .collect(),
            related: VulnRelatedView {
                alarms: r.alarms.map(top_alarms_view),
                cases: r.cases.map(|cases| {
                    cases
                        .into_iter()
                        .map(|c| VulnCaseRefView {
                            id: c.id,
                            number: c.number,
                            title: c.title,
                        })
                        .collect()
                }),
                same_package: VulnSamePackageView {
                    cves: r.same_package.cves,
                    severities: r
                        .same_package
                        .severities
                        .into_iter()
                        .map(|(s, count)| CountView {
                            value: s.as_str().into(),
                            count,
                        })
                        .collect(),
                },
            },
            also_covers: s.also_covers,
            can,
        }
    }
}

impl From<VulnHostsPage> for VulnerabilityHostsPage {
    fn from(p: VulnHostsPage) -> Self {
        let g = p.segments;
        Self {
            rows: p
                .rows
                .into_iter()
                .map(|r| VulnHostRowView {
                    agent_id: r.agent_id,
                    hostname: r.hostname,
                    os: r.os,
                    address: r.address,
                    installed: r.installed,
                    state: r.state,
                    assignee: r
                        .assignee
                        .map(|(id, name)| AlarmListPersonView { id, name }),
                    advisory_id: r.advisory_id,
                    triage_version: r.triage_version,
                })
                .collect(),
            total: p.total,
            segments: VulnSegmentsView {
                all: g.all,
                open: g.open,
                mitigated: g.mitigated,
                resolved: g.resolved,
            },
        }
    }
}
