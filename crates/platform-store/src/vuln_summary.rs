//! A vulnerability's page (roles spec §10.3; step 5b rulings 2, 7, 9, 12):
//! one CVE, or a CVE-less advisory, over its host and advisory pairs in the
//! viewer's `vulnerabilities.read` scope — the header, tiles, what to do
//! per distribution, details, triage history, the Related card and the
//! Hosts table. Pairs follow the Vulnerabilities list (`vuln_list_sql`),
//! so the page and its list row agree. A key with no pair in reach reads
//! as missing.

use chrono::{DateTime, NaiveDate, Utc};
use serde::Deserialize;
use serde_json::json;

use crate::{
    Client, StoreError,
    console_read::AgentScope,
    vuln_list::{AssigneeSummary, Fixed, VulnSeverity},
    vuln_related::{alarms, cases, same_package},
    vuln_summary_sql::{self as sql, resolve},
    vulns::confidence::mapping,
};
pub use crate::{
    vuln_hosts::{HostSegment, Segments, VulnHostRow, VulnHostsPage, vuln_hosts},
    vuln_related::{CaseRef, Related, SamePackage, reaches_any},
};

/// Most triage changes the History card shows.
pub const HISTORY: usize = 50;

/// How a key resolved (ruling 7).
#[derive(Clone, Debug)]
pub enum Lookup<T> {
    /// The page.
    Found(T),
    /// No such key, or none of its pairs in reach.
    Missing,
    /// An advisory naming these CVEs (sorted): the list filtered by it.
    SeveralCves(Vec<String>),
}

/// The viewer's scopes: `vulnerabilities.read`, and `alarms.read` and
/// `cases.read` when held (the Related card's alarms and cases).
#[derive(Clone, Copy, Debug)]
pub struct PageScopes<'a> {
    /// `vulnerabilities.read`.
    pub read: &'a AgentScope,
    /// `alarms.read`.
    pub alarms: Option<&'a AgentScope>,
    /// `cases.read`.
    pub cases: Option<&'a AgentScope>,
}

/// The header.
#[derive(Clone, Debug)]
pub struct Header {
    /// The title of the covering advisory with the most pairs in reach.
    pub title: String,
    /// That advisory (the one with the most pairs when none has a title).
    pub advisory_id: String,
    /// On CISA KEV or EUVD's exploited list (as the list's `exploited`).
    pub exploited: bool,
    /// The worst severity among the covering advisories in reach.
    pub severity: VulnSeverity,
    /// Affected package names, sorted.
    pub packages: Vec<String>,
    /// The fixed version.
    pub fixed: Fixed,
    /// Open pairs.
    pub open: i64,
    /// Every pair.
    pub total: i64,
    /// Who the open pairs are assigned to.
    pub assignee: AssigneeSummary,
    /// KEV due date.
    pub kev_due: Option<NaiveDate>,
    /// KEV lists known ransomware use.
    pub ransomware: bool,
}

/// Whether the distributions with pairs have a fix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Fix {
    /// Every one.
    All,
    /// `n` of `m`.
    Some(u32, u32),
    /// None.
    None,
}

/// The tiles.
#[derive(Clone, Debug)]
pub struct Tiles {
    /// Open pairs.
    pub open: i64,
    /// Every pair.
    pub total: i64,
    /// Distributions with a fix.
    pub fix: Fix,
    /// EPSS score.
    pub epss: Option<f32>,
    /// EPSS percentile.
    pub epss_percentile: Option<f32>,
    /// CVSS base score (NVD's, else a CPE match's).
    pub cvss: Option<f32>,
    /// CVSS version.
    pub cvss_version: Option<String>,
}

/// What to do on one distribution.
#[derive(Clone, Debug)]
pub struct Distribution {
    /// OS id.
    pub os_id: String,
    /// OS version.
    pub os_version: String,
    /// Its covering advisory with the most pairs (ties by id).
    pub advisory_id: String,
    /// Its link (none for a CPE match).
    pub url: Option<String>,
    /// That advisory's package names and fixed versions on the pairs, sorted.
    pub packages: Vec<(String, Option<String>)>,
    /// Hosts in reach not yet fixed.
    pub hosts: i64,
    /// A fix waits for a reboot.
    pub reboot: bool,
}

/// One covering advisory.
#[derive(Clone, Debug)]
pub struct Advisory {
    /// Id (`CPE:<cve>:<product>` for a CPE match).
    pub id: String,
    /// Link.
    pub url: Option<String>,
    /// Feed source (`cpe` for a CPE match).
    pub source: String,
}

/// How sure the matches are, 0 to 100.
#[derive(Clone, Debug, Default)]
pub struct Confidence {
    /// The least sure match.
    pub min: u8,
    /// The surest.
    pub max: u8,
    /// How the least sure one was made.
    pub basis: String,
}

/// The details card.
#[derive(Clone, Debug)]
pub struct Details {
    /// The covering advisories in reach, by id.
    pub advisories: Vec<Advisory>,
    /// The earliest advisory issue date.
    pub published: Option<DateTime<Utc>>,
    /// Confidence.
    pub confidence: Confidence,
    /// CVSS vector.
    pub cvss_vector: Option<String>,
    /// CWE ids.
    pub cwe: Vec<String>,
    /// NVD's description.
    pub description: Option<String>,
}

/// One triage change.
#[derive(Clone, Debug, Deserialize)]
pub struct HistoryEvent {
    /// When.
    #[serde(deserialize_with = "millis")]
    pub at: DateTime<Utc>,
    /// Who: a display name, or the stored actor.
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

/// A vulnerability's page above the Hosts table.
#[derive(Clone, Debug)]
pub struct VulnPageSummary {
    /// The canonical key: the CVE, or the CVE-less advisory.
    pub key: String,
    /// Header.
    pub header: Header,
    /// Tiles.
    pub tiles: Tiles,
    /// What to do, per distribution (by OS id and version).
    pub what_to_do: Vec<Distribution>,
    /// Details.
    pub details: Details,
    /// The last [`HISTORY`] triage changes of pairs in reach, newest first.
    pub history: Vec<HistoryEvent>,
    /// Related.
    pub related: Related,
    /// Other CVEs the covering advisories in reach name, sorted.
    pub also_covers: Vec<String>,
    /// The hosts in reach with a pair, for the actions' permissions.
    pub agents: Vec<String>,
}

fn millis<'de, D: serde::Deserializer<'de>>(d: D) -> Result<DateTime<Utc>, D::Error> {
    let ms = i64::deserialize(d)?;
    DateTime::from_timestamp_millis(ms).ok_or_else(|| serde::de::Error::custom("time"))
}

#[derive(Deserialize)]
struct RawAdvisory {
    id: String,
    os_id: String,
    os_version: String,
    n: i64,
    url: Option<String>,
    title: Option<String>,
    severity: Option<String>,
    issued: Option<i64>,
    source: String,
    cvss: Option<f32>,
}

#[derive(Deserialize)]
struct RawDist {
    os_id: String,
    os_version: String,
    hosts: i64,
    reboot: bool,
}

#[derive(Deserialize, Default)]
struct RawEnrichment {
    kev_due: Option<String>,
    exploited: Option<bool>,
    ransomware: Option<bool>,
    epss: Option<f32>,
    epss_percentile: Option<f32>,
    cvss: Option<f32>,
    cvss_version: Option<String>,
    cvss_vector: Option<String>,
    cwe: Option<Vec<String>>,
    description: Option<String>,
}

#[derive(Deserialize)]
struct Raw {
    open: i64,
    total: i64,
    agents: Vec<String>,
    names: Vec<String>,
    fixed: Vec<String>,
    packages: Vec<(String, String, String, String, Option<String>)>,
    people: Vec<(String, String)>,
    advisories: Vec<RawAdvisory>,
    dists: Vec<RawDist>,
    confidence: Vec<(String, bool, Option<i32>, Option<String>)>,
    also: Vec<String>,
    enrichment: Option<RawEnrichment>,
    history: Vec<HistoryEvent>,
}

/// The severity an advisory gives, else the CVSS band (as the list).
fn severity(given: Option<&str>, cvss: Option<f32>) -> VulnSeverity {
    given.and_then(VulnSeverity::parse).unwrap_or(match cvss {
        Some(s) if s >= 9.0 => VulnSeverity::Critical,
        Some(s) if s >= 7.0 => VulnSeverity::Important,
        Some(s) if s >= 4.0 => VulnSeverity::Moderate,
        Some(s) if s > 0.0 => VulnSeverity::Low,
        _ => VulnSeverity::Unrated,
    })
}

fn n32(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

/// The page of `key` within `scopes`, or why not; `today` dates expired
/// accepted risks.
pub async fn vuln_summary(
    client: &Client,
    key: &str,
    scopes: &PageScopes<'_>,
    today: NaiveDate,
) -> Result<Lookup<VulnPageSummary>, StoreError> {
    let t = match resolve(client, key, scopes.read, today).await? {
        Lookup::Found(t) => t,
        Lookup::Missing => return Ok(Lookup::Missing),
        Lookup::SeveralCves(c) => return Ok(Lookup::SeveralCves(c)),
    };
    let scope = scopes.read;
    let row = client
        .query_one(
            &sql::summary(),
            &[
                &scope.is_global(),
                &scope.group_ids(),
                &t.advisories,
                &t.cve,
                &today,
            ],
        )
        .await?;
    let raw: Raw = serde_json::from_value(row.get(0)).map_err(|_| StoreError::Query)?;
    if raw.total == 0 {
        return Ok(Lookup::Missing);
    }
    let x = raw.enrichment.unwrap_or_default();
    let mut names = raw.names;
    names.sort();
    let mut fixed = raw.fixed;
    // Per advisory id (a CPE match may span releases).
    let mut by_id: Vec<(String, i64, &RawAdvisory)> = Vec::new();
    for a in &raw.advisories {
        match by_id.iter_mut().find(|(id, _, _)| *id == a.id) {
            Some(e) => e.1 += a.n,
            None => by_id.push((a.id.clone(), a.n, a)),
        }
    }
    by_id.sort_by(|a, b| a.0.cmp(&b.0));
    // The most pairs, then the smallest id (as the list's title).
    let most = |a: &&(String, i64, &RawAdvisory), b: &&(String, i64, &RawAdvisory)| {
        a.1.cmp(&b.1).then_with(|| b.0.cmp(&a.0))
    };
    let titled = by_id
        .iter()
        .filter(|(_, _, a)| a.title.is_some())
        .max_by(most);
    let lead = titled.or_else(|| by_id.iter().max_by(most));
    let advisory_id = lead.map(|(id, _, _)| id.clone()).unwrap_or_default();
    let title = titled
        .and_then(|(_, _, a)| a.title.clone())
        .or_else(|| x.description.clone())
        .unwrap_or_else(|| t.key.clone());
    let cvss = x.cvss.or_else(|| {
        raw.advisories
            .iter()
            .filter_map(|a| a.cvss)
            .reduce(f32::max)
    });
    let worst = raw
        .advisories
        .iter()
        .map(|a| severity(a.severity.as_deref(), x.cvss.or(a.cvss)))
        .min_by_key(|s| VulnSeverity::ALL.iter().position(|v| v == s))
        .unwrap_or(VulnSeverity::Unrated);
    let mut dists = raw.dists;
    dists.sort_by(|a, b| (&a.os_id, &a.os_version).cmp(&(&b.os_id, &b.os_version)));
    let what_to_do: Vec<Distribution> = dists
        .iter()
        .filter_map(|d| {
            let here = |a: &&RawAdvisory| a.os_id == d.os_id && a.os_version == d.os_version;
            let lead = raw
                .advisories
                .iter()
                .filter(here)
                .max_by(|a, b| a.n.cmp(&b.n).then_with(|| b.id.cmp(&a.id)))?;
            let mut packages: Vec<(String, Option<String>)> = raw
                .packages
                .iter()
                .filter(|p| p.0 == lead.id && p.1 == d.os_id && p.2 == d.os_version)
                .map(|p| (p.3.clone(), p.4.clone()))
                .collect();
            packages.sort();
            packages.dedup();
            Some(Distribution {
                os_id: d.os_id.clone(),
                os_version: d.os_version.clone(),
                advisory_id: lead.id.clone(),
                url: lead.url.clone(),
                packages,
                hosts: d.hosts,
                reboot: d.reboot,
            })
        })
        .collect();
    let with_fix = dists
        .iter()
        .filter(|d| {
            raw.packages
                .iter()
                .any(|p| p.1 == d.os_id && p.2 == d.os_version && p.4.is_some())
        })
        .count();
    let fix = match (with_fix, dists.len()) {
        (0, _) => Fix::None,
        (n, m) if n == m => Fix::All,
        (n, m) => Fix::Some(n32(n), n32(m)),
    };
    let mut sure: Vec<(u8, String)> = raw
        .confidence
        .iter()
        .map(
            |(source, fixable, confidence, basis)| match (source.as_str(), confidence) {
                ("cpe", Some(c)) => (
                    u8::try_from(*c).unwrap_or(0),
                    basis.clone().unwrap_or_default(),
                ),
                _ => {
                    let m = mapping(source, &json!([{ "fixed": fixable.then_some("x") }]));
                    (m.confidence, m.basis)
                }
            },
        )
        .collect();
    sure.sort();
    let confidence = Confidence {
        min: sure.first().map_or(0, |s| s.0),
        max: sure.last().map_or(0, |s| s.0),
        basis: sure.first().map(|s| s.1.clone()).unwrap_or_default(),
    };
    let mut people = raw.people;
    people.sort();
    let fixed = match fixed.len() {
        0 => Fixed::None,
        1 => Fixed::One(fixed.remove(0)),
        n => Fixed::Several(n32(n)),
    };
    let covering: Vec<String> = by_id.iter().map(|(id, _, _)| id.clone()).collect();
    let related = Related {
        alarms: match scopes.alarms {
            Some(s) => Some(alarms(client, &raw.agents, s).await?),
            None => None,
        },
        cases: match scopes.cases {
            Some(s) => Some(cases(client, &raw.agents, &covering, s).await?),
            None => None,
        },
        same_package: same_package(client, scope, &names, &t.key).await?,
    };
    Ok(Lookup::Found(VulnPageSummary {
        header: Header {
            title,
            advisory_id,
            exploited: x.exploited.unwrap_or(false),
            severity: worst,
            packages: names,
            fixed,
            open: raw.open,
            total: raw.total,
            assignee: match people.len() {
                0 => AssigneeSummary::None,
                1 => {
                    let (id, name) = people.remove(0);
                    AssigneeSummary::One(id, name)
                }
                n => AssigneeSummary::Several(n32(n)),
            },
            kev_due: x.kev_due.as_deref().and_then(|d| d.parse().ok()),
            ransomware: x.ransomware.unwrap_or(false),
        },
        tiles: Tiles {
            open: raw.open,
            total: raw.total,
            fix,
            epss: x.epss,
            epss_percentile: x.epss_percentile,
            cvss,
            cvss_version: x.cvss_version,
        },
        what_to_do,
        details: Details {
            published: by_id
                .iter()
                .filter_map(|(_, _, a)| a.issued)
                .min()
                .and_then(DateTime::from_timestamp_millis),
            advisories: by_id
                .iter()
                .map(|(id, _, a)| Advisory {
                    id: id.clone(),
                    url: a.url.clone(),
                    source: a.source.clone(),
                })
                .collect(),
            confidence,
            cvss_vector: x.cvss_vector,
            cwe: x.cwe.unwrap_or_default(),
            description: x.description,
        },
        history: raw.history,
        related,
        also_covers: raw.also,
        agents: raw.agents,
        key: t.key,
    }))
}
