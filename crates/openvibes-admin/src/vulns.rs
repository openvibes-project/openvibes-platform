//! `openvibes-admin feeds …` and `vulns …`: vulnerability feeds and the
//! vulnerabilities they open on hosts (VM spec §8).

use std::path::PathBuf;

use chrono::{DateTime, SecondsFormat, Utc};
use clap::Subcommand;
use openvibes_vulns::{
    enrich,
    feed::{self, SourceId},
};
use platform_store::vulns::{self, ListFilter, VulnRow};

/// Largest feed file read (compressed or not).
const MAX_FILE: u64 = 512 << 20;

#[derive(Subcommand)]
pub enum FeedsCommand {
    /// Import a downloaded feed file (offline platforms): Fedora
    /// updateinfo.xml[.zst], CISA KEV JSON, or EPSS CSV[.gz].
    Import {
        /// The feed file.
        file: PathBuf,
        /// Source: fedora-<release>-<arch> (e.g. fedora-44-x86_64), kev, or epss.
        #[arg(long)]
        source: String,
    },
    /// Each feed's last check, last change, advisories, and error.
    Status,
}

#[derive(Subcommand)]
pub enum VulnsCommand {
    /// Open vulnerabilities by severity and the most affected hosts.
    Summary,
    /// Vulnerabilities, most severe first.
    List {
        /// Only this host (agent id or hostname).
        #[arg(long)]
        host: Option<String>,
        /// Only this severity (critical, important, moderate, low, unrated).
        #[arg(long)]
        severity: Option<String>,
        /// Only advisories naming this CVE.
        #[arg(long)]
        cve: Option<String>,
        /// Fixed ones instead of open ones.
        #[arg(long)]
        fixed: bool,
    },
    /// One advisory (with its hosts) or one host (with its advisories).
    Show {
        /// Advisory id, agent id, or hostname.
        target: String,
    },
}

impl FeedsCommand {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Import { .. } => "feeds import",
            Self::Status => "feeds status",
        }
    }
}

impl VulnsCommand {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Summary => "vulns summary",
            Self::List { .. } => "vulns list",
            Self::Show { .. } => "vulns show",
        }
    }
}

fn time(at: DateTime<Utc>) -> String {
    at.to_rfc3339_opts(SecondsFormat::Secs, true)
}

pub async fn run_feeds(
    command: &FeedsCommand,
    client: &mut platform_store::Client,
) -> (Result<String, String>, Option<String>) {
    match command {
        FeedsCommand::Import { file, source } => {
            let target = Some(source.clone());
            let enrichment = source.parse::<enrich::Source>().ok();
            let fedora = source.parse::<SourceId>().ok();
            if enrichment.is_none() && fedora.is_none() {
                return (
                    Err("use fedora-<release>-<arch>, kev, or epss".into()),
                    target,
                );
            }
            let content = match std::fs::metadata(file) {
                Ok(meta) if meta.len() > MAX_FILE => {
                    return (
                        Err(format!("feed file larger than {MAX_FILE} bytes")),
                        target,
                    );
                }
                Ok(_) => match std::fs::read(file) {
                    Ok(content) => content,
                    Err(_) => return (Err("cannot read the feed file".into()), target),
                },
                Err(_) => return (Err("cannot read the feed file".into()), target),
            };
            if let Some(source) = enrichment {
                let result = enrich::import(client, source, &content, Utc::now())
                    .await
                    .map(|count| format!("imported {count} CVEs from {source}\n"))
                    .map_err(|error| error.to_string());
                return (result, target);
            }
            let Some(source) = fedora else {
                return (Err("unreachable".into()), target);
            };
            let result = feed::import(client, &source, &content, Utc::now())
                .await
                .map(|report| {
                    format!(
                        "imported {} advisories into {}; {} open on {} {}\n",
                        report.advisories,
                        source.name(),
                        report.open,
                        source.os_id,
                        source.os_version
                    )
                })
                .map_err(|error| error.to_string());
            (result, target)
        }
        FeedsCommand::Status => {
            let result = vulns::feeds(client)
                .await
                .map_err(|e| e.to_string())
                .map(|feeds| {
                    if feeds.is_empty() {
                        return "no feeds yet\n".to_owned();
                    }
                    feeds
                        .iter()
                        .map(|f| {
                            let checked = f.last_checked_at.map_or_else(|| "never".into(), time);
                            let changed = f.last_changed_at.map_or_else(|| "never".into(), time);
                            let error = f
                                .last_error
                                .as_deref()
                                .map_or_else(String::new, |e| format!(" error: {e}"));
                            let unit = if f.os_id == "cve" {
                                "cves"
                            } else {
                                "advisories"
                            };
                            format!(
                                "{} {unit} {} checked {checked} changed {changed}{error}\n",
                                f.source, f.advisories
                            )
                        })
                        .collect()
                });
            (result, None)
        }
    }
}

fn host_label(row: &VulnRow) -> &str {
    row.hostname.as_deref().unwrap_or(&row.agent_id)
}

fn packages(row: &VulnRow) -> String {
    row.packages
        .as_array()
        .map(|list| {
            list.iter()
                .map(|p| {
                    let running = p["running"]
                        .as_str()
                        .map_or_else(String::new, |r| format!(" (running {r})"));
                    format!(
                        "{} {} -> {}{running}",
                        p["name"].as_str().unwrap_or("?"),
                        p["installed"].as_str().unwrap_or("?"),
                        p["fixed"].as_str().unwrap_or("?")
                    )
                })
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default()
}

fn line(row: &VulnRow) -> String {
    let fixed = row
        .fixed_at
        .map_or_else(String::new, |at| format!(" fixed {}", time(at)));
    let cves = if row.cves.is_empty() {
        String::new()
    } else {
        format!(" [{}]", row.cves.join(" "))
    };
    let exploited = if row.exploited {
        let due = row
            .kev_due
            .map_or_else(String::new, |due| format!(", due {due}"));
        let ransomware = if row.ransomware { ", ransomware" } else { "" };
        format!(" exploited (KEV{due}{ransomware})")
    } else {
        String::new()
    };
    let epss = match (row.epss, row.epss_percentile) {
        (Some(score), Some(percentile)) => {
            let top = ((1.0 - f64::from(percentile)) * 100.0).ceil().max(1.0);
            format!(" EPSS {:.1}% (top {top}%)", f64::from(score) * 100.0)
        }
        _ => String::new(),
    };
    let reboot = if row.reboot_needed {
        " (fix installed, reboot needed)"
    } else {
        ""
    };
    format!(
        "{} {} {} since {}{fixed}: {}{cves}{exploited}{epss}{reboot}\n",
        row.severity,
        row.advisory_id,
        host_label(row),
        time(row.first_seen_at),
        packages(row)
    )
}

pub async fn run_vulns(
    command: &VulnsCommand,
    client: &platform_store::Client,
) -> (Result<String, String>, Option<String>) {
    match command {
        VulnsCommand::Summary => {
            let result = vulns::summary(client)
                .await
                .map_err(|e| e.to_string())
                .map(|s| {
                    let total: i64 = s.by_severity.iter().map(|(_, n)| n).sum();
                    let parts: Vec<String> = s
                        .by_severity
                        .iter()
                        .map(|(sev, n)| format!("{sev} {n}"))
                        .collect();
                    let parts = if parts.is_empty() {
                        "none".to_owned()
                    } else {
                        parts.join(", ")
                    };
                    let mut out = format!("open {total} on {} hosts: {parts}\n", s.hosts);
                    if s.exploited > 0 {
                        out.push_str(&format!(
                            "exploited in the wild (CISA KEV): {}\n",
                            s.exploited
                        ));
                    }
                    if s.reboot_hosts > 0 {
                        out.push_str(&format!(
                            "fix installed, reboot needed on {} hosts\n",
                            s.reboot_hosts
                        ));
                    }
                    for (agent, hostname, open, serious) in &s.top_hosts {
                        out.push_str(&format!(
                            "  {} {open} open ({serious} critical or important)\n",
                            hostname.as_deref().unwrap_or(agent)
                        ));
                    }
                    out
                });
            (result, None)
        }
        VulnsCommand::List {
            host,
            severity,
            cve,
            fixed,
        } => {
            let filter = ListFilter {
                host: host.as_deref(),
                severity: severity.as_deref(),
                cve: cve.as_deref(),
                fixed: *fixed,
                ..ListFilter::default()
            };
            let result = vulns::list(client, &filter)
                .await
                .map_err(|e| e.to_string())
                .map(|rows| rows.iter().map(line).collect());
            (result, None)
        }
        VulnsCommand::Show { target } => {
            let as_advisory = ListFilter {
                advisory: Some(target),
                ..ListFilter::default()
            };
            let as_host = ListFilter {
                host: Some(target),
                ..ListFilter::default()
            };
            let result = async {
                let rows = vulns::list(client, &as_advisory).await.map_err(|e| e.to_string())?;
                if let Some(first) = rows.first() {
                    let mut out = format!(
                        "{} {} {}\nhttps://bodhi.fedoraproject.org/updates/{}\nCVEs: {}\nopen on {} hosts:\n",
                        first.advisory_id,
                        first.severity,
                        first.title,
                        first.advisory_id,
                        if first.cves.is_empty() { "none named".into() } else { first.cves.join(" ") },
                        rows.len()
                    );
                    for row in &rows {
                        out.push_str(&format!("  {}: {}\n", host_label(row), packages(row)));
                    }
                    return Ok(out);
                }
                let rows = vulns::list(client, &as_host).await.map_err(|e| e.to_string())?;
                if rows.is_empty() {
                    return Err("no advisory or host with open vulnerabilities by that name".into());
                }
                let mut out = format!("{} open on {}:\n", rows.len(), host_label(&rows[0]));
                for row in &rows {
                    out.push_str(&format!("  {}", line(row)));
                }
                Ok(out)
            }
            .await;
            (result, Some(target.clone()))
        }
    }
}
