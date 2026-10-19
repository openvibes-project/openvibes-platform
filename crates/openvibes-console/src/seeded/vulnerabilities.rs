//! The demo's vulnerability summary, list and advisory detail.

use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
};

use axum::{
    Json,
    extract::{Path, Query, State, rejection::QueryRejection},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};

use super::{
    persona::{Persona, SeedMode, context, read_error},
    repository::{ConsoleRepository, GENERATED_AT},
};
use crate::{
    Permission,
    http::problem::{ProblemDetails, problem_response},
};

fn demo_vulnerabilities(persona: Persona, mode: SeedMode) -> Vec<crate::VulnerabilityView> {
    if matches!(mode, SeedMode::Empty) {
        return Vec::new();
    }
    (1..=40).filter(|number| persona.global_scope() || number % 5 == 0).map(|number| {
        let severity = match number % 5 { 0 => crate::VulnerabilitySeverity::Critical, 1 => crate::VulnerabilitySeverity::Important, 2 => crate::VulnerabilitySeverity::Moderate, 3 => crate::VulnerabilitySeverity::Low, _ => crate::VulnerabilitySeverity::Unrated };
        let cve = format!("CVE-2026-{:04}", 1000 + number);
        crate::VulnerabilityView {
            agent_id: format!("agent-{number:05}"), hostname: Some(format!("host-{number:05}.example.test")),
            advisory_id: format!("FEDORA-2026-{:04}", number), severity,
            title: format!("Security update for package-{}", number % 7), url: format!("https://example.test/advisories/FEDORA-2026-{number:04}"), cves: vec![cve],
            packages: serde_json::json!([{"name":format!("package-{}",number%7),"installed":"1.0-1.fc44","fixed":if number%4==0 { serde_json::Value::Null } else { serde_json::Value::String("1.0-2.fc44".into()) }}]),
            first_seen_at: format!("2026-09-2{}T10:00:00Z", number % 7), fixed_at: None, reboot_needed: number % 9 == 0,
            exploited: number % 7 == 0, kev: number % 11 == 0, euvd: number % 13 == 0, kev_due: None,
            ransomware: number % 17 == 0, epss: Some((number % 100) as f32 / 100.0), epss_percentile: Some((number % 100) as f32 / 100.0), cvss: Some(5.0 + (number % 50) as f32 / 10.0),
            source: "fedora-44-x86_64".into(), match_method: "distribution-advisory".into(), confidence: 98,
            match_basis: "Fedora's own security advisory names this package; the installed version is older than the fixed one.".into(),
            triage_state: "open".into(),
            triage_version: 0,
            assigned_to: None,
        }
    }).collect()
}

pub(super) async fn vulnerability_summary(
    State(_repository): State<Arc<dyn ConsoleRepository>>,
    headers: HeaderMap,
) -> Response {
    let (persona, mode) = match context(&headers, Permission::VulnerabilitiesRead) {
        Ok(v) => v,
        Err(r) => return *r,
    };
    if let Some(error) = read_error(mode) {
        return error;
    }
    let items = demo_vulnerabilities(persona, mode);
    let mut by_severity = Vec::new();
    for (name, severity) in [
        ("critical", crate::VulnerabilitySeverity::Critical),
        ("important", crate::VulnerabilitySeverity::Important),
        ("moderate", crate::VulnerabilitySeverity::Moderate),
        ("low", crate::VulnerabilitySeverity::Low),
        ("unrated", crate::VulnerabilitySeverity::Unrated),
    ] {
        let count = items
            .iter()
            .filter(|item| item.severity == severity && !item.reboot_needed)
            .count() as u64;
        if count > 0 {
            by_severity.push(crate::VulnerabilitySeverityCount { severity, count });
        }
        let _ = name;
    }
    let mut counts = BTreeMap::<String, u64>::new();
    for item in items.iter().filter(|item| !item.reboot_needed) {
        *counts.entry(item.agent_id.clone()).or_default() += 1;
    }
    let hosts = counts.len() as u64;
    let mut top_hosts: Vec<_> = counts
        .into_iter()
        .map(|(agent_id, open)| crate::VulnerabilityTopHost {
            hostname: Some(format!(
                "host-{}.example.test",
                agent_id.trim_start_matches("agent-")
            )),
            agent_id,
            open,
            serious: open,
        })
        .collect();
    top_hosts.sort_by(|a, b| {
        b.open
            .cmp(&a.open)
            .then_with(|| a.agent_id.cmp(&b.agent_id))
    });
    Json(crate::VulnerabilitySummary {
        by_severity,
        hosts,
        top_hosts: top_hosts.into_iter().take(10).collect(),
        reboot_hosts: items.iter().filter(|item| item.reboot_needed).count() as u64,
        no_fix: items
            .iter()
            .filter(|item| item.packages[0]["fixed"].is_null())
            .count() as u64,
        exploited: items
            .iter()
            .filter(|item| item.exploited && !item.reboot_needed)
            .count() as u64,
        // A fresh (empty) platform has no feed yet.
        feed_last_imported_at: (!matches!(mode, SeedMode::Empty))
            .then(|| "2026-09-28T06:00:00Z".to_owned()),
    })
    .into_response()
}

pub(super) async fn vulnerabilities(
    State(_repository): State<Arc<dyn ConsoleRepository>>,
    headers: HeaderMap,
    query: Result<Query<HashMap<String, String>>, QueryRejection>,
) -> Response {
    let (persona, mode) = match context(&headers, Permission::VulnerabilitiesRead) {
        Ok(v) => v,
        Err(r) => return *r,
    };
    if let Some(error) = read_error(mode) {
        return error;
    }
    let Query(params) = match query {
        Ok(v) => v,
        Err(_) => {
            return problem_response(ProblemDetails::new(
                StatusCode::BAD_REQUEST,
                "invalid_vulnerability_query",
                "Vulnerability filters are invalid",
            ));
        }
    };
    if params.keys().any(|key| {
        !matches!(
            key.as_str(),
            "host"
                | "advisory"
                | "severity"
                | "cve"
                | "fixed"
                | "exploited"
                | "reboot_needed"
                | "min_confidence"
        )
    }) {
        return problem_response(ProblemDetails::new(
            StatusCode::BAD_REQUEST,
            "invalid_vulnerability_query",
            "Vulnerability filters are invalid",
        ));
    }
    let mut items = demo_vulnerabilities(persona, mode);
    if let Some(host) = params.get("host") {
        items.retain(|item| item.agent_id == *host || item.hostname.as_deref() == Some(host));
    }
    if let Some(advisory) = params.get("advisory") {
        items.retain(|item| item.advisory_id == *advisory);
    }
    if let Some(severity) = params.get("severity") {
        items.retain(|item| format!("{:?}", item.severity).to_lowercase() == *severity);
    }
    if let Some(cve) = params.get("cve") {
        items.retain(|item| item.cves.iter().any(|value| value == cve));
    }
    if params.get("fixed").is_some_and(|value| value == "true") {
        items.clear();
    }
    if params.get("exploited").is_some_and(|value| value == "true") {
        items.retain(|item| item.exploited);
    }
    if params
        .get("exploited")
        .is_some_and(|value| value == "false")
    {
        items.retain(|item| !item.exploited);
    }
    if params
        .get("reboot_needed")
        .is_some_and(|value| value == "true")
    {
        items.retain(|item| item.reboot_needed);
    }
    if params
        .get("reboot_needed")
        .is_some_and(|value| value == "false")
    {
        items.retain(|item| !item.reboot_needed);
    }
    if let Some(min) = params
        .get("min_confidence")
        .and_then(|v| v.parse::<u8>().ok())
    {
        items.retain(|item| item.confidence >= min);
    }
    Json(crate::VulnerabilityPage {
        more_available: items.len() > 100,
        items: items.into_iter().take(100).collect(),
        generated_at: GENERATED_AT.into(),
    })
    .into_response()
}

pub(super) async fn vulnerability_advisory(
    State(_repository): State<Arc<dyn ConsoleRepository>>,
    headers: HeaderMap,
    Path(advisory_id): Path<String>,
) -> Response {
    let (persona, mode) = match context(&headers, Permission::VulnerabilitiesRead) {
        Ok(v) => v,
        Err(r) => return *r,
    };
    if let Some(error) = read_error(mode) {
        return error;
    }
    let hosts: Vec<_> = demo_vulnerabilities(persona, mode)
        .into_iter()
        .filter(|item| item.advisory_id == advisory_id)
        .collect();
    if hosts.is_empty() {
        return problem_response(ProblemDetails::not_found(
            "advisory_not_found",
            "Advisory not found",
        ));
    }
    let cve_id = hosts[0].cves[0].clone();
    Json(crate::VulnerabilityAdvisoryDetail {
        hosts: crate::VulnerabilityPage {
            items: hosts,
            more_available: false,
            generated_at: GENERATED_AT.into(),
        },
        cves: vec![crate::CveDetailView {
            cve_id,
            cvss_score: Some(7.5),
            cvss_version: Some("3.1".into()),
            cwe: vec!["CWE-79".into()],
            description: Some("Synthetic demo CVE enrichment.".into()),
            kev: true,
            euvd_exploited: Some("EUVD-DEMO-0001".into()),
            epss: Some(0.72),
        }],
    })
    .into_response()
}
