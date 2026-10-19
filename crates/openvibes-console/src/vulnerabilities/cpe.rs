//! CPE findings: matches of installed software against CPE names.

use chrono::SecondsFormat;

use super::list::VulnerabilityListParams;

/// CPE findings are never above this confidence (`openvibes-vulns`).
pub(super) const CPE_MAX_CONFIDENCE: u8 = 75;
/// Most CPE findings in one page.
pub(super) const CPE_PAGE: usize = 200;
/// Prefix of the advisory id a CPE finding is shown under: `CPE:CVE:product`.
pub(super) const CPE_PREFIX: &str = "CPE:";

pub(super) async fn cpe_findings(
    client: &platform_store::Client,
    scope: &platform_store::console_read::AgentScope,
    params: &VulnerabilityListParams,
) -> Result<Vec<platform_store::cpe::FindingRow>, platform_store::StoreError> {
    let agents = match scope {
        platform_store::console_read::AgentScope::Global => None,
        _ => Some(platform_store::console_read::agent_ids_in_scope(client, scope).await?),
    };
    // `CPE:CVE-…:product` names one finding group.
    let group = params
        .advisory
        .as_deref()
        .and_then(|a| a.strip_prefix(CPE_PREFIX));
    let (cve, product) = match group.and_then(|g| g.split_once(':')) {
        Some((cve, product)) => (Some(cve), Some(product)),
        None => (params.cve.as_deref(), None),
    };
    let min = i16::from(params.min_confidence.unwrap_or(0));
    let mut found = platform_store::cpe::list(
        client,
        min,
        params.host.as_deref(),
        cve,
        agents.as_deref(),
        (CPE_PAGE + 1) as i64,
    )
    .await?;
    if let Some(product) = product {
        found.retain(|f| f.product == product);
    }
    found.retain(|f| {
        params
            .severity
            .as_deref()
            .is_none_or(|s| cpe_severity(f.cvss).0 == s)
            && params.exploited.is_none_or(|e| e == f.exploited)
    });
    Ok(found)
}

/// Severity name and enum from a CVSS base score.
pub(super) fn cpe_severity(cvss: Option<f32>) -> (&'static str, crate::VulnerabilitySeverity) {
    match cvss {
        Some(s) if s >= 9.0 => ("critical", crate::VulnerabilitySeverity::Critical),
        Some(s) if s >= 7.0 => ("important", crate::VulnerabilitySeverity::Important),
        Some(s) if s >= 4.0 => ("moderate", crate::VulnerabilitySeverity::Moderate),
        Some(s) if s > 0.0 => ("low", crate::VulnerabilitySeverity::Low),
        _ => ("unrated", crate::VulnerabilitySeverity::Unrated),
    }
}

pub(super) fn cpe_view(row: platform_store::cpe::FindingRow) -> crate::VulnerabilityView {
    crate::VulnerabilityView {
        advisory_id: format!("{CPE_PREFIX}{}:{}", row.cve_id, row.product),
        severity: cpe_severity(row.cvss).1,
        title: format!("{}: {} {}", row.cve_id, row.package, row.range_text),
        url: format!("https://nvd.nist.gov/vuln/detail/{}", row.cve_id),
        packages: serde_json::json!([{
            "name": row.package, "installed": row.installed, "fixed": null,
        }]),
        agent_id: row.agent_id,
        hostname: row.hostname,
        cves: vec![row.cve_id],
        first_seen_at: row.first_seen_at.to_rfc3339_opts(SecondsFormat::Secs, true),
        fixed_at: None,
        reboot_needed: false,
        exploited: row.exploited,
        kev: row.kev,
        euvd: row.euvd,
        kev_due: row.kev_due.map(|v| v.to_string()),
        ransomware: row.ransomware,
        epss: row.epss,
        epss_percentile: row.epss_percentile,
        cvss: row.cvss,
        source: "nvd-cpe".into(),
        match_method: "cpe-nvd".into(),
        confidence: u8::try_from(row.confidence).unwrap_or(0),
        match_basis: row.basis,
        triage_state: "open".into(),
        triage_version: 0,
        assigned_to: None,
    }
}
