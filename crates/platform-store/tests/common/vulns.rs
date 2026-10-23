//! The Vulnerabilities list fixture shared by `vuln_list.rs`: four hosts,
//! three groups and pairs of every kind.
#![allow(dead_code, reason = "each test binary uses some of these")]

use chrono::{Duration, Utc};
use platform_store::{
    Client,
    console_read::AgentScope,
    vuln_list::{VulnListPage, VulnListRow, VulnQuery, VulnSort, VulnState, vuln_list},
};

use super::hosts::id;

pub const ANN: &str = "00000000-0000-4000-8000-0000000000a1";
pub const BOB: &str = "00000000-0000-4000-8000-0000000000b2";
pub const CID: &str = "00000000-0000-4000-8000-0000000000c3";

/// Hosts 1, 2 (Debian 12) and 3 (Fedora 44) are in group Web, the scope;
/// host 4 (Debian 12) only in Other; Alpha holds host 1.
///
/// - FEDORA-1 (critical, CVE-A and CVE-B, curl fixed in 2): host 3,
///   accepted risk (Ann).
/// - DEBIAN-A (important, CVE-A, curl): host 1 open (Ann, fixed in
///   7.88-2), host 2 mitigated (Bob).
/// - DSA-NOCVE (low, no CVE, openssl): host 1, reboot pending.
/// - DEBIAN-NF (moderate, CVE-NF): no fix, zlib on hosts 1, 2 and 4.
/// - DEBIAN-EXP (moderate, CVE-EXP): host 1 open (Bob), host 2 accepted
///   risk expired (Ann).
/// - DEBIAN-R (low, CVE-R): host 1, fixed. DEBIAN-FP (unrated, CVE-FP):
///   host 2, false positive.
/// - MYS-1 (important, CVE-MYS, unknown source): host 2, lower confidence.
/// - CPE match CVE-CPE on nginx, host 2, confidence 60.
/// - DEBIAN-OUT (critical, CVE-OUT, secretpkg): host 4 only.
///
/// KEV: CVE-A due in 10 days, CVE-B in 40, CVE-NF 5 days ago (and EUVD).
pub async fn fixture(c: &Client) -> (String, String) {
    let today = Utc::now().date_naive();
    let due = |d: i64| (today + Duration::days(d)).to_string();
    c.batch_execute(&format!(
        "INSERT INTO console_users (user_id, username, display_name, created_at) VALUES
           ('{ANN}', 'ann', 'Ann', now()), ('{BOB}', 'bob', 'Bob', now());
         INSERT INTO agents (agent_id, status, enrolled_at, last_seen_at, hostname, os_id, os_version) VALUES
           ('{h1}', 'active', now(), now(), 'web-01', 'debian', '12'),
           ('{h2}', 'active', now(), now(), 'web-02', 'debian', '12'),
           ('{h3}', 'active', now(), now(), 'db-01', 'fedora', '44'),
           ('{h4}', 'active', now(), now(), 'secret-01', 'debian', '12');
         INSERT INTO advisories (advisory_id, source, os_id, os_version, severity, title, url) VALUES
           ('FEDORA-1', 'fedora-44-x86_64', 'fedora', '44', 'critical', 'curl: two flaws', 'u'),
           ('DEBIAN-A', 'debian-12', 'debian', '12', 'important', 'curl: flaw A', 'u'),
           ('DSA-NOCVE', 'debian-12', 'debian', '12', 'low', 'openssl hardening', 'u'),
           ('DEBIAN-NF', 'debian-12', 'debian', '12', 'moderate', 'zlib: no fix yet', 'u'),
           ('DEBIAN-EXP', 'debian-12', 'debian', '12', 'moderate', 'bash: flaw', 'u'),
           ('DEBIAN-R', 'debian-12', 'debian', '12', 'low', 'tar: fixed', 'u'),
           ('DEBIAN-FP', 'debian-12', 'debian', '12', 'unrated', 'vim: not real', 'u'),
           ('MYS-1', 'mystery-1', 'debian', '12', 'important', 'odd feed', 'u'),
           ('DEBIAN-OUT', 'debian-12', 'debian', '12', 'critical', 'secret: flaw', 'u');
         INSERT INTO advisory_cves VALUES ('FEDORA-1', 'CVE-A'), ('FEDORA-1', 'CVE-B'),
           ('DEBIAN-A', 'CVE-A'), ('DEBIAN-NF', 'CVE-NF'), ('DEBIAN-EXP', 'CVE-EXP'),
           ('DEBIAN-R', 'CVE-R'), ('DEBIAN-FP', 'CVE-FP'), ('MYS-1', 'CVE-MYS'), ('DEBIAN-OUT', 'CVE-OUT');
         INSERT INTO cve_enrichment (cve_id, kev_added, kev_due, euvd_exploited, epss, epss_percentile, cvss_score) VALUES
           ('CVE-A', '{added}', '{a}', NULL, 0.5, 0.9, 9.8),
           ('CVE-B', '{added}', '{b}', NULL, 0.1, 0.3, 5.0),
           ('CVE-NF', '{added}', '{nf}', true, 0.2, 0.5, 7.5),
           ('CVE-EXP', NULL, NULL, NULL, 0.01, 0.1, 3.0);
         INSERT INTO vulnerabilities (agent_id, advisory_id, packages, first_seen_at, fixed_at, last_evaluated_at, reboot_needed) VALUES
           ('{h3}', 'FEDORA-1', '[{{\"name\":\"curl\",\"installed\":\"1\",\"fixed\":\"2\"}}]', now(), NULL, now(), false),
           ('{h1}', 'DEBIAN-A', '[{{\"name\":\"curl\",\"installed\":\"7.88-1\",\"fixed\":\"7.88-2\"}}]', now(), NULL, now(), false),
           ('{h2}', 'DEBIAN-A', '[{{\"name\":\"curl\",\"installed\":\"7.88-1\",\"fixed\":\"7.88-2\"}}]', now(), NULL, now(), false),
           ('{h1}', 'DSA-NOCVE', '[{{\"name\":\"openssl\",\"installed\":\"3\",\"fixed\":\"3.1\"}}]', now(), NULL, now(), true),
           ('{h1}', 'DEBIAN-EXP', '[{{\"name\":\"bash\",\"installed\":\"5\",\"fixed\":\"5.1\"}}]', now(), NULL, now(), false),
           ('{h2}', 'DEBIAN-EXP', '[{{\"name\":\"bash\",\"installed\":\"5\",\"fixed\":\"5.1\"}}]', now(), NULL, now(), false),
           ('{h1}', 'DEBIAN-R', '[{{\"name\":\"tar\",\"installed\":\"1\",\"fixed\":\"2\"}}]', now(), now(), now(), false),
           ('{h2}', 'DEBIAN-FP', '[{{\"name\":\"vim\",\"installed\":\"9\",\"fixed\":\"9.1\"}}]', now(), NULL, now(), false),
           ('{h2}', 'MYS-1', '[{{\"name\":\"odd\",\"installed\":\"1\",\"fixed\":\"2\"}}]', now(), NULL, now(), false),
           ('{h4}', 'DEBIAN-OUT', '[{{\"name\":\"secretpkg\",\"installed\":\"1\",\"fixed\":\"2\"}}]', now(), NULL, now(), false);
         INSERT INTO vulnerability_triage (agent_id, advisory_id, state, assigned_to, note, accepted_until, version, updated_at, updated_by) VALUES
           ('{h3}', 'FEDORA-1', 'accepted_risk', '{ANN}', 'n', now() + interval '30 days', 1, now(), 't'),
           ('{h1}', 'DEBIAN-A', 'open', '{ANN}', NULL, NULL, 1, now(), 't'),
           ('{h2}', 'DEBIAN-A', 'mitigated', '{BOB}', 'n', NULL, 1, now(), 't'),
           ('{h1}', 'DEBIAN-EXP', 'open', '{BOB}', NULL, NULL, 1, now(), 't'),
           ('{h2}', 'DEBIAN-EXP', 'accepted_risk', '{ANN}', 'n', now() - interval '2 days', 1, now(), 't'),
           ('{h2}', 'DEBIAN-FP', 'false_positive', NULL, 'n', NULL, 1, now(), 't');
         INSERT INTO package_versions (manager, name, version, arch, source) VALUES
           ('dpkg', 'zlib1g', '1.2', 'amd64', 'zlib'), ('dpkg', 'nginx', '1.22', 'amd64', 'nginx');
         INSERT INTO host_packages SELECT h, (SELECT id FROM package_versions WHERE name = 'zlib1g')
           FROM unnest(ARRAY['{h1}', '{h2}', '{h4}']) h;
         INSERT INTO host_packages SELECT '{h2}', id FROM package_versions WHERE name = 'nginx';
         INSERT INTO package_versions (manager, name, version, arch, source)
         SELECT 'dpkg', n, '1', 'amd64', n FROM unnest(ARRAY['curl', 'openssl', 'bash', 'tar', 'vim', 'odd', 'secretpkg']) n;
         INSERT INTO host_packages SELECT h, (SELECT id FROM package_versions WHERE name = n)
         FROM (VALUES ('{h1}', 'curl'), ('{h2}', 'curl'), ('{h3}', 'curl'), ('{h1}', 'openssl'), ('{h1}', 'bash'),
                      ('{h2}', 'bash'), ('{h1}', 'tar'), ('{h2}', 'vim'), ('{h2}', 'odd'), ('{h4}', 'secretpkg')) x(h, n);
         INSERT INTO advisory_packages (advisory_id, name, arch, scheme, match_on, fixed) VALUES
           ('FEDORA-1', 'curl', 'x86_64', 'rpm', 'binary', '2'), ('DEBIAN-A', 'curl', '', 'dpkg', 'source', '7.88-2'),
           ('DSA-NOCVE', 'openssl', '', 'dpkg', 'source', '3.1'), ('DEBIAN-EXP', 'bash', '', 'dpkg', 'source', '5.1'),
           ('DEBIAN-R', 'tar', '', 'dpkg', 'source', '2'), ('DEBIAN-FP', 'vim', '', 'dpkg', 'source', '9.1'),
           ('MYS-1', 'odd', '', 'dpkg', 'source', '2'), ('DEBIAN-OUT', 'secretpkg', '', 'dpkg', 'source', '2'),
           ('DEBIAN-NF', 'zlib', '', 'dpkg', 'source', NULL);
         INSERT INTO version_vulnerabilities SELECT id, 'DEBIAN-NF', 'zlib', now() FROM package_versions WHERE name = 'zlib1g';
         INSERT INTO cpe_findings (package_version_id, os_version, cve_id, product, package, installed, range_text,
                                   confidence, basis, cvss, first_seen_at)
           SELECT id, '12', 'CVE-CPE', 'nginx', 'nginx', '1.22', '< 1.24', 60, 'b', 6.0, now()
           FROM package_versions WHERE name = 'nginx';",
        h1 = id(1),
        h2 = id(2),
        h3 = id(3),
        h4 = id(4),
        added = due(-60),
        a = due(10),
        b = due(40),
        nf = due(-5),
    ))
    .await
    .unwrap();
    let web = super::manual_group(c, "Web", &[id(1), id(2), id(3)]).await;
    super::manual_group(c, "Other", &[id(4)]).await;
    let alpha = super::manual_group(c, "Alpha", &[id(1)]).await;
    (web, alpha)
}

pub fn query() -> VulnQuery<'static> {
    VulnQuery {
        q: None,
        state: VulnState::Open,
        severity: None,
        signal: None,
        package: None,
        group: None,
        host: None,
        advisory: None,
        assignee: None,
        sort: VulnSort::Priority,
        descending: true,
        offset: 0,
        limit: 50,
    }
}

pub fn every() -> VulnQuery<'static> {
    VulnQuery {
        state: VulnState::All,
        ..query()
    }
}

pub async fn run(c: &Client, q: &VulnQuery<'_>, scope: &AgentScope) -> VulnListPage {
    vuln_list(c, q, scope, ANN, Utc::now().date_naive())
        .await
        .unwrap()
}

pub fn keys(page: &VulnListPage) -> Vec<&str> {
    page.rows.iter().map(|r| r.key.as_str()).collect()
}

pub fn row<'a>(page: &'a VulnListPage, key: &str) -> &'a VulnListRow {
    page.rows.iter().find(|r| r.key == key).unwrap()
}
