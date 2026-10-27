//! The software fixture shared by the Software list and package page tests:
//! the ports fixture's hosts (web-01 A, web-02 B, db-01 C, a revoked host
//! and one outside the scope) with packages, advisories and changes.

#![allow(dead_code, reason = "each test binary uses some of these")]

use deadpool_postgres::Client;

pub use super::ports::{A, B, C, GONE, OUTSIDE};

/// Installs `name` at `version` from `manager` on `host`.
pub async fn install(c: &Client, host: &str, manager: &str, name: &str, version: &str) -> i64 {
    let id: i64 = match c
        .query_opt(
            "SELECT id FROM package_versions WHERE manager = $1 AND name = $2 AND version = $3",
            &[&manager, &name, &version],
        )
        .await
        .unwrap()
    {
        Some(row) => row.get(0),
        None => c
            .query_one(
                "INSERT INTO package_versions (manager, name, version, arch)
                 VALUES ($1, $2, $3, 'amd64') RETURNING id",
                &[&manager, &name, &version],
            )
            .await
            .unwrap()
            .get(0),
    };
    c.execute(
        "INSERT INTO host_packages (agent_id, package_version_id) VALUES ($1, $2)",
        &[&host, &id],
    )
    .await
    .unwrap();
    id
}

/// Runs the ports fixture, then adds the packages, advisories, units and
/// package changes; returns (the scope group's id, the web group's id).
///
/// In scope (A, B, C; the revoked host and the outside host are not):
/// - `openssl` (dpkg): 3.0.11 on A and B, 3.0.9 on C; outside has 3.0.11,
///   the revoked host 3.0.9. Advisories: OS-1 (critical, exploited, fixed in
///   3.0.12) open on A, false positive on B; OS-2 (moderate, fixed) on C
///   waiting for a reboot; OS-3 (low) without a fix for 3.0.9; OS-OUT
///   (critical) only on the outside host.
/// - `nginx` (dpkg): 1.22.1 on A, 1.24.0 on B; NG-1 (moderate) has no fix
///   for 1.22.1. Used by `nginx.service` (A, B).
/// - `bash`: rpm 5.2.15 on A and B, dpkg 5.2.15 on C.
/// - `linux-image` (dpkg): 6.1.0 and 6.1.1 both on A.
/// - `curl` (dpkg): 7.88 on A; its advisory CURL-1 comes from an unknown
///   feed (lower confidence).
/// - `openssh-server` (dpkg): 9.2 on A, B and C; used by `sshd.service`.
///
/// Changes: openssl updated on A (2 days ago: the went-away and the appeared
/// share one instant), curl installed on A (1 day ago) and on the outside
/// host, installed on B and removed again a day later (counts in no column), nginx removed from C (3 days ago) and
/// installed on A 40 days ago.
pub async fn fixture(c: &Client) -> (String, String) {
    let groups = super::ports::fixture(c).await;
    for (host, manager, name, version) in [
        (A, "dpkg", "openssl", "3.0.11"),
        (B, "dpkg", "openssl", "3.0.11"),
        (C, "dpkg", "openssl", "3.0.9"),
        (OUTSIDE, "dpkg", "openssl", "3.0.11"),
        (GONE, "dpkg", "openssl", "3.0.9"),
        (A, "dpkg", "nginx", "1.22.1"),
        (B, "dpkg", "nginx", "1.24.0"),
        (A, "rpm", "bash", "5.2.15"),
        (B, "rpm", "bash", "5.2.15"),
        (C, "dpkg", "bash", "5.2.15"),
        (A, "dpkg", "linux-image", "6.1.0"),
        (A, "dpkg", "linux-image", "6.1.1"),
        (A, "dpkg", "curl", "7.88"),
        (OUTSIDE, "dpkg", "curl", "7.88"),
        (A, "dpkg", "openssh-server", "9.2"),
        (B, "dpkg", "openssh-server", "9.2"),
        (C, "dpkg", "openssh-server", "9.2"),
    ] {
        install(c, host, manager, name, version).await;
    }
    c.batch_execute(
        "UPDATE agents SET inventory_at = now();
         INSERT INTO host_services (agent_id, unit, programs, processes, run_as) VALUES
           ('agent.00000000-0000-4000-8000-000000000701', 'nginx.service', '{nginx}', 3, 'www-data'),
           ('agent.00000000-0000-4000-8000-000000000702', 'nginx.service', '{nginx}', 2, 'www-data'),
           ('agent.00000000-0000-4000-8000-000000000701', 'sshd.service', '{sshd}', 1, 'root'),
           ('agent.00000000-0000-4000-8000-000000000702', 'sshd.service', '{sshd}', 1, 'root'),
           ('agent.00000000-0000-4000-8000-000000000703', 'sshd.service', '{sshd}', 1, 'root');
         INSERT INTO advisories (advisory_id, source, os_id, os_version, severity, title, url) VALUES
           ('OS-1', 'debian-12', 'debian', '12', 'critical', 'openssl: flaw one', 'u'),
           ('OS-2', 'debian-12', 'debian', '12', 'moderate', 'openssl: flaw two', 'u'),
           ('OS-3', 'debian-12', 'debian', '12', 'low', 'openssl: no fix yet', 'u'),
           ('OS-OUT', 'debian-12', 'debian', '12', 'critical', 'openssl: elsewhere', 'u'),
           ('NG-1', 'debian-12', 'debian', '12', 'moderate', 'nginx: no fix yet', 'u'),
           ('CURL-1', 'mystery-1', 'debian', '12', 'important', 'curl: odd feed', 'u');
         INSERT INTO advisory_cves VALUES ('OS-1', 'CVE-OS-1'), ('OS-2', 'CVE-OS-2');
         INSERT INTO cve_enrichment (cve_id, kev_added, kev_due, epss, epss_percentile)
           VALUES ('CVE-OS-1', current_date - 30, current_date + 10, 0.5, 0.9);
         INSERT INTO version_vulnerabilities (package_version_id, advisory_id, package, first_seen_at)
         SELECT id, 'OS-3', 'openssl', now() FROM package_versions WHERE name = 'openssl' AND version = '3.0.9'
         UNION ALL
         SELECT id, 'NG-1', 'nginx', now() FROM package_versions WHERE name = 'nginx' AND version = '1.22.1';",
    )
    .await
    .unwrap();
    for (host, advisory, name, reboot) in [
        (A, "OS-1", "openssl", false),
        (B, "OS-1", "openssl", false),
        (C, "OS-2", "openssl", true),
        (OUTSIDE, "OS-OUT", "openssl", false),
        (A, "CURL-1", "curl", false),
    ] {
        c.execute(
            "INSERT INTO vulnerabilities (agent_id, advisory_id, packages, first_seen_at, last_evaluated_at, reboot_needed)
             VALUES ($1, $2, jsonb_build_array(jsonb_build_object('name', $3::text, 'fixed', '3.0.12')), now(), now(), $4)",
            &[&host, &advisory, &name, &reboot],
        )
        .await
        .unwrap();
    }
    c.execute(
        "INSERT INTO vulnerability_triage (agent_id, advisory_id, state, note, version, updated_at, updated_by)
         VALUES ($1, 'OS-1', 'false_positive', 'n', 1, now(), 't')",
        &[&B],
    )
    .await
    .unwrap();
    let at = chrono::Utc::now();
    for (host, key, change, days, version) in [
        (A, "openssl", "went_away", 2, "0:3.0.9-1"),
        (A, "openssl", "appeared", 2, "0:3.0.11-1"),
        (A, "curl", "appeared", 1, "0:7.88-1"),
        (OUTSIDE, "curl", "appeared", 1, "0:7.88-1"),
        (C, "nginx", "went_away", 3, "0:1.22.1-1"),
        (A, "nginx", "appeared", 40, "0:1.22.1-1"),
        (B, "curl", "appeared", 2, "0:7.88-1"),
        (B, "curl", "went_away", 1, "0:7.88-1"),
    ] {
        c.execute(
            "INSERT INTO change_log (at, agent_id, kind, key, change, detail)
             VALUES ($4::timestamptz, $1, 'package', $2, $3,
                     jsonb_build_object('manager', 'dpkg', 'version', $5::text, 'arch', 'amd64'))",
            &[
                &host,
                &key,
                &change,
                &(at - chrono::Duration::days(days)),
                &version,
            ],
        )
        .await
        .unwrap();
    }
    groups
}
