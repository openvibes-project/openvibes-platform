//! The Vulnerabilities list on the `docs/sizing.md` fleet (step 5b ruling
//! 13, Review Focus 5): 10,000 Debian 12 hosts with 389 packages each,
//! 3.2 M fixable pairs and 27.5 M pairs without a fix. Ignored by default;
//! run it explicitly. Timings are recorded in console-read.md.

mod common;

use std::time::{Duration, Instant};

use chrono::Utc;
use platform_store::{
    Client,
    console_read::AgentScope,
    vuln_list::{VulnQuery, VulnSort, VulnState, vuln_list},
};

const ANN: &str = "00000000-0000-4000-8000-0000000000a1";

/// The fleet, generated in SQL: package `pkg-p` has three versions when
/// `p % 10 = 0` (one otherwise), and host `n` has version `n % 20 % 3` of
/// each. Advisories 1–1600 have a fix (host `n` has those with
/// `i % 5 = n % 5`, every tenth fixed, every fiftieth waiting for a
/// reboot), 2001–4750 none (every host has them), the rest of the 46,222
/// none on any host. About 1 % of open pairs are triaged; ten manual
/// groups of about 500 hosts and five host-name rule groups.
async fn sizing_fleet(c: &Client) {
    c.batch_execute(&format!(
        "INSERT INTO console_users (user_id, username, display_name, created_at) VALUES
           ('{ANN}', 'ann', 'Ann', now()), ('00000000-0000-4000-8000-0000000000b2', 'bob', 'Bob', now());
         INSERT INTO agents (agent_id, status, enrolled_at, last_seen_at, hostname, os_id, os_version)
         SELECT 'agent.' || gen_random_uuid()::text, 'active', now() - interval '90 days', now(), 'deb-' || n, 'debian', '12'
         FROM generate_series(1, 10000) n;
         CREATE TEMP TABLE gen AS SELECT agent_id, substr(hostname, 5)::int AS n FROM agents;
         INSERT INTO package_versions (manager, name, version, arch, source)
         SELECT 'dpkg', 'pkg-' || p, '1.0-' || v, 'amd64', 'pkg-' || p
         FROM generate_series(0, 388) p CROSS JOIN LATERAL generate_series(0, CASE WHEN p % 10 = 0 THEN 2 ELSE 0 END) v;
         INSERT INTO host_packages (agent_id, package_version_id)
         SELECT g.agent_id, pv.id FROM gen g CROSS JOIN generate_series(0, 388) p
         JOIN package_versions pv ON pv.name = 'pkg-' || p
          AND pv.version = '1.0-' || ((g.n % 20) % CASE WHEN p % 10 = 0 THEN 3 ELSE 1 END);
         INSERT INTO advisories (advisory_id, source, os_id, os_version, severity, title, url)
         SELECT 'DEBIAN-CVE-2026-' || lpad(i::text, 5, '0'), 'debian-12', 'debian', '12',
                (ARRAY['critical','important','moderate','low','unrated'])[i % 5 + 1], 'pkg-' || (i % 389) || ': flaw ' || i, 'u'
         FROM generate_series(1, 46222) i;
         INSERT INTO advisory_cves
         SELECT 'DEBIAN-CVE-2026-' || lpad(i::text, 5, '0'), 'CVE-2026-' || lpad(i::text, 5, '0') FROM generate_series(1, 46222) i
         UNION ALL
         SELECT 'DEBIAN-CVE-2026-' || lpad(i::text, 5, '0'), 'CVE-2025-' || lpad(i::text, 5, '0') FROM generate_series(50, 1600, 50) i;
         INSERT INTO cve_enrichment (cve_id, kev_added, kev_due, epss, epss_percentile, cvss_score)
         SELECT 'CVE-2026-' || lpad(i::text, 5, '0'), CASE WHEN i % 97 = 0 THEN current_date - 30 END,
                CASE WHEN i % 97 = 0 THEN current_date + (i % 60 - 20) END, (i % 1000) / 1000.0, (i % 997) / 997.0, (i % 100) / 10.0
         FROM generate_series(1, 4750) i;
         INSERT INTO version_vulnerabilities (package_version_id, advisory_id, package, first_seen_at)
         SELECT pv.id, 'DEBIAN-CVE-2026-' || lpad(i::text, 5, '0'), pv.source, now()
         FROM generate_series(2001, 4750) i JOIN package_versions pv ON pv.name = 'pkg-' || (i % 389);
         INSERT INTO vulnerabilities (agent_id, advisory_id, packages, first_seen_at, fixed_at, last_evaluated_at, reboot_needed)
         SELECT g.agent_id, 'DEBIAN-CVE-2026-' || lpad(i::text, 5, '0'),
                jsonb_build_array(jsonb_build_object('name', 'pkg-' || (i % 389), 'installed', '1.0-' || (g.n % 20), 'fixed', '1.1')),
                now(), CASE WHEN (g.n + i) % 10 = 0 THEN now() END, now(), (g.n + i) % 50 = 1
         FROM gen g CROSS JOIN generate_series(1, 1600) i WHERE i % 5 = g.n % 5;
         INSERT INTO vulnerability_triage (agent_id, advisory_id, state, assigned_to, note, accepted_until, version, updated_at, updated_by)
         SELECT v.agent_id, v.advisory_id, s.state,
                (ARRAY['{ANN}', '00000000-0000-4000-8000-0000000000b2', NULL])[abs(hashtext(v.agent_id || v.advisory_id)) % 3 + 1]::uuid,
                CASE WHEN s.state <> 'open' THEN 'n' END,
                CASE WHEN s.state = 'accepted_risk' THEN now() + interval '30 days' END, 1, now(), 't'
         FROM vulnerabilities v
         CROSS JOIN LATERAL (SELECT (ARRAY['open','mitigated','accepted_risk','false_positive'])
                               [abs(hashtext(v.advisory_id || v.agent_id)) % 4 + 1] AS state) s
         WHERE v.fixed_at IS NULL AND abs(hashtext(v.agent_id || v.advisory_id)) % 100 = 0;
         INSERT INTO console_asset_groups (asset_group_id, name, created_at, created_by, kind)
         SELECT gen_random_uuid(), 'manual ' || i, now(), 't', 'manual' FROM generate_series(0, 9) i;
         INSERT INTO console_host_group_members (asset_group_id, agent_id, added_at, added_by)
         SELECT g.asset_group_id, a.agent_id, now(), 't' FROM console_asset_groups g JOIN agents a
           ON abs(hashtext(a.agent_id || g.name)) % 20 = 0;
         INSERT INTO console_asset_groups (asset_group_id, name, created_at, created_by, kind)
         SELECT gen_random_uuid(), 'name ' || i, now(), 't', 'rule' FROM generate_series(0, 4) i;
         INSERT INTO console_host_group_conditions (asset_group_id, position, field, negate, vals)
         SELECT asset_group_id, 0, 'hostname', false, ARRAY['deb-' || substr(name, 6) || '*']
         FROM console_asset_groups WHERE kind = 'rule';"
    ))
    .await
    .unwrap();
    c.batch_execute("VACUUM ANALYZE").await.unwrap();
}

fn query() -> VulnQuery<'static> {
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

async fn median(c: &Client, scope: &AgentScope) -> (Duration, i64, i64) {
    const RUNS: usize = 5;
    let mut samples = Vec::with_capacity(RUNS);
    let mut seen = (0, 0);
    for _ in 0..RUNS {
        let started = Instant::now();
        let page = vuln_list(c, &query(), scope, ANN, Utc::now().date_naive())
            .await
            .unwrap();
        samples.push(started.elapsed());
        seen = (page.total, page.summary.hosts);
        assert_eq!(page.rows.len(), 50);
    }
    samples.sort();
    eprintln!("  all {samples:?}");
    (samples[RUNS / 2], seen.0, seen.1)
}

/// Records the default list (open, by priority, 50 rows, every count and
/// the summary) at full reach and scoped to two manual groups.
#[tokio::test]
#[ignore = "large-fleet timing; run explicitly"]
async fn records_vuln_list_latency_on_the_sizing_fleet() {
    let (db, c) = common::migrated().await;
    c.batch_execute("SET statement_timeout = 0").await.unwrap();
    sizing_fleet(&c).await;
    let pairs: i64 = c
        .query_one("SELECT count(*) FROM vulnerabilities", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(pairs, 3_200_000);

    let (full, total, hosts) = median(&c, &AgentScope::Global).await;
    eprintln!("vuln list, full reach: median {full:?}, {total} rows, {hosts} hosts");
    let groups: Vec<String> = c
        .query(
            "SELECT asset_group_id::text FROM console_asset_groups WHERE name IN ('manual 0', 'manual 1')",
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|r| r.get(0))
        .collect();
    let (scoped, scoped_total, scoped_hosts) = median(&c, &AgentScope::AssetGroups(groups)).await;
    eprintln!(
        "vuln list, two manual groups: median {scoped:?}, {scoped_total} rows, {scoped_hosts} hosts"
    );
    assert_eq!(hosts, 10_000);
    assert!(scoped_hosts < hosts);
    assert!(full < Duration::from_secs(2), "full reach {full:?}");
    assert!(scoped < Duration::from_secs(2), "scoped {scoped:?}");
    db.drop().await;
}
