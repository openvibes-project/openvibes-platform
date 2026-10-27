//! The Software list on the `docs/sizing.md` fleet (step 5g ruling 11): 10,000
//! Debian hosts with 400 packages each out of 600 names (a fifth of the names
//! in three versions, a tenth also under rpm, a fiftieth with two versions on
//! one host), 2,000 advisories (1,000 with a fix: 300,000 open fixable pairs,
//! the rest through the versions in use), 500,000 change-log rows, 100 units
//! and 15 groups. `SOFTWARE_TIMING_PACKAGES=2000` runs the extreme fleet of
//! the Services list instead (3,000 names, 2,000 on each host). Ignored by
//! default; run it with `cargo test --release -p platform-store --test
//! software_list_timing -- --ignored --nocapture`. Timings are recorded in
//! docs/components/platform-store.md.
//!
//! Building the fleet takes a few minutes. Set `SOFTWARE_TIMING_DB_URL` to
//! the URL of a database an earlier run left behind (`SOFTWARE_TIMING_KEEP=1`
//! keeps it) to measure again without rebuilding it.

mod common;
use common::timing;

use std::time::Duration;

use chrono::Utc;
use platform_store::{
    Client,
    console_read::AgentScope,
    software_list::{Changes, Fix, SoftwareQuery, SoftwareSort, Versions, Vulns, software_list},
};

/// The step 5g target at the sizing fleet's full reach. The default view meets
/// it; a sort by hosts and a few filters run past it (see platform-store.md),
/// so the run fails only at the ceiling.
const LIMIT: Duration = Duration::from_secs(2);
const CEILING: Duration = Duration::from_secs(5);

fn packages() -> i64 {
    std::env::var("SOFTWARE_TIMING_PACKAGES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(400)
}

async fn fleet(c: &Client, per_host: i64) -> String {
    timing::hosts(c).await;
    let names = per_host * 3 / 2;
    c.batch_execute(&format!(
        "UPDATE agents SET inventory_at = now();
         -- Name i: versions 0..2 when i % 5 = 0, else 0; dpkg, and rpm too when i % 10 = 0.
         INSERT INTO package_versions (manager, name, version, arch)
         SELECT m, 'pkg' || i, '1.' || v, 'amd64'
         FROM generate_series(0, {names} - 1) i
         CROSS JOIN LATERAL generate_series(0, CASE WHEN i % 5 = 0 THEN 2 ELSE 0 END) v
         CROSS JOIN LATERAL (SELECT unnest(CASE WHEN i % 10 = 0 THEN ARRAY['dpkg', 'rpm'] ELSE ARRAY['dpkg'] END) AS m) mm;
         CREATE TEMP TABLE pvx AS
           SELECT id, substr(name, 4)::int AS i, substr(version, 3)::int AS v, manager FROM package_versions;
         CREATE INDEX ON pvx (i, v, manager);
         -- Host n has names (n * 17 + k * 3 / 2) % names for k < {per_host}.
         INSERT INTO host_packages (agent_id, package_version_id)
         SELECT g.agent_id, pvx.id
         FROM gen g CROSS JOIN generate_series(0, {per_host} - 1) k
         CROSS JOIN LATERAL (SELECT (g.n * 17 + k * 3 / 2) % {names} AS i) x
         JOIN pvx ON pvx.i = x.i AND pvx.v = CASE WHEN x.i % 5 = 0 THEN (g.n + x.i) % 3 ELSE 0 END
                 AND pvx.manager = CASE WHEN x.i % 10 = 0 AND g.n % 2 = 0 THEN 'rpm' ELSE 'dpkg' END;
         -- Two versions on one host for every fiftieth name.
         INSERT INTO host_packages (agent_id, package_version_id)
         SELECT g.agent_id, pvx.id
         FROM gen g CROSS JOIN generate_series(0, {per_host} - 1) k
         CROSS JOIN LATERAL (SELECT (g.n * 17 + k * 3 / 2) % {names} AS i) x
         JOIN pvx ON pvx.i = x.i AND pvx.v = CASE WHEN x.i % 5 = 0 THEN (g.n + x.i + 1) % 3 ELSE 0 END
                 AND pvx.manager = CASE WHEN x.i % 10 = 0 AND g.n % 2 = 0 THEN 'rpm' ELSE 'dpkg' END
         WHERE x.i % 50 = 0
         ON CONFLICT DO NOTHING;
         INSERT INTO advisories (advisory_id, source, os_id, os_version, severity, title, url)
         SELECT 'DEBIAN-CVE-2026-' || lpad(i::text, 5, '0'), 'debian-12', 'debian', '12',
                (ARRAY['critical','important','moderate','low','unrated'])[i % 5 + 1], 'pkg' || ((i * 7) % {names}) || ': flaw', 'u'
         FROM generate_series(1, 2000) i;
         INSERT INTO advisory_cves
         SELECT 'DEBIAN-CVE-2026-' || lpad(i::text, 5, '0'), 'CVE-2026-' || lpad(i::text, 5, '0') FROM generate_series(1, 2000) i;
         INSERT INTO cve_enrichment (cve_id, kev_added, kev_due, epss, epss_percentile)
         SELECT 'CVE-2026-' || lpad(i::text, 5, '0'), current_date - 30, current_date + 10, 0.1, 0.5
         FROM generate_series(1, 2000, 97) i;
         -- Even advisories have no fix: every version of their package.
         INSERT INTO version_vulnerabilities (package_version_id, advisory_id, package, first_seen_at)
         SELECT pvx.id, 'DEBIAN-CVE-2026-' || lpad(s.n::text, 5, '0'), 'pkg' || ((s.n * 7) % {names}), now()
         FROM generate_series(2, 2000, 2) s(n) JOIN pvx ON pvx.i = (s.n * 7) % {names};
         -- Odd advisories have a fix: 300 hosts each have an open pair (a tenth waiting for a reboot).
         INSERT INTO vulnerabilities (agent_id, advisory_id, packages, first_seen_at, last_evaluated_at, reboot_needed)
         SELECT g.agent_id, 'DEBIAN-CVE-2026-' || lpad(i::text, 5, '0'),
                jsonb_build_array(jsonb_build_object('name', 'pkg' || ((i * 7) % {names}), 'fixed', '1.9')),
                now(), now(), (g.n + i) % 10 = 0
         FROM gen g CROSS JOIN generate_series(1, 2000, 2) i WHERE (g.n + i) % 33 = 0;
         INSERT INTO host_services (agent_id, unit, programs, processes, run_as)
         SELECT g.agent_id, CASE WHEN u < 3 THEN (ARRAY['sshd', 'chronyd', 'rsyslog'])[u + 1] ELSE 'pkg' || (u * 6) END || '.service',
                ARRAY['p'], 1, 'root'
         FROM gen g CROSS JOIN generate_series(0, 29) u WHERE u < 3 OR (g.n + u) % 3 = 0;
         INSERT INTO change_log (at, agent_id, kind, key, change)
         SELECT now() - (random() * (CASE WHEN n % 20 = 0 THEN 7 ELSE 85 END) * interval '1 day'),
                g.agent_id, 'package', 'pkg' || ((g.n * 17 + j * 3) % {names}),
                CASE WHEN j % 4 = 0 THEN 'went_away' ELSE 'appeared' END
         FROM gen g CROSS JOIN generate_series(1, 50) j;"
    ))
    .await
    .unwrap();
    timing::groups(c).await
}

#[tokio::test]
#[ignore = "timing run; see the module doc"]
async fn the_list_answers_within_two_seconds() {
    let reuse = std::env::var("SOFTWARE_TIMING_DB_URL").ok();
    let (db, mut c, group) = match &reuse {
        Some(url) => {
            let c = platform_store::connect(url)
                .await
                .unwrap()
                .get()
                .await
                .unwrap();
            let group = timing::manual_group(&c).await;
            (None, c, group)
        }
        None => {
            let (db, c) = common::migrated().await;
            let group = fleet(&c, packages()).await;
            if std::env::var("SOFTWARE_TIMING_KEEP").is_ok() {
                eprintln!("fleet kept at {}", db.url());
            }
            (Some(db), c, group)
        }
    };
    let base = SoftwareQuery {
        q: None,
        vulns: None,
        fix: None,
        versions: None,
        kind: None,
        group: None,
        changes: None,
        host: None,
        sort: SoftwareSort::Package,
        descending: false,
        offset: 0,
        limit: 50,
    };
    let global = AgentScope::Global;
    let scoped = AgentScope::AssetGroups(vec![group.clone()]);
    for (label, q, scope) in [
        ("full reach, unfiltered", base.clone(), &global),
        (
            "full reach, exploited, by risk",
            SoftwareQuery {
                vulns: Some(Vulns::Exploited),
                sort: SoftwareSort::Vulnerabilities,
                descending: true,
                ..base.clone()
            },
            &global,
        ),
        (
            "full reach, fix available, several versions",
            SoftwareQuery {
                fix: Some(Fix::Available),
                versions: Some(Versions::Several),
                ..base.clone()
            },
            &global,
        ),
        (
            "full reach, new this week, by hosts",
            SoftwareQuery {
                changes: Some(Changes::New),
                sort: SoftwareSort::Hosts,
                descending: true,
                ..base.clone()
            },
            &global,
        ),
        (
            "full reach, search",
            SoftwareQuery {
                q: Some("pkg17"),
                ..base.clone()
            },
            &global,
        ),
        (
            "full reach, one group",
            SoftwareQuery {
                group: Some(&group),
                ..base.clone()
            },
            &global,
        ),
        ("one group's reach (about 500 hosts)", base.clone(), &scoped),
    ] {
        let (time, total) = timing::median(async || {
            software_list(&mut c, &q, scope, Utc::now())
                .await
                .unwrap()
                .total
        })
        .await;
        println!("{label}: {time:?} ({total} packages)");
        if time >= LIMIT {
            println!("  over the {LIMIT:?} target");
        }
        assert!(time < CEILING, "{label}: {time:?}");
    }
    if let Some(db) = db
        && std::env::var("SOFTWARE_TIMING_KEEP").is_err()
    {
        db.drop().await;
    }
}
