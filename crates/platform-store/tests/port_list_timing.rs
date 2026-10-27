//! The Ports list on the step 5e ruling 26 fleet: 10,000 hosts with 20
//! listeners each (200,000 rows, about 300 distinct ports, 10 % exposed),
//! 500,000 change-log rows, 15 groups. Ignored by default; run it with
//! `cargo test --release -p platform-store --test port_list_timing -- --ignored --nocapture`.
//! Timings are recorded in docs/components/platform-store.md.

mod common;

use std::time::{Duration, Instant};

use chrono::Utc;
use platform_store::{
    Client,
    console_read::AgentScope,
    port_list::{Changes, PortQuery, PortSort, port_list},
};

async fn fleet(c: &Client) -> String {
    c.batch_execute(
        "SET statement_timeout = 0;
         INSERT INTO agents (agent_id, status, enrolled_at, last_seen_at, hostname, os_id, os_version,
                             services_at, services_owners)
         SELECT 'agent.' || gen_random_uuid()::text, 'active', now() - interval '90 days', now(),
                'host-' || n, 'debian', '12', now(), 'complete'
         FROM generate_series(1, 10000) n;
         CREATE TEMP TABLE gen AS SELECT agent_id, substr(hostname, 6)::int AS n FROM agents;
         -- Host n listens on 20 ports out of about 300; tcp 22, 80, 443 and 5432 are common.
         INSERT INTO host_listeners (agent_id, protocol, address, port, exposed, service, program)
         SELECT g.agent_id, 'tcp', CASE WHEN x.exposed THEN '0.0.0.0'::inet ELSE '127.0.0.1'::inet END,
                x.port, x.exposed, 'unit' || (x.port % 40) || '.service', NULL
         FROM gen g CROSS JOIN LATERAL (
           SELECT DISTINCT ON (port) port, abs(hashtext(g.n || ':' || j)) % 10 = 0 AS exposed
           FROM (SELECT j, CASE WHEN j < 4 THEN (ARRAY[22, 80, 443, 5432])[j + 1]
                                ELSE 1000 + (g.n * 7 + j * 13) % 300 END AS port
                 FROM generate_series(0, 19) j) q ORDER BY port, j) x;
         INSERT INTO change_log (at, agent_id, kind, key, change)
         SELECT now() - (random() * (CASE WHEN n % 20 = 0 THEN 7 ELSE 85 END) * interval '1 day'),
                g.agent_id, 'listener', 'tcp/' || (1000 + (g.n * 7 + j * 13) % 300),
                CASE WHEN j % 4 = 0 THEN 'went_away' ELSE 'appeared' END
         FROM gen g CROSS JOIN generate_series(1, 50) j;
         INSERT INTO console_asset_groups (asset_group_id, name, created_at, created_by, kind)
         SELECT gen_random_uuid(), (CASE WHEN i < 10 THEN 'manual ' ELSE 'rule ' END) || i, now(), 't',
                CASE WHEN i < 10 THEN 'manual' ELSE 'rule' END
         FROM generate_series(0, 14) i;
         INSERT INTO console_host_group_members (asset_group_id, agent_id, added_at, added_by)
         SELECT g.asset_group_id, a.agent_id, now(), 't' FROM console_asset_groups g JOIN agents a
           ON g.kind = 'manual' AND abs(hashtext(a.agent_id || g.name)) % 20 = 0;
         INSERT INTO console_host_group_membership (asset_group_id, agent_id)
         SELECT g.asset_group_id, a.agent_id FROM console_asset_groups g JOIN agents a
           ON abs(hashtext(a.agent_id || g.name)) % 4 = 0
         ON CONFLICT DO NOTHING;",
    )
    .await
    .unwrap();
    c.batch_execute("VACUUM ANALYZE").await.unwrap();
    c.query_one(
        "SELECT asset_group_id::text FROM console_asset_groups WHERE name = 'manual 0'",
        &[],
    )
    .await
    .unwrap()
    .get(0)
}

async fn median(c: &Client, q: &PortQuery<'_>, scope: &AgentScope) -> (Duration, i64) {
    const RUNS: usize = 5;
    let mut samples = Vec::with_capacity(RUNS);
    let mut total = 0;
    for _ in 0..RUNS {
        let started = Instant::now();
        let page = port_list(c, q, scope, Utc::now()).await.unwrap();
        samples.push(started.elapsed());
        total = page.total;
    }
    samples.sort();
    (samples[RUNS / 2], total)
}

#[tokio::test]
#[ignore = "timing run; see the module doc"]
async fn the_list_answers_within_two_seconds() {
    let (db, c) = common::migrated().await;
    let group = fleet(&c).await;
    let base = PortQuery {
        q: None,
        exposure: None,
        protocol: None,
        group: None,
        service: None,
        changes: None,
        host: None,
        sort: PortSort::Port,
        descending: false,
        offset: 0,
        limit: 50,
    };
    let global = AgentScope::Global;
    let scoped = AgentScope::AssetGroups(vec![group.clone()]);
    for (label, q, scope) in [
        ("full reach, unfiltered", &base, &global),
        (
            "full reach, needs a look, by hosts",
            &PortQuery {
                changes: Some(Changes::Look),
                sort: PortSort::Hosts,
                descending: true,
                ..base.clone()
            },
            &global,
        ),
        (
            "full reach, search",
            &PortQuery {
                q: Some("unit7"),
                ..base.clone()
            },
            &global,
        ),
        (
            "full reach, one group",
            &PortQuery {
                group: Some(&group),
                ..base.clone()
            },
            &global,
        ),
        ("one group's reach (about 500 hosts)", &base, &scoped),
    ] {
        let (time, total) = median(&c, q, scope).await;
        println!("{label}: {time:?} ({total} ports)");
        assert!(time < Duration::from_secs(2), "{label}: {time:?}");
    }
    db.drop().await;
}
