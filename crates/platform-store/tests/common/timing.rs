//! What the ignored list-timing runs share: 10,000 hosts with a temp table
//! `gen (agent_id, n)` to build rows from, 15 groups, a median of five runs.
#![allow(dead_code, reason = "each test binary uses some of these")]

use std::{
    future::Future,
    time::{Duration, Instant},
};

use platform_store::Client;

/// 10,000 active hosts reporting services, and the temp table `gen`.
pub async fn hosts(c: &Client) {
    c.batch_execute(
        "SET statement_timeout = 0;
         INSERT INTO agents (agent_id, status, enrolled_at, last_seen_at, hostname, os_id, os_version,
                             services_at, services_owners)
         SELECT 'agent.' || gen_random_uuid()::text, 'active', now() - interval '90 days', now(),
                'host-' || n, 'debian', '12', now(), 'complete'
         FROM generate_series(1, 10000) n;
         CREATE TEMP TABLE gen AS SELECT agent_id, substr(hostname, 6)::int AS n FROM agents;",
    )
    .await
    .unwrap();
}

/// 15 groups (10 manual, 5 rule) holding about a quarter of the hosts each,
/// then `VACUUM ANALYZE`; the id of the group "manual 0".
pub async fn groups(c: &Client) -> String {
    c.batch_execute(
        "INSERT INTO console_asset_groups (asset_group_id, name, created_at, created_by, kind)
         SELECT gen_random_uuid(), (CASE WHEN i < 10 THEN 'manual ' ELSE 'rule ' END) || i, now(), 't',
                CASE WHEN i < 10 THEN 'manual' ELSE 'rule' END
         FROM generate_series(0, 14) i;
         INSERT INTO console_host_group_members (asset_group_id, agent_id, added_at, added_by)
         SELECT g.asset_group_id, a.agent_id, now(), 't' FROM console_asset_groups g JOIN agents a
           ON g.kind = 'manual' AND abs(hashtext(a.agent_id || g.name)) % 20 = 0;
         INSERT INTO console_host_group_membership (asset_group_id, agent_id)
         SELECT g.asset_group_id, a.agent_id FROM console_asset_groups g JOIN agents a
           ON abs(hashtext(a.agent_id || g.name)) % 4 = 0
         ON CONFLICT DO NOTHING;
         VACUUM ANALYZE;",
    )
    .await
    .unwrap();
    manual_group(c).await
}

/// The id of the group "manual 0" of a fleet an earlier run built.
pub async fn manual_group(c: &Client) -> String {
    c.query_one(
        "SELECT asset_group_id::text FROM console_asset_groups WHERE name = 'manual 0'",
        &[],
    )
    .await
    .unwrap()
    .get(0)
}

/// The median of five runs of `run` and the total its last run answered.
pub async fn median<F: Future<Output = i64>>(mut run: impl FnMut() -> F) -> (Duration, i64) {
    const RUNS: usize = 5;
    let mut samples = Vec::with_capacity(RUNS);
    let mut total = 0;
    for _ in 0..RUNS {
        let started = Instant::now();
        total = run().await;
        samples.push(started.elapsed());
    }
    samples.sort();
    (samples[RUNS / 2], total)
}
