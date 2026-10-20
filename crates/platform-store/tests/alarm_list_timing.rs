//! The Alarms list at 200,000 alarms on 20,000 agents in 20 groups: the
//! timing recorded in console-read.md. Ignored by default; run it explicitly.

mod common;

use std::time::{Duration, Instant};

use chrono::Utc;
use common::{
    alarms::{ANN, BOB, query, rule_index, run},
    hosts::large_fleet,
};
use platform_store::{alarm_list::AlarmQuery, console_read::AgentScope};

async fn median(
    c: &platform_store::Client,
    q: &AlarmQuery<'_>,
    scope: &AgentScope,
) -> (Duration, i64) {
    const RUNS: usize = 7;
    let mut samples = Vec::with_capacity(RUNS);
    let mut total = 0;
    for _ in 0..RUNS {
        let started = Instant::now();
        let page = run(c, q, scope).await;
        samples.push(started.elapsed());
        total = page.total;
        assert_eq!(page.rows.len(), 50);
    }
    samples.sort();
    eprintln!("  all {samples:?}");
    (samples[RUNS / 2], total)
}

/// Records the default Alarms list (open, unsuppressed, newest first, 50
/// rows, every count and the summary) at full reach and scoped to two
/// manual groups; see console-read.md.
#[tokio::test]
#[ignore = "large-fleet timing; run explicitly"]
async fn records_alarm_list_latency_at_two_hundred_thousand_alarms() {
    let (db, mut c) = common::migrated().await;
    let week_ago = Utc::now().date_naive() - chrono::Duration::days(7);
    platform_store::ensure_partitions(&c, week_ago, 9)
        .await
        .unwrap();
    large_fleet(&c).await;
    rule_index(&mut c).await;
    let off = r#"{"collector": "ok", "events_dropped_total": 5, "alarms_dropped_total": 0, "pending": 0,
        "platform_unsupported": false, "rules_accepted": 4, "rules_refused": 0,
        "rules_without_prefilter": 0, "events_budget_cut_total": 0, "source": "none"}"#;
    c.batch_execute(&format!(
        "INSERT INTO console_users (user_id, username, display_name, created_at) VALUES
           ('{ANN}', 'ann', 'Ann', now()), ('{BOB}', 'bob', 'Bob', now());
         UPDATE agents SET health = jsonb_build_object('alarms', '{off}'::jsonb || jsonb_build_object(
                             'events_dropped_total', abs(hashtext(agent_id)) % 1000)), health_at = now()
         WHERE abs(hashtext(agent_id)) % 10 = 0;
         INSERT INTO alarm_suppressions (rule_set_id, rule_id, scope, exe, note, created_by, created_at,
                                         state, activated_at)
         VALUES ('rs', 'r', 'program', '/usr/bin/x', 'n', 'a', now(), 'active', now());
         INSERT INTO alarms (first_seen_day, agent_id, alarm_id, rule_set_id, rule_set_version, rule_id,
                             rule_version, severity, confidence, message, first_seen, last_seen, count,
                             process, ancestors, received_at, state, note, assigned_to, suppressed_by)
         SELECT ((x.seen) AT TIME ZONE 'UTC')::date, a.agent_id, md5(a.agent_id || i), 'rs', 1,
                (ARRAY['r', 'ps-encoded', 'cron', 'r', 'other'])[i % 5 + 1], 1,
                (ARRAY['critical', 'high', 'medium', 'low', 'info'])[(abs(hashtext(a.agent_id)) + i) % 5 + 1],
                50, 'process ' || i || ' started a shell', x.seen, x.seen + interval '1 hour', i % 7 + 1,
                jsonb_build_object('exe', '/usr/bin/p' || i), jsonb_build_array(jsonb_build_object('exe', '/bin/sh')),
                now(), CASE WHEN i % 3 = 0 THEN 'mitigated' ELSE 'open' END,
                CASE WHEN i % 3 = 0 THEN 'n' END,
                CASE i % 4 WHEN 0 THEN '{ANN}'::uuid WHEN 1 THEN '{BOB}'::uuid END,
                CASE WHEN i = 9 THEN (SELECT min(id) FROM alarm_suppressions) END
         FROM agents a CROSS JOIN generate_series(0, 9) i
         CROSS JOIN LATERAL (SELECT now() - make_interval(mins => (abs(hashtext(a.agent_id || i)) % 9000)::int) AS seen) x;
         INSERT INTO cases (case_id, title, status, severity, opened_by_user_id, created_at, updated_at)
         VALUES ('00000000-0000-0000-0000-0000000000c1', 'C', 'open', 'high', '{ANN}', now(), now());
         INSERT INTO case_items (item_id, case_id, kind, ref, agent_id, added_by_user_id, added_at)
         SELECT gen_random_uuid(), '00000000-0000-0000-0000-0000000000c1', 'alarm', id::text, agent_id, '{ANN}', now()
         FROM alarms WHERE id % 200 = 0;
         ANALYZE;"
    ))
    .await
    .unwrap();
    let all: i64 = c
        .query_one("SELECT count(*) FROM alarms", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(all, 200_000);

    let (full, total) = median(&c, &query(), &AgentScope::Global).await;
    eprintln!("alarm list, 200k alarms, full reach: median {full:?}, {total} matching");
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
    let scoped = AgentScope::AssetGroups(groups);
    let (in_scope, scoped_total) = median(&c, &query(), &scoped).await;
    eprintln!(
        "alarm list, scoped to two manual groups: median {in_scope:?}, {scoped_total} matching"
    );
    assert!(scoped_total < total);
    assert!(full < Duration::from_secs(1), "median {full:?}");
    db.drop().await;
}
