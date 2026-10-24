//! The Cases list on the step 5d ruling 16 fleet: 10,000 hosts, 20,000
//! cases, 200,000 items (10 per case), 60,000 timeline entries. Ignored by
//! default; run it explicitly with `--test-threads=1`. Timings are
//! recorded in the task report and `docs/components/platform-store.md`.

mod common;

use std::time::{Duration, Instant};

use chrono::Utc;
use platform_store::{
    Client,
    case_list::{CaseQuery, CaseSort, CaseStatus, case_list},
    console_read::AgentScope,
};

const ANN: &str = "00000000-0000-4000-8000-0000000000a1";
const BOB: &str = "00000000-0000-4000-8000-0000000000b2";

/// Case `n` is opened by Bob (Ann for every 50th), assigned to Ann, Bob or
/// nobody, one in five closed, updated within the last 60 days. Its ten
/// items sit on hosts `(n * 7 + k * 13) mod 10000`: 3 alarms, 3
/// vulnerabilities, 2 findings, two host items (a host and a software item
/// on every 10th case), half of the
/// outcome-taking ones with an outcome (a quarter of those `resolved`, so
/// ready to close checks their evidence). Every case has a note, a status
/// change and a second note. Ten manual groups of about 500 hosts.
async fn fleet(c: &Client) {
    c.batch_execute(&format!(
        "INSERT INTO console_users (user_id, username, display_name, created_at) VALUES
           ('{ANN}', 'ann', 'Ann', now()), ('{BOB}', 'bob', 'Bob', now());
         INSERT INTO agents (agent_id, status, enrolled_at, last_seen_at, hostname)
         SELECT 'agent.' || lpad(n::text, 36, '0'), 'active', now(), now(), 'host-' || n
         FROM generate_series(0, 9999) n;
         INSERT INTO console_asset_groups (asset_group_id, name, created_at, created_by, kind)
         SELECT gen_random_uuid(), 'manual ' || i, now(), 't', 'manual' FROM generate_series(0, 9) i;
         INSERT INTO console_host_group_members (asset_group_id, agent_id, added_at, added_by)
         SELECT g.asset_group_id, a.agent_id, now(), 't' FROM console_asset_groups g JOIN agents a
           ON abs(hashtext(a.agent_id || g.name)) % 20 = 0;
         INSERT INTO cases (case_id, title, status, resolution_note, closed_at, severity,
                            assignee_user_id, opened_by_user_id, created_at, updated_at)
         SELECT md5('case' || n)::uuid, 'Case ' || n, s.status,
                CASE WHEN s.status = 'closed' THEN 'done' END, CASE WHEN s.status = 'closed' THEN now() END,
                (ARRAY['critical','high','medium','low'])[n % 4 + 1],
                (ARRAY['{ANN}', '{BOB}', NULL])[n % 3 + 1]::uuid,
                CASE WHEN n % 50 = 0 THEN '{ANN}' ELSE '{BOB}' END::uuid,
                now() - make_interval(days => 90, mins => n), now() - make_interval(mins => n * 4)
         FROM generate_series(0, 19999) n
         CROSS JOIN LATERAL (SELECT (ARRAY['open','investigating','open','investigating','closed'])[n % 5 + 1] AS status) s;
         INSERT INTO case_items (item_id, case_id, kind, ref, agent_id, active, outcome, outcome_note,
                                 added_by_user_id, added_at)
         SELECT gen_random_uuid(), md5('case' || n)::uuid, kd.kind, (n * 10 + k)::text,
                CASE WHEN kd.kind <> 'software' THEN 'agent.' || lpad(((n * 7 + k * 13) % 10000)::text, 36, '0') END,
                n % 5 <> 4, o.outcome, CASE WHEN o.outcome <> 'resolved' THEN 'why' END, '{BOB}', now()
         FROM generate_series(0, 19999) n CROSS JOIN generate_series(0, 9) k
         CROSS JOIN LATERAL (SELECT (ARRAY['alarm','alarm','alarm','vulnerability','vulnerability','vulnerability',
                                           'compliance_finding','compliance_finding','host',
                                           CASE WHEN n % 10 = 0 THEN 'software' ELSE 'host' END])[k + 1] AS kind) kd
         CROSS JOIN LATERAL (SELECT CASE WHEN k < 8 AND (n + k) % 2 = 0
                                   THEN CASE WHEN k % 4 = 0 THEN 'resolved' ELSE 'expected' END END AS outcome) o;
         INSERT INTO case_events (case_id, at, actor_user_id, kind, body)
         SELECT md5('case' || n)::uuid, now() - make_interval(mins => n * 4 + e), '{BOB}',
                CASE WHEN e = 1 THEN 'status' ELSE 'note' END,
                CASE WHEN e <> 1 THEN repeat('note ' || n || ' ', 20) END
         FROM generate_series(0, 19999) n CROSS JOIN generate_series(0, 2) e;"
    ))
    .await
    .unwrap();
    c.batch_execute("VACUUM ANALYZE").await.unwrap();
}

fn query() -> CaseQuery<'static> {
    CaseQuery {
        q: None,
        status: CaseStatus::Active,
        severity: None,
        assignee: None,
        contains: None,
        host: None,
        group: None,
        updated: None,
        sort: CaseSort::Updated,
        descending: true,
        offset: 0,
        limit: 50,
    }
}

async fn median(c: &Client, scope: &AgentScope) -> (Duration, i64) {
    const RUNS: usize = 5;
    let mut samples = Vec::with_capacity(RUNS);
    let mut total = 0;
    for _ in 0..RUNS {
        let started = Instant::now();
        let page = case_list(c, &query(), scope, ANN, Utc::now())
            .await
            .unwrap();
        samples.push(started.elapsed());
        total = page.total;
        assert_eq!(page.rows.len(), 50);
    }
    samples.sort();
    eprintln!("  all {samples:?}");
    (samples[RUNS / 2], total)
}

/// Records the default list (active, newest change first, 50 rows, every
/// count and the summary) at full reach and scoped to two manual groups.
#[tokio::test]
#[ignore = "large-fleet timing; run explicitly"]
async fn records_case_list_latency_on_the_ruling_16_fleet() {
    let (db, c) = common::migrated().await;
    c.batch_execute("SET statement_timeout = 0").await.unwrap();
    fleet(&c).await;
    let items: i64 = c
        .query_one("SELECT count(*) FROM case_items", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(items, 200_000);

    let (full, total) = median(&c, &AgentScope::Global).await;
    eprintln!("case list, full reach: median {full:?}, {total} cases");
    let two = AgentScope::AssetGroups(
        c.query(
            "SELECT asset_group_id::text FROM console_asset_groups WHERE name IN ('manual 0', 'manual 1')",
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|r| r.get(0))
        .collect(),
    );
    let (scoped, scoped_total) = median(&c, &two).await;
    eprintln!("case list, two manual groups: median {scoped:?}, {scoped_total} cases");
    assert_eq!(total, 16_000, "one in five closed");
    assert!(scoped_total < total);
    assert!(full < Duration::from_secs(2), "full reach {full:?}");
    assert!(scoped < Duration::from_secs(2), "scoped {scoped:?}");
    db.drop().await;
}
