//! The Compliance list on the step 5c ruling 18 fleet: 10,000 hosts with
//! heartbeat health, two rule sets of 42 and 43 rules, 500,000 current
//! findings (50 per host). Ignored by default; run it explicitly. Timings
//! are recorded in console-read.md.

mod common;

use std::time::{Duration, Instant};

use chrono::Utc;
use platform_store::{
    Client,
    check_list::{CheckQuery, CheckSort, CheckState, check_list},
    console_read::AgentScope,
};

const ANN: &str = "00000000-0000-4000-8000-0000000000a1";

/// Rule `i` (0–84) is `port.r<i>` in baseline for `i < 42`, else
/// `harden.x.r<i>` in hardening-linux-l1, every one indexed. Host `n`
/// fails the 50 rules `i` with `(i - n) mod 85 < 50`; 1 % of its findings
/// are triaged. Every host reports both sets with every collector ok,
/// except 1 % with stale health and 1 % with baseline not assigned. Ten
/// manual groups of about 500 hosts.
async fn fleet(c: &Client) {
    c.batch_execute(&format!(
        "INSERT INTO console_users (user_id, username, display_name, created_at) VALUES
           ('{ANN}', 'ann', 'Ann', now()), ('00000000-0000-4000-8000-0000000000b2', 'bob', 'Bob', now());
         INSERT INTO rule_sets (rule_set_id) VALUES ('baseline'), ('hardening-linux-l1');
         INSERT INTO rule_trust_keys (rule_set_id, issuer_key_id, public_key)
           SELECT s, 'k', decode(repeat('07', 32), 'hex') FROM unnest(ARRAY['baseline', 'hardening-linux-l1']) s;
         INSERT INTO rule_bundles (rule_set_id, version, envelope, envelope_sha256, issuer_key_id,
                                   created_at_ms, expires_at_ms, published_by)
           SELECT s, 1, '{{}}', sha256(s::bytea), 'k', 1, 9e15, 't'
           FROM unnest(ARRAY['baseline', 'hardening-linux-l1']) s;
         CREATE TEMP TABLE rules AS
           SELECT i, CASE WHEN i < 42 THEN 'baseline' ELSE 'hardening-linux-l1' END AS s,
                  CASE WHEN i < 42 THEN 'port.r' ELSE 'harden.x.r' END || i AS r
           FROM generate_series(0, 84) i;
         INSERT INTO console_rule_meta (rule_set_id, rule_set_version, rule_id, rule_version, title, message, attack, techniques)
           SELECT s, 1, r, 1, 'Rule ' || i, 'm', '[]', '{{}}' FROM rules;
         INSERT INTO agents (agent_id, status, enrolled_at, last_seen_at, hostname, os_id, os_version, health, health_at)
         SELECT 'agent.' || gen_random_uuid()::text, 'active', now() - interval '90 days', now(), 'host-' || n, 'debian', '12',
                jsonb_build_object(
                  'rule_sets', jsonb_build_array(
                    CASE WHEN n % 100 = 1 THEN '{{\"id\":\"baseline\",\"version\":null,\"state\":\"not_assigned\"}}'::jsonb
                         ELSE '{{\"id\":\"baseline\",\"version\":1}}'::jsonb END,
                    '{{\"id\":\"hardening-linux-l1\",\"version\":1}}'::jsonb),
                  'last_scan', '{{\"collectors\":{{\"ports\":\"ok\",\"packages\":\"ok\",\"hardening\":\"ok\",\"processes\":\"ok\"}}}}'::jsonb),
                CASE WHEN n % 100 = 2 THEN now() - interval '2 days' ELSE now() END
         FROM generate_series(1, 10000) n;
         CREATE TEMP TABLE gen AS SELECT agent_id, substr(hostname, 6)::int AS n FROM agents;
         INSERT INTO current_findings (agent_id, rule_set_id, rule_id, last_finding_id, rule_version, severity,
                                       first_observed_at, last_observed_at, last_observed_day, scan_id, confidence,
                                       message, evidence, received_at, origin, authenticated, source)
         SELECT g.agent_id, r.s, r.r, 'f', 1, (ARRAY['critical','high','medium','low','info'])[r.i % 5 + 1],
                now() - (r.i || ' days')::interval, now(), current_date, 's', 90, 'm', '{{}}', now(), 'online', true, 'changes'
         FROM gen g JOIN rules r ON (r.i - g.n % 85 + 85) % 85 < 50;
         INSERT INTO console_finding_triage (agent_id, rule_set_id, rule_id, state, rule_version, assigned_to,
                                             note, accepted_until, version, updated_at, updated_by)
         SELECT f.agent_id, f.rule_set_id, f.rule_id, s.state, 1,
                (ARRAY['{ANN}', '00000000-0000-4000-8000-0000000000b2', NULL])[abs(hashtext(f.agent_id || f.rule_id)) % 3 + 1]::uuid,
                CASE WHEN s.state <> 'open' THEN 'n' END,
                CASE WHEN s.state = 'accepted_risk' THEN now() + interval '30 days' END, 1, now(), 't'
         FROM current_findings f
         CROSS JOIN LATERAL (SELECT (ARRAY['open','mitigated','accepted_risk','false_positive'])
                               [abs(hashtext(f.rule_id || f.agent_id)) % 4 + 1] AS state) s
         WHERE abs(hashtext(f.agent_id || f.rule_id)) % 100 = 0;
         INSERT INTO console_asset_groups (asset_group_id, name, created_at, created_by, kind)
         SELECT gen_random_uuid(), 'manual ' || i, now(), 't', 'manual' FROM generate_series(0, 9) i;
         INSERT INTO console_host_group_members (asset_group_id, agent_id, added_at, added_by)
         SELECT g.asset_group_id, a.agent_id, now(), 't' FROM console_asset_groups g JOIN agents a
           ON abs(hashtext(a.agent_id || g.name)) % 20 = 0;"
    ))
    .await
    .unwrap();
    c.batch_execute("VACUUM ANALYZE").await.unwrap();
}

fn query() -> CheckQuery<'static> {
    CheckQuery {
        q: None,
        state: CheckState::Open,
        severity: None,
        rule_set: None,
        area: None,
        group: None,
        host: None,
        assignee: None,
        sort: CheckSort::Severity,
        descending: true,
        offset: 0,
        limit: 50,
    }
}

async fn median(c: &Client, scope: &AgentScope) -> (Duration, i64, i64, i64) {
    const RUNS: usize = 5;
    let mut samples = Vec::with_capacity(RUNS);
    let mut seen = (0, 0, 0);
    for _ in 0..RUNS {
        let started = Instant::now();
        let page = check_list(c, &query(), scope, ANN, Utc::now())
            .await
            .unwrap();
        samples.push(started.elapsed());
        let passing = page.rows.iter().map(|r| r.passing).sum();
        seen = (page.total, page.summary.hosts, passing);
        assert_eq!(page.rows.len(), 50);
    }
    samples.sort();
    eprintln!("  all {samples:?}");
    (samples[RUNS / 2], seen.0, seen.1, seen.2)
}

/// Records the default list (open, by severity, 50 rows, every count and
/// the summary) at full reach and scoped to two manual groups.
#[tokio::test]
#[ignore = "large-fleet timing; run explicitly"]
async fn records_check_list_latency_on_the_ruling_18_fleet() {
    let (db, c) = common::migrated().await;
    c.batch_execute("SET statement_timeout = 0").await.unwrap();
    fleet(&c).await;
    let findings: i64 = c
        .query_one("SELECT count(*) FROM current_findings", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(findings, 500_000);

    let (full, total, hosts, passing) = median(&c, &AgentScope::Global).await;
    eprintln!(
        "check list, full reach: median {full:?}, {total} rows, {hosts} hosts, {passing} passing on the page"
    );
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
    let (scoped, scoped_total, scoped_hosts, _) =
        median(&c, &AgentScope::AssetGroups(groups)).await;
    eprintln!(
        "check list, two manual groups: median {scoped:?}, {scoped_total} rows, {scoped_hosts} hosts"
    );
    assert_eq!((total, hosts), (85, 10_000));
    assert!(passing > 0);
    assert!(scoped_hosts < hosts);
    assert!(full < Duration::from_secs(2), "full reach {full:?}");
    assert!(scoped < Duration::from_secs(2), "scoped {scoped:?}");
    db.drop().await;
}
