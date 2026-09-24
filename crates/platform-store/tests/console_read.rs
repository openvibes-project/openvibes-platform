//! C2 database read models and recorded 50,000-agent acceptance evidence.

mod common;

use chrono::{Duration, Utc};
use common::TestDb;
use platform_store::{
    console_read::{AgentQuery, FindingEvent, HistoryQuery, LatestQuery, PageLimit, Severity},
    ingest::{self, StoredFinding},
};
use std::time::{Duration as StdDuration, Instant};

const RECENT: &str = "agent.00000000-0000-4000-8000-000000000001";
const STALE: &str = "agent.00000000-0000-4000-8000-000000000002";

#[tokio::test]
async fn console_read_models_are_complete_bounded_and_keyset_stable() {
    let db = TestDb::create().await;
    let mut client = db.pool.get().await.unwrap();
    platform_store::migrate(&mut client).await.unwrap();
    let now = Utc::now();
    platform_store::ensure_partitions(&client, now.date_naive() - Duration::days(1), 2)
        .await
        .unwrap();
    for (agent_id, last_seen_at, hostname) in [
        (RECENT, Some(now - Duration::minutes(1)), Some("host-a")),
        (STALE, Some(now - Duration::minutes(20)), None),
    ] {
        client
            .execute(
                "INSERT INTO agents (agent_id, status, enrolled_at, last_seen_at, hostname)
                 VALUES ($1, 'active', $2, $3, $4)",
                &[
                    &agent_id,
                    &(now - Duration::days(2)),
                    &last_seen_at,
                    &hostname,
                ],
            )
            .await
            .unwrap();
    }
    client
        .execute(
            "INSERT INTO certificates (serial, agent_id, spki_sha256, not_before, not_after,
                 issued_at, chain_pem) VALUES ($1, $2, $3, $4, $5, $6, 'never returned')",
            &[
                &&[1u8; 16][..],
                &RECENT,
                &&[2u8; 32][..],
                &(now - Duration::days(1)),
                &(now + Duration::days(30)),
                &now,
            ],
        )
        .await
        .unwrap();

    let findings = [
        StoredFinding {
            finding_id: "finding-old".into(),
            scan_id: "scan-old".into(),
            rule_set_id: "base".into(),
            rule_id: "rule-1".into(),
            rule_version: 1,
            observed_at: now - Duration::minutes(2),
            severity: "medium".into(),
            confidence: 80,
            message: "old snapshot".into(),
            evidence: vec!["pkg=old".into()],
        },
        StoredFinding {
            finding_id: "finding-new".into(),
            scan_id: "scan-new".into(),
            rule_set_id: "base".into(),
            rule_id: "rule-1".into(),
            rule_version: 2,
            observed_at: now - Duration::minutes(1),
            severity: "critical".into(),
            confidence: 99,
            message: "new snapshot".into(),
            evidence: vec!["pkg=new".into()],
        },
    ];
    ingest::store_findings(&mut client, RECENT, &findings, now)
        .await
        .unwrap();

    let agent_query = AgentQuery {
        state: None,
        after: None,
        limit: PageLimit::new(1).unwrap(),
    };
    let page1 = platform_store::console_read::agents(&client, &agent_query, now)
        .await
        .unwrap();
    assert_eq!(page1.items[0].agent_id, RECENT);
    let cursor = page1.next.unwrap();
    let page2 = platform_store::console_read::agents(
        &client,
        &AgentQuery {
            state: None,
            after: Some(cursor),
            limit: PageLimit::new(1).unwrap(),
        },
        now,
    )
    .await
    .unwrap();
    assert_eq!(page2.items[0].agent_id, STALE);

    let agent_summary = platform_store::console_read::agent_summary(&client, now)
        .await
        .unwrap();
    assert_eq!(
        (
            agent_summary.total,
            agent_summary.active,
            agent_summary.stale
        ),
        (2, 1, 1)
    );
    let agent = platform_store::console_read::agent(&client, RECENT, now)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(agent.hostname.as_deref(), Some("host-a"));
    let certificates = platform_store::console_read::certificates(
        &client,
        RECENT,
        None,
        PageLimit::new(10).unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(certificates.items.len(), 1);
    assert_eq!(certificates.items[0].serial, vec![1; 16]);

    let latest = platform_store::console_read::latest_findings(
        &client,
        &LatestQuery {
            severity: Some(Severity::Critical),
            after: None,
            limit: PageLimit::new(1).unwrap(),
        },
    )
    .await
    .unwrap();
    assert_eq!(latest.items.len(), 1);
    assert_eq!(latest.items[0].finding_id, "finding-new");
    assert_eq!(latest.items[0].hostname.as_deref(), Some("host-a"));
    assert_eq!(latest.items[0].message, "new snapshot");
    assert_eq!(latest.items[0].evidence, ["pkg=new"]);
    let summary = platform_store::console_read::finding_summary(&client)
        .await
        .unwrap();
    assert_eq!(
        (summary.total, summary.impacted_agents, summary.critical),
        (1, 1, 1)
    );
    assert_eq!(
        platform_store::console_read::latest_finding(&client, RECENT, "base", "rule-1")
            .await
            .unwrap()
            .unwrap()
            .finding_id,
        "finding-new"
    );

    let history_page1 = platform_store::console_read::finding_history(
        &client,
        &HistoryQuery {
            since: now - Duration::days(1),
            agent_id: Some(RECENT.into()),
            rule_set_id: Some("base".into()),
            rule_id: Some("rule-1".into()),
            after: None,
            limit: PageLimit::new(1).unwrap(),
        },
    )
    .await
    .unwrap();
    assert_eq!(history_page1.items[0].finding_id, "finding-new");
    let history_cursor = history_page1.next.unwrap();
    let history_page2 = platform_store::console_read::finding_history(
        &client,
        &HistoryQuery {
            since: now - Duration::days(1),
            agent_id: Some(RECENT.into()),
            rule_set_id: Some("base".into()),
            rule_id: Some("rule-1".into()),
            after: Some(history_cursor),
            limit: PageLimit::new(1).unwrap(),
        },
    )
    .await
    .unwrap();
    assert_eq!(history_page2.items[0].finding_id, "finding-old");
    let exact: Option<FindingEvent> =
        platform_store::console_read::finding_event(&client, now.date_naive(), "finding-new")
            .await
            .unwrap();
    assert_eq!(exact.unwrap().scan_id, "scan-new");
    assert!(PageLimit::new(0).is_none());
    assert!(PageLimit::new(101).is_none());

    drop(client);
    db.drop().await;
}

#[tokio::test]
async fn agent_lists_and_lookups_apply_asset_group_conjunctions_in_sql() {
    let db = TestDb::create().await;
    let mut client = db.pool.get().await.unwrap();
    platform_store::migrate(&mut client).await.unwrap();
    let now = Utc::now();
    let ids = [
        "agent.00000000-0000-4000-8000-000000000011",
        "agent.00000000-0000-4000-8000-000000000012",
        "agent.00000000-0000-4000-8000-000000000013",
        "agent.00000000-0000-4000-8000-000000000014",
    ];
    for id in ids {
        client
            .execute(
                "INSERT INTO agents (agent_id, status, enrolled_at, last_seen_at)
                 VALUES ($1, 'active', $2, $2)",
                &[&id, &now],
            )
            .await
            .unwrap();
    }
    client
        .execute(
            "INSERT INTO console_asset_groups (asset_group_id, name, created_at, created_by)
             VALUES ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'production', $1, 'test')",
            &[&now],
        )
        .await
        .unwrap();
    client
        .execute(
            "INSERT INTO console_asset_group_selectors
                 (asset_group_id, tag_key, tag_value, created_at)
             VALUES ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'env', 'prod', $1),
                    ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'team', 'blue', $1)",
            &[&now],
        )
        .await
        .unwrap();
    for (id, key, value) in [
        (ids[0], "env", "prod"),
        (ids[0], "team", "blue"),
        (ids[1], "env", "prod"),
        (ids[1], "team", "blue"),
        (ids[2], "env", "dev"),
        (ids[2], "team", "blue"),
        (ids[3], "team", "blue"),
    ] {
        client
            .execute(
                "INSERT INTO console_agent_tags (agent_id, tag_key, tag_value, changed_at, changed_by)
                 VALUES ($1, $2, $3, $4, 'test')",
                &[&id, &key, &value, &now],
            )
            .await
            .unwrap();
    }
    for (serial, agent_id) in [(1_u8, ids[0]), (2_u8, ids[2])] {
        client
            .execute(
                "INSERT INTO certificates (serial, agent_id, spki_sha256, not_before,
                    not_after, issued_at, chain_pem)
                 VALUES ($1, $2, $3, $4, $5, $4, 'never returned')",
                &[
                    &&[serial; 16][..],
                    &agent_id,
                    &&[serial; 32][..],
                    &now,
                    &(now + Duration::days(90)),
                ],
            )
            .await
            .unwrap();
    }
    let scope = platform_store::console_read::AgentScope::AssetGroups(vec![
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".into(),
    ]);
    let query = AgentQuery {
        state: None,
        after: None,
        limit: PageLimit::new(1).unwrap(),
    };
    let first = platform_store::console_read::agents_in_scope(&client, &query, now, &scope)
        .await
        .unwrap();
    assert_eq!(
        first
            .items
            .iter()
            .map(|a| a.agent_id.as_str())
            .collect::<Vec<_>>(),
        [ids[0]]
    );
    let second = platform_store::console_read::agents_in_scope(
        &client,
        &AgentQuery {
            state: None,
            after: first.next,
            limit: PageLimit::new(10).unwrap(),
        },
        now,
        &scope,
    )
    .await
    .unwrap();
    assert_eq!(
        second
            .items
            .iter()
            .map(|a| a.agent_id.as_str())
            .collect::<Vec<_>>(),
        [ids[1]]
    );
    let summary = platform_store::console_read::agent_summary_in_scope(&client, now, &scope)
        .await
        .unwrap();
    assert_eq!(summary.total, 2);
    let visible_certs = platform_store::console_read::certificates_in_scope(
        &client,
        ids[0],
        None,
        PageLimit::new(10).unwrap(),
        &scope,
    )
    .await
    .unwrap();
    assert_eq!(visible_certs.items.len(), 1);
    let hidden_certs = platform_store::console_read::certificates_in_scope(
        &client,
        ids[2],
        None,
        PageLimit::new(10).unwrap(),
        &scope,
    )
    .await
    .unwrap();
    assert!(hidden_certs.items.is_empty());
    for hidden in [ids[2], ids[3]] {
        assert!(
            platform_store::console_read::agent_in_scope(&client, hidden, now, &scope)
                .await
                .unwrap()
                .is_none()
        );
    }
    assert!(
        platform_store::console_read::agent_in_scope(
            &client,
            ids[0],
            now,
            &platform_store::console_read::AgentScope::AssetGroups(Vec::new()),
        )
        .await
        .unwrap()
        .is_none()
    );
    drop(client);
    db.drop().await;
}

#[tokio::test]
async fn records_console_query_plan_and_latency_at_fifty_thousand_agents() {
    const HOSTS: i32 = 50_000;
    const RUNS: usize = 30;
    let db = TestDb::create().await;
    let mut client = db.pool.get().await.unwrap();
    platform_store::migrate(&mut client).await.unwrap();
    client
        .execute(
            "INSERT INTO agents (agent_id, status, enrolled_at, last_seen_at, hostname)
             SELECT 'agent.' || gen_random_uuid()::text,
                    CASE WHEN n % 29 = 0 THEN 'revoked' ELSE 'active' END,
                    now() - interval '180 days',
                    CASE WHEN n % 17 = 0 THEN NULL
                         ELSE now() - make_interval(mins => (n % 900)::int) END,
                    'host-' || n::text
             FROM generate_series(1, $1) AS n",
            &[&HOSTS],
        )
        .await
        .unwrap();
    client.batch_execute("ANALYZE agents").await.unwrap();

    let plan: Vec<String> = client
        .query(
            "EXPLAIN (ANALYZE, BUFFERS, FORMAT TEXT)
             SELECT agent_id, hostname, last_seen_at FROM agents
             ORDER BY last_seen_at DESC NULLS LAST, agent_id ASC LIMIT 51",
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|row| row.get(0))
        .collect();
    eprintln!("50k agent page plan:\n{}", plan.join("\n"));
    assert!(plan.join("\n").contains("agents_console_last_seen_idx"));

    let threshold = Utc::now() - Duration::minutes(platform_store::OFFLINE_AFTER_MINUTES);
    let summary_plan: Vec<String> = client
        .query(
            "EXPLAIN (ANALYZE, BUFFERS, FORMAT TEXT)
             SELECT count(*),
                    count(*) FILTER (WHERE status = 'active'
                        AND last_seen_at IS NOT NULL AND last_seen_at >= $1),
                    count(*) FILTER (WHERE status = 'active'
                        AND (last_seen_at IS NULL OR last_seen_at < $1)),
                    count(*) FILTER (WHERE status = 'revoked')
             FROM agents",
            &[&threshold],
        )
        .await
        .unwrap()
        .iter()
        .map(|row| row.get(0))
        .collect();
    eprintln!("50k agent summary plan:\n{}", summary_plan.join("\n"));

    let query = AgentQuery {
        state: None,
        after: None,
        limit: PageLimit::new(50).unwrap(),
    };
    let mut samples = Vec::with_capacity(RUNS);
    for _ in 0..RUNS {
        let started = Instant::now();
        let page = platform_store::console_read::agents(&client, &query, Utc::now())
            .await
            .unwrap();
        assert_eq!(page.items.len(), 50);
        samples.push(started.elapsed());
    }
    samples.sort_unstable();
    eprintln!(
        "50k agent page latency: p50={} us p95={} us",
        micros(samples[RUNS / 2]),
        micros(samples[(RUNS * 95 / 100).min(RUNS - 1)])
    );

    let mut summary_samples = Vec::with_capacity(RUNS);
    let mut summary = None;
    for _ in 0..RUNS {
        let started = Instant::now();
        summary = Some(
            platform_store::console_read::agent_summary(&client, Utc::now())
                .await
                .unwrap(),
        );
        summary_samples.push(started.elapsed());
    }
    summary_samples.sort_unstable();
    eprintln!(
        "50k agent summary latency: p50={} us p95={} us",
        micros(summary_samples[RUNS / 2]),
        micros(summary_samples[(RUNS * 95 / 100).min(RUNS - 1)])
    );
    let summary = summary.unwrap();
    assert_eq!(summary.total, i64::from(HOSTS));
    drop(client);
    db.drop().await;
}

fn micros(duration: StdDuration) -> u128 {
    duration.as_micros()
}
