//! The Hosts list at 20,000 agents and 20 groups: the timing recorded in
//! console-read.md. Ignored by default; run it explicitly.

mod common;

use common::hosts::{everywhere, in_group_counts, large_fleet, query, run};

/// Records the default Hosts list (no filters, host order, 50 rows) at
/// 20,000 agents and 20 groups (10 rule, 10 manual); see console-read.md.
#[tokio::test]
#[ignore = "large-fleet timing; run explicitly"]
async fn records_hosts_list_latency_at_twenty_thousand_agents() {
    const RUNS: usize = 7;
    let (db, c) = common::migrated().await;
    large_fleet(&c).await;
    c.batch_execute(
        "INSERT INTO console_host_labels (agent_id, label, added_at, added_by)
         SELECT agent_id, 'label-' || (abs(hashtext(agent_id)) % 80), now(), 't' FROM agents;
         INSERT INTO host_vulnerability_counts (agent_id, no_fix, critical, important, moderate, low, unrated, reboot, counted_at)
         SELECT agent_id, 0, abs(hashtext(agent_id)) % 3, 1, 1, 1, 0, 0, now() FROM agents;
         INSERT INTO host_listed_critical (agent_id, critical)
         SELECT agent_id, abs(hashtext(agent_id)) % 3 FROM agents WHERE abs(hashtext(agent_id)) % 3 > 0;
         INSERT INTO alarms (first_seen_day, agent_id, alarm_id, rule_set_id, rule_set_version, rule_id, rule_version,
                             severity, confidence, message, first_seen, last_seen, count, process, ancestors,
                             received_at, state, note)
         SELECT (now() AT TIME ZONE 'UTC')::date, agent_id, md5(agent_id), 'rs', 1, 'r', 1, 'high', 50, 'm',
                now(), now(), 1, '{}', '[]', now(), 'open', 'n'
         FROM agents WHERE abs(hashtext(agent_id)) % 4 = 0;
         INSERT INTO current_findings (agent_id, rule_id, last_finding_id, rule_version, severity, first_observed_at,
                                       last_observed_at, last_observed_day, scan_id, confidence, message, evidence,
                                       received_at, origin, authenticated)
         SELECT agent_id, 'rule-1', 'f-1', 1, 'high', now(), now(), (now() AT TIME ZONE 'UTC')::date, 's', 50, 'm',
                '{}', now(), 'online', false
         FROM agents WHERE abs(hashtext(agent_id)) % 5 = 0;",
    )
    .await
    .unwrap();
    c.batch_execute("ANALYZE").await.unwrap();

    let mut samples = Vec::with_capacity(RUNS);
    for _ in 0..RUNS {
        let started = std::time::Instant::now();
        let page = run(&c, &query(), &everywhere(), Some("0.4.2")).await;
        samples.push(started.elapsed());
        assert_eq!(page.total, 20_000);
        assert_eq!(page.rows.len(), 50);
    }
    let page = run(&c, &query(), &everywhere(), Some("0.4.2")).await;
    let counted: Vec<_> = page
        .counts
        .groups
        .iter()
        .map(|g| (g.1.clone(), g.3))
        .collect();
    assert_eq!(counted, in_group_counts(&c).await);
    samples.sort();
    let median = samples[RUNS / 2];
    eprintln!("hosts list at 20k agents, 20 groups: median {median:?}, all {samples:?}");
    assert!(
        median < std::time::Duration::from_secs(1),
        "median {median:?}"
    );
    db.drop().await;
}
