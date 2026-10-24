//! The Compliance menu count and the dashboard's Breakdown tile read
//! `finding_summary_in_scope`; the groups read `finding_groups_in_scope`.
//! Both use the Compliance list's one failing definition (step 5c final
//! fixes 3 and 5): an ended, a stale (2 days unseen) and a mitigated
//! finding are not counted, an open one and an expired acceptance are, and
//! an expired acceptance is open in the groups' triage counts.

mod common;

use chrono::{Duration, Utc};
use platform_store::console_read::{
    AgentScope, FindingGroupQuery, PageLimit, finding_groups_in_scope, finding_summary_in_scope,
};

const A: &str = "agent.00000000-0000-4000-8000-0000000000f1";

#[tokio::test]
async fn the_summary_counts_open_failing_pairs_only() {
    let (db, c) = common::migrated().await;
    c.batch_execute(&format!(
        "INSERT INTO agents (agent_id, status, enrolled_at, last_seen_at, hostname)
         VALUES ('{A}', 'active', now(), now(), 'f1');
         INSERT INTO current_findings (agent_id, rule_set_id, rule_id, last_finding_id, rule_version, severity,
                                       first_observed_at, last_observed_at, last_observed_day, scan_id, confidence,
                                       message, evidence, received_at, origin, authenticated, ended_at)
         SELECT '{A}', 'baseline', r, 'f', 1, 'high', now() - interval '3 days',
                CASE WHEN r = 'stale' THEN now() - interval '2 days' ELSE now() END, current_date, 's', 90, 'm',
                '{{}}', now(), 'online', true, CASE WHEN r = 'ended' THEN now() - interval '1 hour' END
         FROM unnest(ARRAY['ended', 'stale', 'mitigated', 'open', 'expired']) r;
         INSERT INTO console_finding_triage (agent_id, rule_set_id, rule_id, state, rule_version, note,
                                             accepted_until, version, updated_at, updated_by)
         VALUES ('{A}', 'baseline', 'mitigated', 'mitigated', 1, 'n', NULL, 1, now(), 't'),
                ('{A}', 'baseline', 'expired', 'accepted_risk', 1, 'n', now() - interval '1 day', 1, now(), 't');"
    ))
    .await
    .unwrap();
    let s = finding_summary_in_scope(&c, &AgentScope::Global)
        .await
        .unwrap();
    assert_eq!(
        (s.total, s.impacted_agents, s.high),
        (2, 1, 2),
        "open and the expired acceptance only"
    );
    let query = FindingGroupQuery {
        since: Utc::now() - Duration::hours(24),
        after: None,
        limit: PageLimit::new(50).unwrap(),
        agent_id: None,
    };
    let page = finding_groups_in_scope(&c, &query, &AgentScope::Global)
        .await
        .unwrap();
    let expired = page.items.iter().find(|g| g.rule_id == "expired").unwrap();
    assert_eq!(
        (expired.open, expired.accepted_risk),
        (1, 0),
        "an expired acceptance is open"
    );
    drop(c);
    db.drop().await;
}
