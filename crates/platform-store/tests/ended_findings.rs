//! An ended finding (the host was fixed) is not failing anywhere (step 5c
//! ruling): the host page's failing checks, the Hosts list, the compliance
//! summary and latest list, the groups' counts and the assistant's reads
//! agree with the Compliance list. The
//! per-rule endpoint list keeps ended rows for its "fixed" badge.

mod common;

use chrono::{Duration, Utc};
use platform_store::{
    assistant::{self, GroupFilter},
    console_read::{
        AgentScope, FindingGroupEndpointQuery, FindingGroupQuery, LatestQuery, PageLimit,
        finding_group_endpoints_in_scope, finding_groups_in_scope, finding_summary_in_scope,
        latest_findings_in_scope,
    },
    host_list::{HostQuery, HostScopes, HostSort, hosts},
    host_summary::summary,
};

const A1: &str = "agent.00000000-0000-4000-8000-0000000000e1";
const A2: &str = "agent.00000000-0000-4000-8000-0000000000e2";

/// A1: `open.rule` open, `fixed.rule` ended an hour ago; A2: `fixed.rule`
/// open.
async fn seed(c: &platform_store::Client) {
    c.batch_execute(&format!(
        "INSERT INTO agents (agent_id, status, enrolled_at, last_seen_at, hostname)
         VALUES ('{A1}', 'active', now(), now(), 'e1'), ('{A2}', 'active', now(), now(), 'e2');
         INSERT INTO current_findings (agent_id, rule_set_id, rule_id, last_finding_id, rule_version, severity,
                                       first_observed_at, last_observed_at, last_observed_day, scan_id, confidence,
                                       message, evidence, received_at, origin, authenticated, source, ended_at)
         VALUES ('{A1}', 'baseline', 'open.rule', 'f', 1, 'high', now(), now(), current_date, 's', 90, 'm', '{{}}',
                 now(), 'online', true, 'changes', NULL),
                ('{A1}', 'baseline', 'fixed.rule', 'f', 1, 'critical', now(), now(), current_date, 's', 90, 'm',
                 '{{}}', now(), 'online', true, 'changes', now() - interval '1 hour'),
                ('{A2}', 'baseline', 'fixed.rule', 'f', 1, 'critical', now(), now(), current_date, 's', 90, 'm',
                 '{{}}', now(), 'online', true, 'changes', NULL);"
    ))
    .await
    .unwrap();
}

#[tokio::test]
async fn ended_findings_are_not_failing_anywhere() {
    let (db, c) = common::migrated().await;
    seed(&c).await;
    let g = AgentScope::Global;
    let scopes = HostScopes {
        hosts: &g,
        alarms: None,
        vulnerabilities: None,
        compliance: Some(&g),
    };
    let host = summary(&c, A1, &scopes, None, Utc::now())
        .await
        .unwrap()
        .unwrap();
    let top = host.top_failing.unwrap();
    assert_eq!(top.total, 1, "the host page: open.rule only");
    assert_eq!(top.items[0].rule_id, "open.rule");

    let list = HostQuery {
        q: None,
        status: None,
        os_family: None,
        group: None,
        label: None,
        problems: None,
        agent: None,
        sort: HostSort::Host,
        descending: false,
        offset: 0,
        limit: 50,
    };
    let list = hosts(&c, &list, &scopes, None, Utc::now()).await.unwrap();
    let a1 = list.rows.iter().find(|r| r.agent_id == A1).unwrap();
    assert_eq!(
        a1.failing,
        Some(1),
        "the Hosts list agrees with the host page"
    );

    // The assistant's reads: groups, endpoints and per-agent counts.
    let all = assistant::AgentScope::All;
    let since = Utc::now() - Duration::hours(24);
    let groups = assistant::finding_groups(&c, &all, &GroupFilter::default(), since, 50)
        .await
        .unwrap();
    let fixed = groups
        .items
        .iter()
        .find(|i| i.rule_id == "fixed.rule")
        .unwrap();
    assert_eq!(fixed.endpoints, 1, "A2 only");
    let page = assistant::finding_endpoints(&c, &all, "baseline", "fixed.rule", since, 50)
        .await
        .unwrap();
    assert_eq!((page.total, page.older, page.items.len()), (1, 0, 1));
    assert_eq!(page.items[0].agent_id, A2);
    let agents = assistant::agent_summaries(&c, &all, "e1", since, 5)
        .await
        .unwrap();
    assert_eq!(agents.items[0].findings, 1);

    let s = finding_summary_in_scope(&c, &g).await.unwrap();
    assert_eq!((s.total, s.impacted_agents, s.critical), (2, 2, 1));

    let latest = LatestQuery {
        severity: None,
        agent_id: Some(A1.into()),
        after: None,
        limit: PageLimit::new(50).unwrap(),
    };
    let latest = latest_findings_in_scope(&c, &latest, &g).await.unwrap();
    let rules: Vec<_> = latest.items.iter().map(|f| f.rule_id.as_str()).collect();
    assert_eq!(rules, ["open.rule"]);

    let groups = FindingGroupQuery {
        since: Utc::now() - Duration::hours(24),
        after: None,
        limit: PageLimit::new(50).unwrap(),
        agent_id: None,
    };
    let page = finding_groups_in_scope(&c, &groups, &g).await.unwrap();
    let fixed = page
        .items
        .iter()
        .find(|i| i.rule_id == "fixed.rule")
        .unwrap();
    assert_eq!((fixed.endpoint_count, fixed.open), (1, 1), "A2 only");
    let one = FindingGroupQuery {
        agent_id: Some(A1.into()),
        ..groups.clone()
    };
    let page = finding_groups_in_scope(&c, &one, &g).await.unwrap();
    let rules: Vec<_> = page.items.iter().map(|i| i.rule_id.as_str()).collect();
    assert_eq!(rules, ["open.rule"], "A1's fixed check is no group of A1");

    // The endpoint list still shows A1's ended row, with its end.
    let endpoints = FindingGroupEndpointQuery {
        since: Utc::now() - Duration::hours(24),
        include_older: false,
        after: None,
        limit: PageLimit::new(50).unwrap(),
    };
    let page = finding_group_endpoints_in_scope(&c, "baseline", "fixed.rule", &endpoints, &g)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(page.items.len(), 2);
    db.drop().await;
}
