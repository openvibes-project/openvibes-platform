//! Assistant lookups (assistant spec §5): scope applies in SQL to every
//! item and every count, results are bounded, and totals say what was left
//! out.

mod common;

use chrono::{DateTime, Duration, Utc};
use common::TestDb;
use platform_store::{
    Client,
    assistant::{self, AgentScope, GroupFilter},
};

const WEB: &str = "agent.00000000-0000-4000-8000-00000000000a";
const DB: &str = "agent.00000000-0000-4000-8000-00000000000b";
const OTHER: &str = "agent.00000000-0000-4000-8000-00000000000c";

fn in_scope() -> AgentScope {
    AgentScope::Only(vec![WEB.into(), DB.into()])
}

async fn agent(client: &Client, id: &str, hostname: &str, last_seen: Option<DateTime<Utc>>) {
    client
        .execute(
            "INSERT INTO agents (agent_id, status, enrolled_at, last_seen_at, hostname, os_id,
                 os_version, capabilities)
             VALUES ($1, 'active', now(), $2, $3, 'fedora', '44', '{collector.ports}')",
            &[&id, &last_seen, &hostname],
        )
        .await
        .unwrap();
}

#[allow(clippy::too_many_arguments)]
async fn finding(
    client: &Client,
    agent_id: &str,
    rule_set: &str,
    rule: &str,
    severity: &str,
    version: i64,
    observed: DateTime<Utc>,
    message: &str,
) {
    let finding_id = format!("{agent_id}-{rule_set}-{rule}");
    client
        .execute(
            "INSERT INTO current_findings (agent_id, rule_set_id, rule_id, last_finding_id,
                 rule_version, severity, first_observed_at, last_observed_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7::timestamptz - interval '1 day', $7)",
            &[
                &agent_id,
                &rule_set,
                &rule,
                &finding_id,
                &version,
                &severity,
                &observed,
            ],
        )
        .await
        .unwrap();
    client
        .execute(
            "INSERT INTO findings (finding_id, observed_day, observed_at, agent_id, scan_id,
                 rule_id, rule_version, severity, confidence, message, evidence, received_at,
                 origin, authenticated, rule_set_id)
             VALUES ($1, $2, $3, $4, 'scan.1', $5, $6, $7, 90, $8, '{}', $3, 'online', true, $9)",
            &[
                &finding_id,
                &observed.date_naive(),
                &observed,
                &agent_id,
                &rule,
                &version,
                &severity,
                &message,
                &rule_set,
            ],
        )
        .await
        .unwrap();
}

async fn vulnerability(client: &Client, agent_id: &str, advisory: &str, first_seen: DateTime<Utc>) {
    client
        .execute(
            "INSERT INTO vulnerabilities (agent_id, advisory_id, packages, first_seen_at,
                 last_evaluated_at)
             VALUES ($1, $2, '[]', $3, $3)",
            &[&agent_id, &advisory, &first_seen],
        )
        .await
        .unwrap();
}

/// Three hosts (the third out of scope), findings, and vulnerabilities.
async fn seed() -> (TestDb, Client, DateTime<Utc>) {
    let db = TestDb::create().await;
    let mut client = db.pool.get().await.unwrap();
    platform_store::migrate(&mut client).await.unwrap();
    let now = Utc::now();
    platform_store::ensure_partitions(&client, (now - Duration::days(3)).date_naive(), 4)
        .await
        .unwrap();
    agent(&client, WEB, "web-01", Some(now)).await;
    agent(&client, DB, "DB-02", Some(now - Duration::hours(2))).await;
    agent(&client, OTHER, "secret-host", Some(now)).await;
    let recent = now - Duration::hours(1);
    let old = now - Duration::hours(48);
    for id in [WEB, DB, OTHER] {
        finding(
            &client,
            id,
            "baseline",
            "ssh.exposed",
            "high",
            3,
            recent,
            "SSH listens on all interfaces",
        )
        .await;
    }
    // The out-of-scope host alone reports a critical finding.
    finding(
        &client,
        OTHER,
        "baseline",
        "telnet.enabled",
        "critical",
        1,
        recent,
        "Telnet on secret-host",
    )
    .await;
    // DB's rule version differs; its latest match is outside a 24 h window.
    finding(
        &client,
        DB,
        "baseline",
        "firewall.off",
        "medium",
        2,
        old,
        "Firewall 50%_off",
    )
    .await;
    finding(
        &client,
        WEB,
        "baseline",
        "firewall.off",
        "medium",
        3,
        recent,
        "Firewall 50%_off",
    )
    .await;
    // A pre-P6 finding (no rule set) and an unrecognised severity.
    finding(
        &client,
        WEB,
        "",
        "legacy.rule",
        "weird",
        1,
        recent,
        "Legacy",
    )
    .await;
    client
        .batch_execute(
            "INSERT INTO advisories (advisory_id, source, os_id, os_version, severity, title,
                 url)
             VALUES ('FEDORA-2026-1', 'fedora-44', 'fedora', '44', 'important', 'openssh fix',
                     'https://example/1'),
                    ('FEDORA-2026-2', 'fedora-44', 'fedora', '44', 'low', 'minor fix',
                     'https://example/2');
             INSERT INTO advisory_cves VALUES ('FEDORA-2026-1', 'CVE-2026-0001'),
                                              ('FEDORA-2026-2', 'CVE-2026-0002');
             INSERT INTO cve_enrichment (cve_id, kev_added, epss_percentile)
             VALUES ('CVE-2026-0001', '2026-09-01', 0.9);",
        )
        .await
        .unwrap();
    for id in [WEB, DB, OTHER] {
        vulnerability(&client, id, "FEDORA-2026-1", now - Duration::days(2)).await;
    }
    vulnerability(&client, WEB, "FEDORA-2026-2", now - Duration::days(1)).await;
    vulnerability(&client, OTHER, "FEDORA-2026-2", now).await;
    (db, client, now)
}

#[tokio::test]
async fn finding_groups_count_only_endpoints_in_scope_and_window() {
    let (db, client, now) = seed().await;
    let since = now - Duration::hours(24);
    let page = assistant::finding_groups(&client, &in_scope(), &GroupFilter::default(), since, 10)
        .await
        .unwrap();
    let names: Vec<_> = page
        .items
        .iter()
        .map(|g| (g.rule_set_id.as_str(), g.rule_id.as_str(), g.endpoints))
        .collect();
    // No telnet group: only the out-of-scope host reports it.
    assert_eq!(
        names,
        [
            ("baseline", "ssh.exposed", 2),
            ("baseline", "firewall.off", 1),
            ("", "legacy.rule", 1)
        ]
    );
    assert_eq!(page.total, 3);
    let ssh = &page.items[0];
    assert_eq!(ssh.severity, "high");
    assert_eq!(
        ssh.message.as_deref(),
        Some("SSH listens on all interfaces")
    );
    assert_eq!(page.items[2].severity, "unknown");
    // With every agent in scope, telnet leads and ssh counts three.
    let all = assistant::finding_groups(
        &client,
        &AgentScope::All,
        &GroupFilter::default(),
        since,
        10,
    )
    .await
    .unwrap();
    assert_eq!(all.items[0].rule_id, "telnet.enabled");
    assert_eq!(all.items[1].endpoints, 3);
    // A wider window brings DB's older firewall match and both versions in.
    let wide = assistant::finding_groups(
        &client,
        &in_scope(),
        &GroupFilter {
            text: Some("firewall"),
            ..GroupFilter::default()
        },
        now - Duration::hours(72),
        10,
    )
    .await
    .unwrap();
    assert_eq!(wide.items.len(), 1);
    assert_eq!(wide.items[0].endpoints, 2);
    assert_eq!(wide.items[0].rule_versions, [3, 2]);
    db.drop().await;
}

#[tokio::test]
async fn group_filters_are_exact_and_bounded() {
    let (db, client, now) = seed().await;
    let since = now - Duration::hours(24);
    let find = |filter: GroupFilter<'static>, limit| {
        let client = &client;
        let scope = in_scope();
        async move {
            assistant::finding_groups(client, &scope, &filter, since, limit)
                .await
                .unwrap()
        }
    };
    let high = find(
        GroupFilter {
            min_severity: Some("high"),
            ..GroupFilter::default()
        },
        10,
    )
    .await;
    assert_eq!(high.items.len(), 1);
    assert_eq!(high.items[0].rule_id, "ssh.exposed");
    // `%` and `_` are literal, not wildcards; message text matches.
    let literal = find(
        GroupFilter {
            text: Some("50%_"),
            ..GroupFilter::default()
        },
        10,
    )
    .await;
    assert_eq!(literal.items.len(), 1);
    let wildcard = find(
        GroupFilter {
            text: Some("5_%o"),
            ..GroupFilter::default()
        },
        10,
    )
    .await;
    assert!(wildcard.items.is_empty());
    let by_set = find(
        GroupFilter {
            rule_set_id: Some(""),
            ..GroupFilter::default()
        },
        10,
    )
    .await;
    assert_eq!(by_set.items[0].rule_id, "legacy.rule");
    let limited = find(GroupFilter::default(), 1).await;
    assert_eq!((limited.items.len(), limited.total), (1, 3));
    db.drop().await;
}

#[tokio::test]
async fn finding_endpoints_stay_in_scope_and_count_older_ones() {
    let (db, client, now) = seed().await;
    let since = now - Duration::hours(24);
    let ssh =
        assistant::finding_endpoints(&client, &in_scope(), "baseline", "ssh.exposed", since, 10)
            .await
            .unwrap();
    let ids: Vec<_> = ssh.items.iter().map(|e| e.agent_id.as_str()).collect();
    assert_eq!(ids.len(), 2);
    assert!(!ids.contains(&OTHER));
    assert_eq!((ssh.total, ssh.older), (2, 0));
    let firewall =
        assistant::finding_endpoints(&client, &in_scope(), "baseline", "firewall.off", since, 10)
            .await
            .unwrap();
    assert_eq!(
        (firewall.total, firewall.older),
        (1, 1),
        "DB is not seen in the window"
    );
    assert_eq!(firewall.items[0].hostname.as_deref(), Some("web-01"));
    // A finding only out-of-scope hosts report reveals nothing.
    let telnet = assistant::finding_endpoints(
        &client,
        &in_scope(),
        "baseline",
        "telnet.enabled",
        since,
        10,
    )
    .await
    .unwrap();
    assert_eq!((telnet.items.len(), telnet.total, telnet.older), (0, 0, 0));
    db.drop().await;
}

#[tokio::test]
async fn agent_summaries_match_id_or_hostname_in_scope() {
    let (db, client, now) = seed().await;
    let since = now - Duration::hours(24);
    let by_name = assistant::agent_summaries(&client, &in_scope(), "db-02", since, 5)
        .await
        .unwrap();
    assert_eq!(
        by_name.items.len(),
        1,
        "host names match case-insensitively"
    );
    let db_02 = &by_name.items[0];
    assert_eq!(db_02.agent_id, DB);
    assert_eq!(db_02.findings, 1, "only ssh is inside the window");
    assert_eq!(db_02.open_vulnerabilities, 1);
    assert_eq!(db_02.exploited_vulnerabilities, 1);
    assert_eq!(db_02.os, Some(("fedora".into(), "44".into())));
    for key in ["secret-host", OTHER] {
        let hidden = assistant::agent_summaries(&client, &in_scope(), key, since, 5)
            .await
            .unwrap();
        assert_eq!((hidden.items.len(), hidden.total), (0, 0), "{key}");
    }
    db.drop().await;
}

#[tokio::test]
async fn vulnerabilities_are_prioritised_and_scoped() {
    let (db, client, _) = seed().await;
    let web = assistant::host_vulnerabilities(&client, &in_scope(), WEB, None, 10)
        .await
        .unwrap();
    let ids: Vec<_> = web.items.iter().map(|v| v.advisory_id.as_str()).collect();
    assert_eq!(ids, ["FEDORA-2026-1", "FEDORA-2026-2"], "exploited first");
    assert!(web.items[0].exploited);
    assert_eq!(web.items[0].cves, ["CVE-2026-0001"]);
    let important =
        assistant::host_vulnerabilities(&client, &in_scope(), WEB, Some("important"), 10)
            .await
            .unwrap();
    assert_eq!(important.total, 1);
    let hidden = assistant::host_vulnerabilities(&client, &in_scope(), OTHER, None, 10)
        .await
        .unwrap();
    assert_eq!((hidden.items.len(), hidden.total), (0, 0));

    for key in ["CVE-2026-0001", "FEDORA-2026-1"] {
        let hosts = assistant::vulnerable_hosts(&client, &in_scope(), key, 10)
            .await
            .unwrap();
        assert_eq!(hosts.total, 2, "{key}");
        assert!(hosts.items.iter().all(|h| h.agent_id != OTHER));
    }
    let limited = assistant::vulnerable_hosts(&client, &in_scope(), "CVE-2026-0001", 1)
        .await
        .unwrap();
    assert_eq!((limited.items.len(), limited.total), (1, 2));
    db.drop().await;
}

#[tokio::test]
async fn the_overview_counts_only_the_scope() {
    let (db, client, now) = seed().await;
    let since = now - Duration::hours(24);
    let scoped = assistant::overview(&client, &in_scope(), since, now, 5)
        .await
        .unwrap();
    assert_eq!(scoped.agents.seen_recently, 1);
    assert_eq!(scoped.agents.offline, 1, "DB was last seen two hours ago");
    assert_eq!(scoped.open_vulnerabilities, 3);
    assert_eq!(scoped.hosts_with_exploited, 2);
    assert_eq!(scoped.top_findings.total, 3);
    assert_eq!(scoped.top_advisories.items[0].advisory_id, "FEDORA-2026-1");
    assert_eq!(scoped.top_advisories.items[0].hosts, 2);
    let all = assistant::overview(&client, &AgentScope::All, since, now, 5)
        .await
        .unwrap();
    assert_eq!(all.agents.seen_recently, 2);
    assert_eq!(all.open_vulnerabilities, 5);
    assert_eq!(all.hosts_with_exploited, 3);
    let nobody = assistant::overview(&client, &AgentScope::Only(Vec::new()), since, now, 5)
        .await
        .unwrap();
    assert_eq!(nobody.agents, Default::default());
    assert_eq!(
        (nobody.open_vulnerabilities, nobody.top_findings.total),
        (0, 0)
    );
    db.drop().await;
}
