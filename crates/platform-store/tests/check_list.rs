//! The Compliance list query (roles spec §10.3; step 5c rulings 2–7, user
//! decision 1): one row per check with failing and inferred passing hosts,
//! triage counts and the assignee, all inside the viewer's scope; the
//! shared passing-hosts fragment agrees with it.

mod common;

use common::checks::{
    ANN, ASLR, BOB, CUSTOM, REDIS, ROOT, SSH, TELNET, every, fixture, h, keys, query, row, run,
};
use platform_store::{
    check_list::{CheckQuery, CheckSeverity, CheckState, passing_hosts_sql},
    console_read::AgentScope,
    vuln_list::AssigneeSummary,
};

#[tokio::test]
async fn one_row_per_check() {
    let (db, c) = common::migrated().await;
    let (web, _) = fixture(&c).await;
    let page = run(&c, &every(), &AgentScope::AssetGroups(vec![web])).await;
    assert_eq!(page.total, 6);
    let ssh = row(&page, SSH);
    assert_eq!(ssh.title, "SSH port exposed", "the newest indexed version");
    assert_eq!(
        ssh.severity,
        Some(CheckSeverity::High),
        "the newest finding"
    );
    assert_eq!(ssh.area, "Network exposure");
    assert_eq!((ssh.failing, ssh.passing), (3, 2), "hosts 9 and 11 pass");
    let custom = row(&page, CUSTOM);
    assert_eq!(custom.title, "custom.check", "no metadata: the rule ID");
    assert_eq!(custom.area, "Other");
    assert_eq!(
        (custom.failing, custom.passing),
        (3, 1),
        "host 9 runs site-x: no metadata, any version"
    );
    assert_eq!(
        row(&page, REDIS).severity,
        Some(CheckSeverity::High),
        "no finding: the indexed severity"
    );
    assert_eq!(row(&page, REDIS).passing, 4, "not host 11, on baseline 1");
    assert_eq!(
        row(&page, ASLR).severity,
        Some(CheckSeverity::Medium),
        "host 9's legacy row"
    );
    db.drop().await;
}

#[tokio::test]
async fn check_list_counts_stay_inside_the_scope() {
    let (db, c) = common::migrated().await;
    let (web, _) = fixture(&c).await;
    let scoped = run(&c, &every(), &AgentScope::AssetGroups(vec![web])).await;
    let global = run(&c, &every(), &AgentScope::Global).await;
    // Host 4 fails ssh, telnet, aslr and custom; only the global reader sees it.
    assert_eq!(row(&global, SSH).failing, 4);
    assert_eq!(row(&global, SSH).severity, Some(CheckSeverity::Critical));
    assert_eq!(row(&scoped, SSH).failing, 3);
    assert_eq!(row(&global, TELNET).failing, 1);
    assert_eq!(row(&scoped, TELNET).failing, 0);
    assert_eq!(row(&global, ASLR).failing, 1);
    assert_eq!(row(&scoped, ASLR).failing, 0);
    assert_eq!(
        (row(&scoped, ASLR).passing, row(&global, ASLR).passing),
        (9, 9)
    );
    let groups: Vec<&str> = scoped.counts.groups.iter().map(|g| g.1.as_str()).collect();
    assert_eq!(groups, ["Alpha", "Web"], "Other is never named");
    assert_eq!(scoped.summary.hosts, 3);
    assert_eq!(global.summary.hosts, 4);
    // A check failing only out of reach, with no passing host in reach, has
    // no row.
    let off = run(&c, &every(), &AgentScope::AssetGroups(vec![])).await;
    assert!(off.rows.is_empty() && off.total == 0, "{:?}", keys(&off));
    db.drop().await;
}

#[tokio::test]
async fn passing_needs_an_assigned_healthy_rule_set() {
    let (db, c) = common::migrated().await;
    let (web, _) = fixture(&c).await;
    let scope = AgentScope::AssetGroups(vec![web]);
    let host = |id: &'static str| CheckQuery {
        host: Some(id),
        state: CheckState::Passing,
        ..query()
    };
    // 5 stale, 6 baseline not assigned, 7 baseline refused, 8 ports failed
    // (so neither its port rules nor site-x's, which need every collector),
    // 10 baseline never accepted (no version), 11 on baseline 1 (no redis
    // rule); 9 passes its legacy scan row three days old and site-x.
    for (n, want) in [
        (5, vec![]),
        (6, vec![ROOT, ASLR]),
        (7, vec![ROOT, ASLR]),
        (8, vec![TELNET, ROOT, ASLR]),
        (9, vec![SSH, TELNET, REDIS, ROOT, ASLR, CUSTOM]),
        (10, vec![ROOT, ASLR]),
        (11, vec![SSH, TELNET, ROOT, ASLR]),
    ] {
        let id: &'static str = Box::leak(h(n).into_boxed_str());
        let page = run(&c, &host(id), &scope).await;
        let mut got = keys(&page);
        got.sort();
        let mut want: Vec<String> = want.iter().map(|s| (*s).to_owned()).collect();
        want.sort();
        assert_eq!(got, want, "host {n}");
    }
    db.drop().await;
}

#[tokio::test]
async fn ended_findings_are_not_failing() {
    let (db, c) = common::migrated().await;
    let (web, _) = fixture(&c).await;
    let scope = AgentScope::AssetGroups(vec![web]);
    let page = run(&c, &every(), &scope).await;
    let telnet = row(&page, TELNET);
    assert_eq!((telnet.failing, telnet.passing), (0, 6), "host 1 is fixed");
    assert_eq!(
        telnet.severity,
        Some(CheckSeverity::Medium),
        "from the ended finding"
    );
    assert_eq!(telnet.since, None);
    // An open P13 match older than the window is neither failing nor
    // passing (its host may be stuck in a resync).
    let root = row(&page, ROOT);
    assert_eq!((root.failing, root.passing), (2, 6));
    let h1 = h(1);
    let one = CheckQuery {
        host: Some(&h1),
        ..every()
    };
    let one = run(&c, &one, &scope).await;
    assert!(!keys(&one).contains(&ROOT.to_owned()), "{:?}", keys(&one));
    let open = run(&c, &query(), &scope).await;
    assert!(!keys(&open).contains(&TELNET.to_owned()));
    db.drop().await;
}

#[tokio::test]
async fn triage_counts_and_assignee() {
    let (db, c) = common::migrated().await;
    let (web, _) = fixture(&c).await;
    let page = run(&c, &every(), &AgentScope::AssetGroups(vec![web])).await;
    let ssh = row(&page, SSH);
    assert_eq!(
        (
            ssh.open,
            ssh.mitigated,
            ssh.accepted_risk,
            ssh.false_positive
        ),
        (2, 1, 0, 0),
        "an expired acceptance is open"
    );
    assert_eq!(ssh.assignee, AssigneeSummary::One(ANN.into(), "Ann".into()));
    let root = row(&page, ROOT);
    assert_eq!((root.open, root.false_positive), (1, 1));
    assert_eq!(
        root.assignee,
        AssigneeSummary::One(BOB.into(), "Bob".into())
    );
    let custom = row(&page, CUSTOM);
    assert_eq!((custom.open, custom.accepted_risk), (2, 1));
    assert_eq!(custom.assignee, AssigneeSummary::Several(2));
    assert_eq!(row(&page, ASLR).assignee, AssigneeSummary::None);
    let since = page.rows.iter().map(|r| r.since).collect::<Vec<_>>();
    assert!(row(&page, SSH).since.is_some() && since.contains(&None));
    db.drop().await;
}

/// The shared fragment a check's page uses finds the same passing hosts.
#[tokio::test]
async fn passing_hosts_sql_agrees_with_the_list() {
    let (db, c) = common::migrated().await;
    let (web, _) = fixture(&c).await;
    let page = run(&c, &every(), &AgentScope::AssetGroups(vec![web])).await;
    let reach: Vec<String> = [1, 2, 3, 5, 6, 7, 8, 9, 10, 11].map(h).to_vec();
    let sql = format!(
        "SELECT x.rule_set_id || '/' || x.rule_id, count(*) FROM ({}) x GROUP BY 1",
        passing_hosts_sql(
            "(SELECT agent_id FROM agents WHERE agent_id = ANY($1))",
            "(SELECT split_part(k, '/', 1) AS rule_set_id, split_part(k, '/', 2) AS rule_id
              FROM unnest($2::text[]) k)",
            "now()",
        )
    );
    let rows = c.query(&sql, &[&reach, &keys(&page)]).await.unwrap();
    assert_eq!(rows.len(), 6, "every check has passing hosts");
    for r in &rows {
        let key: String = r.get(0);
        assert_eq!(row(&page, &key).passing, r.get::<_, i64>(1), "{key}");
    }
    db.drop().await;
}
