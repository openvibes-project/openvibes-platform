//! The Hosts list query (roles spec §10.1, §10.3; plan rulings 2–7):
//! search, filters, per-value counts with the other filters applied, the
//! summary line and paging, all inside the viewer's scope.

mod common;

use common::hosts::{everywhere, fleet, id, in_group_counts, query, run};
use platform_store::{
    console_read::AgentScope,
    host_list::{AgentAge, HostListPage, HostQuery, HostScopes, HostSort, HostStatus, Problems},
};

fn names(page: &HostListPage) -> Vec<&str> {
    page.rows
        .iter()
        .map(|r| r.hostname.as_deref().unwrap())
        .collect()
}

fn ids(page: &HostListPage) -> Vec<&str> {
    page.rows.iter().map(|r| r.agent_id.as_str()).collect()
}

fn n<K: PartialEq>(values: &[(K, i64)], key: K) -> i64 {
    values
        .iter()
        .find(|(k, _)| *k == key)
        .map_or(0, |(_, n)| *n)
}

#[tokio::test]
async fn search_matches_name_agent_id_and_address() {
    let (db, c) = common::migrated().await;
    fleet(&c).await;
    for (q, want) in [
        ("web", vec!["web-01", "web-02"]),
        ("10.0.1.", vec!["web-01", "web-02"]),
        (
            "10.0.0.0/16",
            vec!["app-01", "db-01", "old-01", "web-01", "web-02"],
        ),
        ("WEB-01", vec!["web-01"]),
        ("agent.00000000-0000-4000-8000-000000000003", vec!["db-01"]),
        (
            "AGENT.00000000-0000-4000-8000-00000000000",
            vec![
                "app-01", "db-01", "mail-01", "old-01", "web-01", "web-02", "win-01",
            ],
        ),
        ("import.", vec!["imp-01"]),
        ("10.0.0.0/99", vec![]),
        ("10.0.0.0/+8", vec![]),
        ("10.0.0.0/33", vec![]),
        ("::/129", vec![]),
        ("10.0.0.0/", vec![]),
    ] {
        let page = run(
            &c,
            &HostQuery {
                q: Some(q),
                ..query()
            },
            &everywhere(),
            None,
        )
        .await;
        assert_eq!(names(&page), want, "q {q}");
        assert_eq!(page.total, i64::try_from(want.len()).unwrap());
    }
    db.drop().await;
}

#[tokio::test]
async fn filters_combine_and_counts_apply_the_other_filters() {
    let (db, c) = common::migrated().await;
    fleet(&c).await;
    let q = HostQuery {
        os_family: Some("linux"),
        status: Some(HostStatus::Online),
        ..query()
    };
    let page = run(&c, &q, &everywhere(), None).await;
    assert_eq!(names(&page), ["app-01", "web-01", "web-02"]);
    assert_eq!(page.total, 3);
    let status = &page.counts.status;
    assert_eq!(n(status, HostStatus::Online), 3);
    assert_eq!(n(status, HostStatus::Offline), 2);
    assert_eq!(n(status, HostStatus::Revoked), 1);
    assert_eq!(n(status, HostStatus::Imported), 0);
    assert_eq!(
        page.counts.os_family,
        [("linux".to_owned(), 3), ("windows".to_owned(), 1)]
    );
    assert_eq!(page.summary.online, 3);
    db.drop().await;
}

#[tokio::test]
async fn counts_and_values_stay_inside_the_scope() {
    let (db, c) = common::migrated().await;
    let groups = fleet(&c).await;
    let scope = AgentScope::AssetGroups(vec![groups.web.clone()]);
    let scopes = HostScopes {
        hosts: &scope,
        alarms: Some(&scope),
        vulnerabilities: Some(&scope),
        compliance: Some(&scope),
    };
    let page = run(&c, &query(), &scopes, Some("0.4.2")).await;
    assert_eq!(names(&page), ["web-01", "web-02"]);
    assert_eq!(page.total, 2);
    assert_eq!(n(&page.counts.status, HostStatus::Online), 2);
    assert_eq!(page.counts.status.iter().map(|(_, n)| n).sum::<i64>(), 2);
    let group_names: Vec<_> = page
        .counts
        .groups
        .iter()
        .map(|g| (g.1.as_str(), g.3))
        .collect();
    assert_eq!(group_names, [("Alpha", 1), ("Linux", 2), ("Web", 2)]);
    assert_eq!(page.counts.labels, [("prod".to_owned(), 2)]);
    assert_eq!(page.counts.os_family, [("linux".to_owned(), 2)]);
    assert_eq!(page.summary.online, 2);
    assert_eq!(page.summary.older_agent, 1);
    assert_eq!(page.summary.critical, 1);
    assert_eq!(n(&page.counts.problems, Problems::OpenAlarms), 1);

    // choosing a group outside the scope names nothing and matches nothing
    let outside = HostQuery {
        group: Some(&groups.windows),
        ..query()
    };
    let page = run(&c, &outside, &scopes, None).await;
    assert_eq!(page.total, 0);
    assert!(page.counts.groups.iter().all(|g| g.1 != "Windows box"));
    // a label only found outside is not listed even when chosen
    let label = HostQuery {
        label: Some("win-only"),
        ..query()
    };
    let page = run(&c, &label, &scopes, None).await;
    assert_eq!(page.total, 0);
    assert!(page.counts.labels.iter().all(|l| l.0 != "win-only"));
    db.drop().await;
}

#[tokio::test]
async fn chosen_values_in_reach_are_listed_with_zero() {
    let (db, c) = common::migrated().await;
    let groups = fleet(&c).await;
    // global: no host matching "web" is in Windows box or labelled win-only
    let q = HostQuery {
        q: Some("web"),
        group: Some(&groups.windows),
        label: Some("win-only"),
        ..query()
    };
    let page = run(&c, &q, &everywhere(), None).await;
    assert_eq!(page.total, 0);
    let windows: Vec<_> = page
        .counts
        .groups
        .iter()
        .filter(|g| g.0 == groups.windows)
        .collect();
    assert_eq!(windows.len(), 1);
    assert_eq!((windows[0].1.as_str(), windows[0].3), ("Windows box", 0));
    assert!(page.counts.labels.contains(&("win-only".to_owned(), 0)));

    // scoped to Web: the scope's own group is listed with 0 under a search
    // matching none of its hosts; a label on Web hosts likewise
    let web = AgentScope::AssetGroups(vec![groups.web.clone()]);
    let scopes = HostScopes {
        hosts: &web,
        ..everywhere()
    };
    let q = HostQuery {
        q: Some("zzz"),
        group: Some(&groups.web),
        label: Some("prod"),
        ..query()
    };
    let page = run(&c, &q, &scopes, None).await;
    assert!(
        page.counts
            .groups
            .iter()
            .any(|g| g.0 == groups.web && g.3 == 0)
    );
    assert!(page.counts.labels.contains(&("prod".to_owned(), 0)));
    // an unknown label is never echoed
    let q = HostQuery {
        label: Some("nope"),
        ..query()
    };
    let page = run(&c, &q, &scopes, None).await;
    assert!(page.counts.labels.iter().all(|l| l.0 != "nope"));
    db.drop().await;
}

#[tokio::test]
async fn problem_counts_follow_each_permission() {
    let (db, c) = common::migrated().await;
    let groups = fleet(&c).await;
    let no_alarms = HostScopes {
        alarms: None,
        ..everywhere()
    };
    let page = run(&c, &query(), &no_alarms, None).await;
    assert!(page.rows.iter().all(|r| r.open_alarms.is_none()));
    assert!(
        page.rows
            .iter()
            .all(|r| r.critical.is_some() && (r.failing.is_some() || r.compliance_stale))
    );
    assert_eq!(n(&page.counts.problems, Problems::OpenAlarms), 0);
    assert_eq!(n(&page.counts.problems, Problems::Critical), 2);
    // win-01 (alarm unseen), app-01, old-01; imp-01 never reported (unknown)
    assert_eq!(n(&page.counts.problems, Problems::NoneOpen), 3);
    let filtered = HostQuery {
        problems: Some(Problems::OpenAlarms),
        ..query()
    };
    assert_eq!(run(&c, &filtered, &no_alarms, None).await.total, 0);

    let web = AgentScope::AssetGroups(vec![groups.web.clone()]);
    let some_alarms = HostScopes {
        alarms: Some(&web),
        ..everywhere()
    };
    let page = run(&c, &query(), &some_alarms, None).await;
    let row = |n: u8| page.rows.iter().find(|r| r.agent_id == id(n)).unwrap();
    assert_eq!(row(1).open_alarms, Some(2));
    assert_eq!(row(2).open_alarms, Some(0));
    assert_eq!(row(4).open_alarms, None);
    assert_eq!(n(&page.counts.problems, Problems::OpenAlarms), 1);
    db.drop().await;
}

#[tokio::test]
async fn agent_age_uses_the_latest_release() {
    let (db, c) = common::migrated().await;
    fleet(&c).await;
    let page = run(&c, &query(), &everywhere(), Some("0.4.2")).await;
    let older = |n: u8| {
        page.rows
            .iter()
            .find(|r| r.agent_id == id(n))
            .unwrap()
            .agent_older
    };
    assert_eq!(older(1), Some(true));
    assert_eq!(older(2), Some(false));
    assert_eq!(older(5), Some(true), "0.4.2-rc1");
    assert_eq!(older(6), Some(false), "0.4.2+build");
    assert_eq!(older(8), None, "no version");
    assert_eq!(n(&page.counts.agent, AgentAge::Older), 4);
    assert_eq!(n(&page.counts.agent, AgentAge::Latest), 3);
    assert_eq!(page.summary.older_agent, 4);
    let q = HostQuery {
        agent: Some(AgentAge::Older),
        ..query()
    };
    let page = run(&c, &q, &everywhere(), Some("0.4.2")).await;
    assert_eq!(names(&page), ["mail-01", "old-01", "web-01", "win-01"]);
    db.drop().await;
}

#[tokio::test]
async fn unknown_latest_version_matches_neither() {
    let (db, c) = common::migrated().await;
    fleet(&c).await;
    let page = run(&c, &query(), &everywhere(), None).await;
    assert!(page.rows.iter().all(|r| r.agent_older.is_none()));
    assert_eq!(n(&page.counts.agent, AgentAge::Older), 0);
    assert_eq!(n(&page.counts.agent, AgentAge::Latest), 0);
    assert_eq!(page.summary.older_agent, 0);
    for age in [AgentAge::Older, AgentAge::Latest] {
        let q = HostQuery {
            agent: Some(age),
            ..query()
        };
        assert_eq!(run(&c, &q, &everywhere(), None).await.total, 0);
    }
    db.drop().await;
}

#[tokio::test]
async fn paging_and_sort_are_stable() {
    let (db, c) = common::migrated().await;
    fleet(&c).await;
    let mut seen = Vec::new();
    for offset in [0, 3, 6] {
        let page = run(
            &c,
            &HostQuery {
                limit: 3,
                offset,
                ..query()
            },
            &everywhere(),
            None,
        )
        .await;
        assert_eq!(page.total, 8);
        seen.extend(names(&page).into_iter().map(str::to_owned));
    }
    let all = [
        "app-01", "db-01", "imp-01", "mail-01", "old-01", "web-01", "web-02", "win-01",
    ];
    assert_eq!(seen, all);

    let sorted = |sort, descending| HostQuery {
        sort,
        descending,
        ..query()
    };
    let page = run(&c, &sorted(HostSort::Host, true), &everywhere(), None).await;
    let mut reversed = all;
    reversed.reverse();
    assert_eq!(names(&page), reversed);
    let page = run(&c, &sorted(HostSort::Heartbeat, false), &everywhere(), None).await;
    assert_eq!(ids(&page), [5, 3, 7, 1, 2, 4, 6, 8].map(id));
    let page = run(&c, &sorted(HostSort::Heartbeat, true), &everywhere(), None).await;
    assert_eq!(ids(&page), [1, 2, 4, 6, 7, 3, 5, 8].map(id));
    let page = run(&c, &sorted(HostSort::Problems, true), &everywhere(), None).await;
    assert_eq!(ids(&page), [1, 2, 3, 4, 5, 6, 7, 8].map(id));
    let page = run(&c, &sorted(HostSort::Problems, false), &everywhere(), None).await;
    // mail-01's finding is two days old, so its count is unknown (0 here).
    assert_eq!(ids(&page), [5, 6, 7, 8, 3, 4, 1, 2].map(id));
    let page = run(&c, &sorted(HostSort::Version, false), &everywhere(), None).await;
    assert_eq!(ids(&page), [1, 4, 7, 5, 2, 3, 6, 8].map(id));
    db.drop().await;
}

#[tokio::test]
async fn groups_column_shows_two_and_a_count() {
    let (db, c) = common::migrated().await;
    fleet(&c).await;
    let page = run(
        &c,
        &HostQuery {
            q: Some("web-01"),
            ..query()
        },
        &everywhere(),
        None,
    )
    .await;
    let row = &page.rows[0];
    let shown: Vec<_> = row.groups.iter().map(|g| g.1.as_str()).collect();
    assert_eq!(shown, ["Alpha", "Linux"]);
    assert_eq!(row.group_count, 3);
    assert_eq!(row.labels, ["prod"]);
    assert_eq!(row.address.as_deref(), Some("10.0.1.5"));
    assert_eq!(row.distribution.as_deref(), Some("Debian 12"));
    assert_eq!(row.status, HostStatus::Online);

    // the list's one-pass membership agrees with console_host_in_group
    let page = run(&c, &query(), &everywhere(), None).await;
    let counted: Vec<_> = page
        .counts
        .groups
        .iter()
        .map(|g| (g.1.clone(), g.3))
        .collect();
    assert_eq!(counted, in_group_counts(&c).await);
    let counted: Vec<_> = counted.iter().map(|(n, c)| (n.as_str(), *c)).collect();
    assert_eq!(
        counted,
        [("Alpha", 1), ("Linux", 5), ("Web", 2), ("Windows box", 1)]
    );
    db.drop().await;
}

#[tokio::test]
async fn alarms_off_marks_only_online_hosts_off_by_a_fault() {
    let (db, c) = common::migrated().await;
    fleet(&c).await;
    // web-01 and db-01 (offline) report no source (a fault); web-02 never
    // enabled process events (off by choice); win-01 is on through audit.
    let fault = r#"{"collector": "ok", "events_dropped_total": 0, "alarms_dropped_total": 0, "pending": 0,
        "platform_unsupported": false, "rules_accepted": 1, "rules_refused": 0, "rules_without_prefilter": 0,
        "events_budget_cut_total": 0, "source": "none", "fallback": {"detail": "no_btf", "audit_rule_loaded": true}}"#;
    let on = fault.replace(r#""source": "none""#, r#""source": "audit""#);
    c.batch_execute(&format!(
        "UPDATE agents SET health_at = now(), health = jsonb_build_object('alarms', '{fault}'::jsonb) WHERE agent_id IN ('{}', '{}');
         UPDATE agents SET health_at = now(), health = '{{\"alarms\": null}}'::jsonb WHERE agent_id = '{}';
         UPDATE agents SET health_at = now(), health = jsonb_build_object('alarms', '{on}'::jsonb) WHERE agent_id = '{}';",
        id(1), id(3), id(2), id(4)
    ))
    .await
    .unwrap();
    let page = run(&c, &query(), &everywhere(), None).await;
    let off: Vec<&str> = page
        .rows
        .iter()
        .filter(|r| r.alarms_off)
        .map(|r| r.hostname.as_deref().unwrap())
        .collect();
    assert_eq!(off, ["web-01"]);
    db.drop().await;
}

/// A failing check triaged away (mitigated) is not counted, as the
/// Compliance list and the host page do not show it by default.
#[tokio::test]
async fn a_triaged_finding_is_not_failing() {
    let (db, c) = common::migrated().await;
    fleet(&c).await;
    c.execute(
        "INSERT INTO console_finding_triage (agent_id, rule_set_id, rule_id, state, rule_version,
             note, version, updated_at, updated_by)
         VALUES ($1, '', 'rule-1', 'mitigated', 1, 'patched', 1, now(), 'test')",
        &[&id(1)],
    )
    .await
    .unwrap();
    let page = run(&c, &query(), &everywhere(), None).await;
    let row = |n: u8| page.rows.iter().find(|r| r.agent_id == id(n)).unwrap();
    assert_eq!(row(1).failing, Some(0));
    // mail-01 sent nothing for two days: unknown, not its old finding.
    assert_eq!(row(5).failing, None);
    db.drop().await;
}

/// The list's critical count is what the host page and the Vulnerabilities
/// list show by default: fixable or not, reboot pending or not, one per
/// advisory, mapped at confidence 80 or more, triage open.
#[tokio::test]
async fn critical_counts_what_the_host_page_lists() {
    let (db, c) = common::migrated().await;
    fleet(&c).await;
    let host = id(6);
    c.batch_execute(&format!(
        "INSERT INTO advisories (advisory_id, source, os_id, os_version, severity, title, url) VALUES
             ('ADV-C1', 'rocky', 'rocky', '9', 'critical', 't', 'u'),
             ('ADV-REB', 'rocky', 'rocky', '9', 'critical', 't', 'u'),
             ('ADV-NOFIX', 'rocky', 'rocky', '9', 'critical', 't', 'u'),
             ('ADV-ODD', 'elsewhere', 'rocky', '9', 'critical', 't', 'u'),
             ('ADV-RISK', 'rocky', 'rocky', '9', 'critical', 't', 'u'),
             ('ADV-IMP', 'rocky', 'rocky', '9', 'important', 't', 'u');
         INSERT INTO vulnerabilities (agent_id, advisory_id, packages, first_seen_at, last_evaluated_at, fixed_at, reboot_needed)
         VALUES ('{host}', 'ADV-C1', '[]', now(), now(), NULL, false), ('{host}', 'ADV-REB', '[]', now(), now(), NULL, true),
                ('{host}', 'ADV-ODD', '[]', now(), now(), NULL, false), ('{host}', 'ADV-RISK', '[]', now(), now(), NULL, false),
                ('{host}', 'ADV-IMP', '[]', now(), now(), NULL, false);
         INSERT INTO vulnerability_triage (agent_id, advisory_id, state, note, accepted_until, version, updated_at, updated_by)
         VALUES ('{host}', 'ADV-RISK', 'accepted_risk', 'later', now() + interval '30 days', 1, now(), 'test');
         INSERT INTO package_versions (manager, name, version) VALUES ('rpm', 'openssl', '3');
         INSERT INTO host_packages (agent_id, package_version_id) SELECT '{host}', id FROM package_versions;
         INSERT INTO version_vulnerabilities (package_version_id, advisory_id, package, first_seen_at)
         SELECT id, 'ADV-NOFIX', 'openssl', now() FROM package_versions;"
    ))
    .await
    .unwrap();
    platform_store::vulns::refresh_counts(&c, &[host.to_owned()], chrono::Utc::now())
        .await
        .unwrap();
    let page = run(&c, &query(), &everywhere(), None).await;
    let row = page.rows.iter().find(|r| r.agent_id == host).unwrap();
    assert_eq!(row.critical, Some(3));
    let s =
        platform_store::host_summary::summary(&c, host, &everywhere(), None, chrono::Utc::now())
            .await
            .unwrap()
            .unwrap();
    let top = s.top_vulnerabilities.unwrap();
    assert_eq!(top.total, 4);
    assert!(top.items.iter().all(|v| v.severity == "critical"));
    db.drop().await;
}

/// A host with no report in the last day (the Compliance list's window, as
/// the host page's `compliance_stale`) has an unknown failing count: not
/// 0, so "none open" leaves it out. Without compliance in reach its other
/// kinds still decide.
#[tokio::test]
async fn a_host_silent_for_a_day_is_unknown_not_none_open() {
    let (db, c) = common::migrated().await;
    fleet(&c).await;
    let page = run(&c, &query(), &everywhere(), None).await;
    let row = |n: u8| page.rows.iter().find(|r| r.agent_id == id(n)).unwrap();
    // db-01 a day, mail-01 two days (its finding unknown too), imp-01 never.
    for n in [3, 5, 8] {
        assert!(row(n).compliance_stale, "host {n}");
        assert_eq!(row(n).failing, None, "host {n}");
    }
    for n in [1, 2, 4, 6, 7] {
        assert!(!row(n).compliance_stale, "host {n}");
    }
    assert_eq!(row(1).failing, Some(1));
    // win-01 is out (alarm), so app-01 and old-01; imp-01 is unknown.
    assert_eq!(n(&page.counts.problems, Problems::NoneOpen), 2);
    let none = HostQuery {
        problems: Some(Problems::NoneOpen),
        ..query()
    };
    assert_eq!(
        names(&run(&c, &none, &everywhere(), None).await),
        ["app-01", "old-01"]
    );

    let no_compliance = HostScopes {
        compliance: None,
        ..everywhere()
    };
    let page = run(&c, &none, &no_compliance, None).await;
    assert!(page.rows.iter().all(|r| !r.compliance_stale));
    assert!(ids(&page).contains(&id(8)));
    db.drop().await;
}
