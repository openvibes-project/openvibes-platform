//! The Vulnerabilities list query (roles spec §10.3; step 5b rulings 2–6):
//! one row per CVE, filters, per-value counts with the other filters
//! applied, search, the summary line and offset paging, all inside the
//! viewer's scope.

mod common;

use common::{
    hosts::id,
    vulns::{ANN, BOB, CID, every, fixture, keys, query, row, run},
};
use platform_store::{
    alarm_list::Assignee,
    console_read::AgentScope,
    vuln_list::{
        AssigneeSummary, Fixed, Signal, VulnListPage, VulnQuery, VulnSeverity, VulnSort, VulnState,
    },
};

fn n<K: PartialEq>(values: &[(K, i64)], key: K) -> i64 {
    values
        .iter()
        .find(|(k, _)| *k == key)
        .map_or(0, |(_, n)| *n)
}

#[tokio::test]
async fn rows_are_cves_with_their_covering_advisories() {
    let (db, c) = common::migrated().await;
    let (web, _) = fixture(&c).await;
    let scope = AgentScope::AssetGroups(vec![web]);
    let page = run(&c, &every(), &scope).await;
    // An advisory with two CVEs gives two rows; one CVE on Fedora and
    // Debian advisories is one row listing both.
    let a = row(&page, "CVE-A");
    assert_eq!(a.advisories, ["DEBIAN-A", "FEDORA-1"]);
    assert_eq!(a.also_covers, ["CVE-B"]);
    assert_eq!(a.severity, VulnSeverity::Critical);
    assert_eq!(a.title, "curl: flaw A", "the advisory with the most pairs");
    assert_eq!((a.open, a.total), (1, 3));
    assert_eq!(a.packages, ["curl"]);
    assert_eq!(a.fixed, Fixed::Several(2));
    assert!(a.exploited);
    assert_eq!(a.cvss, Some(9.8));
    let b = row(&page, "CVE-B");
    assert_eq!(b.advisories, ["FEDORA-1"]);
    assert_eq!(b.also_covers, ["CVE-A"]);
    assert_eq!(b.fixed, Fixed::One("2".into()));
    // A CVE-less advisory is keyed by its id.
    let nocve = row(&page, "DSA-NOCVE");
    assert_eq!(nocve.advisories, ["DSA-NOCVE"]);
    assert!(nocve.reboot);
    assert!(nocve.also_covers.is_empty());
    // No-fix pairs appear under their CVE.
    let nf = row(&page, "CVE-NF");
    assert_eq!(nf.fixed, Fixed::None);
    assert_eq!((nf.open, nf.total), (2, 2));
    assert_eq!(nf.packages, ["zlib"]);
    assert!(!nf.low_confidence);
    db.drop().await;
}

#[tokio::test]
async fn each_state_matches_rows_with_a_pair_in_it() {
    let (db, c) = common::migrated().await;
    let (web, _) = fixture(&c).await;
    let scope = AgentScope::AssetGroups(vec![web]);
    for (state, want) in [
        (
            VulnState::Open,
            vec!["CVE-A", "CVE-NF", "CVE-EXP", "DSA-NOCVE"],
        ),
        (VulnState::Mitigated, vec!["CVE-A"]),
        (VulnState::AcceptedRisk, vec!["CVE-A", "CVE-B"]),
        (VulnState::FalsePositive, vec!["CVE-FP"]),
        (VulnState::Resolved, vec!["CVE-R"]),
        (
            VulnState::All,
            vec![
                "CVE-A",
                "CVE-NF",
                "CVE-B",
                "CVE-EXP",
                "DSA-NOCVE",
                "CVE-R",
                "CVE-FP",
            ],
        ),
    ] {
        let page = run(&c, &VulnQuery { state, ..query() }, &scope).await;
        assert_eq!(keys(&page), want, "{state:?}");
        assert_eq!(page.total, want.len() as i64);
        assert_eq!(n(&page.counts.state, state), want.len() as i64, "{state:?}");
    }
    db.drop().await;
}

#[tokio::test]
async fn each_signal_narrows() {
    let (db, c) = common::migrated().await;
    let (web, _) = fixture(&c).await;
    let scope = AgentScope::AssetGroups(vec![web]);
    for (signal, want) in [
        (Signal::Exploited, vec!["CVE-A", "CVE-NF", "CVE-B"]),
        (Signal::Due30, vec!["CVE-A", "CVE-NF"]),
        (Signal::NoFix, vec!["CVE-NF"]),
        (Signal::Reboot, vec!["DSA-NOCVE"]),
        (Signal::LowConf, vec!["CVE-MYS", "CVE-CPE"]),
    ] {
        let q = VulnQuery {
            signal: Some(signal),
            ..every()
        };
        let page = run(&c, &q, &scope).await;
        assert_eq!(keys(&page), want, "{signal:?}");
        assert_eq!(
            n(&page.counts.signal, signal),
            want.len() as i64,
            "{signal:?}"
        );
    }
    // Lower-confidence matches show only with their signal.
    let page = run(&c, &every(), &scope).await;
    assert!(!keys(&page).contains(&"CVE-CPE") && !keys(&page).contains(&"CVE-MYS"));
    let low = run(
        &c,
        &VulnQuery {
            signal: Some(Signal::LowConf),
            ..every()
        },
        &scope,
    )
    .await;
    let cpe = row(&low, "CVE-CPE");
    assert!(cpe.low_confidence);
    assert_eq!(cpe.advisories, ["CPE:CVE-CPE:nginx"]);
    assert_eq!(cpe.packages, ["nginx"]);
    assert_eq!(cpe.severity, VulnSeverity::Moderate);
    db.drop().await;
}

#[tokio::test]
async fn package_group_host_advisory_and_assignee_narrow() {
    let (db, c) = common::migrated().await;
    let (web, alpha) = fixture(&c).await;
    let scope = AgentScope::AssetGroups(vec![web]);
    for (q, want) in [
        (
            VulnQuery {
                package: Some("curl"),
                ..every()
            },
            vec!["CVE-A", "CVE-B"],
        ),
        (
            VulnQuery {
                group: Some(alpha.as_str()),
                ..query()
            },
            vec!["CVE-A", "CVE-NF", "CVE-EXP", "DSA-NOCVE"],
        ),
        (
            VulnQuery {
                host: Some(id(2)),
                ..query()
            },
            vec!["CVE-NF", "CVE-EXP"],
        ),
        (
            VulnQuery {
                advisory: Some("FEDORA-1"),
                ..every()
            },
            vec!["CVE-A", "CVE-B"],
        ),
        (
            VulnQuery {
                assignee: Some(Assignee::Me),
                ..query()
            },
            vec!["CVE-A", "CVE-EXP"],
        ),
        (
            VulnQuery {
                assignee: Some(Assignee::User(BOB)),
                state: VulnState::Mitigated,
                ..query()
            },
            vec!["CVE-A"],
        ),
        (
            VulnQuery {
                assignee: Some(Assignee::Unassigned),
                ..query()
            },
            vec!["CVE-NF", "DSA-NOCVE"],
        ),
        (
            VulnQuery {
                assignee: Some(Assignee::User("not-a-uuid")),
                ..every()
            },
            vec![],
        ),
    ] {
        assert_eq!(keys(&run(&c, &q, &scope).await), want, "{q:?}");
    }
    // The group narrows the pairs a row counts.
    let page = run(
        &c,
        &VulnQuery {
            group: Some(alpha.as_str()),
            ..every()
        },
        &scope,
    )
    .await;
    assert_eq!(
        (row(&page, "CVE-A").open, row(&page, "CVE-A").total),
        (1, 1)
    );
    // Counts: each value with the other filters applied.
    let page = run(&c, &query(), &scope).await;
    let counts = &page.counts;
    assert_eq!(counts.me, 2);
    assert_eq!(counts.unassigned, 2);
    let people: Vec<_> = counts.people.iter().map(|p| (p.1.as_str(), p.2)).collect();
    assert_eq!(people, [("Ann", 2), ("Bob", 1)]);
    let groups: Vec<_> = counts.groups.iter().map(|g| (g.1.as_str(), g.3)).collect();
    assert_eq!(groups, [("Alpha", 4), ("Web", 4)]);
    assert_eq!(n(&counts.severity, VulnSeverity::Critical), 1);
    assert_eq!(n(&counts.severity, VulnSeverity::Moderate), 2);
    assert_eq!(n(&counts.severity, VulnSeverity::Low), 1);
    assert_eq!(n(&counts.packages, "zlib".to_string()), 1);
    assert_eq!(n(&counts.packages, "curl".to_string()), 1);
    db.drop().await;
}

#[tokio::test]
async fn list_counts_stay_inside_the_scope() {
    let (db, c) = common::migrated().await;
    let (web, _) = fixture(&c).await;
    // Span holds host 1 (in reach) and host 4 (out of reach); Cid is
    // assigned only on host 4's pair.
    let span = common::manual_group(&c, "Span", &[id(1), id(4)]).await;
    c.batch_execute(&format!(
        "INSERT INTO console_users (user_id, username, display_name, created_at)
         VALUES ('{CID}', 'cid', 'Cid', now());
         INSERT INTO vulnerability_triage (agent_id, advisory_id, state, assigned_to, version, updated_at, updated_by)
         VALUES ('{h4}', 'DEBIAN-OUT', 'open', '{CID}', 1, now(), 't');",
        h4 = id(4)
    ))
    .await
    .unwrap();
    let group = |page: &VulnListPage| page.counts.groups.iter().find(|g| g.0 == span).map(|g| g.3);
    let everywhere = run(&c, &every(), &AgentScope::Global).await;
    assert!(keys(&everywhere).contains(&"CVE-OUT"));
    assert_eq!(row(&everywhere, "CVE-NF").total, 3);
    assert_eq!(group(&everywhere), Some(6));
    assert!(everywhere.counts.people.iter().any(|p| p.1 == "Cid"));

    let scope = AgentScope::AssetGroups(vec![web]);
    for q in [every(), query()] {
        let page = run(&c, &q, &scope).await;
        assert!(!keys(&page).contains(&"CVE-OUT"));
        let counts = &page.counts;
        assert!(counts.packages.iter().all(|p| p.0 != "secretpkg"));
        assert!(counts.groups.iter().all(|g| g.1 != "Other"));
        let severities: i64 = counts.severity.iter().map(|s| s.1).sum();
        assert_eq!(severities, page.total);
        assert_eq!(page.summary.hosts, 2);
    }
    let page = run(&c, &every(), &scope).await;
    assert_eq!(row(&page, "CVE-NF").total, 2);
    assert_eq!(group(&page), Some(5), "host 1's rows only");
    assert!(page.counts.people.iter().all(|p| p.1 != "Cid"));
    assert_eq!(n(&page.counts.state, VulnState::All), 7);
    // A search or package naming the out-of-reach CVE finds nothing.
    for q in [
        VulnQuery {
            q: Some("CVE-OUT"),
            ..every()
        },
        VulnQuery {
            package: Some("secretpkg"),
            ..every()
        },
    ] {
        let page = run(&c, &q, &scope).await;
        assert_eq!(page.total, 0);
        assert!(page.counts.packages.iter().all(|p| p.0 != "secretpkg"));
    }
    db.drop().await;
}

#[tokio::test]
async fn search_covers_cve_advisory_title_and_package() {
    let (db, c) = common::migrated().await;
    let (web, _) = fixture(&c).await;
    let scope = AgentScope::AssetGroups(vec![web]);
    for (q, want) in [
        ("cve-b", vec!["CVE-B"]),
        ("DSA-NO", vec!["DSA-NOCVE"]),
        ("HARDENING", vec!["DSA-NOCVE"]),
        ("zlib", vec!["CVE-NF"]),
        ("fedora-1", vec!["CVE-A", "CVE-B"]),
        (
            "  ",
            vec![
                "CVE-A",
                "CVE-NF",
                "CVE-B",
                "CVE-EXP",
                "DSA-NOCVE",
                "CVE-R",
                "CVE-FP",
            ],
        ),
    ] {
        let page = run(
            &c,
            &VulnQuery {
                q: Some(q),
                ..every()
            },
            &scope,
        )
        .await;
        assert_eq!(keys(&page), want, "{q}");
    }
    db.drop().await;
}

#[tokio::test]
async fn every_sort_pages_stably() {
    let (db, c) = common::migrated().await;
    let (web, _) = fixture(&c).await;
    let scope = AgentScope::AssetGroups(vec![web]);
    for sort in VulnSort::ALL {
        for descending in [true, false] {
            let q = VulnQuery {
                sort: *sort,
                descending,
                ..every()
            };
            let all = keys(&run(&c, &q, &scope).await)
                .into_iter()
                .map(str::to_owned)
                .collect::<Vec<_>>();
            assert_eq!(all.len(), 7);
            let mut paged = Vec::new();
            for offset in 0..7 {
                let page = run(
                    &c,
                    &VulnQuery {
                        offset,
                        limit: 2,
                        ..q.clone()
                    },
                    &scope,
                )
                .await;
                assert_eq!(page.total, 7);
                paged.push(page.rows[0].key.clone());
            }
            assert_eq!(paged, all, "{sort:?} {descending}");
        }
    }
    let by = |sort, descending| VulnQuery {
        sort,
        descending,
        ..every()
    };
    let order = |p: &VulnListPage| keys(p).into_iter().map(str::to_owned).collect::<Vec<_>>();
    assert_eq!(
        order(&run(&c, &by(VulnSort::Cvss, true), &scope).await)[..4],
        ["CVE-A", "CVE-NF", "CVE-B", "CVE-EXP"]
    );
    assert_eq!(
        order(&run(&c, &by(VulnSort::Due, false), &scope).await)[..3],
        ["CVE-NF", "CVE-A", "CVE-B"]
    );
    assert_eq!(
        order(&run(&c, &by(VulnSort::Open, true), &scope).await)[..2],
        ["CVE-NF", "CVE-EXP"]
    );
    assert_eq!(
        order(&run(&c, &by(VulnSort::Severity, false), &scope).await)[0],
        "CVE-FP"
    );
    assert_eq!(
        order(&run(&c, &by(VulnSort::Epss, true), &scope).await)[0],
        "CVE-A"
    );
    // Past the end: no rows, the meta still there.
    let page = run(
        &c,
        &VulnQuery {
            offset: 50,
            ..every()
        },
        &scope,
    )
    .await;
    assert!(page.rows.is_empty());
    assert_eq!(page.total, 7);
    db.drop().await;
}

#[tokio::test]
async fn assignee_summary_and_summary_line() {
    let (db, c) = common::migrated().await;
    let (web, _) = fixture(&c).await;
    let scope = AgentScope::AssetGroups(vec![web]);
    let page = run(&c, &query(), &scope).await;
    assert_eq!(
        row(&page, "CVE-A").assignee,
        AssigneeSummary::One(ANN.into(), "Ann".into())
    );
    assert_eq!(row(&page, "CVE-EXP").assignee, AssigneeSummary::Several(2));
    assert_eq!(row(&page, "CVE-NF").assignee, AssigneeSummary::None);
    let s = page.summary;
    assert_eq!(
        (
            s.open_rows,
            s.hosts,
            s.exploited,
            s.with_due,
            s.no_fix,
            s.unassigned
        ),
        (4, 2, 2, 2, 1, 2)
    );
    // The summary counts open rows whatever the state filter.
    assert_eq!(run(&c, &every(), &scope).await.summary, s);
    db.drop().await;
}
