//! The Software list query (roles spec §10.3; step 5g rulings 1–10): one row
//! per package name over the hosts in scope, rpm and dpkg together.

mod common;

use chrono::Utc;
use platform_store::{
    console_read::AgentScope,
    software_list::{
        Changes, Fix, PackageType, SoftwareListPage, SoftwareListRow, SoftwareQuery, SoftwareSort,
        Versions, Vulns, software_list,
    },
};

use common::software::{A, B, fixture};

fn query() -> SoftwareQuery<'static> {
    SoftwareQuery {
        q: None,
        vulns: None,
        fix: None,
        versions: None,
        kind: None,
        group: None,
        changes: None,
        host: None,
        sort: SoftwareSort::Package,
        descending: false,
        offset: 0,
        limit: 50,
    }
}

async fn run(
    c: &mut deadpool_postgres::Client,
    q: &SoftwareQuery<'_>,
    scope: &AgentScope,
) -> SoftwareListPage {
    software_list(c, q, scope, Utc::now()).await.unwrap()
}

fn names(page: &SoftwareListPage) -> Vec<&str> {
    page.rows.iter().map(|r| r.name.as_str()).collect()
}

fn row<'a>(page: &'a SoftwareListPage, name: &str) -> &'a SoftwareListRow {
    page.rows
        .iter()
        .find(|r| r.name == name)
        .unwrap_or_else(|| panic!("no row {name}"))
}

fn count<T: PartialEq>(counts: &[(T, i64)], value: T) -> i64 {
    counts.iter().find(|(v, _)| *v == value).unwrap().1
}

#[tokio::test]
async fn one_row_per_name_across_managers_inside_the_scope() {
    let (db, mut c) = common::migrated().await;
    let (mine, _) = fixture(&c).await;
    let page = run(&mut c, &query(), &AgentScope::AssetGroups(vec![mine])).await;
    assert_eq!(
        names(&page),
        [
            "bash",
            "curl",
            "linux-image",
            "nginx",
            "openssh-server",
            "openssl"
        ]
    );
    assert_eq!(page.total, 6);
    let bash = row(&page, "bash");
    assert_eq!((bash.hosts, bash.versions), (3, 1));
    assert!(bash.dpkg && bash.rpm, "rpm on A and B, dpkg on C: one row");
    let openssl = row(&page, "openssl");
    assert_eq!(
        (openssl.hosts, openssl.versions),
        (3, 2),
        "not the revoked or the outside host"
    );
    assert_eq!(
        (openssl.oldest.as_str(), openssl.newest.as_str()),
        ("3.0.9", "3.0.11")
    );
    assert!(openssl.dpkg && !openssl.rpm);
    let kernel = row(&page, "linux-image");
    assert_eq!(
        (kernel.hosts, kernel.versions),
        (1, 2),
        "two versions on one host count the host once"
    );
    assert_eq!(page.summary.reporting_hosts, 3);
    let global = run(&mut c, &query(), &AgentScope::Global).await;
    assert_eq!(
        row(&global, "openssl").hosts,
        4,
        "A, B, C and the outside host"
    );
    assert_eq!(row(&global, "curl").hosts, 2);
    db.drop().await;
}

#[tokio::test]
async fn advisories_are_the_open_ones_with_and_without_a_fix() {
    let (db, mut c) = common::migrated().await;
    let (mine, _) = fixture(&c).await;
    let page = run(&mut c, &query(), &AgentScope::AssetGroups(vec![mine])).await;
    let openssl = row(&page, "openssl");
    assert_eq!(
        openssl.advisories, 3,
        "OS-1 (A), OS-2 (C), OS-3; not OS-OUT"
    );
    assert_eq!(openssl.no_fix, 1, "OS-3");
    assert_eq!(openssl.worst_severity.as_deref(), Some("critical"));
    assert!(openssl.exploited);
    assert_eq!(
        openssl.update_hosts, 1,
        "A; B's is a false positive and C waits for a reboot"
    );
    let nginx = row(&page, "nginx");
    assert_eq!(
        (nginx.advisories, nginx.no_fix, nginx.update_hosts),
        (1, 1, 0)
    );
    assert_eq!(nginx.worst_severity.as_deref(), Some("moderate"));
    assert!(!nginx.exploited);
    assert_eq!(
        row(&page, "curl").advisories,
        0,
        "a match from an unknown feed is lower confidence"
    );
    assert_eq!(row(&page, "bash").advisories, 0);
    db.drop().await;
}

#[tokio::test]
async fn used_by_names_the_units_that_match_by_name() {
    let (db, mut c) = common::migrated().await;
    let (mine, _) = fixture(&c).await;
    let page = run(&mut c, &query(), &AgentScope::AssetGroups(vec![mine])).await;
    let nginx = row(&page, "nginx");
    assert_eq!(
        nginx
            .used_by
            .iter()
            .map(|u| (u.unit.as_str(), u.hosts))
            .collect::<Vec<_>>(),
        [("nginx.service", 2)]
    );
    let ssh = row(&page, "openssh-server");
    assert_eq!(
        ssh.used_by[0].unit, "sshd.service",
        "the service map names it"
    );
    assert_eq!(ssh.used_by[0].hosts, 3);
    assert!(row(&page, "bash").used_by.is_empty());
    let found = run(
        &mut c,
        &SoftwareQuery {
            q: Some("sshd"),
            ..query()
        },
        &AgentScope::Global,
    )
    .await;
    assert_eq!(
        names(&found),
        ["openssh-server"],
        "search reads the units too"
    );
    db.drop().await;
}

#[tokio::test]
async fn no_fix_advisories_follow_the_hosts_os_release() {
    let (db, mut c) = common::migrated().await;
    let (mine, web) = fixture(&c).await;
    let scope = AgentScope::AssetGroups(vec![mine]);
    // nginx 1.22.1 also on C, then C moves to Debian 11: NG-1 and OS-3 are
    // written for Debian 12, so only A (nginx) still has NG-1 and nobody has OS-3.
    common::software::install(&c, common::software::C, "dpkg", "nginx", "1.22.1").await;
    c.execute(
        "UPDATE agents SET os_version = '11' WHERE agent_id = $1",
        &[&common::software::C],
    )
    .await
    .unwrap();
    let page = run(&mut c, &query(), &scope).await;
    assert_eq!(
        row(&page, "openssl").no_fix,
        0,
        "3.0.9 is only on C, now Debian 11"
    );
    assert_eq!(row(&page, "nginx").no_fix, 1, "NG-1 through A");
    c.execute(
        "UPDATE agents SET os_version = '11' WHERE agent_id = $1",
        &[&common::software::A],
    )
    .await
    .unwrap();
    let page = run(&mut c, &query(), &scope).await;
    assert_eq!(row(&page, "nginx").no_fix, 0, "A moved too");

    // A narrow reach (the Web group: A and B, two of the five hosts) with
    // two releases takes its own path: A on Debian 11 holds 1.22.1, B on 12 holds 1.24.0.
    c.execute(
        "UPDATE agents SET os_version = '12' WHERE agent_id = $1",
        &[&common::software::B],
    )
    .await
    .unwrap();
    let web = AgentScope::AssetGroups(vec![web]);
    let page = run(&mut c, &query(), &web).await;
    assert_eq!(
        row(&page, "nginx").no_fix,
        0,
        "NG-1 is for Debian 12, A is on 11"
    );
    c.execute(
        "UPDATE agents SET os_version = '12' WHERE agent_id = $1",
        &[&common::software::A],
    )
    .await
    .unwrap();
    c.execute(
        "UPDATE agents SET os_version = '11' WHERE agent_id = $1",
        &[&common::software::B],
    )
    .await
    .unwrap();
    let page = run(&mut c, &query(), &web).await;
    assert_eq!(row(&page, "nginx").no_fix, 1, "A is on 12 again");
    db.drop().await;
}

#[tokio::test]
async fn this_week_reads_the_change_log_per_host() {
    let (db, mut c) = common::migrated().await;
    let (mine, _) = fixture(&c).await;
    let scope = AgentScope::AssetGroups(vec![mine]);
    let page = run(&mut c, &query(), &scope).await;
    let w = |n: &str| {
        let r = row(&page, n);
        (r.week_added, r.week_updated, r.week_removed)
    };
    assert_eq!(
        w("openssl"),
        (0, 1, 0),
        "went away and appeared on A: updated"
    );
    assert_eq!(
        w("curl"),
        (1, 0, 0),
        "A's install; not the outside host's, and B installed and removed it: neither"
    );
    assert_eq!(
        w("nginx"),
        (0, 0, 1),
        "removed from C; the install on A is 40 days old"
    );
    assert_eq!(w("bash"), (0, 0, 0));
    for (changes, expected) in [
        (Changes::New, ["curl"].as_slice()),
        (Changes::Updated, ["openssl"].as_slice()),
        (Changes::Removed, ["nginx"].as_slice()),
    ] {
        let found = run(
            &mut c,
            &SoftwareQuery {
                changes: Some(changes),
                ..query()
            },
            &scope,
        )
        .await;
        assert_eq!(names(&found), expected);
    }
    assert_eq!(page.summary.new_this_week, 1);
    db.drop().await;
}

#[tokio::test]
async fn filters_and_their_counts_agree() {
    let (db, mut c) = common::migrated().await;
    let (mine, _) = fixture(&c).await;
    let scope = AgentScope::AssetGroups(vec![mine]);
    let all = run(&mut c, &query(), &scope).await;
    // Counts with no filter chosen.
    assert_eq!(count(&all.counts.vulns, Vulns::Exploited), 1);
    assert_eq!(count(&all.counts.vulns, Vulns::CriticalHigh), 1);
    assert_eq!(count(&all.counts.vulns, Vulns::Any), 2);
    assert_eq!(count(&all.counts.vulns, Vulns::None), 4);
    assert_eq!(count(&all.counts.fix, Fix::Available), 1);
    assert_eq!(count(&all.counts.fix, Fix::None), 2);
    assert_eq!(count(&all.counts.versions, Versions::Several), 3);
    assert_eq!(count(&all.counts.versions, Versions::One), 3);
    assert_eq!(count(&all.counts.kind, PackageType::Rpm), 1);
    assert_eq!(count(&all.counts.kind, PackageType::Dpkg), 6);
    assert_eq!(all.summary.exploited, 1);
    assert_eq!(all.summary.fixable, 1);
    assert_eq!(all.summary.several_versions, 3);
    for (q, expected) in [
        (
            SoftwareQuery {
                vulns: Some(Vulns::Exploited),
                ..query()
            },
            vec!["openssl"],
        ),
        (
            SoftwareQuery {
                vulns: Some(Vulns::Any),
                ..query()
            },
            vec!["nginx", "openssl"],
        ),
        (
            SoftwareQuery {
                vulns: Some(Vulns::None),
                ..query()
            },
            vec!["bash", "curl", "linux-image", "openssh-server"],
        ),
        (
            SoftwareQuery {
                fix: Some(Fix::Available),
                ..query()
            },
            vec!["openssl"],
        ),
        (
            SoftwareQuery {
                fix: Some(Fix::None),
                ..query()
            },
            vec!["nginx", "openssl"],
        ),
        (
            SoftwareQuery {
                versions: Some(Versions::Several),
                ..query()
            },
            vec!["linux-image", "nginx", "openssl"],
        ),
        (
            SoftwareQuery {
                kind: Some(PackageType::Rpm),
                ..query()
            },
            vec!["bash"],
        ),
        (
            SoftwareQuery {
                q: Some("SSL"),
                ..query()
            },
            vec!["openssl"],
        ),
        (
            SoftwareQuery {
                host: Some(B),
                ..query()
            },
            vec!["bash", "nginx", "openssh-server", "openssl"],
        ),
    ] {
        let page = run(&mut c, &q, &scope).await;
        assert_eq!(names(&page), expected, "{q:?}");
        assert_eq!(page.total, i64::try_from(expected.len()).unwrap());
    }
    // A filter leaves its own counts alone and narrows the others.
    let several = run(
        &mut c,
        &SoftwareQuery {
            versions: Some(Versions::Several),
            ..query()
        },
        &scope,
    )
    .await;
    assert_eq!(count(&several.counts.versions, Versions::One), 3);
    assert_eq!(count(&several.counts.vulns, Vulns::Any), 2);
    assert_eq!(count(&several.counts.vulns, Vulns::None), 1);
    db.drop().await;
}

#[tokio::test]
async fn groups_list_their_hosts_and_filter_the_rows() {
    let (db, mut c) = common::migrated().await;
    let (mine, web) = fixture(&c).await;
    let scope = AgentScope::AssetGroups(vec![mine.clone()]);
    let page = run(
        &mut c,
        &SoftwareQuery {
            group: Some(&web),
            ..query()
        },
        &scope,
    )
    .await;
    // The web group holds A and B.
    assert_eq!(
        names(&page),
        [
            "bash",
            "curl",
            "linux-image",
            "nginx",
            "openssh-server",
            "openssl"
        ]
    );
    let groups: Vec<_> = page
        .counts
        .groups
        .iter()
        .map(|g| (g.1.as_str(), g.3))
        .collect();
    assert!(groups.contains(&("Web", 2)), "{groups:?}");
    assert!(groups.contains(&("mine", 3)), "{groups:?}");
    let host_c = run(
        &mut c,
        &SoftwareQuery {
            host: Some(common::software::C),
            ..query()
        },
        &scope,
    )
    .await;
    assert_eq!(names(&host_c), ["bash", "openssh-server", "openssl"]);
    let _ = A;
    db.drop().await;
}

#[tokio::test]
async fn sort_and_page() {
    let (db, mut c) = common::migrated().await;
    let (mine, _) = fixture(&c).await;
    let scope = AgentScope::AssetGroups(vec![mine]);
    let by_hosts = run(
        &mut c,
        &SoftwareQuery {
            sort: SoftwareSort::Hosts,
            descending: true,
            ..query()
        },
        &scope,
    )
    .await;
    assert_eq!(
        names(&by_hosts)[..3],
        ["openssl", "openssh-server", "bash"],
        "ties by name, same direction"
    );
    let by_risk = run(
        &mut c,
        &SoftwareQuery {
            sort: SoftwareSort::Vulnerabilities,
            descending: true,
            ..query()
        },
        &scope,
    )
    .await;
    assert_eq!(names(&by_risk)[..2], ["openssl", "nginx"]);
    let by_week = run(
        &mut c,
        &SoftwareQuery {
            sort: SoftwareSort::Week,
            descending: true,
            ..query()
        },
        &scope,
    )
    .await;
    assert_eq!(names(&by_week)[..3], ["openssl", "nginx", "curl"]);
    let second = run(
        &mut c,
        &SoftwareQuery {
            offset: 4,
            limit: 4,
            ..query()
        },
        &scope,
    )
    .await;
    assert_eq!(names(&second), ["openssh-server", "openssl"]);
    assert_eq!(second.total, 6);
    let beyond = run(
        &mut c,
        &SoftwareQuery {
            offset: 60,
            ..query()
        },
        &scope,
    )
    .await;
    assert!(beyond.rows.is_empty());
    assert_eq!(
        beyond.total, 6,
        "an empty page still has the total and counts"
    );
    db.drop().await;
}
