//! A package's page (roles spec §10.3; step 5g rulings 2, 9–13): the summary
//! and the Hosts table inside the viewer's scope.

mod common;

use chrono::Utc;
use common::software::{A, B, C, fixture};
use deadpool_postgres::Client;
use platform_store::{
    console_read::AgentScope,
    software_summary::{SoftwareSegment, SoftwareSummary, software_hosts_page, software_summary},
};

fn scoped(group: &str) -> AgentScope {
    AgentScope::AssetGroups(vec![group.to_owned()])
}

async fn summary(c: &Client, scope: &AgentScope, name: &str) -> Option<SoftwareSummary> {
    software_summary(c, scope, name, Utc::now()).await.unwrap()
}

#[tokio::test]
async fn summary_stays_inside_the_scope() {
    let (db, c) = common::migrated().await;
    let (mine, _) = fixture(&c).await;
    let scope = scoped(&mine);
    let s = summary(&c, &scope, "openssl").await.unwrap();
    assert_eq!(
        (s.hosts, s.of),
        (3, 3),
        "A, B and C; not the revoked or outside host"
    );
    assert_eq!(s.managers, ["dpkg"]);
    assert_eq!(
        s.versions
            .iter()
            .map(|v| (v.full(), v.hosts, v.advisories))
            .collect::<Vec<_>>(),
        [("3.0.11".to_owned(), 2, 1), ("3.0.9".to_owned(), 1, 2)],
        "OS-1 on A's version; OS-2 (C's host) and OS-3 on the old one"
    );
    assert_eq!(s.versions[1].cves, ["CVE-OS-2"]);
    assert_eq!((s.advisory_total, s.no_fix, s.update_hosts), (3, 1, 1));
    assert_eq!(
        s.advisories
            .iter()
            .map(|a| a.advisory_id.as_str())
            .collect::<Vec<_>>(),
        ["OS-1", "OS-2", "OS-3"],
        "exploited first, then by severity; not the outside host's"
    );
    let first = &s.advisories[0];
    assert!(first.exploited);
    assert_eq!(first.fixed_in.as_deref(), Some("3.0.12"));
    assert_eq!(first.hosts, 1, "B's pair is a false positive");
    assert_eq!(s.advisories[2].fixed_in, None);
    assert_eq!((s.week_added, s.week_updated, s.week_removed), (0, 1, 0));
    assert_eq!(s.changes.len(), 2);
    assert!(!s.changes[0].change.is_empty());
    assert!(s.first_seen.is_some());
    let global = summary(&c, &AgentScope::Global, "openssl").await.unwrap();
    assert_eq!(global.hosts, 4);
    assert!(summary(&c, &scope, "no-such-package").await.is_none());
    db.drop().await;
}

#[tokio::test]
async fn a_package_in_two_managers_is_one_page() {
    let (db, c) = common::migrated().await;
    let (mine, _) = fixture(&c).await;
    let s = summary(&c, &scoped(&mine), "bash").await.unwrap();
    assert_eq!(s.managers, ["dpkg", "rpm"]);
    assert_eq!(s.hosts, 3);
    assert_eq!(s.versions.len(), 2, "one per manager");
    assert_eq!((s.advisory_total, s.update_hosts), (0, 0));
    let kernel = summary(&c, &scoped(&mine), "linux-image").await.unwrap();
    assert_eq!((kernel.hosts, kernel.versions.len()), (1, 2));
    db.drop().await;
}

#[tokio::test]
async fn used_by_and_removed_packages() {
    let (db, c) = common::migrated().await;
    let (mine, _) = fixture(&c).await;
    let scope = scoped(&mine);
    let nginx = summary(&c, &scope, "nginx").await.unwrap();
    assert_eq!(
        nginx
            .used_by
            .iter()
            .map(|u| (u.unit.as_str(), u.hosts))
            .collect::<Vec<_>>(),
        [("nginx.service", 2)]
    );
    assert_eq!(
        (nginx.week_added, nginx.week_updated, nginx.week_removed),
        (0, 0, 1)
    );
    assert_eq!((nginx.advisory_total, nginx.no_fix), (1, 1));
    // Nothing in reach has it now, but the log has it for 90 days.
    c.execute("DELETE FROM host_packages WHERE package_version_id IN (SELECT id FROM package_versions WHERE name = 'nginx')", &[]).await.unwrap();
    let gone = summary(&c, &scope, "nginx").await.unwrap();
    assert_eq!(gone.hosts, 0);
    assert!(gone.versions.is_empty());
    db.drop().await;
}

#[tokio::test]
async fn hosts_table_has_segments_and_the_update_to_version() {
    let (db, c) = common::migrated().await;
    let (mine, _) = fixture(&c).await;
    let scope = scoped(&mine);
    let page = software_hosts_page(
        &c,
        &scope,
        "openssl",
        SoftwareSegment::All,
        0,
        50,
        Utc::now(),
    )
    .await
    .unwrap();
    assert_eq!(
        (
            page.segments.all,
            page.segments.update,
            page.segments.current
        ),
        (3, 1, 2)
    );
    assert_eq!(page.total, 3);
    let hosts: Vec<_> = page.rows.iter().map(|r| r.agent_id.as_str()).collect();
    assert_eq!(hosts, [C, A, B], "by hostname: db-01, web-01, web-02");
    let a = &page.rows[1];
    assert_eq!(a.update_to.as_deref(), Some("3.0.12"));
    assert_eq!(a.versions[0].version, "3.0.11");
    assert_eq!(
        page.rows[0].update_to, None,
        "C waits for a reboot, not an update"
    );
    assert_eq!(page.rows[2].update_to, None, "B's pair is a false positive");
    let update = software_hosts_page(
        &c,
        &scope,
        "openssl",
        SoftwareSegment::Update,
        0,
        50,
        Utc::now(),
    )
    .await
    .unwrap();
    assert_eq!(
        update
            .rows
            .iter()
            .map(|r| r.agent_id.as_str())
            .collect::<Vec<_>>(),
        [A]
    );
    assert_eq!(update.total, 1);
    let current = software_hosts_page(
        &c,
        &scope,
        "openssl",
        SoftwareSegment::Current,
        1,
        1,
        Utc::now(),
    )
    .await
    .unwrap();
    assert_eq!((current.total, current.rows.len()), (2, 1));
    let kernel = software_hosts_page(
        &c,
        &scope,
        "linux-image",
        SoftwareSegment::All,
        0,
        50,
        Utc::now(),
    )
    .await
    .unwrap();
    assert_eq!(
        kernel.rows[0]
            .versions
            .iter()
            .map(|v| v.version.as_str())
            .collect::<Vec<_>>(),
        ["6.1.1", "6.1.0"],
        "newest first"
    );
    let ssh = software_hosts_page(
        &c,
        &scope,
        "openssh-server",
        SoftwareSegment::All,
        0,
        50,
        Utc::now(),
    )
    .await
    .unwrap();
    assert_eq!(ssh.rows[0].used_by, ["sshd.service"]);
    let nothing = software_hosts_page(
        &c,
        &scope,
        "nothing",
        SoftwareSegment::All,
        0,
        50,
        Utc::now(),
    )
    .await
    .unwrap();
    assert!(nothing.rows.is_empty());
    assert_eq!(nothing.total, 0);
    db.drop().await;
}
