//! The Ports list query (roles spec §10.3; step 5e rulings 11–17): one row
//! per port over the hosts in scope, one host counted once per port.

mod common;

use chrono::Utc;
use platform_store::{
    console_read::AgentScope,
    port_list::{
        Changes, Exposure, PortListPage, PortListRow, PortQuery, PortSort, ProtocolFilter,
        ServiceFilter, port_list,
    },
};

use common::ports::{C, fixture};

fn query() -> PortQuery<'static> {
    PortQuery {
        q: None,
        exposure: None,
        protocol: None,
        group: None,
        service: None,
        changes: None,
        host: None,
        sort: PortSort::Port,
        descending: false,
        offset: 0,
        limit: 50,
    }
}

async fn run(c: &deadpool_postgres::Client, q: &PortQuery<'_>, scope: &AgentScope) -> PortListPage {
    port_list(c, q, scope, Utc::now()).await.unwrap()
}

fn keys(page: &PortListPage) -> Vec<String> {
    page.rows
        .iter()
        .map(|r| format!("{}/{}", r.protocol, r.port))
        .collect()
}

fn row<'a>(page: &'a PortListPage, key: &str) -> &'a PortListRow {
    page.rows
        .iter()
        .find(|r| format!("{}/{}", r.protocol, r.port) == key)
        .unwrap_or_else(|| panic!("no row {key}"))
}

fn count<T: PartialEq>(counts: &[(T, i64)], value: T) -> i64 {
    counts.iter().find(|(v, _)| *v == value).unwrap().1
}

#[tokio::test]
async fn one_row_per_port_and_a_host_counts_once() {
    let (db, c) = common::migrated().await;
    let (mine, _) = fixture(&c).await;
    let page = run(&c, &query(), &AgentScope::AssetGroups(vec![mine])).await;
    assert_eq!(
        keys(&page),
        [
            "tcp/22", "udp/53", "tcp/443", "tcp/631", "tcp/5432", "tcp/9999"
        ]
        .map(String::from)
    );
    assert_eq!(page.total, 6);
    let ssh = row(&page, "tcp/22");
    assert_eq!(
        (ssh.hosts, ssh.exposed_hosts),
        (3, 3),
        "A binds two addresses; the revoked host is out"
    );
    assert_eq!(ssh.name, Some("SSH"));
    assert_eq!(ssh.services, ["sshd.service"]);
    let web = row(&page, "tcp/443");
    assert_eq!(
        (web.hosts, web.exposed_hosts),
        (2, 2),
        "B has a loopback and a LAN address"
    );
    let pg = row(&page, "tcp/5432");
    assert_eq!((pg.hosts, pg.exposed_hosts), (2, 1));
    let cups = row(&page, "tcp/631");
    assert_eq!((cups.hosts, cups.exposed_hosts), (1, 0));
    assert_eq!(row(&page, "tcp/9999").name, None);
    assert!(row(&page, "tcp/9999").owners_missing);
    assert!(!ssh.owners_missing);
    assert_eq!(
        page.summary.reporting_hosts, 3,
        "A, B, C; not the revoked or outside host"
    );
    db.drop().await;
}

#[tokio::test]
async fn port_list_counts_stay_inside_the_scope() {
    let (db, c) = common::migrated().await;
    let (mine, _) = fixture(&c).await;
    let scoped = run(&c, &query(), &AgentScope::AssetGroups(vec![mine])).await;
    let global = run(&c, &query(), &AgentScope::Global).await;
    assert!(!keys(&scoped).contains(&"tcp/7777".to_string()));
    assert!(keys(&global).contains(&"tcp/7777".to_string()));
    assert_eq!(row(&global, "tcp/22").hosts, 4);
    assert_eq!(row(&scoped, "tcp/22").hosts, 3);
    assert_eq!(global.summary.reporting_hosts, 4);
    assert_eq!(scoped.summary.reporting_hosts, 3);
    // This week: the outside host's appearance is not counted for the scope.
    assert_eq!(row(&scoped, "tcp/22").week_added, 1);
    assert_eq!(row(&scoped, "tcp/22").week_removed, 1);
    assert!(scoped.rows.iter().all(|r| r.port != 7777));
    assert_eq!(count(&scoped.counts.protocol, ProtocolFilter::Tcp), 5);
    assert_eq!(count(&global.counts.protocol, ProtocolFilter::Tcp), 6);
    assert!(
        scoped
            .counts
            .services
            .iter()
            .all(|(unit, _)| unit != "far.service")
    );
    db.drop().await;
}

#[tokio::test]
async fn every_filter_and_its_counts() {
    let (db, c) = common::migrated().await;
    let (mine, web) = fixture(&c).await;
    let scope = AgentScope::AssetGroups(vec![mine]);

    let local = run(
        &c,
        &PortQuery {
            exposure: Some(Exposure::Local),
            ..query()
        },
        &scope,
    )
    .await;
    assert_eq!(keys(&local), ["tcp/631"]);
    let exposed = run(
        &c,
        &PortQuery {
            exposure: Some(Exposure::Exposed),
            ..query()
        },
        &scope,
    )
    .await;
    assert_eq!(exposed.total, 5);
    // The counts of a filter's values leave its own condition out.
    assert_eq!(count(&local.counts.exposure, Exposure::Exposed), 5);
    assert_eq!(count(&local.counts.exposure, Exposure::Local), 1);

    let udp = run(
        &c,
        &PortQuery {
            protocol: Some(ProtocolFilter::Udp),
            ..query()
        },
        &scope,
    )
    .await;
    assert_eq!(keys(&udp), ["udp/53"]);
    assert_eq!(count(&udp.counts.protocol, ProtocolFilter::Tcp), 5);
    assert_eq!(
        count(&udp.counts.exposure, Exposure::Local),
        0,
        "udp/53 is exposed"
    );

    let new = run(
        &c,
        &PortQuery {
            changes: Some(Changes::New),
            ..query()
        },
        &scope,
    )
    .await;
    assert_eq!(keys(&new), ["tcp/22", "tcp/9999"]);
    let look = run(
        &c,
        &PortQuery {
            changes: Some(Changes::Look),
            ..query()
        },
        &scope,
    )
    .await;
    assert_eq!(keys(&look), ["tcp/5432", "tcp/9999"]);
    assert_eq!(count(&look.counts.changes, Changes::New), 2);
    assert_eq!(count(&look.counts.changes, Changes::Look), 2);
    assert_eq!(look.summary.need_a_look, 2);
    assert_eq!(look.summary.new_this_week, 1);
    assert_eq!(look.summary.exposed, 2);

    let nginx = run(
        &c,
        &PortQuery {
            service: Some(ServiceFilter::Unit("nginx.service")),
            ..query()
        },
        &scope,
    )
    .await;
    assert_eq!(keys(&nginx), ["tcp/443"]);
    let none = run(
        &c,
        &PortQuery {
            service: Some(ServiceFilter::NotCollected),
            ..query()
        },
        &scope,
    )
    .await;
    assert_eq!(keys(&none), ["tcp/9999"]);
    assert_eq!(none.counts.owner_not_collected, 1);
    assert!(
        none.counts
            .services
            .contains(&("sshd.service".to_string(), 1))
    );

    let grouped = run(
        &c,
        &PortQuery {
            group: Some(&web),
            ..query()
        },
        &scope,
    )
    .await;
    assert_eq!(
        keys(&grouped),
        [
            "tcp/22", "udp/53", "tcp/443", "tcp/631", "tcp/5432", "tcp/9999"
        ]
        .map(String::from),
        "every port has a web host"
    );
    let only_c = run(
        &c,
        &PortQuery {
            host: Some(C),
            ..query()
        },
        &scope,
    )
    .await;
    assert_eq!(keys(&only_c), ["tcp/22", "tcp/5432"]);
    let web_count = grouped.counts.groups.iter().find(|g| g.0 == web).unwrap();
    assert_eq!((web_count.1.as_str(), web_count.3), ("Web", 6));
    db.drop().await;
}

#[tokio::test]
async fn needs_a_look_rules() {
    let (db, c) = common::migrated().await;
    let (mine, _) = fixture(&c).await;
    let page = run(&c, &query(), &AgentScope::AssetGroups(vec![mine])).await;
    assert_eq!(row(&page, "tcp/5432").look, ["database_exposed"]);
    assert_eq!(row(&page, "tcp/9999").look, ["new_unusual"]);
    assert!(row(&page, "tcp/22").look.is_empty(), "SSH is not flagged");
    assert!(row(&page, "tcp/631").look.is_empty());
    db.drop().await;
}

#[tokio::test]
async fn search_covers_number_key_name_and_owner() {
    let (db, c) = common::migrated().await;
    let (mine, _) = fixture(&c).await;
    let scope = AgentScope::AssetGroups(vec![mine]);
    for (q, want) in [
        ("5432", vec!["tcp/5432"]),
        ("22/tcp", vec!["tcp/22"]),
        ("tcp/22", vec!["tcp/22"]),
        ("postgres", vec!["tcp/5432"]),
        ("POSTGRESQL.service", vec!["tcp/5432"]),
        ("nginx", vec!["tcp/443"]),
        ("secure remote", vec!["tcp/22"]),
        ("nothing", vec![]),
    ] {
        let page = run(
            &c,
            &PortQuery {
                q: Some(q),
                ..query()
            },
            &scope,
        )
        .await;
        assert_eq!(keys(&page), want, "search {q}");
    }
    db.drop().await;
}

#[tokio::test]
async fn sorts_and_pages_are_stable() {
    let (db, c) = common::migrated().await;
    let (mine, _) = fixture(&c).await;
    let scope = AgentScope::AssetGroups(vec![mine]);
    let by_hosts = run(
        &c,
        &PortQuery {
            sort: PortSort::Hosts,
            descending: true,
            ..query()
        },
        &scope,
    )
    .await;
    assert_eq!(keys(&by_hosts)[0], "tcp/22");
    assert_eq!(
        keys(&by_hosts)[1],
        "tcp/5432",
        "ties: higher port first when descending"
    );
    let week = run(
        &c,
        &PortQuery {
            sort: PortSort::Week,
            descending: true,
            ..query()
        },
        &scope,
    )
    .await;
    assert_eq!(keys(&week)[..2], ["tcp/9999", "tcp/22"]);
    let exposed = run(
        &c,
        &PortQuery {
            sort: PortSort::Exposed,
            descending: true,
            ..query()
        },
        &scope,
    )
    .await;
    assert_eq!(keys(&exposed)[0], "tcp/22");
    let mut seen = Vec::new();
    for offset in [0, 2, 4, 6] {
        let page = run(
            &c,
            &PortQuery {
                offset,
                limit: 2,
                ..query()
            },
            &scope,
        )
        .await;
        assert_eq!(page.total, 6);
        seen.extend(keys(&page));
    }
    assert_eq!(seen, keys(&run(&c, &query(), &scope).await));
    let beyond = run(
        &c,
        &PortQuery {
            offset: 100,
            ..query()
        },
        &scope,
    )
    .await;
    assert!(beyond.rows.is_empty());
    assert_eq!(beyond.total, 6, "the meta still answers on an empty page");
    db.drop().await;
}

#[tokio::test]
async fn groups_column_names_rule_groups_not_manual_ones() {
    let (db, c) = common::migrated().await;
    let (mine, web) = fixture(&c).await;
    let page = run(&c, &query(), &AgentScope::AssetGroups(vec![mine])).await;
    let ssh = row(&page, "tcp/22");
    assert_eq!(ssh.groups.len(), 1, "the manual group is left out");
    assert_eq!(
        (
            ssh.groups[0].id.as_str(),
            ssh.groups[0].name.as_str(),
            ssh.groups[0].hosts
        ),
        (web.as_str(), "Web", 2)
    );
    assert_eq!(ssh.groups_total, 1);
    assert!(
        page.counts.groups.iter().any(|g| g.1 == "mine"),
        "the filter still offers it"
    );
    db.drop().await;
}
