//! The Services list query (roles spec §10.3; step 5f rulings 1–10): one row
//! per unit over the hosts in scope, one host counted once per unit.

mod common;

use chrono::Utc;
use platform_store::{
    console_read::AgentScope,
    service_list::{
        Changes, Listens, Packaged, RunsAs, ServiceListPage, ServiceListRow, ServiceQuery,
        ServiceSort, service_list,
    },
};

use common::services::{A, B, fixture};

fn query() -> ServiceQuery<'static> {
    ServiceQuery {
        q: None,
        runs_as: None,
        listens: None,
        packaged: None,
        group: None,
        changes: None,
        host: None,
        sort: ServiceSort::Service,
        descending: false,
        offset: 0,
        limit: 50,
    }
}

async fn run(
    c: &mut deadpool_postgres::Client,
    q: &ServiceQuery<'_>,
    scope: &AgentScope,
) -> ServiceListPage {
    service_list(c, q, scope, Utc::now()).await.unwrap()
}

fn units(page: &ServiceListPage) -> Vec<&str> {
    page.rows.iter().map(|r| r.unit.as_str()).collect()
}

fn row<'a>(page: &'a ServiceListPage, unit: &str) -> &'a ServiceListRow {
    page.rows
        .iter()
        .find(|r| r.unit == unit)
        .unwrap_or_else(|| panic!("no row {unit}"))
}

fn count<T: PartialEq>(counts: &[(T, i64)], value: T) -> i64 {
    counts.iter().find(|(v, _)| *v == value).unwrap().1
}

#[tokio::test]
async fn one_row_per_unit_stays_inside_the_scope() {
    let (db, mut c) = common::migrated().await;
    let (mine, _) = fixture(&c).await;
    let page = run(&mut c, &query(), &AgentScope::AssetGroups(vec![mine])).await;
    assert_eq!(
        units(&page),
        [
            "cups.service",
            "mystery.service",
            "named.service",
            "nginx.service",
            "postgresql.service",
            "sshd.service"
        ]
    );
    assert_eq!(page.total, 6);
    let ssh = row(&page, "sshd.service");
    assert_eq!(
        (ssh.hosts, ssh.root_hosts, ssh.package_hosts),
        (3, 3, 3),
        "A, B, C; not the revoked or outside host"
    );
    assert_eq!(ssh.name, Some("OpenSSH server"));
    assert_eq!(ssh.package.as_deref(), Some("openssh-server"));
    assert_eq!(ssh.run_as, ["root"]);
    assert_eq!(ssh.programs, ["sshd"]);
    assert_eq!(
        ssh.ports
            .iter()
            .map(|p| (p.port, p.exposed, p.hosts))
            .collect::<Vec<_>>(),
        [(22, true, 3)]
    );
    let nginx = row(&page, "nginx.service");
    assert_eq!((nginx.hosts, nginx.root_hosts), (2, 0));
    assert_eq!((nginx.exposed_hosts, nginx.listening_hosts), (2, 2));
    let pg = row(&page, "postgresql.service");
    assert_eq!(
        (pg.exposed_hosts, pg.listening_hosts),
        (1, 2),
        "A is loopback only"
    );
    assert_eq!(pg.run_as, ["postgres"]);
    assert_eq!(page.summary.reporting_hosts, 3);
    let global = run(&mut c, &query(), &AgentScope::Global).await;
    assert!(units(&global).contains(&"far.service"));
    assert_eq!(row(&global, "sshd.service").hosts, 4);
    db.drop().await;
}

#[tokio::test]
async fn packages_match_by_name_and_the_map() {
    let (db, mut c) = common::migrated().await;
    let (mine, _) = fixture(&c).await;
    let page = run(&mut c, &query(), &AgentScope::AssetGroups(vec![mine])).await;
    assert_eq!(
        row(&page, "nginx.service").package.as_deref(),
        Some("nginx")
    );
    assert_eq!(
        row(&page, "named.service").package.as_deref(),
        Some("bind"),
        "the map names bind for named"
    );
    assert_eq!(row(&page, "cups.service").package, None);
    assert_eq!(row(&page, "mystery.service").package_hosts, 0);
    db.drop().await;
}

/// A stock host runs systemd-journald, getty@ and the like as root; their
/// packages are systemd and util-linux, so none of them needs a look.
#[tokio::test]
async fn stock_system_units_come_from_their_packages() {
    let (db, mut c) = common::migrated().await;
    let (mine, _) = fixture(&c).await;
    for unit in [
        "systemd-journald.service",
        "systemd-resolved.service",
        "getty@tty1.service",
        "serial-getty@ttyS0.service",
    ] {
        c.execute(
            "INSERT INTO host_services (agent_id, unit, programs, processes, run_as)
             VALUES ($1, $2, '{x}', 1, 'root')",
            &[&A, &unit],
        )
        .await
        .unwrap();
    }
    for name in ["systemd", "util-linux"] {
        let id: i64 = c
            .query_one(
                "INSERT INTO package_versions (manager, name, version, arch)
                 VALUES ('deb', $1, '252', 'amd64') RETURNING id",
                &[&name],
            )
            .await
            .unwrap()
            .get(0);
        c.execute(
            "INSERT INTO host_packages (agent_id, package_version_id) VALUES ($1, $2)",
            &[&A, &id],
        )
        .await
        .unwrap();
    }
    let page = run(&mut c, &query(), &AgentScope::AssetGroups(vec![mine])).await;
    for (unit, package) in [
        ("systemd-journald.service", "systemd"),
        ("systemd-resolved.service", "systemd"),
        ("getty@tty1.service", "systemd"),
        ("serial-getty@ttyS0.service", "systemd"),
    ] {
        let r = row(&page, unit);
        assert!(r.look.is_empty(), "{unit}: {:?}", r.look);
        assert_eq!(r.package_hosts, 1, "{unit}");
        assert_eq!(r.package.as_deref(), Some(package), "{unit}");
    }
    db.drop().await;
}

#[tokio::test]
async fn needs_a_look_and_this_week() {
    let (db, mut c) = common::migrated().await;
    let (mine, _) = fixture(&c).await;
    let page = run(&mut c, &query(), &AgentScope::AssetGroups(vec![mine])).await;
    assert_eq!(row(&page, "cups.service").look, ["root_unpackaged"]);
    assert_eq!(
        row(&page, "mystery.service").look,
        ["root_unpackaged", "new_unusual"]
    );
    assert_eq!(row(&page, "postgresql.service").look, ["database_exposed"]);
    assert!(row(&page, "sshd.service").look.is_empty());
    assert_eq!(
        (
            row(&page, "mystery.service").week_added,
            row(&page, "mystery.service").week_removed
        ),
        (1, 0)
    );
    assert_eq!(
        (
            row(&page, "cups.service").week_added,
            row(&page, "cups.service").week_removed
        ),
        (0, 1)
    );
    assert_eq!(
        row(&page, "nginx.service").week_added,
        0,
        "40 days ago is not this week"
    );
    let s = &page.summary;
    assert_eq!((s.root, s.exposed, s.not_packaged), (4, 4, 2));
    assert_eq!((s.new_this_week, s.need_a_look), (1, 3));
    db.drop().await;
}

#[tokio::test]
async fn filters_and_their_counts() {
    let (db, mut c) = common::migrated().await;
    let (mine, web) = fixture(&c).await;
    let scope = AgentScope::AssetGroups(vec![mine]);

    let q = ServiceQuery {
        runs_as: Some(RunsAs::Other),
        ..query()
    };
    assert_eq!(
        units(&run(&mut c, &q, &scope).await),
        ["nginx.service", "postgresql.service"]
    );

    let q = ServiceQuery {
        listens: Some(Listens::Local),
        ..query()
    };
    assert_eq!(units(&run(&mut c, &q, &scope).await), ["cups.service"]);
    let q = ServiceQuery {
        listens: Some(Listens::None),
        ..query()
    };
    assert_eq!(units(&run(&mut c, &q, &scope).await), ["mystery.service"]);
    let q = ServiceQuery {
        listens: Some(Listens::Exposed),
        ..query()
    };
    assert_eq!(
        units(&run(&mut c, &q, &scope).await),
        [
            "named.service",
            "nginx.service",
            "postgresql.service",
            "sshd.service"
        ]
    );

    let q = ServiceQuery {
        packaged: Some(Packaged::No),
        ..query()
    };
    assert_eq!(
        units(&run(&mut c, &q, &scope).await),
        ["cups.service", "mystery.service"]
    );
    let q = ServiceQuery {
        packaged: Some(Packaged::Yes),
        ..query()
    };
    assert_eq!(run(&mut c, &q, &scope).await.total, 4);

    let q = ServiceQuery {
        changes: Some(Changes::New),
        ..query()
    };
    assert_eq!(units(&run(&mut c, &q, &scope).await), ["mystery.service"]);
    let q = ServiceQuery {
        changes: Some(Changes::Look),
        ..query()
    };
    assert_eq!(run(&mut c, &q, &scope).await.total, 3);

    let q = ServiceQuery {
        host: Some(A),
        ..query()
    };
    assert_eq!(
        units(&run(&mut c, &q, &scope).await),
        ["nginx.service", "postgresql.service", "sshd.service"]
    );
    let q = ServiceQuery {
        group: Some(&web),
        ..query()
    };
    let page = run(&mut c, &q, &scope).await;
    assert_eq!(
        units(&page),
        [
            "cups.service",
            "mystery.service",
            "named.service",
            "nginx.service",
            "postgresql.service",
            "sshd.service"
        ],
        "web-01 and web-02 between them run all but nothing else"
    );

    // Counts apply the other filters but not their own.
    let q = ServiceQuery {
        runs_as: Some(RunsAs::Other),
        packaged: Some(Packaged::No),
        ..query()
    };
    let page = run(&mut c, &q, &scope).await;
    assert_eq!(page.total, 0);
    assert_eq!(
        count(&page.counts.runs_as, RunsAs::Root),
        2,
        "cups and mystery"
    );
    assert_eq!(count(&page.counts.runs_as, RunsAs::Other), 0);
    assert_eq!(
        count(&page.counts.packaged, Packaged::Yes),
        2,
        "nginx and postgresql run as other users"
    );
    assert_eq!(count(&page.counts.listens, Listens::None), 0);
    db.drop().await;
}

#[tokio::test]
async fn search_covers_unit_name_program_package_and_port() {
    let (db, mut c) = common::migrated().await;
    let (mine, _) = fixture(&c).await;
    let scope = AgentScope::AssetGroups(vec![mine]);
    for (text, want) in [
        ("ngin", vec!["nginx.service"]),
        ("secure remote", vec!["sshd.service"]),
        ("helper", vec!["mystery.service"]),
        ("bind", vec!["named.service"]),
        ("5432/tcp", vec!["postgresql.service"]),
        ("POSTGRES", vec!["postgresql.service"]),
        ("zzz", vec![]),
    ] {
        let q = ServiceQuery {
            q: Some(text),
            ..query()
        };
        assert_eq!(units(&run(&mut c, &q, &scope).await), want, "{text}");
    }
    db.drop().await;
}

#[tokio::test]
async fn sorts_and_pages_are_stable() {
    let (db, mut c) = common::migrated().await;
    let (mine, _) = fixture(&c).await;
    let scope = AgentScope::AssetGroups(vec![mine]);
    let q = ServiceQuery {
        sort: ServiceSort::Hosts,
        descending: true,
        ..query()
    };
    assert_eq!(units(&run(&mut c, &q, &scope).await)[0], "sshd.service");
    let q = ServiceQuery {
        sort: ServiceSort::Week,
        descending: true,
        ..query()
    };
    assert_eq!(units(&run(&mut c, &q, &scope).await)[0], "mystery.service");
    let q = ServiceQuery {
        limit: 2,
        offset: 4,
        ..query()
    };
    let page = run(&mut c, &q, &scope).await;
    assert_eq!(units(&page), ["postgresql.service", "sshd.service"]);
    assert_eq!(page.total, 6);
    let q = ServiceQuery {
        offset: 50,
        ..query()
    };
    let page = run(&mut c, &q, &scope).await;
    assert!(page.rows.is_empty());
    assert_eq!(page.total, 6, "an empty page still carries the total");
    let _ = B;
    db.drop().await;
}

#[tokio::test]
async fn the_sql_base_equals_the_rust_base() {
    let (db, c) = common::migrated().await;
    let sql = format!(
        "SELECT {}",
        platform_store::service_names::base_sql("$1::text")
    );
    for unit in [
        "sshd.service",
        "PostgreSQL@16-main.service",
        "getty@tty1.service",
        "a@b.c.service",
        "telnet.socket",
        "Spooler",
        "x.service.service",
    ] {
        let from_sql: String = c.query_one(&sql, &[&unit]).await.unwrap().get(0);
        assert_eq!(
            from_sql,
            platform_store::service_names::base(unit),
            "{unit}"
        );
    }
    db.drop().await;
}
