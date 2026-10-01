//! Console reads of installed software (assets v1), run as the
//! `openvibes-console` role: a host's packages, the fleet's software, one
//! package's versions and hosts; vulnerable flags; scoped counts.

mod common;

use common::TestDb;
use platform_store::{
    Client,
    console_inventory::{self, SoftwareFilters},
    console_read::AgentScope,
};

const WEB: &str = "agent.00000000-0000-4000-8000-000000000001";
const DB: &str = "agent.00000000-0000-4000-8000-000000000002";
const IMPORTED: &str = "import.00000000000000000000000000000003";
const REVOKED: &str = "agent.00000000-0000-4000-8000-000000000004";
const PROD: &str = "00000000-0000-4000-8000-0000000000a1";

/// web-01 (tag env=prod): openssl 3.0.13 (an open fixable vulnerability),
/// bash 5.2 (only a no-fix vulnerability: not flagged), glibc for two
/// architectures.
/// db-01 (env=dev): openssl 3.0.14 (its vulnerability is fixed), bash 5.2.
/// An imported host: openssl 3.0.13. A revoked agent: openssl and bash
/// (it is not a host any more and never counts).
async fn setup() -> TestDb {
    let db = TestDb::create().await;
    let mut admin = db.pool.get().await.unwrap();
    platform_store::migrate(&mut admin).await.unwrap();
    admin
        .batch_execute(&format!(
            "INSERT INTO agents (agent_id, status, enrolled_at, hostname, last_seen_at) VALUES
                ('{WEB}', 'active', now(), 'web-01', now()),
                ('{DB}', 'active', now(), 'db-01', now()),
                ('{IMPORTED}', 'imported', now(), 'old-01', NULL),
                ('{REVOKED}', 'revoked', now(), 'gone-01', now());
             INSERT INTO console_agent_tags VALUES
                ('{WEB}', 'env', 'prod', now(), 't'), ('{DB}', 'env', 'dev', now(), 't');
             INSERT INTO console_asset_groups VALUES ('{PROD}', 'prod', now(), 't');
             INSERT INTO console_asset_group_selectors VALUES ('{PROD}', 'env', 'prod', now());
             INSERT INTO package_versions (id, manager, name, epoch, version, release, arch) VALUES
                (1, 'rpm', 'openssl', 1, '3.0.13', '1.fc44', 'x86_64'),
                (2, 'rpm', 'openssl', 1, '3.0.14', '1.fc44', 'x86_64'),
                (3, 'rpm', 'bash', 0, '5.2', '1.fc44', 'x86_64'),
                (4, 'rpm', 'glibc', 0, '2.41', '1.fc44', 'x86_64'),
                (5, 'rpm', 'glibc', 0, '2.41', '1.fc44', 'i686');
             INSERT INTO host_packages VALUES
                ('{WEB}', 1), ('{WEB}', 3), ('{WEB}', 4), ('{WEB}', 5),
                ('{DB}', 2), ('{DB}', 3), ('{IMPORTED}', 1), ('{REVOKED}', 1), ('{REVOKED}', 3);
             INSERT INTO advisories (advisory_id, source, os_id, os_version, severity, title, url)
             VALUES ('FEDORA-1', 'fedora', 'fedora', '44', 'important', 'openssl', 'https://x'),
                    ('FEDORA-2', 'fedora', 'fedora', '44', 'low', 'bash', 'https://x');
             INSERT INTO vulnerabilities (agent_id, advisory_id, packages, first_seen_at,
                fixed_at, last_evaluated_at) VALUES
                ('{WEB}', 'FEDORA-1',
                 '[{{\"name\": \"openssl\", \"installed\": \"1:3.0.13-1.fc44\", \"fixed\": \"1:3.0.14-1.fc44\"}}]',
                 now(), NULL, now()),
                ('{DB}', 'FEDORA-1',
                 '[{{\"name\": \"openssl\", \"installed\": \"1:3.0.13-1.fc44\", \"fixed\": \"1:3.0.14-1.fc44\"}}]',
                 now(), now(), now());
             INSERT INTO version_vulnerabilities VALUES (3, 'FEDORA-2', 'bash', now());"
        ))
        .await
        .unwrap();
    db
}

async fn as_console(db: &TestDb) -> Client {
    let client = db.pool.get().await.unwrap();
    client
        .batch_execute("SET ROLE \"openvibes-console\"")
        .await
        .unwrap();
    client
}

fn prod() -> AgentScope {
    AgentScope::AssetGroups(vec![PROD.into()])
}

#[tokio::test]
async fn a_hosts_packages_are_sorted_paged_filtered_and_flagged() {
    let db = setup().await;
    let client = as_console(&db).await;
    let all = console_inventory::host_packages(&client, &AgentScope::Global, WEB, None, None, 10)
        .await
        .unwrap()
        .unwrap();
    let names: Vec<(&str, &str, bool)> = all
        .iter()
        .map(|(_, p)| (p.name.as_str(), p.arch.as_str(), p.fixable_vulnerable))
        .collect();
    assert_eq!(
        names,
        [
            ("bash", "x86_64", false),
            ("glibc", "x86_64", false),
            ("glibc", "i686", false),
            ("openssl", "x86_64", true)
        ]
    );
    // Keyset paging over (name, id): the multilib pair splits cleanly.
    let first = console_inventory::host_packages(&client, &AgentScope::Global, WEB, None, None, 2)
        .await
        .unwrap()
        .unwrap();
    let (last_id, last) = first.last().unwrap();
    let rest = console_inventory::host_packages(
        &client,
        &AgentScope::Global,
        WEB,
        None,
        Some((last.name.as_str(), *last_id)),
        10,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(first.len() + rest.len(), 4);
    assert_eq!(rest[0].1.arch, "i686");
    // q: a case-insensitive substring; `%` is a plain character.
    let ssl =
        console_inventory::host_packages(&client, &AgentScope::Global, WEB, Some("SSL"), None, 10)
            .await
            .unwrap()
            .unwrap();
    assert_eq!(ssl.len(), 1);
    let none =
        console_inventory::host_packages(&client, &AgentScope::Global, WEB, Some("%"), None, 10)
            .await
            .unwrap()
            .unwrap();
    assert!(none.is_empty());
    // db-01's openssl vulnerability is fixed: not vulnerable.
    let db_packages =
        console_inventory::host_packages(&client, &AgentScope::Global, DB, None, None, 10)
            .await
            .unwrap()
            .unwrap();
    assert!(
        db_packages
            .iter()
            .any(|(_, p)| p.name == "openssl" && !p.fixable_vulnerable)
    );
    db.drop().await;
}

#[tokio::test]
async fn a_host_outside_the_scope_reads_as_absent() {
    let db = setup().await;
    let client = as_console(&db).await;
    assert!(
        console_inventory::host_packages(&client, &prod(), DB, None, None, 10)
            .await
            .unwrap()
            .is_none()
    );
    // Imported hosts are visible only to a global caller.
    assert!(
        console_inventory::host_packages(&client, &prod(), IMPORTED, None, None, 10)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        console_inventory::host_packages(&client, &AgentScope::Global, IMPORTED, None, None, 10)
            .await
            .unwrap()
            .is_some()
    );
    // A revoked agent is not a host: absent even to a global caller.
    assert!(
        console_inventory::host_packages(&client, &AgentScope::Global, REVOKED, None, None, 10)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        console_inventory::host_packages(&client, &prod(), WEB, None, None, 10)
            .await
            .unwrap()
            .is_some()
    );
    db.drop().await;
}

#[tokio::test]
async fn fleet_software_counts_only_visible_hosts() {
    let db = setup().await;
    let client = as_console(&db).await;
    let all = SoftwareFilters::default();
    let global = console_inventory::software(&client, &AgentScope::Global, &all, None, 10)
        .await
        .unwrap();
    let row = |rows: &[console_inventory::Software], name: &str| {
        rows.iter()
            .find(|s| s.name == name)
            .map(|s| (s.hosts, s.versions, s.fixable_vulnerable_hosts))
    };
    // openssl: web-01, db-01, the imported host; two versions; only web-01
    // has it open (the imported host has no vulnerability rows).
    assert_eq!(row(&global, "openssl"), Some((3, 2, 1)));
    assert_eq!(row(&global, "bash"), Some((2, 1, 0)));
    assert_eq!(row(&global, "glibc"), Some((1, 1, 0)));
    let names: Vec<&str> = global.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(names, ["bash", "glibc", "openssl"]);

    // A scoped caller's counts never reveal hosts outside the scope.
    let scoped = console_inventory::software(&client, &prod(), &all, None, 10)
        .await
        .unwrap();
    assert_eq!(row(&scoped, "openssl"), Some((1, 1, 1)));
    assert_eq!(row(&scoped, "bash"), Some((1, 1, 0)));

    // Vulnerable only, a name filter, and the keyset cursor.
    let vulnerable = SoftwareFilters {
        fixable: true,
        ..SoftwareFilters::default()
    };
    let flagged = console_inventory::software(&client, &AgentScope::Global, &vulnerable, None, 10)
        .await
        .unwrap();
    assert_eq!(
        flagged.iter().map(|s| s.name.as_str()).collect::<Vec<_>>(),
        ["openssl"]
    );
    let after =
        console_inventory::software(&client, &AgentScope::Global, &all, Some(("bash", "rpm")), 1)
            .await
            .unwrap();
    assert_eq!(after[0].name, "glibc");
    let ssl = SoftwareFilters {
        q: Some("ssl".into()),
        ..SoftwareFilters::default()
    };
    assert_eq!(
        console_inventory::software(&client, &AgentScope::Global, &ssl, None, 10)
            .await
            .unwrap()
            .len(),
        1
    );
    db.drop().await;
}

#[tokio::test]
async fn one_packages_versions_and_hosts() {
    let db = setup().await;
    let client = as_console(&db).await;
    let versions =
        console_inventory::software_versions(&client, &AgentScope::Global, "rpm", "openssl")
            .await
            .unwrap();
    let summary: Vec<(&str, i64, i64)> = versions
        .iter()
        .map(|v| (v.version.as_str(), v.hosts, v.fixable_vulnerable_hosts))
        .collect();
    assert_eq!(summary, [("3.0.13", 2, 1), ("3.0.14", 1, 0)]);
    let hosts =
        console_inventory::software_hosts(&client, &AgentScope::Global, "rpm", "openssl", None, 10)
            .await
            .unwrap();
    let rows: Vec<(&str, &str, bool)> = hosts
        .iter()
        .map(|(_, h)| {
            (
                h.hostname.as_deref().unwrap(),
                h.version.as_str(),
                h.fixable_vulnerable,
            )
        })
        .collect();
    assert_eq!(
        rows,
        [
            ("db-01", "1:3.0.14-1.fc44", false),
            ("old-01", "1:3.0.13-1.fc44", false),
            ("web-01", "1:3.0.13-1.fc44", true)
        ]
    );
    // Paging over (hostname, agent, version row) keeps a multilib host's
    // two rows apart.
    let glibc =
        console_inventory::software_hosts(&client, &AgentScope::Global, "rpm", "glibc", None, 1)
            .await
            .unwrap();
    let (id, host) = &glibc[0];
    let next = console_inventory::software_hosts(
        &client,
        &AgentScope::Global,
        "rpm",
        "glibc",
        Some((
            host.hostname.as_deref().unwrap(),
            host.agent_id.as_str(),
            *id,
        )),
        10,
    )
    .await
    .unwrap();
    assert_eq!(next.len(), 1);
    assert_ne!(next[0].1.arch, host.arch);
    // Scoped: only web-01; a package no visible host has is empty.
    assert_eq!(
        console_inventory::software_hosts(&client, &prod(), "rpm", "openssl", None, 10)
            .await
            .unwrap()
            .len(),
        1
    );
    assert!(
        console_inventory::software_versions(&client, &prod(), "rpm", "nothing")
            .await
            .unwrap()
            .is_empty()
    );
    db.drop().await;
}

/// Design §4: the fleet aggregate on 1,000 hosts × 2,000 packages (2 M
/// host_packages rows, three versions per name), 50 open fixable
/// vulnerabilities per host (50 k rows over 100 advisories), and an asset
/// group of 100 hosts. Prints timings.
/// `cargo test --release -p platform-store --test console_inventory -- --ignored --nocapture`
#[tokio::test]
#[ignore = "measurement: builds a 2 M-row fixture"]
async fn measure_the_fleet_aggregate_on_1000_hosts() {
    let db = TestDb::create().await;
    let mut admin = db.pool.get().await.unwrap();
    platform_store::migrate(&mut admin).await.unwrap();
    admin
        .batch_execute(
            "SET statement_timeout = 0;
             INSERT INTO agents (agent_id, status, enrolled_at, hostname, last_seen_at)
             SELECT 'agent.00000000-0000-4000-8000-' || lpad(h::text, 12, '0'), 'active', now(),
                    'host-' || lpad(h::text, 4, '0'), now()
             FROM generate_series(1, 1000) h;
             INSERT INTO package_versions (manager, name, version, release, arch)
             SELECT 'rpm', 'pkg-' || lpad(p::text, 4, '0'), '1.' || v, '1.fc44', 'x86_64'
             FROM generate_series(1, 2000) p, generate_series(0, 2) v;
             INSERT INTO host_packages
             SELECT 'agent.00000000-0000-4000-8000-' || lpad(h::text, 12, '0'), pv.id
             FROM generate_series(1, 1000) h
             JOIN package_versions pv ON pv.version = '1.' || (h % 3);
             INSERT INTO advisories (advisory_id, source, os_id, os_version, severity, title, url)
             SELECT 'FEDORA-' || k, 'fedora', 'fedora', '44', 'important', 't', 'https://x'
             FROM generate_series(1, 100) k;
             INSERT INTO vulnerabilities (agent_id, advisory_id, packages, first_seen_at,
                last_evaluated_at)
             SELECT 'agent.00000000-0000-4000-8000-' || lpad(h::text, 12, '0'), 'FEDORA-' || k,
                    jsonb_build_array(jsonb_build_object('name', 'pkg-' || lpad((k * 20)::text, 4, '0'))),
                    now(), now()
             FROM generate_series(1, 1000) h, generate_series(1, 100) k WHERE (h + k) % 2 = 0;
             INSERT INTO console_agent_tags
             SELECT 'agent.00000000-0000-4000-8000-' || lpad(h::text, 12, '0'), 'env', 'prod', now(), 't'
             FROM generate_series(1, 100) h;
             INSERT INTO console_asset_groups VALUES ('00000000-0000-4000-8000-0000000000a1', 'prod', now(), 't');
             INSERT INTO console_asset_group_selectors
             VALUES ('00000000-0000-4000-8000-0000000000a1', 'env', 'prod', now());
             ANALYZE;",
        )
        .await
        .unwrap();
    let client = db.pool.get().await.unwrap();
    client
        .batch_execute("SET ROLE \"openvibes-console\"")
        .await
        .unwrap();
    let all = SoftwareFilters::default();
    let vulnerable = SoftwareFilters {
        fixable: true,
        ..SoftwareFilters::default()
    };
    let time = |label: &'static str| {
        let start = std::time::Instant::now();
        move || eprintln!("{label}: {:?}", start.elapsed())
    };
    let done = time("software, first page (50)");
    let page = console_inventory::software(&client, &AgentScope::Global, &all, None, 50)
        .await
        .unwrap();
    done();
    assert_eq!(page.len(), 50);
    assert_eq!((page[0].hosts, page[0].versions), (1000, 3));
    let done = time("software, a page in the middle (after pkg-1500)");
    console_inventory::software(
        &client,
        &AgentScope::Global,
        &all,
        Some(("pkg-1500", "rpm")),
        50,
    )
    .await
    .unwrap();
    done();
    let done = time("software, vulnerable only");
    let flagged = console_inventory::software(&client, &AgentScope::Global, &vulnerable, None, 50)
        .await
        .unwrap();
    done();
    assert_eq!(flagged.len(), 50);
    assert_eq!(flagged[0].fixable_vulnerable_hosts, 500);
    let done = time("software, scoped to a 100-host group, first page");
    let scoped = console_inventory::software(&client, &prod(), &all, None, 50)
        .await
        .unwrap();
    done();
    assert_eq!(scoped[0].hosts, 100);
    let done = time("software, scoped to an empty group");
    console_inventory::software(
        &client,
        &AgentScope::AssetGroups(vec!["00000000-0000-4000-8000-0000000000ff".into()]),
        &all,
        None,
        50,
    )
    .await
    .unwrap();
    done();
    let agent = "agent.00000000-0000-4000-8000-000000000001";
    let done = time("one host's packages, first page (50)");
    console_inventory::host_packages(&client, &AgentScope::Global, agent, None, None, 50)
        .await
        .unwrap();
    done();
    let done = time("one package's versions");
    console_inventory::software_versions(&client, &AgentScope::Global, "rpm", "pkg-1000")
        .await
        .unwrap();
    done();
    let done = time("one package's hosts, first page (50)");
    console_inventory::software_hosts(&client, &AgentScope::Global, "rpm", "pkg-1000", None, 50)
        .await
        .unwrap();
    done();
    db.drop().await;
}
