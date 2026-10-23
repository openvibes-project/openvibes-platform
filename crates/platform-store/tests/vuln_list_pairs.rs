//! The Vulnerabilities list's pairs (step 5b ruling 2): one pair per host
//! and advisory, and the package names and fixed versions of the pairs
//! themselves.

mod common;

use common::{
    hosts::id,
    vulns::{every, fixture, keys, query, row, run},
};
use platform_store::{
    Client,
    console_read::AgentScope,
    vuln_list::{Fixed, VulnQuery, VulnState},
};

/// One fixable pair of `advisory` on `host` with `packages` (JSON).
async fn pair(c: &Client, host: &str, advisory: &str, packages: &str, fixed: bool) {
    c.execute(
        "INSERT INTO vulnerabilities (agent_id, advisory_id, packages, first_seen_at, fixed_at, last_evaluated_at)
         VALUES ($1, $2, $3::text::jsonb, now(), CASE WHEN $4::boolean THEN now() END, now())",
        &[&host, &advisory, &packages, &fixed],
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn a_host_with_fixable_and_no_fix_rows_counts_once() {
    let (db, c) = common::migrated().await;
    let (web, alpha) = fixture(&c).await;
    // Host 1 also has a fixable row for DEBIAN-NF (zlib without a fix on
    // the other package), mitigated: one pair, the fixable one.
    c.batch_execute(&format!(
        "INSERT INTO vulnerabilities (agent_id, advisory_id, packages, first_seen_at, fixed_at, last_evaluated_at)
         VALUES ('{h1}', 'DEBIAN-NF', '[{{\"name\":\"zlib\",\"installed\":\"1.2\",\"fixed\":\"1.3\"}}]', now(), NULL, now());
         INSERT INTO vulnerability_triage (agent_id, advisory_id, state, note, version, updated_at, updated_by)
         VALUES ('{h1}', 'DEBIAN-NF', 'mitigated', 'n', 1, now(), 't');",
        h1 = id(1)
    ))
    .await
    .unwrap();
    let scope = AgentScope::AssetGroups(vec![web]);
    let page = run(&c, &every(), &scope).await;
    let nf = row(&page, "CVE-NF");
    assert_eq!((nf.open, nf.total), (1, 2));
    let mitigated = run(
        &c,
        &VulnQuery {
            state: VulnState::Mitigated,
            ..query()
        },
        &scope,
    )
    .await;
    assert_eq!(keys(&mitigated), ["CVE-A", "CVE-NF"]);
    // Host 1 keeps open pairs elsewhere; host 2 its no-fix one.
    let open = run(&c, &query(), &scope).await;
    assert_eq!(open.summary.hosts, 2);
    // Alpha (host 1) no longer has CVE-NF open: CVE-A, CVE-EXP, DSA-NOCVE.
    let alpha_open = open
        .counts
        .groups
        .iter()
        .find(|g| g.0 == alpha)
        .map(|g| g.3);
    assert_eq!(alpha_open, Some(3));
    db.drop().await;
}

#[tokio::test]
async fn a_fixed_row_leaves_a_package_without_a_fix_open() {
    let (db, c) = common::migrated().await;
    let (web, _) = fixture(&c).await;
    // Host 2's fixable row for DEBIAN-NF is fixed; zlib, without a fix, is
    // still installed: that pair stays open.
    pair(
        &c,
        id(2),
        "DEBIAN-NF",
        r#"[{"name":"zlib","installed":"1.2","fixed":"1.3"}]"#,
        true,
    )
    .await;
    let scope = AgentScope::AssetGroups(vec![web]);
    let page = run(&c, &every(), &scope).await;
    assert_eq!(row(&page, "CVE-NF").open, 2);
    let resolved = run(
        &c,
        &VulnQuery {
            state: VulnState::Resolved,
            ..query()
        },
        &scope,
    )
    .await;
    assert!(keys(&resolved).contains(&"CVE-NF"));
    let open = run(&c, &query(), &scope).await;
    assert!(keys(&open).contains(&"CVE-NF"));
    assert_eq!(open.summary.hosts, 2);
    db.drop().await;
}

#[tokio::test]
async fn names_and_fixed_versions_are_those_of_the_pairs() {
    let (db, c) = common::migrated().await;
    let (web, alpha) = fixture(&c).await;
    // DEBIAN-M updates firefox and nss; host 1 holds the firefox pair, nss
    // is installed on host 2 (in reach) without a pair. DEBIAN-RNG has two
    // libx ranges; host 2 is on the 2.x branch.
    c.batch_execute(
        "INSERT INTO advisories (advisory_id, source, os_id, os_version, severity, title, url) VALUES
           ('DEBIAN-M', 'debian-12', 'debian', '12', 'moderate', 'firefox and nss', 'u'),
           ('DEBIAN-RNG', 'debian-12', 'debian', '12', 'low', 'libx: two branches', 'u');
         INSERT INTO advisory_cves VALUES ('DEBIAN-M', 'CVE-M'), ('DEBIAN-RNG', 'CVE-RNG');
         INSERT INTO advisory_packages (advisory_id, name, arch, scheme, match_on, introduced, fixed) VALUES
           ('DEBIAN-M', 'firefox', '', 'dpkg', 'source', NULL, '120'),
           ('DEBIAN-M', 'nss', '', 'dpkg', 'source', NULL, '3.9'),
           ('DEBIAN-RNG', 'libx', '', 'dpkg', 'source', '1.0', '1.5'),
           ('DEBIAN-RNG', 'libx', '', 'dpkg', 'source', '2.0', '2.3');
         INSERT INTO package_versions (manager, name, version, arch, source) VALUES ('dpkg', 'nss', '3.8', 'amd64', 'nss');",
    )
    .await
    .unwrap();
    c.execute(
        "INSERT INTO host_packages SELECT $1, id FROM package_versions WHERE name = 'nss'",
        &[&id(2)],
    )
    .await
    .unwrap();
    pair(
        &c,
        id(1),
        "DEBIAN-M",
        r#"[{"name":"firefox","installed":"119","fixed":"120"}]"#,
        false,
    )
    .await;
    pair(
        &c,
        id(2),
        "DEBIAN-RNG",
        r#"[{"name":"libx","installed":"2.1","fixed":"2.3"}]"#,
        false,
    )
    .await;
    let scope = AgentScope::AssetGroups(vec![web]);
    let page = run(&c, &every(), &scope).await;
    let m = row(&page, "CVE-M");
    assert_eq!(m.packages, ["firefox"]);
    assert_eq!(m.fixed, Fixed::One("120".into()));
    assert_eq!(row(&page, "CVE-RNG").fixed, Fixed::One("2.3".into()));
    let nss = run(
        &c,
        &VulnQuery {
            package: Some("nss"),
            ..every()
        },
        &scope,
    )
    .await;
    assert!(!keys(&nss).contains(&"CVE-M"));
    assert!(page.counts.packages.iter().all(|p| p.0 != "nss"));

    // Host 2 now holds the nss pair: both names everywhere, firefox alone
    // on Alpha's side (host 1).
    pair(
        &c,
        id(2),
        "DEBIAN-M",
        r#"[{"name":"nss","installed":"3.8","fixed":"3.9"}]"#,
        false,
    )
    .await;
    let page = run(&c, &every(), &scope).await;
    let m = row(&page, "CVE-M");
    assert_eq!(m.packages, ["firefox", "nss"]);
    assert_eq!(m.fixed, Fixed::Several(2));
    let alpha_side = run(
        &c,
        &VulnQuery {
            group: Some(alpha.as_str()),
            ..every()
        },
        &scope,
    )
    .await;
    let m = row(&alpha_side, "CVE-M");
    assert_eq!(m.packages, ["firefox"]);
    assert_eq!(m.fixed, Fixed::One("120".into()));
    let nss = run(
        &c,
        &VulnQuery {
            package: Some("nss"),
            group: Some(alpha.as_str()),
            ..every()
        },
        &scope,
    )
    .await;
    assert!(!keys(&nss).contains(&"CVE-M"));
    db.drop().await;
}
