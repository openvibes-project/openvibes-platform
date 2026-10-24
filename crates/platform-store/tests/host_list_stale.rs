//! The Hosts list's compliance-stale hosts (step 5c): a host with no report
//! in the last day has an unknown failing count and is never "none open".

mod common;

use common::hosts::{everywhere, fleet, id, query, run};
use platform_store::host_list::{HostListPage, HostQuery, HostScopes, Problems};

fn names(page: &HostListPage) -> Vec<&str> {
    page.rows
        .iter()
        .map(|r| r.hostname.as_deref().unwrap())
        .collect()
}

fn n(values: &[(Problems, i64)], key: Problems) -> i64 {
    values
        .iter()
        .find(|(k, _)| *k == key)
        .map_or(0, |(_, n)| *n)
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
    assert!(page.rows.iter().any(|r| r.agent_id == id(8)));
    db.drop().await;
}
