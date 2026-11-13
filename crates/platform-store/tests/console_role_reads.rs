//! Reads the console makes, run as the `openvibes-console` role (#572).
//! The other store tests connect as the owner, which may read every table,
//! so a missing grant shows up only here.

mod common;

use chrono::Utc;
use common::vulns::{ANN, every, fixture};
use platform_store::{
    console_read::AgentScope,
    host_sort::HostOrder,
    vuln_list::vuln_list,
    vuln_summary::{HostSegment, Lookup, PageScopes, vuln_hosts, vuln_summary},
};

#[tokio::test]
async fn the_console_role_reads_vulnerabilities_and_ca_certificates() {
    let (db, c) = common::migrated().await;
    let (web, _) = fixture(&c).await;
    let not_after = Utc::now() + chrono::Duration::days(30);
    platform_store::ca::record(&c, "intermediate", [7; 32], "PEM", not_after)
        .await
        .unwrap();
    let scope = AgentScope::AssetGroups(vec![web]);
    let today = Utc::now().date_naive();
    c.batch_execute("SET ROLE \"openvibes-console\"")
        .await
        .unwrap();

    let page = vuln_list(&c, &every(), &scope, ANN, today).await.unwrap();
    assert!(page.rows.iter().any(|r| r.key == "CVE-A"));
    let scopes = PageScopes {
        read: &scope,
        alarms: None,
        cases: None,
    };
    let found = vuln_summary(&c, "CVE-A", &scopes, today).await.unwrap();
    assert!(matches!(found, Lookup::Found(_)));
    let hosts = vuln_hosts(
        &c,
        "CVE-A",
        &scope,
        HostSegment::All,
        HostOrder::default(),
        0,
        50,
        today,
    )
    .await
    .unwrap();
    assert!(matches!(hosts, Lookup::Found(_)));
    assert_eq!(platform_store::ca::list(&c).await.unwrap().len(), 1);

    c.batch_execute("RESET ROLE").await.unwrap();
    drop(c);
    db.drop().await;
}
