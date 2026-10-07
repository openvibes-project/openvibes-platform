mod common;

use chrono::{NaiveDate, TimeZone, Utc};
use platform_store::history::{self, Expr};

const CRIT: Expr = Expr::Sum(&["alarms_critical", "vulns_critical", "compliance_critical"]);
const A1: &str = "agent.00000000-0000-0000-0000-000000000001";
const A2: &str = "agent.00000000-0000-0000-0000-000000000002";

#[tokio::test]
async fn record_counts_each_host_and_replaces_the_same_day() {
    let (db, client) = common::migrated().await;
    common::seed_agent(&client, A1).await;
    common::seed_agent(&client, A2).await;
    common::seed_alarm(&client, A1, "critical", "open").await;
    common::seed_alarm(&client, A1, "high", "mitigated").await; // not active
    common::seed_alarm(&client, A1, "info", "open").await; // info is in no count
    common::seed_host_vuln_counts(&client, A1, 2, 1, 0, 0).await;
    common::seed_current_finding(&client, A1, "critical").await;
    let day = NaiveDate::from_ymd_opt(2026, 10, 7).unwrap();
    let now = Utc.with_ymd_and_hms(2026, 10, 7, 3, 0, 0).unwrap();
    assert_eq!(history::record(&client, day, now).await.unwrap(), 2);
    assert_eq!(
        history::record(&client, day, now).await.unwrap(),
        2,
        "same day replaced"
    );
    let rows: i64 = client
        .query_one("SELECT count(*) FROM host_daily_counts", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(rows, 2);
    let series = history::series(&client, &CRIT, day, None).await.unwrap();
    assert_eq!(series, [(day, 4)]);
    let high = Expr::Sum(&["alarms_high", "vulns_high", "compliance_high"]);
    assert_eq!(
        history::series(&client, &high, day, None).await.unwrap(),
        [(day, 1)]
    );
    assert_eq!(
        history::current(&client, &CRIT, now, None).await.unwrap(),
        4
    );
    let only_2 = [A2.to_owned()];
    assert_eq!(
        history::series(&client, &CRIT, day, Some(&only_2))
            .await
            .unwrap(),
        [(day, 0)]
    );
    assert_eq!(
        history::current(&client, &CRIT, now, Some(&only_2))
            .await
            .unwrap(),
        0
    );
    // Seen at 02:59: active at 03:00, stale an hour later.
    let active = Expr::HostsWhere("status = 'active'");
    assert_eq!(
        history::current(&client, &active, now, None).await.unwrap(),
        2
    );
    let later = now + chrono::Duration::hours(1);
    assert_eq!(
        history::current(&client, &active, later, None)
            .await
            .unwrap(),
        0
    );
    db.drop().await;
}

#[tokio::test]
async fn retention_deletes_only_older_days() {
    let (db, client) = common::migrated().await;
    common::seed_agent(&client, A1).await;
    let now = Utc.with_ymd_and_hms(2026, 10, 7, 3, 0, 0).unwrap();
    for d in [1, 5, 7] {
        history::record(&client, NaiveDate::from_ymd_opt(2026, 10, d).unwrap(), now)
            .await
            .unwrap();
    }
    let deleted = history::delete_before(&client, NaiveDate::from_ymd_opt(2026, 10, 5).unwrap())
        .await
        .unwrap();
    assert_eq!(deleted, 1);
    let days = history::series(
        &client,
        &Expr::HostsWhere("status = 'active'"),
        NaiveDate::from_ymd_opt(2026, 10, 1).unwrap(),
        None,
    )
    .await
    .unwrap();
    assert_eq!(
        days.iter().map(|(d, _)| d.to_string()).collect::<Vec<_>>(),
        ["2026-10-05", "2026-10-07"]
    );
    db.drop().await;
}

#[tokio::test]
async fn exploited_counts_open_non_reboot_vulnerabilities_on_kev() {
    let (db, client) = common::migrated().await;
    common::seed_agent(&client, A1).await;
    client
        .batch_execute(&format!(
            "INSERT INTO advisories (advisory_id, source, os_id, os_version, severity, title, url)
             VALUES ('A1', 's', 'debian', '12', 'critical', 't', 'u'), ('A2', 's', 'debian', '12', 'low', 't', 'u');
             INSERT INTO advisory_cves VALUES ('A1', 'CVE-1'), ('A2', 'CVE-2');
             INSERT INTO cve_enrichment (cve_id, kev_added) VALUES ('CVE-1', '2026-01-01');
             INSERT INTO cve_enrichment (cve_id, euvd_exploited) VALUES ('CVE-2', false);
             INSERT INTO vulnerabilities (agent_id, advisory_id, packages, first_seen_at, last_evaluated_at)
             VALUES ('{A1}', 'A1', '[]', now(), now()), ('{A1}', 'A2', '[]', now(), now());"
        ))
        .await
        .unwrap();
    let now = Utc.with_ymd_and_hms(2026, 10, 7, 3, 0, 0).unwrap();
    let exploited = Expr::Sum(&["vulns_exploited"]);
    assert_eq!(
        history::current(&client, &exploited, now, None)
            .await
            .unwrap(),
        1
    );
    db.drop().await;
}
