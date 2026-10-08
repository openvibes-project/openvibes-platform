mod common;

use chrono::{NaiveDate, TimeZone, Utc};
use platform_store::history::{self, Expr};

const CRIT: Expr = Expr::Sum(&["alarms_critical", "vulns_critical", "compliance_critical"]);
const A1: &str = "agent.00000000-0000-0000-0000-000000000001";
const A2: &str = "agent.00000000-0000-0000-0000-000000000002";

#[tokio::test]
async fn record_counts_each_host_and_replaces_the_same_day() {
    let (db, mut client) = common::migrated().await;
    common::seed_agent(&client, A1).await;
    common::seed_agent(&client, A2).await;
    common::seed_alarm(&client, A1, "critical", "open").await;
    common::seed_alarm(&client, A1, "high", "mitigated").await; // not active
    common::seed_alarm(&client, A1, "info", "open").await; // own column
    common::seed_host_vuln_counts(&client, A1, 2, 1, 0, 0).await;
    common::seed_current_finding(&client, A1, "critical").await;
    let day = NaiveDate::from_ymd_opt(2026, 10, 7).unwrap();
    let now = Utc.with_ymd_and_hms(2026, 10, 7, 3, 0, 0).unwrap();
    assert_eq!(history::record(&mut client, day, now).await.unwrap(), 2);
    assert_eq!(
        history::record(&mut client, day, now).await.unwrap(),
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
    let info = Expr::Sum(&["alarms_info"]);
    assert_eq!(
        history::series(&client, &info, day, None).await.unwrap(),
        [(day, 1)]
    );
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
    let (db, mut client) = common::migrated().await;
    common::seed_agent(&client, A1).await;
    let now = Utc.with_ymd_and_hms(2026, 10, 7, 3, 0, 0).unwrap();
    for d in [1, 5, 7] {
        history::record(
            &mut client,
            NaiveDate::from_ymd_opt(2026, 10, d).unwrap(),
            now,
        )
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

#[tokio::test]
async fn failed_record_keeps_the_days_previous_rows() {
    let (db, mut client) = common::migrated().await;
    common::seed_agent(&client, A1).await;
    let day = NaiveDate::from_ymd_opt(2026, 10, 7).unwrap();
    let now = Utc.with_ymd_and_hms(2026, 10, 7, 3, 0, 0).unwrap();
    assert_eq!(history::record(&mut client, day, now).await.unwrap(), 1);
    // Existing rows satisfy this; the next run's insert will not.
    client
        .batch_execute("ALTER TABLE host_daily_counts ADD CONSTRAINT t CHECK (alarms_critical = 0)")
        .await
        .unwrap();
    common::seed_alarm(&client, A1, "critical", "open").await;
    history::record(&mut client, day, now).await.unwrap_err();
    let rows: i64 = client
        .query_one("SELECT count(*) FROM host_daily_counts", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(rows, 1, "delete rolled back with the failed insert");
    db.drop().await;
}

#[tokio::test]
async fn overlapping_records_of_the_same_day_both_succeed() {
    let (db, mut first) = common::migrated().await;
    let mut second = db.pool.get().await.unwrap();
    for n in 0..50 {
        common::seed_agent(&first, &format!("agent.00000000-0000-0000-0000-{n:012}")).await;
    }
    let day = NaiveDate::from_ymd_opt(2026, 10, 7).unwrap();
    let now = Utc.with_ymd_and_hms(2026, 10, 7, 3, 0, 0).unwrap();
    for _ in 0..10 {
        let (a, b) = tokio::join!(
            history::record(&mut first, day, now),
            history::record(&mut second, day, now)
        );
        assert_eq!((a.unwrap(), b.unwrap()), (50, 50));
    }
    db.drop().await;
}

#[tokio::test]
async fn top_hosts_rank_by_critical_and_high_across_kinds_then_total() {
    let (db, client) = common::migrated().await;
    let (a3, a4) = (
        "agent.00000000-0000-0000-0000-000000000003",
        "agent.00000000-0000-0000-0000-000000000004",
    );
    for id in [A1, A2, a3, a4] {
        common::seed_agent(&client, id).await;
    }
    // A1: one high vulnerability. A2: two critical compliance findings.
    // A3: one high vulnerability plus many mediums (same serious as A1, more open).
    // A4: nothing, never listed.
    common::seed_host_vuln_counts(&client, A1, 0, 1, 0, 0).await;
    common::seed_host_vuln_counts(&client, a3, 0, 1, 5, 0).await;
    for rule in ["r1", "r2"] {
        client
            .execute(
                "INSERT INTO current_findings (agent_id, rule_id, last_finding_id, rule_version,
                     severity, first_observed_at, last_observed_at, last_observed_day, scan_id,
                     confidence, message, evidence, received_at, origin, authenticated)
                 VALUES ($1, $2, 'f', 1, 'critical', now(), now(), (now() AT TIME ZONE 'UTC')::date,
                     's', 50, 'm', '{}', now(), 'online', false)",
                &[&A2, &rule],
            )
            .await
            .unwrap();
    }
    let now = Utc.with_ymd_and_hms(2026, 10, 7, 3, 0, 0).unwrap();
    let rank = |hosts: Vec<history::TopHost>| {
        hosts
            .into_iter()
            .map(|h| (h.agent_id, h.serious, h.open))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        rank(history::top_hosts(&client, now, 10, None).await.unwrap()),
        [
            (A2.to_owned(), 2, 2),
            (a3.to_owned(), 1, 6),
            (A1.to_owned(), 1, 1)
        ]
    );
    assert_eq!(
        history::top_hosts(&client, now, 1, None)
            .await
            .unwrap()
            .len(),
        1
    );
    let scope = [A1.to_owned(), a3.to_owned()];
    assert_eq!(
        rank(
            history::top_hosts(&client, now, 10, Some(&scope))
                .await
                .unwrap()
        ),
        [(a3.to_owned(), 1, 6), (A1.to_owned(), 1, 1)]
    );
    db.drop().await;
}
