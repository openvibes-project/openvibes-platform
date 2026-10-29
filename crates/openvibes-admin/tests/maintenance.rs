//! `openvibes-admin maintenance` records daily count history.
// The tests start the CLI binary they verify; this is not shipped code.
#![allow(clippy::disallowed_types)]

mod common;

use common::{Fixture, stdout};

#[tokio::test]
async fn maintenance_records_todays_counts_and_reports_them() {
    let fixture = Fixture::create().await;
    stdout(&fixture.run(&["migrate"]));
    let out = stdout(&fixture.run(&["maintenance", "--history-days", "30"]));
    assert!(
        out.contains("recorded history for 0 hosts, deleted 0 old rows"),
        "{out}"
    );
    let bad = fixture.run(&["maintenance", "--history-days", "10"]);
    assert!(
        !bad.status.success(),
        "below 30 is refused before any change"
    );
    fixture.drop().await;
}

#[tokio::test]
async fn maintenance_keeps_findings_as_long_as_the_console_setting_says() {
    let fixture = Fixture::create().await;
    stdout(&fixture.run(&["migrate"]));
    fixture
        .count(
            "INSERT INTO console_settings (key, value, changed_at, changed_by) \
             VALUES ('ingest.finding_retention_days', '30', now(), 'test') RETURNING 1::bigint",
        )
        .await;
    // 30 days back to 7 ahead is 38 days; migrate already made the last 8.
    let out = stdout(&fixture.run(&["maintenance"]));
    assert!(out.contains("created 90 partitions, dropped 0"), "{out}");
    // The flag wins over the setting.
    let out = stdout(&fixture.run(&["maintenance", "--retention-days", "40"]));
    assert!(out.contains("created 30 partitions, dropped 0"), "{out}");
    fixture.drop().await;
}
