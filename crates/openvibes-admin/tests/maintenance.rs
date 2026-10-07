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
    assert!(!bad.status.success(), "below 30 is refused before any change");
    fixture.drop().await;
}
