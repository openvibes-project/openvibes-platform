//! Migration 64: per-item accepted-risk dates and closes without a resolution.

use super::*;

const U: &str = "00000000-0000-0000-0000-000000000001";

#[tokio::test]
async fn migration_64_backfills_each_accepted_items_date() {
    let db = TestDb::create().await;
    let client = common::at_version(&db, 63).await;
    let case = |n: u8| format!("00000000-0000-0000-0000-0000000000c{n}");
    let (c1, c2, c3) = (case(1), case(2), case(3));
    client
        .batch_execute(&format!(
            "INSERT INTO console_users (user_id, username, display_name, created_at)
             VALUES ('{U}', 'u', 'U', now());
             INSERT INTO cases (case_id, title, status, resolution, resolution_note,
                 accepted_until, severity, opened_by_user_id, created_at, updated_at, closed_at)
             VALUES ('{c1}', 'Accepted', 'closed', 'accepted_risk', 'n',
                     '2027-01-15T00:00:00Z', 'high', '{U}', now(), now(), now()),
                    ('{c2}', 'Mitigated', 'closed', 'mitigated', 'n',
                     NULL, 'high', '{U}', now(), now(), now()),
                    ('{c3}', 'Open', 'open', NULL, NULL, NULL, 'high', '{U}', now(), now(), NULL);
             INSERT INTO case_items (item_id, case_id, kind, ref, agent_id, active, outcome,
                 outcome_note, added_by_user_id, added_at)
             VALUES ('00000000-0000-0000-0000-0000000000e1', '{c1}', 'alarm', '1', 'a', false,
                     'accepted_risk', 'n', '{U}', '2026-09-01T00:00:00Z'),
                    ('00000000-0000-0000-0000-0000000000e2', '{c2}', 'alarm', '2', 'a', false,
                     'accepted_risk', 'n', '{U}', '2026-09-01T00:00:00Z'),
                    ('00000000-0000-0000-0000-0000000000e3', '{c3}', 'alarm', '3', 'a', true,
                     'accepted_risk', 'n', '{U}', '2026-10-01T00:00:00Z'),
                    ('00000000-0000-0000-0000-0000000000e4', '{c1}', 'alarm', '4', 'a', false,
                     'false_positive', 'n', '{U}', now());"
        ))
        .await
        .unwrap();
    common::step_to(&client, 64).await;
    let rows = client
        .query(
            "SELECT right(item_id::text, 2),
                    to_char(outcome_until AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI')
             FROM case_items ORDER BY item_id",
            &[],
        )
        .await
        .unwrap();
    let dates: Vec<(String, Option<String>)> =
        rows.iter().map(|row| (row.get(0), row.get(1))).collect();
    let date = |text: &str| Some(text.to_owned());
    assert_eq!(
        dates,
        [
            // The case's own date, when it was closed as accepted risk.
            ("e1".into(), date("2027-01-15 00:00")),
            // Otherwise added_at + 90 days.
            ("e2".into(), date("2026-11-30 00:00")),
            ("e3".into(), date("2026-12-30 00:00")),
            ("e4".into(), None),
        ]
    );
    // Old closes keep their resolution; a close with only a note fits now.
    let kept: Option<String> = client
        .query_one(
            &format!("SELECT resolution FROM cases WHERE case_id = '{c2}'"),
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(kept.as_deref(), Some("mitigated"));
    client
        .batch_execute(&format!(
            "UPDATE cases SET status = 'closed', resolution_note = 'x', closed_at = now()
             WHERE case_id = '{c3}'"
        ))
        .await
        .unwrap();
    db.drop().await;
}
