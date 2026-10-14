//! The console role's rights on the rule-set assignment tables are only
//! what the store code does: no INSERT/DELETE on the sets, no UPDATE of ids.

mod common;

use common::TestDb;

#[tokio::test]
async fn the_console_role_cannot_rewrite_assignment_identity() {
    let db = TestDb::create().await;
    let mut client = db.pool.get().await.unwrap();
    platform_store::migrate(&mut client).await.unwrap();
    let row = client
        .query_one(
            "SELECT has_table_privilege('openvibes-console', 'rule_set_assignment', 'INSERT'),
                    has_table_privilege('openvibes-console', 'rule_set_assignment', 'DELETE'),
                    has_column_privilege('openvibes-console', 'rule_set_assignment', 'rule_set_id', 'UPDATE'),
                    has_column_privilege('openvibes-console', 'rule_set_group_assignment', 'rule_set_id', 'UPDATE'),
                    has_column_privilege('openvibes-console', 'rule_set_group_assignment', 'asset_group_id', 'UPDATE'),
                    has_column_privilege('openvibes-console', 'rule_set_assignment', 'default_enabled', 'UPDATE'),
                    has_column_privilege('openvibes-console', 'rule_set_group_assignment', 'enabled', 'UPDATE')",
            &[],
        )
        .await
        .unwrap();
    let got: Vec<bool> = (0..7).map(|i| row.get(i)).collect();
    assert_eq!(got, [false, false, false, false, false, true, true]);
    drop(client);
    db.drop().await;
}
