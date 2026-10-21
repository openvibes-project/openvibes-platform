//! `console_version_older` (SQL) and `version_order::older` (Rust) give
//! the same answers on one table (plan ruling 7).

mod common;

use platform_store::version_order::older;

/// (version, latest, older?) — `None` where either side is unknown.
const TABLE: &[(&str, &str, Option<bool>)] = &[
    ("0.4.1", "0.4.2", Some(true)),
    ("0.4.2", "0.4.1", Some(false)),
    ("0.10.0", "0.9.9", Some(false)),
    ("0.9.9", "0.10.0", Some(true)),
    ("1.0.0-rc1", "1.0.0", Some(true)),
    ("1.0.0", "1.0.0-rc1", Some(false)),
    ("1.0.0+abc", "1.0.0", Some(false)),
    ("1.0.0", "1.0.0+abc", Some(false)),
    ("1.0", "1.0.0", Some(false)),
    ("1.0", "1.0.1", Some(true)),
    ("abc", "1.0.0", None),
    ("1.0.0", "abc", None),
    ("", "1.0.0", None),
    ("1.0.0", "", None),
    ("1..0", "1.0.0", None),
    ("99999999999", "1.0.0", None),
];

#[test]
fn rust_twin_follows_the_table() {
    for (v, latest, want) in TABLE {
        assert_eq!(older(v, latest), *want, "{v} vs {latest}");
    }
}

#[tokio::test]
async fn sql_function_follows_the_same_table() {
    let (db, client) = common::migrated().await;
    for (v, latest, want) in TABLE {
        let got: Option<bool> = client
            .query_one("SELECT console_version_older($1, $2)", &[v, latest])
            .await
            .unwrap()
            .get(0);
        assert_eq!(got, *want, "{v} vs {latest}");
    }
    let null: Option<bool> = client
        .query_one("SELECT console_version_older(NULL, '1.0.0')", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(null, None);
    db.drop().await;
}
