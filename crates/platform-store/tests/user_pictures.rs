//! Profile pictures in the store (spec §9.2): set, replace, remove, read by
//! size, ETags, audit, and the cascade when the person goes.

mod common;

use chrono::Utc;
use common::TestDb;
use platform_store::console_people::{
    PictureSize, picture, picture_etag, picture_etags, remove_picture, set_picture,
};

const USER: &str = "11111111-1111-4111-8111-111111111111";
const OTHER: &str = "33333333-3333-4333-8333-333333333333";

async fn setup() -> (TestDb, platform_store::Client) {
    let db = TestDb::create().await;
    let mut client = db.pool.get().await.unwrap();
    platform_store::migrate(&mut client).await.unwrap();
    client
        .batch_execute(&format!(
            "INSERT INTO console_users (user_id, username, display_name, created_at) VALUES
               ('{USER}','ana','Ana',now()), ('{OTHER}','bo','Bo',now())"
        ))
        .await
        .unwrap();
    (db, client)
}

#[tokio::test]
async fn a_picture_is_stored_replaced_read_and_removed_with_audit() {
    let (db, mut client) = setup().await;
    assert!(
        picture(&client, USER, PictureSize::Large)
            .await
            .unwrap()
            .is_none()
    );
    let first = set_picture(
        &mut client,
        USER,
        b"large-1",
        b"small-1",
        false,
        OTHER,
        Utc::now(),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(first.len(), 64);
    let large = picture(&client, USER, PictureSize::Large)
        .await
        .unwrap()
        .unwrap();
    let small = picture(&client, USER, PictureSize::Small)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (large.image.as_slice(), small.image.as_slice()),
        (&b"large-1"[..], &b"small-1"[..])
    );
    assert_eq!(
        (large.etag.as_str(), small.etag.as_str()),
        (first.as_str(), first.as_str())
    );
    // Replacing changes the ETag; nobody else's picture is touched.
    let second = set_picture(
        &mut client,
        USER,
        b"large-2",
        b"small-2",
        true,
        USER,
        Utc::now(),
    )
    .await
    .unwrap()
    .unwrap();
    assert_ne!(first, second);
    assert_eq!(
        picture_etag(&client, USER).await.unwrap(),
        Some(second.clone())
    );
    assert_eq!(picture_etag(&client, OTHER).await.unwrap(), None);
    assert_eq!(picture_etags(&client).await.unwrap().len(), 1);
    assert!(
        remove_picture(&mut client, USER, OTHER, Utc::now())
            .await
            .unwrap()
    );
    assert!(
        !remove_picture(&mut client, USER, OTHER, Utc::now())
            .await
            .unwrap()
    );
    assert!(
        picture(&client, USER, PictureSize::Small)
            .await
            .unwrap()
            .is_none()
    );
    let audited: Vec<(String, String, String)> = client
        .query(
            "SELECT action, actor_id, target_id FROM audit_log WHERE action LIKE 'user.picture.%' ORDER BY id",
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|r| (r.get(0), r.get(1), r.get(2)))
        .collect();
    assert_eq!(
        audited,
        [
            (
                "user.picture.set".to_owned(),
                OTHER.to_owned(),
                USER.to_owned()
            ),
            (
                "user.picture.set".to_owned(),
                USER.to_owned(),
                USER.to_owned()
            ),
            (
                "user.picture.removed".to_owned(),
                OTHER.to_owned(),
                USER.to_owned()
            ),
        ]
    );
    // The image bytes are never in the audit log.
    let leaked: i64 = client
        .query_one(
            "SELECT count(*) FROM audit_log WHERE detail::text LIKE '%large-%'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(leaked, 0);
    db.drop().await;
}

#[tokio::test]
async fn no_such_person_and_a_deleted_person_leave_no_picture() {
    let (db, mut client) = setup().await;
    let nobody = "99999999-9999-4999-8999-999999999999";
    assert_eq!(
        set_picture(&mut client, nobody, b"l", b"s", false, USER, Utc::now())
            .await
            .unwrap(),
        None
    );
    set_picture(&mut client, OTHER, b"l", b"s", false, USER, Utc::now())
        .await
        .unwrap();
    client
        .execute(
            "DELETE FROM console_users WHERE user_id = $1::text::uuid",
            &[&OTHER],
        )
        .await
        .unwrap();
    assert!(picture_etags(&client).await.unwrap().is_empty());
    db.drop().await;
}
