//! Saved views and hidden list columns: per person and page, name rules,
//! the 50-view cap and cascade on user delete.

mod common;

use chrono::Utc;
use common::TestDb;
use platform_store::{
    Client,
    console_auth::{NewLocalUser, create_local_user},
    saved_views::{self, ViewWrite},
};

const ALICE: &str = "11111111-1111-4111-8111-111111111111";
const BOB: &str = "33333333-3333-4333-8333-333333333333";

async fn user(client: &mut Client, id: &str, binding: &str, name: &str) {
    create_local_user(
        client,
        &NewLocalUser {
            user_id: id,
            binding_id: binding,
            username: name,
            display_name: name,
            password_phc: "$argon2id$v=19$m=19456,t=2,p=1$opaque-salt$opaque-hash",
            role_id: "admin",
            actor_id: "test",
            actor_kind: "local_admin",
            password_must_change: false,
            now: Utc::now(),
        },
    )
    .await
    .unwrap();
}

async fn setup() -> (TestDb, Client) {
    let db = TestDb::create().await;
    let mut client = db.pool.get().await.unwrap();
    platform_store::migrate(&mut client).await.unwrap();
    user(
        &mut client,
        ALICE,
        "22222222-2222-4222-8222-222222222222",
        "alice",
    )
    .await;
    user(
        &mut client,
        BOB,
        "44444444-4444-4444-8444-444444444444",
        "bob",
    )
    .await;
    (db, client)
}

async fn add(c: &mut Client, who: &str, page: &str, name: &str) -> ViewWrite {
    saved_views::create(c, who, page, name, "status=online", Utc::now())
        .await
        .unwrap()
}

#[tokio::test]
async fn saved_views_are_per_person() {
    let (db, mut c) = setup().await;
    let ViewWrite::Saved(view) = add(&mut c, ALICE, "hosts", "Prod online").await else {
        panic!("not saved");
    };
    assert_eq!(
        (view.page.as_str(), view.query.as_str()),
        ("hosts", "status=online")
    );
    assert!(
        saved_views::list(&c, BOB, "hosts")
            .await
            .unwrap()
            .is_empty()
    );
    assert!(!saved_views::delete(&c, BOB, &view.id).await.unwrap());
    assert_eq!(
        saved_views::list(&c, ALICE, "hosts").await.unwrap().len(),
        1
    );
    assert!(saved_views::delete(&c, ALICE, &view.id).await.unwrap());
    assert!(!saved_views::delete(&c, ALICE, "not-a-uuid").await.unwrap());
    drop(c);
    db.drop().await;
}

#[tokio::test]
async fn names_are_unique_per_person_and_page_regardless_of_case() {
    let (db, mut c) = setup().await;
    assert!(matches!(
        add(&mut c, ALICE, "hosts", "Prod").await,
        ViewWrite::Saved(_)
    ));
    assert!(matches!(
        add(&mut c, ALICE, "hosts", "prod").await,
        ViewWrite::NameTaken
    ));
    assert!(matches!(
        add(&mut c, BOB, "hosts", "Prod").await,
        ViewWrite::Saved(_)
    ));
    assert!(matches!(
        add(&mut c, ALICE, "other", "Prod").await,
        ViewWrite::Saved(_)
    ));
    // name order, regardless of case
    add(&mut c, ALICE, "hosts", "alpha").await;
    add(&mut c, ALICE, "hosts", "Zulu").await;
    let names: Vec<String> = saved_views::list(&c, ALICE, "hosts")
        .await
        .unwrap()
        .into_iter()
        .map(|v| v.name)
        .collect();
    assert_eq!(names, ["alpha", "Prod", "Zulu"]);
    drop(c);
    db.drop().await;
}

#[tokio::test]
async fn at_most_50_views_per_person_and_page() {
    let (db, mut c) = setup().await;
    for i in 0..50 {
        assert!(matches!(
            add(&mut c, ALICE, "hosts", &format!("v{i}")).await,
            ViewWrite::Saved(_)
        ));
    }
    assert!(matches!(
        add(&mut c, ALICE, "hosts", "v50").await,
        ViewWrite::TooMany
    ));
    assert!(matches!(
        add(&mut c, BOB, "hosts", "v50").await,
        ViewWrite::Saved(_)
    ));
    drop(c);
    db.drop().await;
}

#[tokio::test]
async fn hidden_columns_round_trip() {
    let (db, c) = setup().await;
    assert!(
        saved_views::hidden_columns(&c, ALICE, "hosts")
            .await
            .unwrap()
            .is_empty()
    );
    let cols = vec!["labels".to_string(), "agent".to_string()];
    saved_views::set_hidden_columns(&c, ALICE, "hosts", &cols, Utc::now())
        .await
        .unwrap();
    assert_eq!(
        saved_views::hidden_columns(&c, ALICE, "hosts")
            .await
            .unwrap(),
        cols
    );
    assert!(
        saved_views::hidden_columns(&c, BOB, "hosts")
            .await
            .unwrap()
            .is_empty()
    );
    saved_views::set_hidden_columns(&c, ALICE, "hosts", &[], Utc::now())
        .await
        .unwrap();
    assert!(
        saved_views::hidden_columns(&c, ALICE, "hosts")
            .await
            .unwrap()
            .is_empty()
    );
    drop(c);
    db.drop().await;
}

#[tokio::test]
async fn deleting_a_person_deletes_their_views() {
    let (db, mut c) = setup().await;
    add(&mut c, ALICE, "hosts", "Prod").await;
    saved_views::set_hidden_columns(&c, ALICE, "hosts", &["agent".into()], Utc::now())
        .await
        .unwrap();
    c.execute(
        "DELETE FROM console_users WHERE user_id = $1::text::uuid",
        &[&ALICE],
    )
    .await
    .unwrap();
    for table in ["console_saved_views", "console_list_columns"] {
        let n: i64 = c
            .query_one(&format!("SELECT count(*) FROM {table}"), &[])
            .await
            .unwrap()
            .get(0);
        assert_eq!(n, 0, "{table}");
    }
    drop(c);
    db.drop().await;
}
