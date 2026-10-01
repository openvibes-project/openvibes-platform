//! Dashboards: ownership, visibility through role bindings, versions,
//! limits, home fallback, and transactional audit rows.

mod common;

use chrono::Utc;
use common::TestDb;
use platform_store::{
    Client,
    console_auth::{
        NewLocalUser, create_local_user, create_user_role_binding, revoke_user_role_binding,
    },
    dashboards::{self, Refusal},
};
use serde_json::json;

const ALICE: &str = "11111111-1111-4111-8111-111111111111";
const BOB: &str = "33333333-3333-4333-8333-333333333333";

async fn user(client: &mut Client, id: &str, binding: &str, name: &str, role: &str) {
    create_local_user(
        client,
        &NewLocalUser {
            user_id: id,
            binding_id: binding,
            username: name,
            display_name: name,
            password_phc: "$argon2id$v=19$m=19456,t=2,p=1$opaque-salt$opaque-hash",
            role_id: role,
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
        "admin",
    )
    .await;
    user(
        &mut client,
        BOB,
        "44444444-4444-4444-8444-444444444444",
        "bob",
        "viewer",
    )
    .await;
    (db, client)
}

fn layout() -> serde_json::Value {
    json!({"schema": 1, "widgets": [{"id": "w1", "type": "number", "x": 0, "y": 0, "w": 3, "h": 2, "config": {"metric": "agents.active"}}]})
}

#[tokio::test]
async fn owner_creates_updates_and_deletes_with_versions_and_audit() {
    let (db, mut client) = setup().await;
    let created = dashboards::create(&mut client, ALICE, "Morning", &layout(), Utc::now())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (created.version, created.owner_display_name.as_str()),
        (1, "alice")
    );
    let updated = dashboards::update(
        &mut client,
        ALICE,
        &created.dashboard_id,
        "Morning check",
        &layout(),
        1,
        Utc::now(),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        (updated.version, updated.name.as_str()),
        (2, "Morning check")
    );
    assert_eq!(
        dashboards::delete(&mut client, ALICE, &created.dashboard_id)
            .await
            .unwrap(),
        Ok(())
    );
    assert!(
        dashboards::get_visible(&client, ALICE, &created.dashboard_id)
            .await
            .unwrap()
            .is_none()
    );
    let actions: Vec<String> = client
        .query(
            "SELECT action FROM audit_log WHERE target_kind = 'dashboard' ORDER BY id",
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|row| row.get(0))
        .collect();
    assert_eq!(
        actions,
        ["dashboard.create", "dashboard.update", "dashboard.delete"]
    );
    let leaked: i64 = client
        .query_one(
            "SELECT count(*) FROM audit_log WHERE detail::text LIKE '%widgets%'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        leaked, 0,
        "the layout must not be copied into the audit log"
    );
    db.drop().await;
}

#[tokio::test]
async fn stale_update_is_refused_and_keeps_the_first_save() {
    let (db, mut client) = setup().await;
    let created = dashboards::create(&mut client, ALICE, "A", &layout(), Utc::now())
        .await
        .unwrap()
        .unwrap();
    dashboards::update(
        &mut client,
        ALICE,
        &created.dashboard_id,
        "First tab",
        &layout(),
        1,
        Utc::now(),
    )
    .await
    .unwrap()
    .unwrap();
    let second = dashboards::update(
        &mut client,
        ALICE,
        &created.dashboard_id,
        "Second tab",
        &layout(),
        1,
        Utc::now(),
    )
    .await
    .unwrap();
    assert_eq!(second, Err(Refusal::Stale));
    assert_eq!(
        dashboards::get_visible(&client, ALICE, &created.dashboard_id)
            .await
            .unwrap()
            .unwrap()
            .name,
        "First tab"
    );
    db.drop().await;
}

#[tokio::test]
async fn others_see_only_what_is_shared_with_their_role_and_cannot_change_it() {
    let (db, mut client) = setup().await;
    let created = dashboards::create(&mut client, ALICE, "Team", &layout(), Utc::now())
        .await
        .unwrap()
        .unwrap();
    assert!(
        dashboards::list_visible(&client, BOB)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        dashboards::get_visible(&client, BOB, &created.dashboard_id)
            .await
            .unwrap()
            .is_none()
    );
    let shared = dashboards::set_sharing(
        &mut client,
        ALICE,
        &created.dashboard_id,
        Some("viewer"),
        Utc::now(),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(shared.shared_role_id.as_deref(), Some("viewer"));
    assert_eq!(
        dashboards::list_visible(&client, BOB).await.unwrap().len(),
        1
    );
    assert_eq!(
        dashboards::update(
            &mut client,
            BOB,
            &created.dashboard_id,
            "Mine now",
            &layout(),
            shared.version,
            Utc::now()
        )
        .await
        .unwrap(),
        Err(Refusal::NotOwner)
    );
    assert_eq!(
        dashboards::delete(&mut client, BOB, &created.dashboard_id)
            .await
            .unwrap(),
        Err(Refusal::NotOwner)
    );
    assert_eq!(
        dashboards::set_sharing(
            &mut client,
            ALICE,
            &created.dashboard_id,
            Some("no_such_role"),
            Utc::now()
        )
        .await
        .unwrap(),
        Err(Refusal::UnknownRole)
    );
    assert_eq!(
        dashboards::update(
            &mut client,
            BOB,
            "not-a-uuid",
            "x",
            &layout(),
            1,
            Utc::now()
        )
        .await
        .unwrap(),
        Err(Refusal::NotFound)
    );
    db.drop().await;
}

#[tokio::test]
async fn scoped_binding_sees_shared_dashboard() {
    let (db, mut client) = setup().await;
    let group: String = client
        .query_one(
            "INSERT INTO console_asset_groups (asset_group_id, name, created_at, created_by)
             VALUES (gen_random_uuid(), 'Production', now(), 'test') RETURNING asset_group_id::text",
            &[],
        )
        .await.unwrap().get(0);
    create_user_role_binding(
        &mut client,
        BOB,
        "analyst",
        Some(&group),
        "test",
        Utc::now(),
    )
    .await
    .unwrap()
    .unwrap();
    let created = dashboards::create(&mut client, ALICE, "Analysts", &layout(), Utc::now())
        .await
        .unwrap()
        .unwrap();
    dashboards::set_sharing(
        &mut client,
        ALICE,
        &created.dashboard_id,
        Some("analyst"),
        Utc::now(),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        dashboards::list_visible(&client, BOB).await.unwrap()[0].name,
        "Analysts"
    );
    db.drop().await;
}

#[tokio::test]
async fn revoked_binding_hides_dashboard_and_home() {
    let (db, mut client) = setup().await;
    let binding = create_user_role_binding(&mut client, BOB, "analyst", None, "test", Utc::now())
        .await
        .unwrap()
        .unwrap();
    let created = dashboards::create(&mut client, ALICE, "Analysts", &layout(), Utc::now())
        .await
        .unwrap()
        .unwrap();
    dashboards::set_sharing(
        &mut client,
        ALICE,
        &created.dashboard_id,
        Some("analyst"),
        Utc::now(),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        dashboards::set_home(&mut client, BOB, Some(&created.dashboard_id))
            .await
            .unwrap(),
        Ok(())
    );
    assert_eq!(
        dashboards::home(&client, BOB).await.unwrap(),
        Some(created.dashboard_id.clone())
    );
    revoke_user_role_binding(&mut client, &binding.binding_id, "test", Utc::now())
        .await
        .unwrap();
    assert!(
        dashboards::list_visible(&client, BOB)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        dashboards::get_visible(&client, BOB, &created.dashboard_id)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(dashboards::home(&client, BOB).await.unwrap(), None);
    db.drop().await;
}

#[tokio::test]
async fn home_is_cleared_with_its_dashboard_and_must_be_visible() {
    let (db, mut client) = setup().await;
    let created = dashboards::create(&mut client, ALICE, "Mine", &layout(), Utc::now())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        dashboards::set_home(&mut client, BOB, Some(&created.dashboard_id))
            .await
            .unwrap(),
        Err(Refusal::NotFound)
    );
    dashboards::set_home(&mut client, ALICE, Some(&created.dashboard_id))
        .await
        .unwrap()
        .unwrap();
    dashboards::delete(&mut client, ALICE, &created.dashboard_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(dashboards::home(&client, ALICE).await.unwrap(), None);
    assert_eq!(
        dashboards::set_home(&mut client, ALICE, None)
            .await
            .unwrap(),
        Ok(())
    );
    db.drop().await;
}

#[tokio::test]
async fn an_owner_may_keep_at_most_one_hundred_dashboards() {
    let (db, mut client) = setup().await;
    for index in 0..dashboards::MAX_DASHBOARDS_PER_OWNER {
        dashboards::create(
            &mut client,
            ALICE,
            &format!("D{index}"),
            &layout(),
            Utc::now(),
        )
        .await
        .unwrap()
        .unwrap();
    }
    assert_eq!(
        dashboards::create(&mut client, ALICE, "One too many", &layout(), Utc::now())
            .await
            .unwrap(),
        Err(Refusal::TooMany)
    );
    db.drop().await;
}

#[tokio::test]
async fn ids_are_uuids_in_any_case_and_malformed_ids_are_not_found() {
    let (db, mut client) = setup().await;
    let created = dashboards::create(&mut client, ALICE, "Case", &layout(), Utc::now())
        .await
        .unwrap()
        .unwrap();
    let upper = created.dashboard_id.to_uppercase();
    assert_eq!(
        dashboards::get_visible(&client, ALICE, &upper)
            .await
            .unwrap()
            .map(|d| d.name),
        Some("Case".to_owned())
    );
    assert!(
        dashboards::get_visible(&client, ALICE, "not-a-uuid")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        dashboards::get_visible(&client, ALICE, "'; DROP TABLE console_dashboards; --")
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        dashboards::delete(&mut client, ALICE, "0000")
            .await
            .unwrap(),
        Err(Refusal::NotFound)
    );
    db.drop().await;
}
