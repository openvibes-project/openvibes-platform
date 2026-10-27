//! Dashboards: ownership, visibility through role bindings, versions,
//! limits, home fallback, and transactional audit rows.

mod common;

use chrono::Utc;
use common::TestDb;
use platform_store::{
    Client,
    console_auth::{NewLocalUser, create_local_user},
    console_people::{give_role, remove_role},
    console_roles::{Principal, Reach, RoleInput, RoleWrite, create_role, delete_role},
    dashboards::{self, Refusal, Visibility},
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
    common::seed_role(&client, "viewer", &["hosts.read"]).await;
    common::seed_role(&client, "analyst", &["hosts.read"]).await;
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
    give_role(
        &mut client,
        Principal::User(ALICE),
        "viewer",
        "test",
        Utc::now(),
    )
    .await
    .unwrap();
    let shared = dashboards::set_sharing(
        &mut client,
        ALICE,
        &created.dashboard_id,
        Visibility::Roles,
        &["viewer".to_owned()],
        Utc::now(),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(shared.visibility, Visibility::Roles);
    assert_eq!(
        shared
            .roles
            .iter()
            .map(|r| r.role_id.as_str())
            .collect::<Vec<_>>(),
        ["viewer"]
    );
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
            Visibility::Roles,
            &["no_such_role".to_owned()],
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
    // A role reaching one group (what a scoped binding became in schema 52).
    let scoped = match create_role(
        &mut client,
        &RoleInput {
            name: "Analyst (Production)",
            description: "",
            permissions: &["hosts.read".to_owned()],
            reach: &Reach::Groups(vec![group]),
        },
        "test",
        Utc::now(),
    )
    .await
    .unwrap()
    {
        RoleWrite::Saved(role) => role.role_id,
        _ => panic!("role not saved"),
    };
    give_role(
        &mut client,
        Principal::User(BOB),
        &scoped,
        "test",
        Utc::now(),
    )
    .await
    .unwrap();
    give_role(
        &mut client,
        Principal::User(ALICE),
        &scoped,
        "test",
        Utc::now(),
    )
    .await
    .unwrap();
    let created = dashboards::create(&mut client, ALICE, "Analysts", &layout(), Utc::now())
        .await
        .unwrap()
        .unwrap();
    dashboards::set_sharing(
        &mut client,
        ALICE,
        &created.dashboard_id,
        Visibility::Roles,
        std::slice::from_ref(&scoped),
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
    give_role(
        &mut client,
        Principal::User(BOB),
        "analyst",
        "test",
        Utc::now(),
    )
    .await
    .unwrap();
    give_role(
        &mut client,
        Principal::User(ALICE),
        "analyst",
        "test",
        Utc::now(),
    )
    .await
    .unwrap();
    let created = dashboards::create(&mut client, ALICE, "Analysts", &layout(), Utc::now())
        .await
        .unwrap()
        .unwrap();
    dashboards::set_sharing(
        &mut client,
        ALICE,
        &created.dashboard_id,
        Visibility::Roles,
        &["analyst".to_owned()],
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
    remove_role(
        &mut client,
        Principal::User(BOB),
        "analyst",
        "test",
        Utc::now(),
    )
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

async fn share(
    client: &mut Client,
    dashboard_id: &str,
    visibility: Visibility,
    roles: &[&str],
) -> Result<dashboards::Dashboard, Refusal> {
    let roles: Vec<String> = roles.iter().map(|r| (*r).to_owned()).collect();
    dashboards::set_sharing(client, ALICE, dashboard_id, visibility, &roles, Utc::now())
        .await
        .unwrap()
}

#[tokio::test]
async fn sharing_with_roles_needs_roles_the_owner_holds() {
    let (db, mut client) = setup().await;
    let made = dashboards::create(&mut client, ALICE, "Team", &layout(), Utc::now())
        .await
        .unwrap()
        .unwrap();
    // Alice holds only Administrator; she cannot share with a role she lacks.
    assert_eq!(
        share(
            &mut client,
            &made.dashboard_id,
            Visibility::Roles,
            &["viewer"]
        )
        .await,
        Err(Refusal::RoleNotHeld)
    );
    assert_eq!(
        share(&mut client, &made.dashboard_id, Visibility::Roles, &[]).await,
        Err(Refusal::NoRoles)
    );
    assert_eq!(
        share(
            &mut client,
            &made.dashboard_id,
            Visibility::Roles,
            &["admin", "viewer"]
        )
        .await,
        Err(Refusal::RoleNotHeld)
    );
    // Nothing changed.
    let still = dashboards::get_visible(&client, ALICE, &made.dashboard_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!((still.visibility, still.version), (Visibility::Private, 1));
    db.drop().await;
}

#[tokio::test]
async fn several_roles_and_everyone_and_back_to_private() {
    let (db, mut client) = setup().await;
    for role in ["viewer", "analyst"] {
        give_role(
            &mut client,
            Principal::User(ALICE),
            role,
            "test",
            Utc::now(),
        )
        .await
        .unwrap();
    }
    give_role(
        &mut client,
        Principal::User(BOB),
        "viewer",
        "test",
        Utc::now(),
    )
    .await
    .unwrap();
    let made = dashboards::create(&mut client, ALICE, "Team", &layout(), Utc::now())
        .await
        .unwrap()
        .unwrap();
    let id = made.dashboard_id.clone();
    let roles = share(
        &mut client,
        &id,
        Visibility::Roles,
        &["analyst", "viewer", "viewer"],
    )
    .await
    .unwrap();
    assert_eq!(
        roles
            .roles
            .iter()
            .map(|r| r.role_id.as_str())
            .collect::<Vec<_>>(),
        ["analyst", "viewer"]
    );
    // Bob holds viewer only: he sees the dashboard, and only his own role on it.
    let seen = dashboards::get_visible(&client, BOB, &id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        seen.roles
            .iter()
            .map(|r| r.role_id.as_str())
            .collect::<Vec<_>>(),
        ["viewer"]
    );
    // Everyone: roles no longer matter, and a person with no role sees it.
    let everyone = share(&mut client, &id, Visibility::Everyone, &["viewer"])
        .await
        .unwrap();
    assert_eq!(
        (everyone.visibility, everyone.roles.len()),
        (Visibility::Everyone, 0)
    );
    remove_role(
        &mut client,
        Principal::User(BOB),
        "viewer",
        "test",
        Utc::now(),
    )
    .await
    .unwrap();
    assert!(
        dashboards::get_visible(&client, BOB, &id)
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(
        dashboards::list_visible(&client, BOB).await.unwrap().len(),
        1
    );
    // Private again: gone for Bob, version bumped each time.
    let private = share(&mut client, &id, Visibility::Private, &[])
        .await
        .unwrap();
    assert_eq!(
        (private.visibility, private.version),
        (Visibility::Private, 4)
    );
    assert!(
        dashboards::get_visible(&client, BOB, &id)
            .await
            .unwrap()
            .is_none()
    );
    // Each change is audited with before and after, and carries no layout.
    let audited: Vec<(String, String)> = client
        .query(
            "SELECT detail->'from'->>'visibility', detail->'to'->>'visibility'
             FROM audit_log WHERE action = 'dashboard.share' ORDER BY id",
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|r| (r.get(0), r.get(1)))
        .collect();
    assert_eq!(
        audited,
        [
            ("private".to_owned(), "roles".to_owned()),
            ("roles".to_owned(), "everyone".to_owned()),
            ("everyone".to_owned(), "private".to_owned()),
        ]
    );
    db.drop().await;
}

#[tokio::test]
async fn deleting_the_last_role_makes_the_dashboard_private() {
    let (db, mut client) = setup().await;
    let made = dashboards::create(&mut client, ALICE, "Team", &layout(), Utc::now())
        .await
        .unwrap()
        .unwrap();
    let mut role_ids = Vec::new();
    for name in ["Ops", "Night"] {
        let role = match create_role(
            &mut client,
            &RoleInput {
                name,
                description: "",
                permissions: &["hosts.read".to_owned()],
                reach: &Reach::None,
            },
            "test",
            Utc::now(),
        )
        .await
        .unwrap()
        {
            RoleWrite::Saved(role) => role.role_id,
            _ => panic!("role not saved"),
        };
        give_role(
            &mut client,
            Principal::User(ALICE),
            &role,
            "test",
            Utc::now(),
        )
        .await
        .unwrap();
        role_ids.push(role);
    }
    let both: Vec<&str> = role_ids.iter().map(String::as_str).collect();
    share(&mut client, &made.dashboard_id, Visibility::Roles, &both)
        .await
        .unwrap();
    // Alice stops holding the roles so they can be deleted.
    for role in &role_ids {
        remove_role(
            &mut client,
            Principal::User(ALICE),
            role,
            "test",
            Utc::now(),
        )
        .await
        .unwrap();
    }
    let first = delete_role(&mut client, &role_ids[0], "test", Utc::now())
        .await
        .unwrap();
    assert!(matches!(first, RoleWrite::Saved(_)));
    let after_one = dashboards::get_visible(&client, ALICE, &made.dashboard_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after_one.visibility, Visibility::Roles);
    assert_eq!(after_one.roles.len(), 1);
    delete_role(&mut client, &role_ids[1], "test", Utc::now())
        .await
        .unwrap();
    let after_two = dashboards::get_visible(&client, ALICE, &made.dashboard_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (after_two.visibility, after_two.roles.len()),
        (Visibility::Private, 0)
    );
    assert!(after_two.version > after_one.version);
    db.drop().await;
}

#[tokio::test]
async fn upgrade_makes_role_shares_roles_and_the_rest_private() {
    let db = TestDb::create().await;
    let client = common::at_version(&db, 67).await;
    client
        .batch_execute(
            "INSERT INTO console_users (user_id, username, display_name, created_at)
               VALUES ('11111111-1111-4111-8111-111111111111','alice','Alice',now());
             INSERT INTO console_roles (role_id, display_name) VALUES ('ops','Ops');
             INSERT INTO console_dashboards (dashboard_id, owner_user_id, name, layout, created_at, updated_at) VALUES
               ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','11111111-1111-4111-8111-111111111111','Shared','{\"schema\":1,\"widgets\":[]}',now(),now()),
               ('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb','11111111-1111-4111-8111-111111111111','Mine','{\"schema\":1,\"widgets\":[]}',now(),now());
             INSERT INTO console_dashboard_roles VALUES ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','ops');",
        )
        .await
        .unwrap();
    common::step_to(&client, 68).await;
    let rows: Vec<(String, String)> = client
        .query(
            "SELECT name, visibility FROM console_dashboards ORDER BY name",
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|r| (r.get(0), r.get(1)))
        .collect();
    assert_eq!(
        rows,
        [
            ("Mine".to_owned(), "private".to_owned()),
            ("Shared".to_owned(), "roles".to_owned()),
        ]
    );
    db.drop().await;
}
