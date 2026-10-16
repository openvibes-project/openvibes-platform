//! The role store (`console_roles`): writes round-trip and refuse what they
//! must, grants come back per principal, and the last enabled Administrator
//! stays (spec 2026-10-16-roles-permissions-design.md §4).
mod common;

use chrono::Utc;
use platform_store::{
    Client,
    console_auth::{
        AuditContext, BindingRevocation, DisableOutcome, NewLocalUser, create_local_user,
        create_user_role_binding, disable_local_user, revoke_user_role_binding,
    },
    console_roles::{
        Principal, Reach, RoleInput, RoleWrite, StoredRole, create_role, delete_role, grants, role,
        update_role,
    },
};

const ANA: &str = "00000000-0000-4000-8000-0000000000a1";
const OP: &str = "00000000-0000-4000-8000-0000000000a2";
const ADM: &str = "00000000-0000-4000-8000-0000000000a4";
const G_LAB: &str = "00000000-0000-4000-8000-0000000000f1";

fn saved(write: RoleWrite) -> StoredRole {
    match write {
        RoleWrite::Saved(role) => role,
        _ => panic!("not saved"),
    }
}

async fn person(client: &mut Client, id: &str, name: &str, role_id: &str) {
    create_local_user(
        client,
        &NewLocalUser {
            user_id: id,
            binding_id: &id.replace("4000", "4111"),
            username: name,
            display_name: name,
            password_phc: "$argon2id$v=19$m=19456,t=2,p=1$opaque-salt$opaque-hash",
            role_id,
            actor_id: "test",
            actor_kind: "local_admin",
            password_must_change: false,
            now: Utc::now(),
        },
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn roles_crud_round_trips_and_refuses_name_clash_and_stale_versions() {
    let (db, mut client) = common::migrated().await;
    let now = Utc::now();
    let perms = vec!["hosts.read".to_owned()];
    let input = RoleInput {
        name: "Night shift",
        description: "Watches at night",
        permissions: &perms,
        reach: &Reach::All,
    };
    let created = saved(create_role(&mut client, &input, "t", now).await.unwrap());
    assert!(created.role_id.starts_with("r_") && created.role_id.len() == 18);
    assert_eq!((created.version, created.members), (1, 0));
    assert_eq!(created.permissions, perms);
    let more = vec!["hosts.read".to_owned(), "alarms.read".to_owned()];
    let edited = RoleInput {
        permissions: &more,
        description: "",
        ..input
    };
    let updated = saved(
        update_role(&mut client, &created.role_id, 1, &edited, "t", now)
            .await
            .unwrap(),
    );
    assert_eq!(updated.version, 2);
    assert_eq!(updated.permissions.len(), 2);
    assert!(matches!(
        update_role(&mut client, &created.role_id, 1, &edited, "t", now)
            .await
            .unwrap(),
        RoleWrite::Stale
    ));
    let clash = RoleInput {
        name: "NIGHT SHIFT",
        ..input
    };
    assert!(matches!(
        create_role(&mut client, &clash, "t", now).await.unwrap(),
        RoleWrite::NameTaken
    ));
    assert!(matches!(
        update_role(&mut client, "admin", 1, &input, "t", now)
            .await
            .unwrap(),
        RoleWrite::Protected
    ));
    assert!(matches!(
        delete_role(&mut client, "admin", "t", now).await.unwrap(),
        RoleWrite::Protected
    ));
    assert!(matches!(
        delete_role(&mut client, "r_0000000000000000", "t", now)
            .await
            .unwrap(),
        RoleWrite::NotFound
    ));
    person(&mut client, ANA, "ana", &created.role_id).await;
    assert!(matches!(
        delete_role(&mut client, &created.role_id, "t", now)
            .await
            .unwrap(),
        RoleWrite::InUse(1)
    ));
    let spare = RoleInput {
        name: "Spare",
        ..input
    };
    let spare = saved(create_role(&mut client, &spare, "t", now).await.unwrap());
    let renamed = RoleInput {
        name: "night SHIFT",
        ..input
    };
    assert!(matches!(
        update_role(&mut client, &spare.role_id, 1, &renamed, "t", now)
            .await
            .unwrap(),
        RoleWrite::NameTaken
    ));
    saved(
        delete_role(&mut client, &spare.role_id, "t", now)
            .await
            .unwrap(),
    );
    assert!(role(&client, &spare.role_id).await.unwrap().is_none());
    let audited: Vec<String> = client
        .query(
            "SELECT action FROM audit_log WHERE target_kind = 'role' ORDER BY id",
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|r| r.get(0))
        .collect();
    assert_eq!(
        audited,
        [
            "rbac.role.created",
            "rbac.role.updated",
            "rbac.role.created",
            "rbac.role.deleted"
        ]
    );
    db.drop().await;
}

#[tokio::test]
async fn grants_are_one_query_per_principal() {
    let (db, mut client) = common::migrated().await;
    let now = Utc::now();
    client
        .batch_execute(&format!(
            "INSERT INTO console_asset_groups VALUES ('{G_LAB}','Lab',now(),'t')"
        ))
        .await
        .unwrap();
    let read = vec!["hosts.read".to_owned()];
    let audit = vec!["audit.read".to_owned()];
    let lab = Reach::Groups(vec![G_LAB.to_owned()]);
    let a = saved(
        create_role(
            &mut client,
            &RoleInput {
                name: "A",
                description: "",
                permissions: &read,
                reach: &lab,
            },
            "t",
            now,
        )
        .await
        .unwrap(),
    );
    let b = saved(
        create_role(
            &mut client,
            &RoleInput {
                name: "B",
                description: "",
                permissions: &audit,
                reach: &Reach::None,
            },
            "t",
            now,
        )
        .await
        .unwrap(),
    );
    assert_eq!(a.group_names, [(G_LAB.to_owned(), "Lab".to_owned())]);
    person(&mut client, ANA, "ana", &a.role_id).await;
    create_user_role_binding(&mut client, ANA, &b.role_id, "t", now)
        .await
        .unwrap()
        .unwrap();
    let mut held = grants(&client, Principal::User(ANA)).await.unwrap();
    held.sort_by(|x, y| x.role_id.cmp(&y.role_id));
    let mut expected = vec![
        (a.role_id.clone(), read, lab),
        (b.role_id.clone(), audit, Reach::None),
    ];
    expected.sort_by(|x, y| x.0.cmp(&y.0));
    assert_eq!(
        held.into_iter()
            .map(|g| (g.role_id, g.permissions, g.reach))
            .collect::<Vec<_>>(),
        expected
    );
    let sa = platform_store::console_auth::create_service_account(
        &mut client,
        "ci",
        &a.role_id,
        "t",
        now,
    )
    .await
    .unwrap()
    .unwrap();
    let held = grants(&client, Principal::ServiceAccount(&sa))
        .await
        .unwrap();
    assert_eq!(held.len(), 1);
    assert_eq!(held[0].role_id, a.role_id);
    db.drop().await;
}

#[tokio::test]
async fn the_last_enabled_administrator_cannot_be_removed_or_disabled() {
    let (db, mut client) = common::migrated().await;
    let now = Utc::now();
    person(&mut client, ADM, "adm", "admin").await;
    let binding: String = client
        .query_one(
            "SELECT binding_id::text FROM console_role_bindings WHERE user_id = $1::text::uuid",
            &[&ADM],
        )
        .await
        .unwrap()
        .get(0);
    let audit = AuditContext::default();
    assert_eq!(
        revoke_user_role_binding(&mut client, &binding, "t", now)
            .await
            .unwrap(),
        BindingRevocation::LastAdministrator
    );
    assert_eq!(
        disable_local_user(&mut client, ADM, now, &audit, "t", "user")
            .await
            .unwrap(),
        DisableOutcome::LastAdministrator
    );
    person(&mut client, OP, "op", "admin").await;
    assert_eq!(
        disable_local_user(&mut client, ADM, now, &audit, "t", "user")
            .await
            .unwrap(),
        DisableOutcome::Disabled
    );
    assert_eq!(
        disable_local_user(&mut client, ADM, now, &audit, "t", "user")
            .await
            .unwrap(),
        DisableOutcome::NotFound
    );
    db.drop().await;
}

#[tokio::test]
async fn unknown_permissions_and_groups_are_refused_and_duplicates_collapse() {
    let (db, mut client) = common::migrated().await;
    let now = Utc::now();
    client
        .batch_execute(&format!(
            "INSERT INTO console_asset_groups VALUES ('{G_LAB}','Lab',now(),'t')"
        ))
        .await
        .unwrap();
    let read = vec!["hosts.read".to_owned()];
    let unknown_permission = vec!["no.such".to_owned()];
    let missing_group = Reach::Groups(vec!["00000000-0000-4000-8000-0000000000ff".to_owned()]);
    let not_a_uuid = Reach::Groups(vec!["lab".to_owned()]);
    for (permissions, reach) in [
        (&unknown_permission, &Reach::All),
        (&read, &missing_group),
        (&read, &not_a_uuid),
    ] {
        let input = RoleInput {
            name: "X",
            description: "",
            permissions,
            reach,
        };
        assert!(matches!(
            create_role(&mut client, &input, "t", now).await.unwrap(),
            RoleWrite::UnknownReference
        ));
    }
    let twice = vec!["hosts.read".to_owned(), "hosts.read".to_owned()];
    let lab_twice = Reach::Groups(vec![G_LAB.to_owned(), G_LAB.to_owned()]);
    let input = RoleInput {
        name: "X",
        description: "",
        permissions: &twice,
        reach: &lab_twice,
    };
    let created = saved(create_role(&mut client, &input, "t", now).await.unwrap());
    assert_eq!(created.permissions, read);
    assert_eq!(created.reach, Reach::Groups(vec![G_LAB.to_owned()]));
    let edit = RoleInput {
        permissions: &unknown_permission,
        ..input
    };
    assert!(matches!(
        update_role(&mut client, &created.role_id, 1, &edit, "t", now)
            .await
            .unwrap(),
        RoleWrite::UnknownReference
    ));
    let kept = role(&client, &created.role_id).await.unwrap().unwrap();
    assert_eq!((kept.version, kept.permissions), (1, read));
    db.drop().await;
}
