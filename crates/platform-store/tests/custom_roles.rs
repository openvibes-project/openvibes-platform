//! Migration 52 turns roles into named sets of permissions with a host reach
//! and moves scoped bindings into roles without changing anyone's access
//! (spec 2026-10-16-roles-permissions-design.md §4, §12 parts 2–3), and the
//! role store (`console_roles`) round-trips.
mod common;

use std::collections::BTreeSet;

use chrono::Utc;
use platform_store::{
    Client,
    console_auth::{
        AuditContext, BindingRevocation, DisableOutcome, NewLocalUser, create_local_user,
        create_user_role_binding, disable_local_user, revoke_user_role_binding,
    },
    console_roles::{
        Principal, Reach, RoleInput, RoleWrite, StoredRole, create_role, delete_role, grants,
        list_roles, role, update_role,
    },
};

const ANA: &str = "00000000-0000-4000-8000-0000000000a1";
const OP: &str = "00000000-0000-4000-8000-0000000000a2";
const LAB: &str = "00000000-0000-4000-8000-0000000000a3";
const ADM: &str = "00000000-0000-4000-8000-0000000000a4";
const CI: &str = "00000000-0000-4000-8000-0000000000c1";
const G_LAB: &str = "00000000-0000-4000-8000-0000000000f1";
const G_PROD: &str = "00000000-0000-4000-8000-0000000000f2";

/// Version-51 shapes: two groups, three agents, and the people of the brief.
/// `ana` also has a revoked viewer binding (history must not block the drop).
async fn seed_v51(c: &Client, with_ci: bool) {
    let mut sql = format!(
        "INSERT INTO agents (agent_id, status, enrolled_at) VALUES
           ('agent.00000000-0000-4000-8000-000000000001','active',now()),
           ('agent.00000000-0000-4000-8000-000000000002','active',now()),
           ('agent.00000000-0000-4000-8000-000000000003','active',now());
         INSERT INTO console_agent_tags VALUES
           ('agent.00000000-0000-4000-8000-000000000001','env','lab',now(),'t'),
           ('agent.00000000-0000-4000-8000-000000000002','env','prod',now(),'t');
         INSERT INTO console_asset_groups VALUES ('{G_LAB}','Lab',now(),'t'), ('{G_PROD}','Prod',now(),'t');
         INSERT INTO console_asset_group_selectors VALUES
           ('{G_LAB}','env','lab',now()), ('{G_PROD}','env','prod',now());
         INSERT INTO console_users (user_id, username, display_name, created_at) VALUES
           ('{ANA}','ana','Ana',now()), ('{OP}','op','Op',now()),
           ('{LAB}','lab','Lab',now()), ('{ADM}','adm','Adm',now());
         INSERT INTO console_role_bindings (binding_id, user_id, role_id, asset_group_id, created_at, created_by, revoked_at, revoked_by) VALUES
           (gen_random_uuid(),'{ANA}','analyst',NULL,now(),'t',NULL,NULL),
           (gen_random_uuid(),'{ANA}','viewer',NULL,now(),'t',now(),'t'),
           (gen_random_uuid(),'{OP}','operator',NULL,now(),'t',NULL,NULL),
           (gen_random_uuid(),'{OP}','operator','{G_LAB}',now(),'t',NULL,NULL),
           (gen_random_uuid(),'{LAB}','operator','{G_LAB}',now(),'t',NULL,NULL),
           (gen_random_uuid(),'{LAB}','operator','{G_PROD}',now(),'t',NULL,NULL),
           (gen_random_uuid(),'{ADM}','admin',NULL,now(),'t',NULL,NULL);"
    );
    if with_ci {
        sql += &format!(
            "INSERT INTO console_service_accounts (service_account_id, name, created_at, created_by)
               VALUES ('{CI}','ci',now(),'t');
             INSERT INTO console_role_bindings (binding_id, service_account_id, role_id, created_at, created_by)
               VALUES (gen_random_uuid(),'{CI}','viewer',now(),'t');"
        );
    }
    c.batch_execute(&sql).await.unwrap();
}

const MEMBERS: &str = "SELECT g.asset_group_id::text, a.agent_id FROM console_asset_groups g CROSS JOIN agents a
    WHERE EXISTS (SELECT 1 FROM console_asset_group_selectors s WHERE s.asset_group_id = g.asset_group_id)
      AND NOT EXISTS (SELECT 1 FROM console_asset_group_selectors s WHERE s.asset_group_id = g.asset_group_id
        AND NOT EXISTS (SELECT 1 FROM console_agent_tags t WHERE t.agent_id = a.agent_id
                        AND t.tag_key = s.tag_key AND t.tag_value = s.tag_value))";

type Access = BTreeSet<(String, String, String)>;

/// v51 semantics: a global binding grants every permission of the role on
/// every agent; a scoped one only the agent-scoped permissions on its group.
async fn access_v51(c: &Client) -> Access {
    let sql = format!(
        "WITH m AS ({MEMBERS})
         SELECT COALESCE(b.user_id, b.service_account_id)::text, rp.permission_id, a.agent_id
         FROM console_role_bindings b JOIN console_role_permissions rp USING (role_id) CROSS JOIN agents a
         WHERE b.revoked_at IS NULL AND b.asset_group_id IS NULL
         UNION
         SELECT COALESCE(b.user_id, b.service_account_id)::text, rp.permission_id, m.agent_id
         FROM console_role_bindings b JOIN console_role_permissions rp USING (role_id)
         JOIN console_permissions p USING (permission_id) JOIN m ON m.asset_group_id = b.asset_group_id::text
         WHERE b.revoked_at IS NULL AND p.scope_class = 'agent'"
    );
    let rows = c.query(&sql, &[]).await.unwrap();
    rows.iter()
        .map(|r| (r.get(0), r.get(1), r.get(2)))
        .collect()
}

/// The same, from `console_roles::grants`.
async fn access_v52(c: &Client) -> Access {
    let agents: Vec<String> = c
        .query("SELECT agent_id FROM agents", &[])
        .await
        .unwrap()
        .iter()
        .map(|r| r.get(0))
        .collect();
    let members: Vec<(String, String)> = c
        .query(MEMBERS, &[])
        .await
        .unwrap()
        .iter()
        .map(|r| (r.get(0), r.get(1)))
        .collect();
    let mut out = Access::new();
    for (id, principal) in [
        (ANA, Principal::User(ANA)),
        (OP, Principal::User(OP)),
        (LAB, Principal::User(LAB)),
        (ADM, Principal::User(ADM)),
        (CI, Principal::ServiceAccount(CI)),
    ] {
        for grant in grants(c, principal).await.unwrap() {
            let reached: Vec<&String> = match &grant.reach {
                Reach::All => agents.iter().collect(),
                Reach::Groups(groups) => members
                    .iter()
                    .filter(|(g, _)| groups.contains(g))
                    .map(|(_, a)| a)
                    .collect(),
                Reach::None => Vec::new(),
            };
            for permission in &grant.permissions {
                for agent in &reached {
                    out.insert((id.into(), permission.clone(), (*agent).clone()));
                }
            }
        }
    }
    out
}

async fn upgraded(with_ci: bool) -> (common::TestDb, Client, Access) {
    let db = common::TestDb::create().await;
    let client = common::at_version(&db, 51).await;
    seed_v51(&client, with_ci).await;
    let before = access_v51(&client).await;
    drop(client);
    let mut client = db.pool.get().await.unwrap();
    assert_eq!(platform_store::migrate(&mut client).await.unwrap(), 52);
    (db, client, before)
}

#[tokio::test]
async fn upgrade_keeps_everyones_effective_access() {
    let (db, client, before) = upgraded(true).await;
    assert!(before.iter().any(|(p, _, _)| p == CI));
    assert!(before.iter().any(|(p, _, _)| p == LAB));
    assert_eq!(access_v52(&client).await, before);
    db.drop().await;
}

#[tokio::test]
async fn upgrade_merges_one_holders_scoped_bindings() {
    let (db, client, _) = upgraded(false).await;
    let held = grants(&client, Principal::User(LAB)).await.unwrap();
    assert_eq!(held.len(), 1);
    let stored = role(&client, &held[0].role_id).await.unwrap().unwrap();
    assert_eq!(stored.name, "Operator (Lab, Prod)");
    let mut both = vec![G_LAB.to_owned(), G_PROD.to_owned()];
    both.sort();
    assert_eq!(stored.reach, Reach::Groups(both));
    assert!(!stored.builtin);
    let agent_scoped: Vec<String> = client
        .query(
            "SELECT rp.permission_id FROM console_role_permissions rp
             JOIN console_permissions p USING (permission_id)
             WHERE rp.role_id = 'operator' AND p.scope_class = 'agent' ORDER BY 1",
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|r| r.get(0))
        .collect();
    let mut permissions = stored.permissions.clone();
    permissions.sort();
    assert_eq!(permissions, agent_scoped);
    // op keeps the global operator and gains "Operator (Lab)".
    let names: BTreeSet<String> = list_roles(&client)
        .await
        .unwrap()
        .into_iter()
        .map(|r| r.name)
        .collect();
    assert!(names.contains("Operator (Lab)"));
    let moved: i64 = client
        .query_one(
            "SELECT count(*) FROM audit_log WHERE action = 'rbac.binding.migrated'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(moved, 3);
    db.drop().await;
}

#[tokio::test]
async fn unused_builtin_roles_are_dropped_and_admin_stays_protected() {
    let (db, client, _) = upgraded(false).await;
    assert!(role(&client, "viewer").await.unwrap().is_none());
    for id in ["analyst", "operator"] {
        let r = role(&client, id).await.unwrap().unwrap();
        assert!(!r.builtin, "{id}");
        assert_eq!(r.reach, Reach::All, "{id}");
    }
    let admin = role(&client, "admin").await.unwrap().unwrap();
    assert!(admin.builtin);
    assert_eq!(admin.name, "Administrator");
    assert_eq!(admin.reach, Reach::All);
    assert_eq!(admin.members, 1);
    db.drop().await;
}

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
