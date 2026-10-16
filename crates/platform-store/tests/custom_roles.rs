//! Migration 52 turns roles into named sets of permissions with a host reach
//! and moves scoped bindings into roles without changing anyone's access or
//! shared dashboards (spec 2026-10-16-roles-permissions-design.md §4, §12
//! parts 2–3). Role writes are tested in `role_writes.rs`.
mod common;

use std::collections::BTreeSet;

use platform_store::{
    Client,
    console_roles::{Principal, Reach, grants, list_roles, role},
};

const ANA: &str = "00000000-0000-4000-8000-0000000000a1";
const OP: &str = "00000000-0000-4000-8000-0000000000a2";
const LAB: &str = "00000000-0000-4000-8000-0000000000a3";
const ADM: &str = "00000000-0000-4000-8000-0000000000a4";
const VW: &str = "00000000-0000-4000-8000-0000000000a5";
const SAD: &str = "00000000-0000-4000-8000-0000000000a6";
const CI: &str = "00000000-0000-4000-8000-0000000000c1";
const CI2: &str = "00000000-0000-4000-8000-0000000000c2";
const G_LAB: &str = "00000000-0000-4000-8000-0000000000f1";
const G_PROD: &str = "00000000-0000-4000-8000-0000000000f2";

/// Version-51 shapes: two groups, three agents, and the people of the brief.
/// `ana` also has a revoked viewer binding (history must not block the drop);
/// viewer is otherwise held only through scoped bindings (`vw`, service
/// account `ci2`) unless `with_ci` adds a global holder; `sad` holds `admin`
/// on Prod only. `adm` owns two dashboards: "Ops" shared with operator and
/// "View" shared with viewer.
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
           ('{LAB}','lab','Lab',now()), ('{ADM}','adm','Adm',now()),
           ('{VW}','vw','Vw',now()), ('{SAD}','sad','Sad',now());
         INSERT INTO console_service_accounts (service_account_id, name, created_at, created_by)
           VALUES ('{CI2}','ci2',now(),'t');
         INSERT INTO console_role_bindings (binding_id, user_id, role_id, asset_group_id, created_at, created_by, revoked_at, revoked_by) VALUES
           (gen_random_uuid(),'{ANA}','analyst',NULL,now(),'t',NULL,NULL),
           (gen_random_uuid(),'{ANA}','viewer',NULL,now(),'t',now(),'t'),
           (gen_random_uuid(),'{OP}','operator',NULL,now(),'t',NULL,NULL),
           (gen_random_uuid(),'{OP}','operator','{G_LAB}',now(),'t',NULL,NULL),
           (gen_random_uuid(),'{LAB}','operator','{G_LAB}',now(),'t',NULL,NULL),
           (gen_random_uuid(),'{LAB}','operator','{G_PROD}',now(),'t',NULL,NULL),
           (gen_random_uuid(),'{ADM}','admin',NULL,now(),'t',NULL,NULL),
           (gen_random_uuid(),'{VW}','viewer','{G_PROD}',now(),'t',NULL,NULL),
           (gen_random_uuid(),'{SAD}','admin','{G_PROD}',now(),'t',NULL,NULL);
         INSERT INTO console_role_bindings (binding_id, service_account_id, role_id, asset_group_id, created_at, created_by)
           VALUES (gen_random_uuid(),'{CI2}','viewer','{G_LAB}',now(),'t');
         INSERT INTO console_dashboards (dashboard_id, owner_user_id, name, layout, shared_role_id, created_at, updated_at) VALUES
           (gen_random_uuid(),'{ADM}','Ops','{{\"schema\":1,\"widgets\":[]}}','operator',now(),now()),
           (gen_random_uuid(),'{ADM}','View','{{\"schema\":1,\"widgets\":[]}}','viewer',now(),now());"
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
        (VW, Principal::User(VW)),
        (SAD, Principal::User(SAD)),
        (CI, Principal::ServiceAccount(CI)),
        (CI2, Principal::ServiceAccount(CI2)),
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
    // With a global viewer (kept) and without (viewer held only through
    // scoped bindings, so deleted after its permissions are copied).
    for with_ci in [true, false] {
        let (db, client, before) = upgraded(with_ci).await;
        for principal in [LAB, VW, SAD, CI2] {
            assert!(before.iter().any(|(p, _, _)| p == principal), "{principal}");
        }
        assert_eq!(before.iter().any(|(p, _, _)| p == CI), with_ci);
        assert_eq!(
            role(&client, "viewer").await.unwrap().is_some(),
            with_ci,
            "viewer kept only while held globally"
        );
        assert_eq!(access_v52(&client).await, before, "with_ci {with_ci}");
        db.drop().await;
    }
}

async fn visible(client: &Client, user: &str) -> BTreeSet<String> {
    platform_store::dashboards::list_visible(client, user)
        .await
        .unwrap()
        .into_iter()
        .map(|d| d.name)
        .collect()
}

#[tokio::test]
async fn upgrade_keeps_shared_dashboards_visible() {
    let (db, client, _) = upgraded(false).await;
    // Shared with operator: its global holder and its scoped holders.
    assert!(visible(&client, OP).await.contains("Ops"));
    assert!(visible(&client, LAB).await.contains("Ops"));
    // Shared with viewer, which only scoped holders had and is now gone.
    assert!(role(&client, "viewer").await.unwrap().is_none());
    assert_eq!(
        visible(&client, VW).await,
        BTreeSet::from(["View".to_owned()])
    );
    assert!(!visible(&client, ANA).await.contains("View"));
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
    assert_eq!(moved, 6);
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
