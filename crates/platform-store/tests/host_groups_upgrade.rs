//! Migration 53 turns every tag-based asset group into a manual group of the
//! hosts it matched, tags into labels, and makes automatic groups for the
//! facts already reported, without changing which hosts a role reaches
//! (spec 2026-10-16-roles-permissions-design.md §5.3, §12 part 4).
mod common;

use std::collections::{BTreeMap, BTreeSet};

use platform_store::{
    Client,
    console_read::{AgentScope, agent_ids_in_scope},
};

const G_PROD: &str = "00000000-0000-4000-8000-0000000000f1";
const G_PROD_WEB: &str = "00000000-0000-4000-8000-0000000000f2";
const G_EMPTY: &str = "00000000-0000-4000-8000-0000000000f3";
const PROD: &str = "agent.00000000-0000-4000-8000-000000000001";
const PROD_WEB: &str = "agent.00000000-0000-4000-8000-000000000002";
const LAB: &str = "agent.00000000-0000-4000-8000-000000000003";
const REVOKED: &str = "agent.00000000-0000-4000-8000-000000000004";

/// Version-52 shapes: tagged agents (one revoked, one imported), groups with
/// one selector, two selectors and none, and roles reaching them.
async fn seed_v52(c: &Client) {
    c.batch_execute(&format!(
        "INSERT INTO agents (agent_id, status, enrolled_at, os_id, os_version) VALUES
           ('{PROD}','active',now(),'debian','12'),
           ('{PROD_WEB}','active',now(),'rocky','9.4'),
           ('{LAB}','active',now(),'debian','12'),
           ('{REVOKED}','revoked',now(),'fedora','44');
         INSERT INTO agents (agent_id, status, enrolled_at) VALUES ('import.1','imported',now());
         INSERT INTO console_agent_tags VALUES
           ('{PROD}','env','prod',now(),'t'),
           ('{PROD_WEB}','env','prod',now(),'t'), ('{PROD_WEB}','role','web',now(),'t'),
           ('{LAB}','env','lab',now(),'t'),
           ('{REVOKED}','env','prod',now(),'t'), ('{REVOKED}','role','web',now(),'t'),
           ('import.1','env','prod',now(),'t');
         INSERT INTO console_asset_groups VALUES
           ('{G_PROD}','Production',now(),'t'), ('{G_PROD_WEB}','Prod web',now(),'t'),
           ('{G_EMPTY}','Debian 12',now(),'t');
         INSERT INTO console_asset_group_selectors VALUES
           ('{G_PROD}','env','prod',now()),
           ('{G_PROD_WEB}','env','prod',now()), ('{G_PROD_WEB}','role','web',now());
         INSERT INTO console_roles (role_id, display_name) VALUES
           ('r_prod','Prod'), ('r_web','Web'), ('r_empty','Empty'), ('r_both','Both');
         INSERT INTO console_role_groups VALUES
           ('r_prod','{G_PROD}'), ('r_web','{G_PROD_WEB}'), ('r_empty','{G_EMPTY}'),
           ('r_both','{G_PROD_WEB}'), ('r_both','{G_EMPTY}');"
    ))
    .await
    .unwrap();
}

async fn role_groups(c: &Client) -> BTreeMap<String, Vec<String>> {
    c.query(
        "SELECT role_id, array_agg(asset_group_id::text) FROM console_role_groups GROUP BY 1",
        &[],
    )
    .await
    .unwrap()
    .iter()
    .map(|r| (r.get(0), r.get(1)))
    .collect()
}

type Reached = BTreeMap<String, BTreeSet<String>>;

/// v52 `agent_visibility` for a scoped caller: a group with selectors whose
/// every tag the host carries; imported hosts never.
async fn reached_v52(c: &Client) -> Reached {
    let mut out = Reached::new();
    for (role, groups) in role_groups(c).await {
        let rows = c
            .query(
                "SELECT a.agent_id FROM agents a WHERE a.status <> 'imported' AND EXISTS (
                   SELECT 1 FROM console_asset_group_selectors s
                   WHERE s.asset_group_id::text = ANY($1::text[])
                     AND NOT EXISTS (SELECT 1 FROM console_asset_group_selectors r
                       WHERE r.asset_group_id = s.asset_group_id
                         AND NOT EXISTS (SELECT 1 FROM console_agent_tags t
                           WHERE t.agent_id = a.agent_id AND t.tag_key = r.tag_key
                             AND t.tag_value = r.tag_value)))",
                &[&groups],
            )
            .await
            .unwrap();
        out.insert(role, rows.iter().map(|r| r.get(0)).collect());
    }
    out
}

async fn reached_v53(c: &Client) -> Reached {
    let mut out = Reached::new();
    for (role, groups) in role_groups(c).await {
        let ids = agent_ids_in_scope(c, &AgentScope::AssetGroups(groups))
            .await
            .unwrap();
        out.insert(role, ids.into_iter().collect());
    }
    out
}

#[tokio::test]
async fn upgrade_keeps_every_roles_hosts() {
    let db = common::TestDb::create().await;
    let client = common::at_version(&db, 52).await;
    seed_v52(&client).await;
    let mut before = reached_v52(&client).await;
    drop(client);
    let mut c = db.pool.get().await.unwrap();
    assert_eq!(platform_store::migrate(&mut c).await.unwrap(), 58);

    // Revoked hosts are members of no group now (§5.1): the one change.
    assert!(before["r_prod"].contains(REVOKED));
    for hosts in before.values_mut() {
        hosts.remove(REVOKED);
    }
    assert_eq!(reached_v53(&c).await, before);
    assert_eq!(
        before["r_prod"],
        BTreeSet::from([PROD.to_owned(), PROD_WEB.to_owned()])
    );
    assert!(before["r_empty"].is_empty());

    let labels: BTreeSet<(String, String)> = c
        .query("SELECT agent_id, label FROM console_host_labels", &[])
        .await
        .unwrap()
        .iter()
        .map(|r| (r.get(0), r.get(1)))
        .collect();
    assert!(labels.contains(&(PROD.to_owned(), "env:prod".to_owned())));
    assert!(labels.contains(&(PROD_WEB.to_owned(), "role:web".to_owned())));
    assert!(labels.contains(&(REVOKED.to_owned(), "env:prod".to_owned())));
    assert_eq!(labels.len(), 7);

    for (group, description) in [
        (
            G_PROD,
            "Upgraded from an asset group (it used the env=prod tag): the same hosts, now hand-picked. Turn it into a rule when you can.",
        ),
        (
            G_PROD_WEB,
            "Upgraded from an asset group (it used the env=prod, role=web tags): the same hosts, now hand-picked. Turn it into a rule when you can.",
        ),
        (
            G_EMPTY,
            "Upgraded from an asset group without tags, which matched no host. Pick hosts or turn it into a rule.",
        ),
    ] {
        let row = c
            .query_one(
                "SELECT kind, upgraded_from_tags, description,
                        (SELECT count(*) FROM console_host_group_members m WHERE m.asset_group_id = g.asset_group_id),
                        (SELECT count(*) FROM audit_log WHERE action = 'host_group.migrated' AND target_id = $1)
                 FROM console_asset_groups g WHERE asset_group_id = $1::text::uuid",
                &[&group],
            )
            .await
            .unwrap();
        assert_eq!(row.get::<_, &str>(0), "manual", "{group}");
        assert!(row.get::<_, bool>(1), "{group}");
        assert_eq!(row.get::<_, &str>(2), description);
        assert_eq!(
            row.get::<_, i64>(3),
            match group {
                G_PROD => 2,
                G_PROD_WEB => 1,
                _ => 0,
            }
        );
        assert_eq!(row.get::<_, i64>(4), 1, "{group}");
    }

    // Automatic groups for the active hosts' facts (the revoked Fedora host
    // makes none); "Debian 12" is taken by an upgraded group.
    let automatic: BTreeSet<(String, String, String, String)> = c
        .query(
            "SELECT g.auto_key, g.name, c.field, c.vals[1] FROM console_asset_groups g
             JOIN console_host_group_conditions c USING (asset_group_id)
             WHERE g.kind = 'automatic'",
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|r| (r.get(0), r.get(1), r.get(2), r.get(3)))
        .collect();
    let row = |k: &str, n: &str, f: &str, v: &str| (k.into(), n.into(), f.into(), v.into());
    assert_eq!(
        automatic,
        BTreeSet::from([
            row("os_family:linux", "Linux", "os_family", "linux"),
            row(
                "distribution:debian 12",
                "Debian 12 (automatic)",
                "distribution",
                "debian 12"
            ),
            row(
                "distribution:rocky 9",
                "Rocky Linux 9",
                "distribution",
                "rocky 9"
            ),
        ])
    );
    let created: i64 = c
        .query_one(
            "SELECT count(*) FROM audit_log WHERE action = 'host_group.created_automatically'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(created, 3);
    db.drop().await;
}

#[tokio::test]
async fn the_tag_tables_and_their_grants_are_gone() {
    let (db, c) = common::migrated().await;
    let row = c
        .query_one(
            "SELECT to_regclass('console_agent_tags') IS NULL,
                    to_regclass('console_asset_group_selectors') IS NULL,
                    has_function_privilege('openvibes-distribution', 'console_host_in_group(text, uuid)', 'EXECUTE')",
            &[],
        )
        .await
        .unwrap();
    assert!(row.get::<_, bool>(0));
    assert!(row.get::<_, bool>(1));
    assert!(row.get::<_, bool>(2));
    db.drop().await;
}

/// A version-52 database seeded with `sql`, migrated to 53.
async fn upgraded_from(sql: &str) -> (common::TestDb, Client) {
    let db = common::TestDb::create().await;
    let client = common::at_version(&db, 52).await;
    client.batch_execute(sql).await.unwrap();
    drop(client);
    let mut c = db.pool.get().await.unwrap();
    assert_eq!(platform_store::migrate(&mut c).await.unwrap(), 58);
    (db, c)
}

#[tokio::test]
async fn names_differing_only_in_case_are_renamed_and_keep_their_hosts() {
    let (db, c) = upgraded_from(&format!(
        "INSERT INTO agents (agent_id, status, enrolled_at) VALUES ('{PROD}','active',now());
         INSERT INTO console_agent_tags VALUES ('{PROD}','env','prod',now(),'t');
         INSERT INTO console_asset_groups VALUES
           ('{G_PROD}','Prod',now() - interval '1 day','t'), ('{G_PROD_WEB}','prod',now(),'t'),
           ('{G_EMPTY}','PROD',now(),'t');
         INSERT INTO console_asset_group_selectors VALUES
           ('{G_PROD}','env','prod',now()), ('{G_PROD_WEB}','env','prod',now());"
    ))
    .await;
    let rows = c
        .query(
            "SELECT g.asset_group_id::text, g.name,
                    (SELECT count(*) FROM console_host_group_members m WHERE m.asset_group_id = g.asset_group_id),
                    a.detail
             FROM console_asset_groups g JOIN audit_log a
               ON a.action = 'host_group.migrated' AND a.target_id = g.asset_group_id::text
             ORDER BY g.created_at, g.asset_group_id",
            &[],
        )
        .await
        .unwrap();
    let got: Vec<(String, String, i64, serde_json::Value)> = rows
        .iter()
        .map(|r| (r.get(0), r.get(1), r.get(2), r.get(3)))
        .collect();
    assert_eq!(got[0].1, "Prod");
    assert!(got[0].3.get("renamed_from").is_none());
    let renamed: BTreeMap<String, (String, i64, serde_json::Value)> = got[1..]
        .iter()
        .map(|(id, name, hosts, detail)| (id.clone(), (name.clone(), *hosts, detail.clone())))
        .collect();
    let (name, hosts, detail) = &renamed[G_PROD_WEB];
    assert_eq!(*hosts, 1, "same hosts as before");
    assert_eq!(detail["renamed_from"], "prod");
    assert_eq!(detail["renamed_to"], name.as_str());
    let names: BTreeSet<String> = got.iter().map(|g| g.1.to_lowercase()).collect();
    assert_eq!(names.len(), 3, "{got:?}");
    assert!(names.contains("prod (2)") && names.contains("prod (3)"));
    db.drop().await;
}

#[tokio::test]
async fn automatic_names_clash_at_two_levels_and_odd_releases_get_none() {
    let long_id = "x".repeat(128);
    let long_version = "9".repeat(128);
    let (db, c) = upgraded_from(&format!(
        "INSERT INTO agents (agent_id, status, enrolled_at, os_id, os_version) VALUES
           ('{PROD}','active',now(),'debian','12'),
           ('{LAB}','active',now(),'{long_id}','{long_version}');
         INSERT INTO console_asset_groups VALUES
           ('{G_PROD}','Linux',now(),'t'), ('{G_PROD_WEB}','linux (AUTOMATIC)',now(),'t');"
    ))
    .await;
    let names: BTreeMap<String, String> = c
        .query(
            "SELECT auto_key, name FROM console_asset_groups WHERE kind = 'automatic'",
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|r| (r.get(0), r.get(1)))
        .collect();
    assert_eq!(names["os_family:linux"], "Linux (automatic 2)");
    assert_eq!(names["distribution:debian 12"], "Debian 12");
    // an unknown id or a non-numeric release gets no group
    assert!(!names.contains_key(&format!("distribution:{long_id} {long_version}")));
    db.drop().await;
}

#[tokio::test]
async fn cut_or_merged_tags_are_audited() {
    let long_a = format!("{}a", "v".repeat(70));
    let long_b = format!("{}b", "v".repeat(70));
    let (db, c) = upgraded_from(&format!(
        "INSERT INTO agents (agent_id, status, enrolled_at) VALUES
           ('{PROD}','active',now()), ('{LAB}','active',now());
         INSERT INTO console_agent_tags VALUES
           ('{PROD}','k','{long_a}',now(),'t'), ('{PROD}','l','x',now(),'t'),
           ('{PROD}','k2','{long_b}',now(),'t'),
           ('{PROD}','m','n:o',now(),'t'), ('{PROD}','m:n','o',now(),'t'),
           ('{LAB}','env','lab',now(),'t');"
    ))
    .await;
    let rows = c
        .query(
            "SELECT target_id, detail FROM audit_log WHERE action = 'host.labels_migrated'",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(rows.len(), 1, "only the host whose tags were cut or merged");
    assert_eq!(rows[0].get::<_, &str>(0), PROD);
    let detail: serde_json::Value = rows[0].get(1);
    assert_eq!(detail["truncated"].as_array().unwrap().len(), 2);
    let tags = |key: &str| -> BTreeSet<String> {
        detail[key]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["tag"].as_str().unwrap().to_owned())
            .collect()
    };
    assert_eq!(
        tags("truncated"),
        BTreeSet::from([format!("k:{long_a}"), format!("k2:{long_b}")])
    );
    assert_eq!(tags("merged"), BTreeSet::from(["m:n:o".to_owned()]));
    let labels: i64 = c
        .query_one(
            "SELECT count(*) FROM console_host_labels WHERE agent_id = $1",
            &[&PROD],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(labels, 4);
    db.drop().await;
}

#[tokio::test]
async fn a_128_character_name_differing_only_in_case_is_renamed_within_128() {
    let (a, b) = ("A".repeat(128), "a".repeat(128));
    let (db, c) = upgraded_from(&format!(
        "INSERT INTO agents (agent_id, status, enrolled_at) VALUES ('{PROD}','active',now());
         INSERT INTO console_agent_tags VALUES ('{PROD}','env','prod',now(),'t');
         INSERT INTO console_asset_groups VALUES ('{G_PROD}','{a}',now() - interval '1 hour','t'),
                                                 ('{G_PROD_WEB}','{b}',now(),'t');
         INSERT INTO console_asset_group_selectors VALUES
           ('{G_PROD}','env','prod',now()), ('{G_PROD_WEB}','env','prod',now());"
    ))
    .await;
    let rows = c
        .query(
            "SELECT g.name, (SELECT count(*) FROM console_host_group_members m
                             WHERE m.asset_group_id = g.asset_group_id)
             FROM console_asset_groups g WHERE g.kind = 'manual' ORDER BY g.created_at",
            &[],
        )
        .await
        .unwrap();
    let (first, second): (String, String) = (rows[0].get(0), rows[1].get(0));
    assert_eq!(first, a);
    assert!(
        second.chars().count() <= 128 && second.ends_with(" (2)"),
        "{second}"
    );
    assert!(second.starts_with(&"a".repeat(124)));
    assert_eq!((rows[0].get::<_, i64>(1), rows[1].get::<_, i64>(1)), (1, 1));
    db.drop().await;
}

#[tokio::test]
async fn the_backfill_makes_at_most_20_releases_per_distribution() {
    let (db, c) = upgraded_from(
        "INSERT INTO agents (agent_id, status, enrolled_at, os_id, os_version)
         SELECT 'agent.00000000-0000-4000-8000-' || lpad(n::text, 12, '0'), 'active', now(),
                'debian', n::text
         FROM generate_series(1, 21) n;
         INSERT INTO agents (agent_id, status, enrolled_at, os_id, os_version) VALUES
           ('agent.00000000-0000-4000-8000-000000000100','active',now(),'ubuntu','24.04'),
           ('agent.00000000-0000-4000-8000-000000000101','active',now(),'debian','prod-servers');",
    )
    .await;
    let keys: BTreeSet<String> = c
        .query(
            "SELECT auto_key FROM console_asset_groups WHERE kind = 'automatic'",
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|r| r.get(0))
        .collect();
    let debian = keys
        .iter()
        .filter(|k| k.starts_with("distribution:debian "))
        .count();
    assert_eq!(debian, 20, "{keys:?}");
    assert!(keys.contains("distribution:ubuntu 24.04"));
    assert!(keys.contains("os_family:linux"));
    assert!(!keys.contains("distribution:debian prod-servers"));
    db.drop().await;
}
