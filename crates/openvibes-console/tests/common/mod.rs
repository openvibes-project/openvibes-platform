//! Roles for the console HTTP tests. Since schema 52 a fresh database holds
//! only the Administrator, so each test creates the roles it binds.
#![allow(dead_code, reason = "each test binary uses some of these")]

pub mod http;
pub mod people;

use chrono::Utc;
use platform_store::{
    Client,
    console_roles::{self, Reach, RoleInput, RoleWrite},
};

/// The former built-in roles as an upgraded install keeps them (migration
/// 51's mapping, closed under needs), reaching every host.
const FORMER_BUILTINS: [(&str, &[&str]); 3] = [
    (
        "viewer",
        &[
            "alarms.read",
            "alarms.suppressions.read",
            "alarms.export",
            "compliance.read",
            "compliance.export",
            "vulnerabilities.read",
            "vulnerabilities.export",
            "hosts.read",
            "hosts.export",
        ],
    ),
    (
        "analyst",
        &[
            "alarms.read",
            "alarms.suppressions.read",
            "alarms.triage",
            "alarms.suppress",
            "alarms.export",
            "compliance.read",
            "compliance.triage",
            "compliance.export",
            "vulnerabilities.read",
            "vulnerabilities.triage",
            "vulnerabilities.export",
            "hosts.read",
            "hosts.export",
            "cases.read",
            "cases.write",
            "cases.assign",
            "assistant.use",
        ],
    ),
    (
        "operator",
        &[
            "alarms.read",
            "alarms.suppressions.read",
            "alarms.export",
            "compliance.read",
            "compliance.export",
            "vulnerabilities.read",
            "vulnerabilities.export",
            "hosts.read",
            "hosts.revoke",
            "hosts.export",
            "rules.read",
            "rules.assignment.read",
            "rules.coverage.read",
            "rules.assignment.write",
            "rules.publish",
            "site_rules.read",
            "site_rules.write",
            "site_rules.test",
            "site_rules.publish",
            "tokens.read",
            "tokens.manage",
            "tokens.installer",
        ],
    ),
];

/// Makes sure role `role_id` exists: `viewer`, `analyst` and `operator` are
/// created as an upgraded install holds them; any other id is left alone.
pub async fn ensure_role(client: &Client, role_id: &str) {
    let Some((_, permissions)) = FORMER_BUILTINS.iter().find(|(id, _)| *id == role_id) else {
        return;
    };
    client
        .execute(
            "INSERT INTO console_roles (role_id, display_name, all_hosts)
             VALUES ($1, initcap($1), true) ON CONFLICT DO NOTHING",
            &[&role_id],
        )
        .await
        .unwrap();
    client
        .execute(
            "INSERT INTO console_role_permissions (role_id, permission_id)
             SELECT $1, unnest($2::text[]) ON CONFLICT DO NOTHING",
            &[&role_id, permissions],
        )
        .await
        .unwrap();
}

/// Creates role `name` holding `permissions` with `reach`; returns its id.
pub async fn create_role(
    client: &mut Client,
    name: &str,
    permissions: &[&str],
    reach: Reach,
) -> String {
    let permissions: Vec<String> = permissions.iter().map(|p| (*p).to_owned()).collect();
    let input = RoleInput {
        name,
        description: "",
        permissions: &permissions,
        reach: &reach,
    };
    match console_roles::create_role(client, &input, "test", Utc::now())
        .await
        .unwrap()
    {
        RoleWrite::Saved(role) => role.role_id,
        other => panic!("role {name} not created: {other:?}"),
    }
}

/// Migration 52's conversion, for tests that scope a grant to a group: each
/// active binding matching `filter` (SQL on `console_role_bindings`) moves
/// to a copy of its role that reaches only `group_id`.
pub async fn scope_bindings(client: &mut Client, filter: &str, group_id: &str) {
    let rows = client
        .query(
            &format!(
                "SELECT binding_id::text, role_id FROM console_role_bindings
                 WHERE revoked_at IS NULL AND ({filter})"
            ),
            &[],
        )
        .await
        .unwrap();
    assert!(!rows.is_empty(), "no binding matches {filter}");
    for row in rows {
        let (binding, role): (String, String) = (row.get(0), row.get(1));
        let permissions: Vec<String> = client
            .query_one(
                "SELECT COALESCE(array_agg(permission_id), '{}') FROM console_role_permissions
                 WHERE role_id = $1",
                &[&role],
            )
            .await
            .unwrap()
            .get(0);
        let permissions: Vec<&str> = permissions.iter().map(String::as_str).collect();
        let reach = Reach::Groups(vec![group_id.to_owned()]);
        let copy = create_role(client, &format!("{role} @{binding}"), &permissions, reach).await;
        client
            .execute(
                "UPDATE console_role_bindings SET role_id = $1 WHERE binding_id = $2::text::uuid",
                &[&copy, &binding],
            )
            .await
            .unwrap();
    }
}
