//! Fixtures shared by the host-group store tests: web-01 (Debian 12,
//! online), db-02 (Fedora 44, offline), old-03 (revoked); people, roles.
#![allow(dead_code, reason = "each test binary uses some of these")]

use platform_store::{
    Client,
    host_group_writes::{GroupContent, GroupInput, GroupWrite, Preview, PreviewOutcome},
    host_groups::{Condition, GroupSummary},
};

pub const A1: &str = "agent.00000000-0000-4000-8000-000000000001";
pub const A2: &str = "agent.00000000-0000-4000-8000-000000000002";
pub const A3: &str = "agent.00000000-0000-4000-8000-000000000003";
pub const U1: &str = "00000000-0000-4000-8000-0000000000a1";
pub const U2: &str = "00000000-0000-4000-8000-0000000000a2";
pub const U3: &str = "00000000-0000-4000-8000-0000000000a3";

/// web-01 (Debian 12, online), db-02 (Fedora 44, offline), old-03 (revoked).
pub async fn fleet(c: &Client) {
    c.batch_execute(&format!(
        "INSERT INTO agents (agent_id, status, enrolled_at, revoked_at, last_seen_at, hostname, os_id, os_version, last_address) VALUES
           ('{A1}','active',now(),NULL,now(),'web-01','debian','12','10.0.0.1'),
           ('{A2}','active',now(),NULL,now() - interval '1 day','db-02','fedora','44','10.9.0.2'),
           ('{A3}','revoked',now(),now(),now(),'old-03','debian','12','10.0.0.3');"
    ))
    .await
    .unwrap();
}

pub async fn person(c: &Client, id: &str, name: &str, enabled: bool) {
    c.execute(
        "INSERT INTO console_users (user_id, username, display_name, enabled, created_at, disabled_at)
         VALUES ($1::text::uuid, $2, initcap($2), $3, now(), CASE WHEN $3 THEN NULL ELSE now() END)",
        &[&id, &name, &enabled],
    )
    .await
    .unwrap();
}

pub async fn bind(c: &Client, user: &str, role: &str) {
    c.execute(
        "INSERT INTO console_role_bindings (binding_id, user_id, role_id, created_at, created_by)
         VALUES (gen_random_uuid(), $1::text::uuid, $2, now(), 't')",
        &[&user, &role],
    )
    .await
    .unwrap();
}

/// A role reaching exactly `group`.
pub async fn group_role(c: &Client, role: &str, group: &str) {
    c.execute(
        "INSERT INTO console_roles (role_id, display_name, all_hosts) VALUES ($1, initcap($1), false)",
        &[&role],
    )
    .await
    .unwrap();
    c.execute(
        "INSERT INTO console_role_groups (role_id, asset_group_id) VALUES ($1, $2::text::uuid)",
        &[&role, &group],
    )
    .await
    .unwrap();
}

pub fn named<'a>(groups: &'a [GroupSummary], name: &str) -> &'a GroupSummary {
    groups.iter().find(|g| g.name == name).unwrap()
}

pub fn input<'a>(name: &'a str, content: GroupContent<'a>) -> GroupInput<'a> {
    GroupInput {
        name,
        description: "",
        content,
    }
}

pub fn saved(write: GroupWrite) -> GroupSummary {
    match write {
        GroupWrite::Saved(summary) => summary,
        other => panic!("not saved: {other:?}"),
    }
}

pub fn cond(field: &str, negate: bool, values: &[&str]) -> Condition {
    Condition {
        field: field.into(),
        negate,
        values: values.iter().map(|v| (*v).into()).collect(),
    }
}

pub async fn count(c: &Client, sql: &str) -> i64 {
    c.query_one(sql, &[]).await.unwrap().get(0)
}

/// The preview of a ready outcome.
pub trait Ready {
    /// Panics unless ready.
    fn ready(self) -> Preview;
}

impl Ready for PreviewOutcome {
    fn ready(self) -> Preview {
        match self {
            PreviewOutcome::Ready(preview) => preview,
            other => panic!("not ready: {other:?}"),
        }
    }
}
