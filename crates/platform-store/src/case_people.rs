//! Who can see a case (roles plan 2026-10-25 step 5d ruling 13): its
//! opener and assignee, and enabled people whose live role binding holds
//! `cases.read` on every host (Administrator does) or on a group holding
//! the host of one of its host-bound items. Only items in the viewer's
//! reach are looked at, so a person who sees the case only through a host
//! the viewer cannot see is neither named nor counted (Review Focus 1).
//! A case with no host-bound item in reach thus lists its opener, its
//! assignee and the all-hosts readers, as "hosts decide" has it.

use crate::{
    Client, StoreError,
    case_summary::{CasePeople, MAX_PEOPLE},
    console_cases::{UserRef, item_in_scope},
    console_read::AgentScope,
};

pub(crate) async fn people(
    client: &Client,
    scope: &AgentScope,
    case_id: &str,
) -> Result<CasePeople, StoreError> {
    let in_scope = item_in_scope("i");
    let rows = client
        .query(
            &format!(
                "WITH hosts AS (SELECT DISTINCT i.agent_id FROM case_items i
                                WHERE i.case_id = $3::text::uuid AND {in_scope}),
                 p AS (
                   SELECT unnest(ARRAY[c.opened_by_user_id, c.assignee_user_id]) AS user_id
                   FROM cases c WHERE c.case_id = $3::text::uuid
                   UNION
                   SELECT b.user_id FROM console_role_bindings b
                   JOIN console_users u ON u.user_id = b.user_id
                   JOIN console_roles r ON r.role_id = b.role_id
                   WHERE b.revoked_at IS NULL AND u.enabled
                     AND (r.role_id = 'admin' OR (
                       EXISTS (SELECT 1 FROM console_role_permissions rp
                               WHERE rp.role_id = r.role_id AND rp.permission_id = 'cases.read')
                       AND (r.all_hosts OR EXISTS (
                         SELECT 1 FROM console_role_groups rg
                         JOIN console_host_group_membership m ON m.asset_group_id = rg.asset_group_id
                         JOIN hosts h ON h.agent_id = m.agent_id
                         JOIN agents a ON a.agent_id = m.agent_id
                         WHERE rg.role_id = r.role_id AND a.status <> 'imported')))))
                 SELECT u.user_id::text, u.username, u.display_name, count(*) OVER ()
                 FROM p JOIN console_users u ON u.user_id = p.user_id
                 ORDER BY lower(u.display_name), u.username, u.user_id
                 LIMIT $4"
            ),
            &[&scope.is_global(), &scope.group_ids(), &case_id, &MAX_PEOPLE],
        )
        .await?;
    Ok(CasePeople {
        total: rows.first().map_or(0, |r| r.get(3)),
        names: rows
            .iter()
            .map(|r| UserRef {
                user_id: r.get(0),
                username: r.get(1),
                display_name: r.get(2),
            })
            .collect(),
    })
}
