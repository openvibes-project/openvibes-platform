//! The preview before saving or deleting a host group (spec §5.1): hosts
//! that would join or leave, and the people who would gain or lose them.

use crate::{
    Client, StoreError,
    host_group_writes::{GroupContent, invalid_content, overrides},
};

/// Most entries in each preview list.
pub const PREVIEW_CAP: usize = 50;

/// A host in a preview.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostRef {
    /// Agent id.
    pub agent_id: String,
    /// Hostname.
    pub hostname: Option<String>,
}

/// A person in a preview.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersonRef {
    /// User id.
    pub user_id: String,
    /// Username.
    pub username: String,
    /// Display name.
    pub display_name: String,
}

/// The answer to a preview request.
#[derive(Clone, Debug)]
pub enum PreviewOutcome {
    /// What would change.
    Ready(Preview),
    /// The group does not exist.
    NotFound,
    /// The proposed rule is malformed (the part, as `GroupWrite::Invalid`).
    Invalid(String),
}

/// What saving (or deleting) would change. Lists hold at most
/// [`PREVIEW_CAP`] entries; the totals count them all.
#[derive(Clone, Debug)]
pub struct Preview {
    /// Joins.
    pub joins: Vec<HostRef>,
    /// Leaves.
    pub leaves: Vec<HostRef>,
    /// Gains.
    pub gains: Vec<PersonRef>,
    /// Loses.
    pub loses: Vec<PersonRef>,
    /// Joins total.
    pub joins_total: i64,
    /// Leaves total.
    pub leaves_total: i64,
    /// People total.
    pub people_total: i64,
    /// Rule-set switches a delete removes.
    pub overrides_removed: i64,
}

/// Hosts joining and leaving, newest membership `prop` against today's.
/// `$1` group id or NULL, `$2` 'rule' | 'manual' | 'none', `$3` conditions
/// (jsonb), `$4` picked ids.
const DIFF: &str = "
WITH cur AS (SELECT a.agent_id FROM agents a
             WHERE $1::text IS NOT NULL AND a.status = 'active'
               AND console_host_in_group(a.agent_id, $1::text::uuid)),
prop AS (SELECT a.agent_id FROM agents a WHERE a.status = 'active' AND CASE $2::text
           WHEN 'manual' THEN a.agent_id = ANY($4::text[])
           WHEN 'rule' THEN jsonb_array_length($3::jsonb) > 0 AND NOT EXISTS (
             SELECT 1 FROM jsonb_array_elements($3::jsonb) c
             WHERE NOT COALESCE(console_condition_holds(a, c->>'field', (c->>'negate')::boolean,
                                  ARRAY(SELECT jsonb_array_elements_text(c->'values'))), false))
           ELSE false END),
d AS (SELECT agent_id, true AS joins FROM (SELECT agent_id FROM prop EXCEPT SELECT agent_id FROM cur) j
      UNION ALL
      SELECT agent_id, false FROM (SELECT agent_id FROM cur EXCEPT SELECT agent_id FROM prop) l),
r AS (SELECT d.agent_id, a.hostname, d.joins, count(*) OVER (PARTITION BY d.joins) AS total,
             row_number() OVER (PARTITION BY d.joins
                                ORDER BY COALESCE(lower(a.hostname), ''), d.agent_id) AS n
      FROM d JOIN agents a USING (agent_id))
SELECT agent_id, hostname, joins, total FROM r WHERE n <= $5 ORDER BY joins DESC, n";

/// People reaching the group through a role, unless another role of theirs
/// reaches every host anyway. `$1` group id, `$2` cap.
const PEOPLE: &str = "
SELECT user_id, username, display_name, count(*) OVER () FROM (
  SELECT DISTINCT u.user_id::text, u.username, u.display_name
  FROM console_role_groups rg JOIN console_role_bindings b USING (role_id)
  JOIN console_users u USING (user_id)
  WHERE rg.asset_group_id::text = $1 AND b.revoked_at IS NULL AND u.enabled
    AND NOT EXISTS (SELECT 1 FROM console_role_bindings b2 JOIN console_roles r2 USING (role_id)
                    WHERE b2.user_id = u.user_id AND b2.revoked_at IS NULL
                      AND (r2.all_hosts OR r2.role_id = 'admin'))) p
ORDER BY username LIMIT $2";

/// What saving `proposed` into group `id` (or a new group, `id` None)
/// would change; `proposed` None previews deleting `id`. `NotFound` when
/// `id` does not exist, `Invalid` for a malformed rule (checked before any
/// value reaches the database). People of roles reaching the group gain the joining
/// hosts and lose the leaving ones (simplified: their other roles' groups
/// are not checked, only whether one reaches all hosts).
pub async fn preview(
    client: &Client,
    id: Option<&str>,
    proposed: Option<&GroupContent<'_>>,
) -> Result<PreviewOutcome, StoreError> {
    if let Some(part) = proposed.and_then(invalid_content) {
        return Ok(PreviewOutcome::Invalid(part));
    }
    if let Some(id) = id {
        let exists = client
            .query_opt(
                "SELECT 1 FROM console_asset_groups WHERE asset_group_id::text = $1",
                &[&id],
            )
            .await?;
        if exists.is_none() {
            return Ok(PreviewOutcome::NotFound);
        }
    }
    let (kind, conditions, picked) = match proposed {
        Some(GroupContent::Rule(conditions)) => ("rule", serde_json::json!(conditions), Vec::new()),
        Some(GroupContent::Manual(picked)) => ("manual", serde_json::json!([]), picked.to_vec()),
        None => ("none", serde_json::json!([]), Vec::new()),
    };
    let cap = i64::try_from(PREVIEW_CAP).unwrap_or(50);
    let rows = client
        .query(DIFF, &[&id, &kind, &conditions, &picked, &cap])
        .await?;
    let mut preview = Preview {
        joins: Vec::new(),
        leaves: Vec::new(),
        gains: Vec::new(),
        loses: Vec::new(),
        joins_total: 0,
        leaves_total: 0,
        people_total: 0,
        overrides_removed: 0,
    };
    for row in &rows {
        let host = HostRef {
            agent_id: row.get(0),
            hostname: row.get(1),
        };
        if row.get(2) {
            preview.joins_total = row.get(3);
            preview.joins.push(host);
        } else {
            preview.leaves_total = row.get(3);
            preview.leaves.push(host);
        }
    }
    if let Some(id) = id {
        let people = client.query(PEOPLE, &[&id, &cap]).await?;
        preview.people_total = people.first().map_or(0, |row| row.get(3));
        let people: Vec<PersonRef> = people
            .iter()
            .map(|row| PersonRef {
                user_id: row.get(0),
                username: row.get(1),
                display_name: row.get(2),
            })
            .collect();
        if preview.joins_total > 0 {
            preview.gains.clone_from(&people);
        }
        if preview.leaves_total > 0 {
            preview.loses = people;
        }
        if proposed.is_none() {
            preview.overrides_removed = overrides(client, id).await?;
        }
    }
    Ok(PreviewOutcome::Ready(preview))
}
