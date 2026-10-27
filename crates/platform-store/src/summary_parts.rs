//! The queries a port's and a service's page share: the change log's counts
//! and newest entries for one key, "first seen", and the group bars. The
//! caller passes the visibility predicate (`agent_visibility("a.agent_id",
//! "$1", "$2")`) and the scope as `$1` and `$2`.

use chrono::{DateTime, Duration, Utc};

use crate::{
    Client, StoreError,
    host_groups::GroupKind,
    port_summary::{FirstSeen, GroupShare},
};

/// How long the change log keeps a page viewable after its last host.
pub(crate) const KEPT: i64 = 90;

/// The change log's counts for one key.
pub(crate) struct ChangeCounts {
    /// Hosts it appeared on in the last 7 days.
    pub week_added: i64,
    /// Hosts it went away from in the last 7 days.
    pub week_removed: i64,
    /// The earliest `appeared` in the log.
    pub first_logged: Option<DateTime<Utc>>,
    /// Entries in the last 90 days.
    pub logged: i64,
}

pub(crate) async fn change_counts(
    client: &Client,
    kind: &str,
    visible: &str,
    scope: (&bool, &Vec<String>),
    key: &str,
    now: DateTime<Utc>,
) -> Result<ChangeCounts, StoreError> {
    let row = client
        .query_one(
            &format!(
                "SELECT count(DISTINCT c.agent_id) FILTER (WHERE c.change = 'appeared' AND c.at > $5::timestamptz),
                        count(DISTINCT c.agent_id) FILTER (WHERE c.change = 'went_away' AND c.at > $5::timestamptz),
                        min(c.at) FILTER (WHERE c.change = 'appeared'),
                        count(*)
                 FROM change_log c JOIN agents a ON a.agent_id = c.agent_id
                 WHERE c.kind = '{kind}' AND c.key = $3::text AND a.status <> 'revoked' AND {visible}
                   AND c.at > $4::timestamptz - interval '{KEPT} days'"
            ),
            &[scope.0, scope.1, &key, &now, &(now - Duration::days(7))],
        )
        .await?;
    Ok(ChangeCounts {
        week_added: row.get(0),
        week_removed: row.get(1),
        first_logged: row.get(2),
        logged: row.get(3),
    })
}

/// The 20 newest changes in reach, each built by `make(at, agent_id, hostname, change)`.
pub(crate) async fn recent_changes<T>(
    client: &Client,
    kind: &str,
    visible: &str,
    scope: (&bool, &Vec<String>),
    key: &str,
    now: DateTime<Utc>,
    make: impl Fn(DateTime<Utc>, String, Option<String>, String) -> T,
) -> Result<Vec<T>, StoreError> {
    Ok(client
        .query(
            &format!(
                "SELECT c.at, c.agent_id, a.hostname, c.change
                 FROM change_log c JOIN agents a ON a.agent_id = c.agent_id
                 WHERE c.kind = '{kind}' AND c.key = $3::text AND a.status <> 'revoked' AND {visible}
                   AND c.at > $4::timestamptz - interval '{KEPT} days'
                 ORDER BY c.at DESC, c.agent_id, c.change
                 LIMIT 20"
            ),
            &[scope.0, scope.1, &key, &now],
        )
        .await?
        .iter()
        .map(|row| make(row.get(0), row.get(1), row.get(2), row.get(3)))
        .collect())
}

/// The earlier of the log's first `appeared` and the first enrolment among the hosts.
pub(crate) fn first_seen(
    first_logged: Option<DateTime<Utc>>,
    enrolled_first: Option<DateTime<Utc>>,
    floor: DateTime<Utc>,
) -> Option<FirstSeen> {
    [first_logged, enrolled_first]
        .into_iter()
        .flatten()
        .min()
        .map(|at| FirstSeen {
            at,
            before: at <= floor,
        })
}

/// A bar per group with a member among `hosts`, most of them first.
pub(crate) async fn group_shares(
    client: &Client,
    visible: &str,
    scope: (&bool, &Vec<String>),
    hosts: &[String],
) -> Result<Vec<GroupShare>, StoreError> {
    Ok(client
        .query(
            &format!(
                "SELECT g.asset_group_id::text, g.name, g.kind,
                        count(*) FILTER (WHERE m.agent_id = ANY($3::text[])), count(*)
                 FROM console_host_group_membership m
                 JOIN agents a ON a.agent_id = m.agent_id
                 JOIN console_asset_groups g ON g.asset_group_id = m.asset_group_id
                 WHERE a.status <> 'revoked' AND {visible}
                   AND m.asset_group_id IN (SELECT asset_group_id FROM console_host_group_membership
                                            WHERE agent_id = ANY($3::text[]))
                 GROUP BY g.asset_group_id, g.name, g.kind
                 ORDER BY 4 DESC, lower(g.name), g.asset_group_id"
            ),
            &[scope.0, scope.1, &hosts],
        )
        .await?
        .iter()
        .map(|row| GroupShare {
            id: row.get(0),
            name: row.get(1),
            kind: GroupKind::parse(&row.get::<_, String>(2)),
            listening: row.get(3),
            of: row.get(4),
        })
        .collect())
}
