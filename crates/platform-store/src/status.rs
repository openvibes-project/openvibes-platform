use chrono::{DateTime, Duration, NaiveDate, Utc};
use deadpool_postgres::Client;

use crate::{StoreError, maintenance::partition_days, schema_version};

/// An agent with no heartbeat for this long is offline. It must stay well
/// above the 5-minute `last_seen_at` write throttle.
pub const OFFLINE_AFTER_MINUTES: i64 = 15;

/// A point-in-time summary for operators.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Status {
    /// Applied schema version, `None` on an empty database.
    pub schema_version: Option<i32>,
    /// Agents with status active (including offline ones).
    pub agents_active: i64,
    /// Active agents with no heartbeat for [`OFFLINE_AFTER_MINUTES`].
    pub agents_offline: i64,
    /// Revoked agents.
    pub agents_revoked: i64,
    /// Enrollment tokens that are unrevoked, unexpired, and not used up.
    pub tokens_usable: i64,
    /// Oldest day with a findings partition.
    pub oldest_partition: Option<NaiveDate>,
    /// Newest day with a findings partition.
    pub newest_partition: Option<NaiveDate>,
}

/// The current summary, with `now` as the reference time.
pub async fn status(client: &Client, now: DateTime<Utc>) -> Result<Status, StoreError> {
    let offline_before = now - Duration::minutes(OFFLINE_AFTER_MINUTES);
    let agents = client
        .query_one(
            "SELECT count(*) FILTER (WHERE status = 'active'),
                    count(*) FILTER (WHERE status = 'active'
                                     AND (last_seen_at IS NULL OR last_seen_at < $1)),
                    count(*) FILTER (WHERE status = 'revoked')
             FROM agents",
            &[&offline_before],
        )
        .await?;
    let tokens: i64 = client
        .query_one(
            "SELECT count(*) FROM enrollment_tokens t
             WHERE t.revoked_at IS NULL AND t.expires_at > $1
               AND (SELECT count(*) FROM token_uses u WHERE u.token_id = t.token_id) < t.max_uses",
            &[&now],
        )
        .await?
        .get(0);
    let days = partition_days(client).await?;
    Ok(Status {
        schema_version: schema_version(client).await?,
        agents_active: agents.get(0),
        agents_offline: agents.get(1),
        agents_revoked: agents.get(2),
        tokens_usable: tokens,
        oldest_partition: days.first().copied(),
        newest_partition: days.last().copied(),
    })
}
