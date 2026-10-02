//! What the rule signer reads and writes (board #107): a console user's
//! credential and `rules.upload` permission, and the per-account sign-in
//! failure bucket. Its database role is granted exactly these columns
//! (migration 32); nothing here writes `audit_log`.

use chrono::{DateTime, Duration, Utc};
use deadpool_postgres::Client;

use crate::StoreError;

/// The credential the signer checks a password against.
pub struct SignerUser {
    /// The account's id, for the permission check.
    pub user_id: String,
    /// An Argon2id PHC string; never logged.
    pub password_phc: String,
    /// Disabled accounts are returned so the caller does the same work.
    pub enabled: bool,
    /// The account must change its password before it may sign (either
    /// flag: the credential's, or the account's from New user).
    pub must_change: bool,
}

impl std::fmt::Debug for SignerUser {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SignerUser")
            .field("user_id", &self.user_id)
            .field("enabled", &self.enabled)
            .field("must_change", &self.must_change)
            .finish_non_exhaustive()
    }
}

/// The account `username` (already canonical), if it exists.
pub async fn signer_user(
    client: &Client,
    username: &str,
) -> Result<Option<SignerUser>, StoreError> {
    let row = client
        .query_opt(
            "SELECT u.user_id::text, c.password_phc, u.enabled,
                    c.must_change OR u.password_must_change
             FROM console_users u JOIN console_credentials c USING (user_id)
             WHERE u.username = $1",
            &[&username],
        )
        .await?;
    Ok(row.map(|row| SignerUser {
        user_id: row.get(0),
        password_phc: row.get(1),
        enabled: row.get(2),
        must_change: row.get(3),
    }))
}

/// Whether the user holds `rules.upload` through an active, global (not
/// asset-group) role binding: publishing a rule set reaches every agent.
pub async fn may_upload_rules(client: &Client, user_id: &str) -> Result<bool, StoreError> {
    let row = client
        .query_one(
            "SELECT EXISTS (
                SELECT 1 FROM console_role_bindings b
                JOIN console_role_permissions p USING (role_id)
                WHERE b.user_id = $1::text::uuid AND b.revoked_at IS NULL
                  AND b.asset_group_id IS NULL AND p.permission_id = 'rules.upload'
             )",
            &[&user_id],
        )
        .await?;
    Ok(row.get(0))
}

/// Counts one wrong password in the account's sign-in bucket, as console
/// sign-in does (`failure_limit` within `window` locks it for `lock_for`),
/// without an audit row: the signer audits to its own journal.
pub async fn record_signer_failure(
    client: &Client,
    bucket_sha256: &[u8],
    now: DateTime<Utc>,
    window: Duration,
    failure_limit: i32,
    lock_for: Duration,
) -> Result<(), StoreError> {
    if failure_limit < 1 {
        return Err(StoreError::Query);
    }
    crate::console_auth::count_failure(client, bucket_sha256, now, window, failure_limit, lock_for)
        .await
}
