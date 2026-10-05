//! Enrollment tokens. Only the SHA-256 of a token is ever stored.

use chrono::{DateTime, Utc};

use crate::{Client, StoreError};

/// A token to create.
#[derive(Clone, Debug)]
pub struct NewToken {
    /// SHA-256 of the token.
    pub token_sha256: [u8; 32],
    /// Operator's note.
    pub label: Option<String>,
    /// Audit actor that created it.
    pub created_by: String,
    /// End of validity.
    pub expires_at: DateTime<Utc>,
    /// Enrollments it allows.
    pub max_uses: i32,
}

/// A token as listed; never includes the token or its hash.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TokenInfo {
    /// Token id (UUID).
    pub token_id: String,
    /// Operator's note.
    pub label: Option<String>,
    /// Creation time.
    pub created_at: DateTime<Utc>,
    /// End of validity.
    pub expires_at: DateTime<Utc>,
    /// Enrollments it allows.
    pub max_uses: i32,
    /// Enrollments so far.
    pub uses: i64,
    /// Whether it was revoked.
    pub revoked: bool,
    /// Whether it is the standing token: never expires, no use limit.
    pub standing: bool,
}

/// Creates a token and returns its id.
pub async fn create(client: &Client, token: &NewToken) -> Result<String, StoreError> {
    let row = client
        .query_one(
            "INSERT INTO enrollment_tokens
                 (token_id, token_sha256, label, created_at, created_by, expires_at, max_uses)
             VALUES (gen_random_uuid(), $1, $2, now(), $3, $4, $5)
             RETURNING token_id::text",
            &[
                &token.token_sha256.as_slice(),
                &token.label,
                &token.created_by,
                &token.expires_at,
                &token.max_uses,
            ],
        )
        .await?;
    Ok(row.get(0))
}

/// Every token, newest first.
pub async fn list(client: &Client) -> Result<Vec<TokenInfo>, StoreError> {
    let rows = client
        .query(
            "SELECT t.token_id::text, t.label, t.created_at, t.expires_at, t.max_uses,
                    (SELECT count(*) FROM token_uses u WHERE u.token_id = t.token_id),
                    t.revoked_at IS NOT NULL, t.standing
             FROM enrollment_tokens t ORDER BY t.created_at DESC",
            &[],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|row| TokenInfo {
            token_id: row.get(0),
            label: row.get(1),
            created_at: row.get(2),
            expires_at: row.get(3),
            max_uses: row.get(4),
            uses: row.get(5),
            revoked: row.get(6),
            standing: row.get(7),
        })
        .collect())
}

/// Stand-in expiry stored for a standing token, which ignores it: far past
/// any deployment's life, so readers that predate the flag still see a
/// valid token.
const STANDING_YEARS: i64 = 100;

/// Creates the standing token: it never expires and has no use limit. The
/// secret is stored beside the hash (see migration 0034) so the install
/// line can be shown again. Returns its id, or `None` when a live standing
/// token already exists (revoke it first to replace it).
pub async fn create_standing(
    client: &Client,
    secret: &str,
    token_sha256: [u8; 32],
    created_by: &str,
    now: DateTime<Utc>,
) -> Result<Option<String>, StoreError> {
    let row = client
        .query_opt(
            "WITH t AS (
                 INSERT INTO enrollment_tokens
                     (token_id, token_sha256, label, created_at, created_by, expires_at, max_uses, standing)
                 VALUES (gen_random_uuid(), $1, 'standing token', $2, $3, $4, $5, true)
                 ON CONFLICT ((true)) WHERE standing AND revoked_at IS NULL DO NOTHING
                 RETURNING token_id)
             INSERT INTO standing_token_secret (token_id, secret)
             SELECT token_id, $6 FROM t RETURNING token_id::text",
            &[
                &token_sha256.as_slice(),
                &now,
                &created_by,
                &(now + chrono::Duration::days(365 * STANDING_YEARS)),
                &i32::MAX,
                &secret,
            ],
        )
        .await?;
    Ok(row.map(|row| row.get(0)))
}

/// The live (unrevoked) standing token's id and secret, if there is one.
pub async fn live_standing(client: &Client) -> Result<Option<(String, String)>, StoreError> {
    let row = client
        .query_opt(
            "SELECT t.token_id::text, s.secret
             FROM enrollment_tokens t JOIN standing_token_secret s USING (token_id)
             WHERE t.standing AND t.revoked_at IS NULL",
            &[],
        )
        .await?;
    Ok(row.map(|row| (row.get(0), row.get(1))))
}

/// Revokes a token. Returns whether it was unrevoked before; an unknown id
/// is `false`, a malformed one [`StoreError::Query`].
pub async fn revoke(
    client: &Client,
    token_id: &str,
    now: DateTime<Utc>,
) -> Result<bool, StoreError> {
    let changed = client
        .execute(
            "UPDATE enrollment_tokens SET revoked_at = $2
             WHERE token_id = $1::text::uuid AND revoked_at IS NULL",
            &[&token_id, &now],
        )
        .await?;
    Ok(changed == 1)
}
