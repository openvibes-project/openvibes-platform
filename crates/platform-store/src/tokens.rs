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
                    t.revoked_at IS NOT NULL
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
        })
        .collect())
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
