use deadpool_postgres::Client;

use crate::StoreError;

/// Appends one audit entry. `detail` must never contain secrets.
pub async fn record(
    client: &Client,
    actor: &str,
    action: &str,
    target: Option<&str>,
    result: &str,
) -> Result<(), StoreError> {
    client
        .execute(
            "INSERT INTO audit_log (actor, action, target, result) VALUES ($1, $2, $3, $4)",
            &[&actor, &action, &target, &result],
        )
        .await?;
    Ok(())
}
