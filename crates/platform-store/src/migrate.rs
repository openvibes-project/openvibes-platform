use deadpool_postgres::Client;

use crate::StoreError;

/// Schema version this build expects. Services refuse any other version.
pub const SCHEMA_VERSION: i32 = 2;

/// Every migration, in order, embedded at build time.
const MIGRATIONS: &[(i32, &str)] = &[
    (1, include_str!("../../../migrations/0001_initial.sql")),
    (
        2,
        include_str!("../../../migrations/0002_ca_tokens_agents.sql"),
    ),
];

const VERSION_TABLE: &str = "CREATE TABLE IF NOT EXISTS schema_version (version integer NOT NULL)";

/// The applied schema version, or `None` for an empty database.
pub async fn schema_version(client: &Client) -> Result<Option<i32>, StoreError> {
    let exists: bool = client
        .query_one("SELECT to_regclass('schema_version') IS NOT NULL", &[])
        .await?
        .get(0);
    if !exists {
        return Ok(None);
    }
    let row = client
        .query_opt("SELECT version FROM schema_version", &[])
        .await?;
    Ok(row.map(|row| row.get(0)))
}

/// Applies every pending migration in one transaction and returns the
/// version now in place. The version table is locked for the duration, so
/// two concurrent runs cannot both apply a migration. A newer schema is
/// refused, never rolled back.
pub async fn migrate(client: &mut Client) -> Result<i32, StoreError> {
    let transaction = client.transaction().await?;
    transaction.batch_execute(VERSION_TABLE).await?;
    transaction
        .batch_execute("LOCK TABLE schema_version IN EXCLUSIVE MODE")
        .await?;
    let current: Option<i32> = transaction
        .query_opt("SELECT version FROM schema_version", &[])
        .await?
        .map(|row| row.get(0));
    let applied = current.unwrap_or(0);
    if applied > SCHEMA_VERSION {
        return Err(StoreError::NewerSchema(applied));
    }
    for (_, sql) in MIGRATIONS.iter().filter(|(version, _)| *version > applied) {
        transaction.batch_execute(sql).await?;
    }
    if applied < SCHEMA_VERSION {
        transaction
            .batch_execute("DELETE FROM schema_version")
            .await?;
        transaction
            .execute("INSERT INTO schema_version VALUES ($1)", &[&SCHEMA_VERSION])
            .await?;
    }
    transaction.commit().await?;
    Ok(SCHEMA_VERSION.max(applied))
}
