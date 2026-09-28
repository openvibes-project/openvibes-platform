use deadpool_postgres::Client;

use crate::StoreError;

/// Schema version this build expects. Services refuse any other version.
pub const SCHEMA_VERSION: i32 = 26;

/// Every migration, in order, embedded at build time.
const MIGRATIONS: &[(i32, &str)] = &[
    (1, include_str!("../../../migrations/0001_initial.sql")),
    (
        2,
        include_str!("../../../migrations/0002_ca_tokens_agents.sql"),
    ),
    (
        3,
        include_str!("../../../migrations/0003_agent_hostname.sql"),
    ),
    (
        4,
        include_str!("../../../migrations/0004_ingest_least_privilege.sql"),
    ),
    (
        5,
        include_str!("../../../migrations/0005_finding_rule_set.sql"),
    ),
    (
        6,
        include_str!("../../../migrations/0006_rule_distribution.sql"),
    ),
    (7, include_str!("../../../migrations/0007_inventory.sql")),
    (
        8,
        include_str!("../../../migrations/0008_vulnerabilities.sql"),
    ),
    (
        9,
        include_str!("../../../migrations/0009_running_kernel.sql"),
    ),
    (
        10,
        include_str!("../../../migrations/0010_cve_enrichment.sql"),
    ),
    (11, include_str!("../../../migrations/0011_nvd_euvd.sql")),
    (
        12,
        include_str!("../../../migrations/0012_vulns_analyze.sql"),
    ),
    (13, include_str!("../../../migrations/0013_osv.sql")),
    (
        14,
        include_str!("../../../migrations/0014_version_vulnerabilities.sql"),
    ),
    (
        15,
        include_str!("../../../migrations/0015_imported_hosts.sql"),
    ),
    (
        16,
        include_str!("../../../migrations/0016_console_read_models.sql"),
    ),
    (
        17,
        include_str!("../../../migrations/0017_console_identity.sql"),
    ),
    (
        18,
        include_str!("../../../migrations/0018_console_enrollment_tokens.sql"),
    ),
    (
        19,
        include_str!("../../../migrations/0019_console_rule_read.sql"),
    ),
    (
        20,
        include_str!("../../../migrations/0020_console_triage_history.sql"),
    ),
    (
        21,
        include_str!("../../../migrations/0021_console_assistant_permission.sql"),
    ),
    (
        22,
        include_str!("../../../migrations/0022_console_write_privileges.sql"),
    ),
    (
        23,
        include_str!("../../../migrations/0023_agent_health.sql"),
    ),
    (
        24,
        include_str!("../../../migrations/0024_console_rules_permission_cleanup.sql"),
    ),
    (
        25,
        include_str!("../../../migrations/0025_console_vulnerability_reads.sql"),
    ),
    (
        26,
        include_str!("../../../migrations/0026_console_dashboards.sql"),
    ),
];

// The build fails if a migration is added without bumping SCHEMA_VERSION or
// the reverse, so the two can never drift apart.
const _: () = assert!(MIGRATIONS[MIGRATIONS.len() - 1].0 == SCHEMA_VERSION);

/// Advisory lock key for `migrate` ("ovmi").
const MIGRATE_LOCK: i64 = 0x6f76_6d69;

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
    // Serializes concurrent runs before anything else, including creating
    // the version table (a racing CREATE ... IF NOT EXISTS fails).
    transaction
        .execute("SELECT pg_advisory_xact_lock($1)", &[&MIGRATE_LOCK])
        .await?;
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

#[cfg(test)]
mod tests {
    use super::MIGRATIONS;

    // Two branches once both added a 0023 migration and the merge kept only
    // one: every file in migrations/ must be embedded, each number once.
    #[test]
    fn every_migration_file_is_embedded_once_in_order() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../migrations");
        let mut files: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .filter(|n| n.ends_with(".sql"))
            .collect();
        files.sort();
        assert_eq!(files.len(), MIGRATIONS.len(), "migrations/ has {files:?}");
        for (i, (file, (version, sql))) in files.iter().zip(MIGRATIONS).enumerate() {
            assert_eq!(
                *version,
                i as i32 + 1,
                "{file}: versions must be 1, 2, 3, ..."
            );
            assert_eq!(file[..4].parse::<i32>().unwrap(), *version, "{file}");
            let text = std::fs::read_to_string(format!("{dir}/{file}")).unwrap();
            assert_eq!(
                text, *sql,
                "{file} is not the migration embedded as {version}"
            );
        }
    }
}
