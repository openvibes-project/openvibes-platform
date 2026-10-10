use deadpool_postgres::Client;

use crate::StoreError;

/// Schema version this build expects. Services refuse any other version.
pub const SCHEMA_VERSION: i32 = 47;

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
    (
        27,
        include_str!("../../../migrations/0027_finding_matches.sql"),
    ),
    (
        28,
        include_str!("../../../migrations/0028_console_feed_state.sql"),
    ),
    (29, include_str!("../../../migrations/0029_alarms.sql")),
    (
        30,
        include_str!("../../../migrations/0030_console_password_change.sql"),
    ),
    (
        31,
        include_str!("../../../migrations/0031_host_services.sql"),
    ),
    (32, include_str!("../../../migrations/0032_rule_signer.sql")),
    (
        33,
        include_str!("../../../migrations/0033_vulnerability_match_state.sql"),
    ),
    (
        34,
        include_str!("../../../migrations/0034_cases_permission.sql"),
    ),
    (35, include_str!("../../../migrations/0035_cases.sql")),
    (
        36,
        include_str!("../../../migrations/0036_cases_closed_index.sql"),
    ),
    (
        37,
        include_str!("../../../migrations/0037_standing_enrollment_token.sql"),
    ),
    (
        38,
        include_str!("../../../migrations/0038_console_standing_token_read.sql"),
    ),
    (
        39,
        include_str!("../../../migrations/0039_cpe_matching.sql"),
    ),
    (
        40,
        include_str!("../../../migrations/0040_agent_presence.sql"),
    ),
    (
        41,
        include_str!("../../../migrations/0041_detection_evidence.sql"),
    ),
    (42, include_str!("../../../migrations/0042_rule_drafts.sql")),
    (
        43,
        include_str!("../../../migrations/0043_compliance_names.sql"),
    ),
    (
        44,
        include_str!("../../../migrations/0044_host_daily_counts.sql"),
    ),
    (45, include_str!("../../../migrations/0045_triage_v2.sql")),
    (
        46,
        include_str!("../../../migrations/0046_network_devices.sql"),
    ),
    (
        47,
        include_str!("../../../migrations/0047_assistant_internet.sql"),
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

/// The header line of a migration that drops or rewrites stored data. The
/// automatic migration after a package upgrade stops before it (board #77).
pub const NEEDS_BACKUP: &str = "-- openvibes: needs-backup";

/// Migrations from before the marker that change stored data, reviewed
/// once: 13 (OSV columns folded and dropped), 14 (duplicate vulnerabilities
/// deleted), 16 (findings backfilled and pruned), 20 (triage backfill), 24
/// (role permissions deleted). Migrations are immutable, so they carry no
/// header; later ones must.
const CHANGES_DATA: [i32; 5] = [13, 14, 16, 20, 24];

fn needs_backup(version: i32, sql: &str) -> bool {
    CHANGES_DATA.contains(&version) || sql.lines().any(|line| line.trim() == NEEDS_BACKUP)
}

/// The first migration after `applied` that changes stored data, if any:
/// the automatic migration stops there and Update, which backs up, runs it.
#[must_use]
pub fn needs_backup_after(applied: i32) -> Option<i32> {
    MIGRATIONS
        .iter()
        .find(|(version, sql)| *version > applied && needs_backup(*version, sql))
        .map(|(version, _)| *version)
}

/// Applies every pending migration in one transaction and returns the
/// version now in place. The version table is locked for the duration, so
/// two concurrent runs cannot both apply a migration. A newer schema is
/// refused, never rolled back.
pub async fn migrate(client: &mut Client) -> Result<i32, StoreError> {
    migrate_with(client, true).await
}

/// [`migrate`], refusing ([`StoreError::NeedsBackup`], nothing applied)
/// when a pending migration changes stored data: the unit that runs after
/// a package upgrade, where no backup was taken.
pub async fn migrate_additive(client: &mut Client) -> Result<i32, StoreError> {
    migrate_with(client, false).await
}

async fn migrate_with(client: &mut Client, backed_up: bool) -> Result<i32, StoreError> {
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
    if !backed_up && let Some(version) = needs_backup_after(applied) {
        return Err(StoreError::NeedsBackup(version));
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
    use super::{CHANGES_DATA, MIGRATIONS, NEEDS_BACKUP};

    /// A migration that looks like it changes stored data carries the
    /// needs-backup header (board #77), so a plain package upgrade never
    /// applies it without a backup.
    #[test]
    fn data_changing_migrations_are_marked() {
        // Statement starts that change rows, and clauses that drop or
        // retype stored columns or tables.
        const STARTS: [&str; 3] = ["update ", "delete from", "truncate"];
        const CLAUSES: [&str; 7] = [
            "drop column",
            "drop table",
            " type ",
            "rename column",
            // An upsert rewrites rows; a dropped schema or view loses them.
            "do update",
            "drop schema",
            "drop materialized view",
        ];
        for (version, sql) in MIGRATIONS {
            let changes = sql
                .lines()
                .map(|line| line.trim().to_lowercase())
                .filter(|line| !line.starts_with("--"))
                .find(|line| {
                    STARTS.iter().any(|start| line.starts_with(start))
                        || CLAUSES.iter().any(|clause| line.contains(clause))
                });
            if let Some(line) = changes {
                assert!(
                    CHANGES_DATA.contains(version) || sql.contains(NEEDS_BACKUP),
                    "migration {version} changes stored data ({line:?}): add a \
                     `{NEEDS_BACKUP}` line"
                );
            }
        }
    }

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
