//! `openvibes-admin import PATH...`: agent export files (protocol P3b) as
//! imported hosts. Each file is validated like its online counterpart and
//! stored on its own; a refused file never stops the others.

use std::{
    collections::BTreeMap,
    io::Read,
    path::{Path, PathBuf},
};

use chrono::{DateTime, Duration, Utc};
use openvibes_core::{FindingExport, Identifier, InventoryExport, ResourceLimits, Validate};
use platform_store::{
    Client, StoreError,
    imports::{self, ImportedHost, InventoryImport},
    ingest::{self, Origin},
    wire,
};
use serde::de::DeserializeOwned;

const NO_OS: &str = "no operating system: export again with a newer agent";

/// What one accepted file added.
#[derive(Default)]
struct Imported {
    findings: u64,
    inventories: u64,
}

/// Runs an import; returns the output and the audit target (the totals).
/// Any refused file makes the whole run an error (exit code 1), with every
/// line still reported.
pub async fn run(
    paths: &[PathBuf],
    retention_days: u32,
    client: &mut Client,
) -> (Result<String, String>, Option<String>) {
    let mut output = String::new();
    let (mut files, mut refused) = (0, 0);
    let mut totals = Imported::default();
    for (path, listed) in files_in(paths) {
        files += 1;
        let result = match listed {
            Ok(()) => import_file(&path, retention_days, client, Utc::now()).await,
            Err(reason) => Err(reason),
        };
        let line = match result {
            Ok((line, imported)) => {
                totals.findings += imported.findings;
                totals.inventories += imported.inventories;
                line
            }
            Err(reason) => {
                refused += 1;
                format!("refused: {reason}")
            }
        };
        let shown = printable(&format!("{}: {line}", path.display()));
        output.push_str(&shown);
        output.push('\n');
    }
    let total = format!(
        "{files} files: {} findings, {} inventories, {refused} refused",
        totals.findings, totals.inventories
    );
    // The audit keeps where unsigned data came from; bounded like any target.
    let named: Vec<String> = paths
        .iter()
        .map(|path| path.display().to_string())
        .collect();
    let target: String = printable(&format!("{total} from {}", named.join(" ")))
        .chars()
        .take(1000)
        .collect();
    output.push_str(&total);
    output.push('\n');
    if refused > 0 {
        (Err(output.trim_end().to_owned()), Some(target))
    } else {
        (Ok(output), Some(target))
    }
}

/// The files to import: each file path as given, and each directory's
/// `*.json` files in name order (not recursive). A directory that cannot
/// be read is one refused entry.
fn files_in(paths: &[PathBuf]) -> Vec<(PathBuf, Result<(), String>)> {
    let mut files = Vec::new();
    for path in paths {
        if !path.is_dir() {
            files.push((path.clone(), Ok(())));
            continue;
        }
        match std::fs::read_dir(path) {
            Ok(entries) => {
                let mut listed: Vec<PathBuf> = entries
                    .filter_map(|entry| entry.ok().map(|entry| entry.path()))
                    .filter(|file| file.extension().is_some_and(|ext| ext == "json"))
                    .collect();
                listed.sort();
                files.extend(listed.into_iter().map(|file| (file, Ok(()))));
            }
            Err(error) => files.push((path.clone(), Err(format!("cannot read: {error}")))),
        }
    }
    files
}

fn store(error: StoreError) -> String {
    format!("database error: {error}")
}

/// Control characters from untrusted files and file names, escaped so they
/// never reach the operator's terminal as escape sequences.
fn printable(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c.is_control() {
                c.escape_default().to_string()
            } else {
                c.to_string()
            }
        })
        .collect()
}

/// A file time; one later than online delivery accepts is refused, since it
/// would win newest-wins forever.
fn time(field: &str, unix_ms: i64, now: DateTime<Utc>) -> Result<DateTime<Utc>, String> {
    let at = DateTime::from_timestamp_millis(unix_ms)
        .ok_or_else(|| format!("invalid: {field} out of range"))?;
    if at > now + Duration::minutes(wire::MAX_FUTURE_MINUTES) {
        return Err(format!("invalid: {field} is in the future"));
    }
    Ok(at)
}

/// Labels shown to operators must not carry control characters.
fn label(field: &str, value: Option<&str>) -> Result<(), String> {
    if value.is_some_and(|value| value.chars().any(char::is_control)) {
        return Err(format!("invalid: {field} contains control characters"));
    }
    Ok(())
}

/// Decoded and validated with the same types and limits as online documents.
fn decode<T: DeserializeOwned + Validate>(value: serde_json::Value) -> Result<T, String> {
    let document: T = serde_json::from_value(value).map_err(|error| format!("invalid: {error}"))?;
    document
        .validate(ResourceLimits::V1)
        .map_err(|error| format!("invalid: {error}"))?;
    Ok(document)
}

async fn import_file(
    path: &Path,
    retention_days: u32,
    client: &mut Client,
    now: DateTime<Utc>,
) -> Result<(String, Imported), String> {
    // Read up to the inventory limit (8 MiB); finding files are held to the
    // 1 MiB document limit once their kind is known (M1 limits review).
    let limit = ResourceLimits::V1.inventory_document_bytes;
    let too_large = || String::from("larger than 8 MiB");
    let unreadable = |error: std::io::Error| format!("cannot read: {error}");
    // A symlink to a device, a FIFO, or a socket is never opened: opening a
    // FIFO blocks until a writer appears. Checked again on the open file in
    // case the path was swapped in between.
    let not_regular = || String::from("not a regular file");
    if !std::fs::metadata(path).map_err(unreadable)?.is_file() {
        return Err(not_regular());
    }
    let file = std::fs::File::open(path).map_err(unreadable)?;
    let metadata = file.metadata().map_err(unreadable)?;
    if !metadata.is_file() {
        return Err(not_regular());
    }
    if metadata.len() > limit as u64 {
        return Err(too_large());
    }
    // Bounded even if the file grows after the size check.
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(unreadable)?;
    if bytes.len() > limit {
        return Err(too_large());
    }
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|_| String::from("not valid JSON"))?;
    if value.get("findings").is_some() {
        if bytes.len() > ResourceLimits::V1.document_bytes {
            return Err("larger than 1 MiB".into());
        }
        findings(decode(value)?, retention_days, client, now).await
    } else if value.get("packages").is_some() {
        inventory(decode(value)?, client, now).await
    } else {
        Err("not an OpenVIBES export file".into())
    }
}

async fn findings(
    export: FindingExport,
    retention_days: u32,
    client: &mut Client,
    now: DateTime<Utc>,
) -> Result<(String, Imported), String> {
    let host = ImportedHost {
        install_id: export.install_id.as_str(),
        claimed_agent_id: export.agent_id.as_ref().map(Identifier::as_str),
        hostname: export.hostname.as_deref(),
        scanner_version: &export.scanner_version,
        seen_at: time("exported_at_unix_ms", export.exported_at_unix_ms, now)?,
    };
    label("hostname", host.hostname)?;
    label("scanner_version", Some(host.scanner_version))?;
    let id = imports::upsert_host(client, &host, now)
        .await
        .map_err(store)?;
    let partitions = platform_store::partition_days(client)
        .await
        .map_err(store)?;
    let oldest = now - Duration::days(i64::from(retention_days));
    let latest = now + Duration::minutes(wire::MAX_FUTURE_MINUTES);
    let mut keep = Vec::with_capacity(export.findings.len());
    let mut reasons: BTreeMap<&str, u64> = BTreeMap::new();
    for finding in &export.findings {
        match wire::finding(finding, oldest, latest, &partitions) {
            Ok(row) => keep.push(row),
            Err(reason) => *reasons.entry(reason).or_default() += 1,
        }
    }
    let new = ingest::store_findings(client, &id, &keep, Origin::Import, now)
        .await
        .map_err(store)?;
    let present = keep.len() as u64 - new;
    let mut line = format!("imported {new} findings ({present} already present");
    if !reasons.is_empty() {
        let count: u64 = reasons.values().sum();
        let names: Vec<&str> = reasons.keys().copied().collect();
        line.push_str(&format!(", {count} refused: {}", names.join(", ")));
    }
    line.push(')');
    Ok((
        line,
        Imported {
            findings: new,
            inventories: 0,
        },
    ))
}

async fn inventory(
    mut export: InventoryExport,
    client: &mut Client,
    now: DateTime<Utc>,
) -> Result<(String, Imported), String> {
    let os = export.os.clone().ok_or_else(|| String::from(NO_OS))?;
    let collected_at = time("collected_at_unix_ms", export.collected_at_unix_ms, now)?;
    label("hostname", export.hostname.as_deref())?;
    label("scanner_version", Some(&export.scanner_version))?;
    let (rows, digest) =
        wire::inventory(&os, export.running_kernel.as_deref(), &mut export.packages)
            .map_err(store)?;
    let host = ImportedHost {
        install_id: export.install_id.as_str(),
        claimed_agent_id: export.agent_id.as_ref().map(Identifier::as_str),
        hostname: export.hostname.as_deref(),
        scanner_version: &export.scanner_version,
        seen_at: collected_at,
    };
    let id = imports::upsert_host(client, &host, now)
        .await
        .map_err(store)?;
    let outcome = imports::replace_inventory(
        client,
        &id,
        os.id.as_str(),
        os.version_id.as_str(),
        export.running_kernel.as_deref(),
        &rows,
        digest,
        collected_at,
    )
    .await
    .map_err(store)?;
    let line = match outcome {
        InventoryImport::Stored => format!("inventory accepted ({} packages)", rows.len()),
        InventoryImport::Unchanged => "inventory unchanged".into(),
        InventoryImport::Older => "older inventory ignored".into(),
    };
    Ok((
        line,
        Imported {
            findings: 0,
            inventories: 1,
        },
    ))
}
