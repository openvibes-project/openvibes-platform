//! `openvibes-admin import`: agent export files (protocol P3b) become
//! imported hosts; bad files are refused one by one, all audited.
// The test starts the CLI binary it verifies; this is not shipped code.
#![allow(clippy::disallowed_types)]

mod common;

use std::{path::Path, process::Output};

use chrono::{Duration, Utc};
use common::{Fixture, scratch_dir, stdout};
use serde_json::{Value, json};

const CLAIMED: &str = "agent.00000000-0000-4000-8000-000000000001";

async fn migrated() -> Fixture {
    let fixture = Fixture::create().await;
    stdout(&fixture.run(&["migrate"]));
    stdout(&fixture.run(&["maintenance"]));
    fixture
}

fn finding(id: &str, observed_ms: i64) -> Value {
    json!({
        "schema_version": 1, "finding_id": id, "scan_id": "scan.1",
        "rule_id": "process.ssh.running", "rule_version": 1,
        "observed_at_unix_ms": observed_ms, "severity": "medium", "confidence": 100,
        "message": "An SSH server process was observed", "evidence": ["process.names"]
    })
}

fn finding_export(findings: Vec<Value>) -> Value {
    json!({
        "schema_version": 1, "install_id": "inst-1", "agent_id": CLAIMED,
        "hostname": "db-archive-03", "scanner_version": "0.1.0",
        "exported_at_unix_ms": Utc::now().timestamp_millis(), "findings": findings
    })
}

fn inventory_export(collected_ms: i64, with_os: bool) -> Value {
    let mut document = json!({
        "schema_version": 1, "install_id": "inst-1", "scanner_version": "0.1.0",
        "collected_at_unix_ms": collected_ms,
        "packages": [
            {"manager": "rpm", "name": "bash", "version": "5.2.37", "release": "1.fc44", "arch": "x86_64"},
            {"manager": "rpm", "name": "curl", "version": "8.11.1", "release": "2.fc44", "arch": "x86_64"},
            {"manager": "rpm", "name": "zlib", "version": "1.3.1", "release": "1.fc44", "arch": "x86_64"}
        ]
    });
    if with_os {
        document["os"] = json!({"id": "fedora", "version_id": "44"});
    }
    document
}

fn write(dir: &Path, name: &str, document: &Value) {
    std::fs::write(dir.join(name), serde_json::to_vec(document).unwrap()).unwrap();
}

/// Everything the command printed, stdout then stderr.
fn text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[tokio::test]
async fn imports_findings_and_inventory_once() {
    let fixture = migrated().await;
    let dir = scratch_dir("import-once");
    let now = Utc::now().timestamp_millis();
    write(
        &dir,
        "openvibes-export-a.json",
        &finding_export(vec![finding("finding.1", now), finding("finding.2", now)]),
    );
    write(
        &dir,
        "openvibes-inventory-a.json",
        &inventory_export(now, true),
    );
    let dir_arg = dir.to_str().unwrap();

    let first = stdout(&fixture.run(&["import", dir_arg]));
    assert!(
        first.contains("imported 2 findings (0 already present)"),
        "{first}"
    );
    assert!(first.contains("inventory accepted (3 packages)"), "{first}");
    let imported = "SELECT count(*) FROM findings
                    WHERE agent_id = 'import.inst-1' AND origin = 'import' AND NOT authenticated";
    assert_eq!(fixture.count(imported).await, 2);
    assert_eq!(
        fixture
            .count("SELECT count(*) FROM host_packages WHERE agent_id = 'import.inst-1'")
            .await,
        3
    );
    assert_eq!(
        fixture
            .count(&format!(
                "SELECT count(*) FROM agents WHERE agent_id = '{CLAIMED}'"
            ))
            .await,
        0,
        "a claimed agent id never creates or touches an enrolled agent"
    );

    let second = stdout(&fixture.run(&["import", dir_arg]));
    assert!(
        second.contains("imported 0 findings (2 already present)"),
        "{second}"
    );
    assert!(second.contains("inventory unchanged"), "{second}");
    let audit = fixture.audit_targets().await;
    let imports: Vec<_> = audit.iter().filter(|row| row.0 == "import").collect();
    assert_eq!(imports.len(), 2);
    for (_, target, result) in imports {
        assert_eq!(result, "ok");
        let target = target.as_deref().unwrap();
        assert!(target.starts_with("2 files:"), "{target}");
        assert!(
            target.contains(dir_arg),
            "the audit names the paths: {target}"
        );
    }
    fixture.drop().await;
}

#[tokio::test]
async fn refuses_bad_files_and_keeps_going() {
    let fixture = migrated().await;
    let dir = scratch_dir("import-bad");
    let now = Utc::now().timestamp_millis();
    write(
        &dir,
        "good.json",
        &finding_export(vec![finding("finding.1", now)]),
    );
    write(&dir, "notes.json", &json!({"hello": 1}));
    write(&dir, "inv-noos.json", &inventory_export(now, false));
    std::fs::write(dir.join("big.json"), vec![b' '; 9 * 1024 * 1024]).unwrap();
    std::fs::write(dir.join("broken.json"), b"{not json").unwrap();
    std::fs::write(dir.join("readme.txt"), b"not an export").unwrap();

    let output = fixture.run(&["import", dir.to_str().unwrap()]);
    let all = text(&output);
    assert_eq!(output.status.code(), Some(1), "{all}");
    assert!(
        all.contains("notes.json: refused: not an OpenVIBES export file"),
        "{all}"
    );
    assert!(
        all.contains("big.json: refused: larger than 8 MiB"),
        "{all}"
    );
    assert!(
        all.contains("broken.json: refused: not valid JSON"),
        "{all}"
    );
    assert!(
        all.contains(
            "inv-noos.json: refused: no operating system: export again with a newer agent"
        ),
        "{all}"
    );
    assert!(all.contains("good.json: imported 1 findings"), "{all}");
    assert!(!all.contains("readme.txt"), "{all}");
    assert_eq!(
        fixture
            .count("SELECT count(*) FROM findings WHERE agent_id = 'import.inst-1'")
            .await,
        1
    );
    let audit = fixture.audit_targets().await;
    let last = audit.last().unwrap();
    assert_eq!((last.0.as_str(), last.2.as_str()), ("import", "error"));
    fixture.drop().await;
}

#[tokio::test]
async fn older_inventory_ignored() {
    let fixture = migrated().await;
    let dir = scratch_dir("import-older");
    let now = Utc::now();
    let newer = dir.join("newer.json");
    let older = dir.join("older.json");
    write(
        &dir,
        "newer.json",
        &inventory_export(now.timestamp_millis(), true),
    );
    write(
        &dir,
        "older.json",
        &inventory_export((now - Duration::hours(1)).timestamp_millis(), true),
    );
    stdout(&fixture.run(&["import", newer.to_str().unwrap()]));
    let second = stdout(&fixture.run(&["import", older.to_str().unwrap()]));
    assert!(second.contains("older inventory ignored"), "{second}");
    fixture.drop().await;
}

#[tokio::test]
async fn old_findings_refused_individually() {
    let fixture = migrated().await;
    let dir = scratch_dir("import-old-findings");
    let now = Utc::now();
    write(
        &dir,
        "export.json",
        &finding_export(vec![
            finding(
                "finding.old",
                (now - Duration::days(100)).timestamp_millis(),
            ),
            finding("finding.new", now.timestamp_millis()),
        ]),
    );
    let out = stdout(&fixture.run(&["import", dir.to_str().unwrap()]));
    assert!(
        out.contains("imported 1 findings (0 already present, 1 refused: retention_expired)"),
        "{out}"
    );
    fixture.drop().await;
}

#[tokio::test]
async fn future_dated_files_are_refused() {
    let fixture = migrated().await;
    let dir = scratch_dir("import-future");
    let tomorrow = (Utc::now() + Duration::days(1)).timestamp_millis();
    write(&dir, "inventory.json", &inventory_export(tomorrow, true));
    let mut export = finding_export(vec![finding("finding.1", Utc::now().timestamp_millis())]);
    export["exported_at_unix_ms"] = json!(tomorrow);
    write(&dir, "findings.json", &export);
    let output = fixture.run(&["import", dir.to_str().unwrap()]);
    let all = text(&output);
    assert_eq!(output.status.code(), Some(1), "{all}");
    assert!(
        all.contains("inventory.json: refused: invalid: collected_at_unix_ms is in the future"),
        "{all}"
    );
    assert!(
        all.contains("findings.json: refused: invalid: exported_at_unix_ms is in the future"),
        "{all}"
    );
    assert_eq!(
        fixture.count("SELECT count(*) FROM agents").await,
        0,
        "a refused file creates no host"
    );
    fixture.drop().await;
}

/// Runs `import DIR` capped at 4 GiB of address space and 60 seconds, so a
/// regression that reads `/dev/zero` or blocks on a FIFO fails this test
/// instead of exhausting the machine's memory or hanging the suite.
fn import_bounded(fixture: &Fixture, dir: &Path) -> Output {
    std::process::Command::new("timeout")
        .args(["60", "prlimit", "--as=4294967296", "--"])
        .arg(env!("CARGO_BIN_EXE_openvibes-admin"))
        .arg("--config")
        .arg(&fixture.config)
        .arg("import")
        .arg(dir)
        .env("USER", "ov-test")
        .env_remove("SUDO_USER")
        .output()
        .unwrap()
}

#[tokio::test]
async fn special_files_are_refused_unread() {
    let fixture = migrated().await;
    let dir = scratch_dir("import-special");
    std::os::unix::fs::symlink("/dev/zero", dir.join("zero.json")).unwrap();
    let made = std::process::Command::new("mkfifo")
        .arg(dir.join("fifo.json"))
        .status()
        .unwrap();
    assert!(made.success());
    let output = import_bounded(&fixture, &dir);
    let all = text(&output);
    assert_eq!(output.status.code(), Some(1), "{all}");
    assert!(
        all.contains("zero.json: refused: not a regular file"),
        "{all}"
    );
    assert!(
        all.contains("fifo.json: refused: not a regular file"),
        "{all}"
    );
    fixture.drop().await;
}

#[tokio::test]
async fn control_characters_never_reach_the_terminal() {
    let fixture = migrated().await;
    let dir = scratch_dir("import-control");
    let now = Utc::now().timestamp_millis();
    let mut export = finding_export(vec![finding("finding.1", now)]);
    export["hostname"] = json!("host\u{1b}[2J");
    write(&dir, "host.json", &export);
    let mut inventory = inventory_export(now, true);
    inventory["packages"][0]["manager"] = json!("rpm\u{1b}]0;owned\u{7}");
    write(&dir, "manager.json", &inventory);
    write(&dir, "name\u{1b}[31m.json", &json!({"hello": 1}));
    let output = fixture.run(&["import", dir.to_str().unwrap()]);
    let all = text(&output);
    assert_eq!(output.status.code(), Some(1), "{all}");
    assert!(!all.contains('\u{1b}') && !all.contains('\u{7}'), "{all:?}");
    assert!(
        all.contains("host.json: refused: invalid: hostname contains control characters"),
        "{all}"
    );
    assert!(all.contains("manager.json: refused: invalid:"), "{all}");
    assert_eq!(fixture.count("SELECT count(*) FROM agents").await, 0);
    fixture.drop().await;
}

// M1 limits review: inventory files may be up to 8 MiB; finding files
// keep the 1 MiB limit.
#[tokio::test]
async fn large_inventory_files_are_imported_large_finding_files_refused() {
    let fixture = migrated().await;
    let dir = scratch_dir("import-large");
    let now = Utc::now().timestamp_millis();
    let mut inventory = inventory_export(now, true);
    inventory["packages"] = Value::Array(
        (0..30_000)
            .map(|i| {
                json!({"manager": "rpm", "name": format!("texlive-collection-package-{i:06}"),
                            "version": "20250308", "release": "91.fc44", "arch": "noarch",
                            "vendor": "Fedora Project"})
            })
            .collect(),
    );
    write(&dir, "inventory.json", &inventory);
    assert!(std::fs::metadata(dir.join("inventory.json")).unwrap().len() > 2 * 1024 * 1024);
    let mut findings = finding_export(vec![finding("finding.1", now)]);
    findings["hostname"] = json!("h");
    findings["padding"] = json!("x".repeat(2 * 1024 * 1024));
    write(&dir, "findings.json", &findings);
    let output = fixture.run(&["import", dir.to_str().unwrap()]);
    let all = text(&output);
    assert!(
        all.contains("inventory.json: inventory accepted (30000 packages)"),
        "{all}"
    );
    assert!(
        all.contains("findings.json: refused: larger than 1 MiB"),
        "{all}"
    );
    fixture.drop().await;
}
