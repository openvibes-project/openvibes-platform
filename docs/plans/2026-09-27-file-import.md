# File import (protocol P3b) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:executing-plans (native) or superpowers:subagent-driven-development. Steps use checkboxes.

**Goal:** `openvibes-admin import PATH...` stores agent export files as imported hosts with findings and vulnerability matching.

**Architecture:** Protocol first (`os`, `running_kernel` on `InventoryExport`), then the agent writes them, then the platform: imported hosts are `agents` rows with status `imported` and id `import.<install_id>`; the importer reuses the online store code for findings and inventories.

**Tech Stack:** Rust (tokio-postgres, clap, serde), PostgreSQL, Python schema validator, bash systemd e2e.

**Spec:** `docs/specs/2026-09-27-file-import-design.md` (approved 2026-09-27).

## Global Constraints

- Order: protocol PR → agent PR (pins protocol) → platform PR (pins agent). Each merges only with the user's approval and green CI.
- Migration **0015** is reserved for imported-host support. Console migrations
  in PR #29 follow as **0016–0021**, and the least-privilege console grant fix
  is **0022** (`SCHEMA_VERSION = 22`); migration **0023** adds vulnerability
  reads and synchronizes the built-in role permissions.
- Imported id: `import.` + `install_id`; `install_id` matches `^[A-Za-z0-9._:-]{1,128}$` (protocol identifier).
- Files over `ResourceLimits::V1.document_bytes` (1 MiB) are refused before decoding.
- Imports never touch an `agent.` row; a file's `agent_id` goes only to `claimed_agent_id`.
- Findings: same refusal rules as online delivery (future > 1 h, older than retention, no partition); `origin = 'import'`, `authenticated = false`.
- Inventory: newest `collected_at` wins; inventories without `os` are refused.
- New crate dependencies: none outside the workspace (`platform-store` gains `openvibes-core` and `sha2`, both already workspace dependencies).
- Files under 500 lines; component docs updated in the same PR; commits end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- Build with `CARGO_NET_GIT_FETCH_WITH_CLI=true`; test database via `eval "$(scripts/test-db.sh)"`.

## Review Focus

- The same file imported twice, or two files in reverse order: second run stores nothing and reports "already present" / "older inventory ignored" (Task 4 store test, Task 5 CLI test).
- A file claiming the `agent_id` of an enrolled agent: that agent's row, findings and inventory stay untouched (Task 4 store test).
- A directory with junk (`notes.json` that is not an export, a 2 MiB file, a `.txt`): junk JSON refused with a reason, `.txt` skipped, other files still imported, exit 1 (Task 5 CLI test).
- Findings older than retention or with no partition: refused per finding, the rest of the file stored (Task 5 CLI test).
- `agent revoke import.…`: refused with "imported hosts have no identity to revoke", nothing changed (Task 6 test).

---

### Task 1: Protocol — `os` and `running_kernel` on `InventoryExport` (openvibes-protocol)

**Files:**
- Modify: `schemas/v1/inventory-export.schema.json`
- Create: `fixtures/v1/inventory-export/valid-os.json`, `invalid-os-missing-version.json`, `invalid-bad-kernel.json`
- Modify: `spec/contracts-v1.md` (`### Inventory Export`, and `## Local-Only Export` import paragraph), `PLAN.md` (P3)

**Interfaces:** Produces the wire fields `os: {id, version_id}` and `running_kernel` (optional) that Task 2 writes and Task 5 reads.

- [ ] **Step 1:** Branch `p3b-import` from `main`. Write the three fixtures. `valid-os.json` = `valid.json` plus `"os": {"id": "debian", "version_id": "12"}` and `"running_kernel": "6.1.0-25-amd64"`; `invalid-os-missing-version.json` has `"os": {"id": "debian"}`; `invalid-bad-kernel.json` has `"running_kernel": "6.1 bad"`.
- [ ] **Step 2:** Run `python3 tools/validate.py`. Expected: FAIL — `invalid-os-missing-version.json` and `invalid-bad-kernel.json` are reported as unexpectedly valid (the schema still allows unknown members).
- [ ] **Step 3:** Add to `properties` of `inventory-export.schema.json`, copying the definitions from `inventory-report.schema.json`:

```json
"os": {
  "type": "object",
  "description": "From os-release: ID and VERSION_ID. Required by the importer for vulnerability matching; optional for files from older agents.",
  "required": ["id", "version_id"],
  "properties": {
    "id": { "$ref": "common.schema.json#/$defs/identifier" },
    "version_id": { "$ref": "common.schema.json#/$defs/identifier" }
  }
},
"running_kernel": {
  "type": "string",
  "description": "Optional: the running kernel's release as uname -r reports it.",
  "pattern": "^[A-Za-z0-9._+~^-]{1,128}$"
}
```

- [ ] **Step 4:** `python3 tools/validate.py` → all fixtures as expected.
- [ ] **Step 5:** Contract text. In `### Inventory Export` add: "It also carries the host's `os` (os-release `ID` and `VERSION_ID`) and `running_kernel`, as in `InventoryReport`; both are optional in the schema so files from older agents stay valid." Replace the last two sentences of the `Local-Only Export` import paragraph ("Import is idempotent … signature for enrolled agents.") with:

```markdown
Import rules: each `install_id` is one imported host, separate from any
enrolled agent. Findings are idempotent on `finding_id` within an
`install_id`. Of several `InventoryExport` files, the one with the newest
`collected_at_unix_ms` wins; an older or equal one is ignored, so files
can be imported in any order. An inventory without `os` cannot be matched
for vulnerabilities and is refused. `agent_id` and `hostname` in a file are
labels for operators, never identity. A later schema version may add a
signature for enrolled agents.
```

- [ ] **Step 6:** `PLAN.md` P3: replace the unticked line with `- [ ] Platform: \`openvibes-admin import\` stores export files as imported hosts (findings, inventory with \`os\`); spec \`openvibes-platform/docs/specs/2026-09-27-file-import-design.md\`.` and add under it `- [x] \`InventoryExport\` carries optional \`os\` and \`running_kernel\` (P3b).`
- [ ] **Step 7:** Commit `P3b: InventoryExport carries os and running_kernel; import rules`, push, open PR, wait for CI and the user's approval to merge.

### Task 2: Agent — export writes `os` and `running_kernel` (openvibes-agent)

**Files:**
- Modify: `crates/openvibes-core/src/export.rs` (`InventoryExport`, its `Validate`)
- Modify: `crates/openvibes-agent/src/service.rs:~434` (export builds the document)
- Modify: `crates/openvibes-agent/tests/local_only.rs` (assert the fields)
- Modify: `protocol` submodule → Task 1's merge commit

**Interfaces:**
- Consumes: Task 1 schema.
- Produces: `InventoryExport { os: Option<OsRelease>, running_kernel: Option<String>, .. }` in `openvibes-core` (Task 5 reads it).

- [ ] **Step 1:** Branch `p3b-export-os`; `git -C protocol fetch && git -C protocol checkout <task-1 merge sha>`. Run `cargo test -p openvibes-core --test protocol_fixtures`. Expected: FAIL on `invalid-bad-kernel.json` (accepted, because the struct ignores unknown members).
- [ ] **Step 2:** In `local_only_keeps_findings_across_restart_and_exports_each_once`, after reading `inventories`, add:

```rust
#[cfg(target_os = "linux")]
{
    let os = inventories[0].os.as_ref().expect("export carries os on Linux");
    assert!(!os.id.as_str().is_empty());
    assert!(inventories[0].running_kernel.is_some());
}
```

Run `cargo test -p openvibes-agent --test local_only`. Expected: compile error, no field `os`.
- [ ] **Step 3:** Add to `InventoryExport` after `hostname`:

```rust
    /// Operating system from os-release; absent in files from older agents.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os: Option<OsRelease>,
    /// The running kernel's release as `uname -r` reports it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub running_kernel: Option<String>,
```

and in `impl Validate for InventoryExport`, after the `collected_at_unix_ms` check:

```rust
        if let Some(kernel) = &self.running_kernel
            && !is_kernel_release(kernel)
        {
            return Err(ValidationError::new(
                "running_kernel",
                "must be 1 to 128 characters from A-Z a-z 0-9 . _ + ~ ^ -",
            ));
        }
```

`os` needs no extra check: `Identifier` validates on deserialize. In `service.rs` export, set `os: openvibes_collectors::os_release(), running_kernel: openvibes_collectors::running_kernel(),` in the `InventoryExport` literal.
- [ ] **Step 4:** `cargo test --workspace` → PASS; `cargo clippy --workspace --all-targets -- -D warnings` clean; `cargo fmt --check`.
- [ ] **Step 5:** Update `docs/components/` page for export (the file describing `openvibes-agent export`) with the two fields. Commit `Export: InventoryExport carries os and running_kernel (P3b)`, push, PR, CI, user approval, merge.

### Task 3: Platform — shared wire conversions in `platform-store`

Pure move so the admin importer and ingest share one conversion. No behaviour change.

**Files:**
- Create: `crates/platform-store/src/wire.rs`
- Modify: `crates/platform-store/Cargo.toml` (+ `openvibes-core.workspace = true`, `sha2.workspace = true`), `crates/platform-store/src/lib.rs` (`pub mod wire;`)
- Modify: `crates/openvibes-ingest/src/delivery.rs` (use `wire::*`, delete moved fns)
- Test: unit tests in `wire.rs`

**Interfaces — Produces:**

```rust
/// Store row for a protocol finding, or the reason it is refused.
pub fn finding(
    finding: &openvibes_core::Finding,
    oldest: DateTime<Utc>,
    latest: DateTime<Utc>,
    partitions: &BTreeSet<NaiveDate>,
) -> Result<StoredFinding, &'static str>;
/// Canonical package rows and the inventory digest (order-independent).
pub fn inventory(
    os: &openvibes_core::OsRelease,
    running_kernel: Option<&str>,
    packages: &mut [openvibes_core::InstalledPackage],
) -> Result<(Vec<PackageRow>, [u8; 32]), StoreError>;
```

- [ ] **Step 1:** Branch: rename `import-design` → `p3b-file-import` (`git branch -m`). Write `wire.rs` tests first:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    // Two orders of the same packages give one digest and the same rows.
    #[test]
    fn inventory_digest_ignores_package_order() {
        let os: OsRelease = serde_json::from_str(r#"{"id":"fedora","version_id":"44"}"#).unwrap();
        let a: InstalledPackage = serde_json::from_str(r#"{"manager":"rpm","name":"a","version":"1"}"#).unwrap();
        let b: InstalledPackage = serde_json::from_str(r#"{"manager":"dpkg","name":"b","version":"2","epoch":1}"#).unwrap();
        let (rows1, d1) = inventory(&os, None, &mut [a.clone(), b.clone()]).unwrap();
        let (rows2, d2) = inventory(&os, None, &mut [b, a]).unwrap();
        assert_eq!(d1, d2);
        assert_eq!(rows1, rows2);
        assert_eq!(rows1[0].epoch, 1);
    }
    fn sample(observed: DateTime<Utc>) -> openvibes_core::Finding {
        serde_json::from_value(serde_json::json!({
            "schema_version": 1, "finding_id": "finding.1", "scan_id": "scan.1",
            "rule_id": "process.ssh.running", "rule_version": 3,
            "observed_at_unix_ms": observed.timestamp_millis(),
            "severity": "medium", "confidence": 100,
            "message": "An SSH server process was observed", "evidence": ["process.names"]
        }))
        .unwrap()
    }
    #[test]
    fn finding_outside_retention_is_refused_and_inside_is_kept() {
        let now = Utc::now();
        let days: BTreeSet<NaiveDate> = [now.date_naive()].into();
        let (oldest, latest) = (now - chrono::Duration::days(1), now + chrono::Duration::hours(1));
        let old = sample(now - chrono::Duration::days(2));
        assert_eq!(finding(&old, oldest, latest, &days), Err("retention_expired"));
        let kept = finding(&sample(now), oldest, latest, &days).unwrap();
        assert_eq!((kept.rule_version, kept.severity.as_str()), (3, "medium"));
    }
}
```
- [ ] **Step 2:** `cargo test -p platform-store --lib wire` → FAIL (module missing).
- [ ] **Step 3:** Move `severity`, `stored` and `refusal` from `delivery.rs` into `wire.rs` as private helpers behind `pub fn finding` (which calls `refusal` then `stored`); move the sort + digest + `PackageRow` mapping from `delivery.rs::inventory` into `pub fn inventory` (sort by `serde_json::to_string(package)`, digest `sha256(serde_json::to_vec(&(os, running_kernel, packages)))` — keep the tuple exactly so stored digests stay equal). Make `delivery.rs` call them; `refusal` errors still become `RejectedFinding`.
- [ ] **Step 4:** `cargo test -p platform-store -p openvibes-ingest` (with the test DB) → PASS. Clippy, fmt.
- [ ] **Step 5:** Commit `Store: shared wire conversions for findings and inventories`.

### Task 4: Migration 0015 and the import store

**Files:**
- Create: `migrations/0015_imported_hosts.sql`, `crates/platform-store/src/imports.rs`, `crates/platform-store/tests/imports.rs`
- Modify: `crates/platform-store/src/migrate.rs` (entry 15, `SCHEMA_VERSION = 15`), `lib.rs` (`pub mod imports;`), `ingest.rs::store_findings` (origin parameter), `inventory.rs::replace` (no change to signature; import passes `collected_at` as `now`)

**Interfaces:**
- Consumes: Task 3 `wire::finding`, `wire::inventory`.
- Produces:

```rust
pub enum Origin { Online, Import }   // in ingest.rs; store_findings(client, agent_id, findings, origin, now)
pub struct ImportedHost<'a> {
    pub install_id: &'a str,
    pub claimed_agent_id: Option<&'a str>,
    pub hostname: Option<&'a str>,
    pub scanner_version: &'a str,
    pub seen_at: DateTime<Utc>,        // exported_at or collected_at
}
/// Creates or updates `import.<install_id>`; returns the id.
pub async fn upsert_host(client: &Client, host: &ImportedHost<'_>, now: DateTime<Utc>) -> Result<String, StoreError>;
pub enum InventoryImport { Stored, Unchanged, Older }
/// Replaces the imported host's inventory if `collected_at` is newer than its `inventory_at`.
pub async fn replace_inventory(client: &mut Client, agent_id: &str, os_id: &str, os_version: &str,
    running_kernel: Option<&str>, packages: &[PackageRow], sha256: [u8; 32],
    collected_at: DateTime<Utc>) -> Result<InventoryImport, StoreError>;
```

- [ ] **Step 1:** Write `tests/imports.rs` (pattern: `tests/inventory.rs`, `common::TestDb::create()`, migrate):
  - `reimport_stores_nothing_new`: upsert host, `store_findings(.., Origin::Import, ..)` twice with the same finding → returns 1 then 0; `SELECT origin, authenticated FROM findings` → `('import', false)`.
  - `newest_inventory_wins`: replace at t2 → `Stored`; at t1 < t2 → `Older`; at t2 same digest → `Unchanged`; at t3 → `Stored`; `inventory_at` = t3.
  - `claimed_enrolled_agent_is_untouched`: insert active `agent.0000…0001` with hostname `real`, one `host_packages` row; upsert host with `claimed_agent_id = Some("agent.0000…0001")`, hostname `fake`, store a finding and inventory for it → the enrolled row's hostname, findings count (0) and package count unchanged; imported row has `claimed_agent_id` set.
  - `import_ids_cannot_be_active`: `INSERT INTO agents (agent_id, status, enrolled_at) VALUES ('import.x', 'active', now())` fails; `('agent.…', 'imported', …)` fails.
  - `upsert_keeps_first_import_time_and_latest_seen`: two upserts with seen_at t2 then t1 → `enrolled_at` = first call's now, `last_seen_at` = t2, hostname from the newer file.
- [ ] **Step 2:** `cargo test -p platform-store --test imports` → FAIL (module/migration missing).
- [ ] **Step 3:** Migration (check constraint names first: `psql -c '\d agents'` on the test DB; expected `agents_agent_id_check`, `agents_status_check`):

```sql
-- OpenVIBES platform schema version 15: hosts imported from agent export
-- files (protocol P3b; spec docs/specs/2026-09-27-file-import-design.md).
-- An imported host never authenticates: certificates only name agent.<uuid>.
ALTER TABLE agents
    DROP CONSTRAINT agents_agent_id_check,
    DROP CONSTRAINT agents_status_check,
    ADD CONSTRAINT agents_status_check CHECK (status IN ('active', 'revoked', 'imported')),
    ADD CONSTRAINT agents_agent_id_check CHECK (
        (status <> 'imported' AND agent_id ~ '^agent\.[0-9a-f-]{36}$')
        OR (status = 'imported' AND agent_id ~ '^import\.[A-Za-z0-9._:-]{1,128}$')),
    ADD COLUMN claimed_agent_id text;
```

`upsert_host`:

```sql
INSERT INTO agents (agent_id, status, enrolled_at, last_seen_at, scanner_version, hostname, claimed_agent_id)
VALUES ('import.' || $1, 'imported', $6, $5, $4, $3, $2)
ON CONFLICT (agent_id) DO UPDATE SET
    last_seen_at = GREATEST(agents.last_seen_at, EXCLUDED.last_seen_at),
    scanner_version = CASE WHEN EXCLUDED.last_seen_at >= agents.last_seen_at THEN EXCLUDED.scanner_version ELSE agents.scanner_version END,
    hostname = CASE WHEN EXCLUDED.last_seen_at >= agents.last_seen_at THEN EXCLUDED.hostname ELSE agents.hostname END,
    claimed_agent_id = CASE WHEN EXCLUDED.last_seen_at >= agents.last_seen_at THEN EXCLUDED.claimed_agent_id ELSE agents.claimed_agent_id END
WHERE agents.status = 'imported'
RETURNING agent_id
```

(`WHERE status = 'imported'` is belt and braces: the id prefix already keeps it off enrolled rows.) `replace_inventory`: `SELECT inventory_at FROM agents WHERE agent_id = $1 AND status = 'imported'`; if `Some(at) && at > collected_at` → `Older`; else `inventory::replace(.., collected_at)` mapping `Stored`/`Unchanged`. `// ponytail: check and replace are two transactions; a single operator CLI makes the race moot. One transaction if imports ever run concurrently.` `store_findings`: add `origin: Origin` and bind `origin` text and `authenticated` bool (`$14`, `$15`) instead of the literals; update the ingest call site with `Origin::Online`.
- [ ] **Step 4:** `cargo test -p platform-store` → PASS (all store tests; `migrate` test expects 15). Clippy, fmt.
- [ ] **Step 5:** Update `docs/components/platform-store.md` (imports module, migration 15). Commit `Store: imported hosts (migration 15)`.

### Task 5: `openvibes-admin import`

**Files:**
- Create: `crates/openvibes-admin/src/import.rs`, `crates/openvibes-admin/tests/import.rs`
- Modify: `crates/openvibes-admin/src/main.rs` (`mod import;`, `Command::Import`, dispatch with `require_current_schema`)

**Interfaces:**
- Consumes: Task 2 `openvibes_core::{FindingExport, InventoryExport, Validate, ResourceLimits}`, Task 3 `wire::{finding, inventory}`, Task 4 `imports::*`, `ingest::{store_findings, Origin}`, `platform_store::partition_days`.
- Produces: CLI `openvibes-admin import [--retention-days N] PATH...`.

```rust
/// Import agent export files (FindingExport, InventoryExport).
Import {
    /// Keep findings for this many days; must match `maintenance`.
    #[arg(long, default_value_t = 90, value_parser = clap::value_parser!(u32).range(1..=36500))]
    retention_days: u32,
    /// Export files, or directories whose *.json files are imported.
    #[arg(required = true)]
    paths: Vec<PathBuf>,
},
```

- [ ] **Step 1:** Write `tests/import.rs` (pattern: `tests/agent.rs`; `Fixture::create()`, `migrate`, `maintenance` to create partitions, `scratch_dir`). Build the files in the test with `serde_json::json!`:
  - `imports_findings_and_inventory_once`: dir with one FindingExport (install `inst-1`, 2 findings observed now − 1 h, `agent_id: "agent.00000000-0000-4000-8000-000000000001"`) and one InventoryExport (`os: fedora 44`, 3 rpm packages). Run `import DIR` → exit 0; stdout contains `imported 2 findings (0 already present)` and `inventory accepted (3 packages)`; `SELECT count(*) FROM findings WHERE agent_id = 'import.inst-1' AND origin = 'import' AND NOT authenticated` = 2; `host_packages` for it = 3; no `agent.…0001` row exists. Run again → `imported 0 findings (2 already present)` and `inventory unchanged`; exit 0. Audit: two `import` rows with result `ok`, target starting `2 files:`.
  - `refuses_bad_files_and_keeps_going`: dir with a valid FindingExport, `notes.json` = `{"hello":1}`, `big.json` of 2 MiB, `inv-noos.json` (InventoryExport without `os`), `readme.txt`. Exit code 1; stderr/stdout lines: `notes.json: refused: not an OpenVIBES export file`, `big.json: refused: larger than 1 MiB`, `inv-noos.json: refused: no operating system: export again with a newer agent`; the valid file imported; `readme.txt` not mentioned. Audit row result `error`.
  - `older_inventory_ignored`: import inventory with collected_at t2, then a file with t1 → second line `older inventory ignored`.
  - `old_findings_refused_individually`: FindingExport with one finding observed now − 100 days and one now − 1 h → `imported 1 findings (0 already present, 1 refused: retention_expired)`, exit 0 (a refused finding is not a refused file).
- [ ] **Step 2:** `cargo test -p openvibes-admin --test import` → FAIL (no `import` subcommand).
- [ ] **Step 3:** `import.rs`:

```rust
//! `openvibes-admin import PATH...`: agent export files (protocol P3b) as
//! imported hosts. Each file is validated like its online counterpart and
//! stored on its own; a refused file never stops the others.

pub async fn run(paths: &[PathBuf], retention_days: u32, client: &mut Client)
    -> (Result<String, String>, Option<String>)
```

  - `files(paths)`: a directory → its entries with extension `json`, sorted by name (not recursive); a file → itself; unreadable path → one refusal line.
  - Per file `import_file(path, ..) -> Result<String, String>` (Ok line / refusal reason): `metadata.len() > ResourceLimits::V1.document_bytes as u64` → `"larger than 1 MiB"`; read; `serde_json::from_slice::<serde_json::Value>` fails → `"not valid JSON"`; has `findings` → `FindingExport`, has `packages` → `InventoryExport`, else `"not an OpenVIBES export file"`; `serde_json::from_value` + `.validate(ResourceLimits::V1)` errors → `"invalid: {error}"`.
  - FindingExport: `upsert_host` (seen_at = exported_at); partitions via `platform_store::partition_days`; `oldest = now − retention_days`, `latest = now + 1 h`; `wire::finding` per finding, collect refusal reasons; `store_findings(.., Origin::Import, now)` → new count; line `imported {new} findings ({present} already present[, {n} refused: {reasons}])` where `present = kept − new`.
  - InventoryExport: `os` None → `"no operating system: export again with a newer agent"`; `wire::inventory`; `upsert_host` (seen_at = collected_at); `replace_inventory` → `inventory accepted ({n} packages)` / `inventory unchanged` / `older inventory ignored`.
  - Output: `"{path}: {line}\n"` per file, then `"{files} files: {findings} findings, {inventories} inventories, {refused} refused\n"`; that total line (without `\n`) is the audit target. Any refusal → `Err(whole output)` so the exit code is 1 (main prints it to stderr).
- [ ] **Step 4:** Wire into `main.rs` (`Self::Import { .. } => "import"` in `name`; dispatch like `Rules` with `&mut client`). `cargo test -p openvibes-admin` → PASS; clippy, fmt; `wc -l` each file < 500.
- [ ] **Step 5:** Update `docs/components/openvibes-admin.md` (import section: usage, output lines, exit code, refusal reasons). Commit `Admin: import agent export files (P3b)`.

### Task 6: Imported hosts in `agent list|show|revoke` and `status`

**Files:**
- Modify: `crates/platform-store/src/agents.rs` (`AgentInfo.claimed_agent_id`, `AgentInfo.hostname`, `Filter::Imported`, `Revoke::Imported`), `crates/platform-store/src/status.rs` (imported count)
- Modify: `crates/openvibes-admin/src/agent.rs` (`--imported`, show lines, revoke message), `main.rs` status output
- Test: `crates/openvibes-admin/tests/agent.rs`

- [ ] **Step 1:** Extend `seeded()` with `('import.inst-1', 'imported', …)` and `claimed_agent_id = RECENT`. Tests: `agent list` includes it with `imported`; `agent list --imported` shows only it; `--offline` and `--revoked` exclude it; `agent show import.inst-1` prints `claims agent.…0001`; `agent revoke import.inst-1` fails with stderr `imported hosts have no identity to revoke` and the row is still `imported`; `status` prints `imported hosts 1`.
- [ ] **Step 2:** Run → FAIL.
- [ ] **Step 3:** `SELECT` adds `a.claimed_agent_id, a.hostname`; `Filter::Imported` → `WHERE a.status = 'imported'`; `revoke`: when 0 rows changed, `SELECT status` → `imported` → `Revoke::Imported`; admin maps it to `Err("imported hosts have no identity to revoke")`; `list` line appends `  claims {id}` when set; `--imported` conflicts with `--offline`/`--revoked`. `status.rs`: `count(*) FILTER (WHERE status = 'imported')`, printed as `imported hosts N`.
- [ ] **Step 4:** `cargo test -p openvibes-admin -p platform-store` → PASS; clippy, fmt.
- [ ] **Step 5:** Docs: `openvibes-admin.md` agent section. Commit `Admin: imported hosts in agent list, show, revoke and status`.

### Task 7: End to end, pins, docs, PR

**Files:**
- Modify: `Cargo.toml` (agent `rev` → Task 2 merge sha for `openvibes-core`, `openvibes-transport`, `openvibes-rules`), `Cargo.lock`, CI's agent RPM rev if pinned separately (grep `e1005ff` across `.github/` and `scripts/`)
- Modify: `scripts/systemd-e2e.sh` (after step 7's vulns checks)
- Modify: `docs/specs/2026-09-23-platform-architecture-design.md` (ingest row: drop "later file import"; §7 file import via `openvibes-admin import`), `docs/components/README.md` if a page was added

- [ ] **Step 1:** Pin the agent; `cargo update -p openvibes-core`; `cargo test --workspace` (test DB) → PASS.
- [ ] **Step 2:** Add to `systemd-e2e.sh`:

```bash
# 7b. File import (P3b): a local-only agent's export becomes an imported
# host whose inventory is matched like an enrolled one.
in_c 'install -d -m 0700 /run/local-state /run/exports &&
      printf "state_dir = \"/run/local-state\"\n" > /run/local.toml &&
      openvibes-agent export /run/local.toml /run/exports' >/dev/null 2>&1 || fail "local-only export"
in_c 'chmod 0755 /run/exports && chmod 0644 /run/exports/*.json &&
      runuser -u openvibes_admin -- openvibes-admin import /run/exports' | grep -q 'inventory accepted' ||
    fail "import of the export files"
IMP=$(in_c "$SQL \"SELECT agent_id FROM agents WHERE status = 'imported'\"")
wait_for "the vulns service matched the imported host: bash vulnerable" 60 \
    "[[ \$($SQL \"SELECT count(*) FROM vulnerabilities WHERE agent_id = '$IMP' AND advisory_id = 'FEDORA-TEST-bash' AND fixed_at IS NULL\") == 1 ]]"
in_c "runuser -u openvibes_admin -- openvibes-admin agent list --imported" | grep -q "^$IMP  imported" ||
    fail "agent list --imported"
ok "an imported host is stored and matched for vulnerabilities"
```

- [ ] **Step 3:** Run the e2e locally (`scripts/build-rpm.sh` then `scripts/systemd-e2e.sh <rpm dir>` as CI does; see the workflow for exact args) → all `ok`.
- [ ] **Step 4:** Docs (architecture lines; `docs/components/openvibes-ingest.md` no longer promises import). Commit `E2E: file import; pin agent with export os`, push `p3b-file-import`, open PR "P3b: import agent export files", body ends with the Claude Code line.
- [ ] **Step 5:** After merge (user approval): protocol PR ticking P3's platform line; workspace `status.md`, `decisions.md` (import via admin CLI, imported hosts as agents rows), `requests.md`/board "File import" → done; note for Codex about `agents.status = 'imported'` and `claimed_agent_id`.
