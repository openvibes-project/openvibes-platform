# Inventory changes and compression (protocol P11) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:executing-plans (native) or superpowers:subagent-driven-development. Steps use checkboxes.

**Goal:** After an agent's first full inventory, it sends only what changed (`POST /v1/inventory/changes`), gzip-compressed. The platform always holds the complete list, checks every change set against the agent's fingerprint, and answers 409 `inventory_resync` so the agent sends the full list whenever they disagree.

**Architecture:** Three repositories, one PR each, merged in order: protocol → agent → platform.
- **Protocol:** defines `InventoryChanges`, the `inventory_resync` error code, the fingerprint and its test vectors.
- **Agent:**
  - `openvibes-core` gains the fingerprint (`NormalizedPackage`, `inventory_fingerprint`) and the change computation;
  - `openvibes-transport` gzips both inventory endpoints and maps 404 and 409 on the changes endpoint;
  - the service keeps the last acknowledged inventory as its base and chooses changes or the full list.
- **Platform:**
  - `platform-agent-server` decodes gzip with an 8 MiB output cap;
  - `platform-store` applies changes under the host's row lock and checks the result's fingerprint;
  - ingest adds the route.

**Tech Stack:** Rust (serde_json, sha2 0.11, flate2 1.1.10 with `rust_backend`), JSON Schema 2020-12 + the Python validator, PostgreSQL, bash e2e.

**Spec:** `docs/specs/2026-09-27-inventory-changes-design.md` (all sections). One amendment, recorded in Task 1: the fingerprint's exact definition (see Global Constraints).

## Global Constraints

- **Fingerprint (the contract, replaces spec §3's wording):**
  - It is SHA-256 over the UTF-8 compact JSON (no whitespace; non-ASCII not escaped) of `[[os.id, os.version_id], running_kernel, [record, …]]`.
  - `running_kernel` is JSON `null` when absent.
  - Each record is `[manager, name, epoch, version, release, arch, source, source_version]`:
    - `epoch` is an integer, `0` when absent;
    - `release` and `arch` are `""` when absent;
    - `source` and `source_version` are `null` when absent;
    - `vendor` is not included.
  - Records are deduplicated and sorted by their compact JSON text, byte order.
  - Why normalized: the platform stores exactly this (`package_versions` is unique over these eight fields, and `vendor` is not kept), so it can recompute the fingerprint from what it holds. The old digest (serde of `InstalledPackage`) is replaced on both sides, which costs each agent one full report after its upgrade.
- **Vectors:** three, in `openvibes-protocol/vectors/inventory-fingerprint.json`, with digests computed independently in Python:

  | Case | Digest |
  |---|---|
  | `inventory-report/valid.json`'s inventory | `0aec6f76ae2bd8749130718bc52381e8517e9f652e9315cec4275b3651bda505` |
  | Debian 13, no kernel, no packages | `cf8b1a5076db80106dff407963b7c3fe6090665cc998065ece281a6b07ea316c` |
  | Debian with duplicates, `vendor`, `source`, non-ASCII | `0cdc5d5f0b04c13ec1b8423ded68b49897575085f7db12210fd1b9b360b3acc5` |

- **Endpoints:**
  - `POST /v1/inventory/changes`: 204 on success; 409 with body `{"schema_version":1,"code":"inventory_resync"}` when anything disagrees (nothing is stored).
  - An older platform answers 404. The agent then sends full reports until it restarts.
- **`InventoryChanges` limits:** `added` + `removed` hold at most `inventory_items` (50,000) together; the body is at most `inventory_document_bytes` (8 MiB) before compression and after. `base_sha256` and `sha256` are 64 lowercase hex characters.
- **Compression:**
  - The agent always sends `Content-Encoding: gzip` (level 6) on both inventory endpoints.
  - The platform accepts gzip or no encoding (older agents). It refuses any other encoding (400), and output over 8 MiB (400, decompressed as a stream).
  - The existing limits still apply to both endpoints: 4 inventory requests at once, the 180 s deadline, and 8 MiB compressed.
- **Agent decisions:** it sends changes only when it holds a base whose fingerprint equals the acknowledged one, the platform has not answered 404 since start, and the serialized changes are at most half the serialized full report. Otherwise it sends the full report. On 409 or 404 it sends the full report in the same tick. The base file (`inventory-base.json`, 0600) is written only after a 2xx, before `inventory.sha256`.
- **Unchanged:** export files stay full and uncompressed; findings, heartbeats and rule bundles are untouched.
- **Known ceiling:** an epoch above 2,147,483,647 (the platform stores `int`) never matches, so that host always gets full reports. No real package has one.
- **New dependency** only in the agent: `flate2 = { version = "1.1.10", default-features = false, features = ["rust_backend"] }` (workspace dependency; `openvibes-transport` normal, `openvibes-testkit` normal). The platform already uses the same version (`openvibes-vulns`); add it to `platform-agent-server`, and to `openvibes-ingest` as a dev-dependency.
- **Workflow:**
  - One worktree per repository: `../openvibes-protocol-changes`, `../openvibes-agent-changes`, `../openvibes-platform-changes`, each on branch `inventory-changes`, with `git submodule update --init` and the `itismelime` identity (`testing.md` §1).
  - Commits end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
  - Files stay under 500 lines.
  - Component docs are updated in the same task.
  - Every merge needs the user's approval.
- **Gates:** protocol `.venv/bin/python tools/validate.py`; agent `testing.md` §4; platform `testing.md` §2 plus §3 (the systemd e2e changes).

## Review Focus

- A platform upgraded under agents that reported before: stored digests are old-format, so the first change set must get 409 and then a full report, never a stuck host (Task 7 `a_wrong_base_or_result_is_a_resync_and_nothing_changes`).
- An agent upgraded against an old platform (404): full reports keep flowing, with no error every tick (Task 4 `a_resync_or_an_old_platform_gets_the_full_report`).
- A missing, corrupt or stale base file (crash between writes, hand edit): the agent must fall back to a full report, never send changes against a wrong base (Task 4 `a_corrupt_base_means_a_full_report`).
- A small gzip body that expands past 8 MiB, or an unknown `Content-Encoding`: 400 without allocating the output (Task 6 unit tests; Task 7 over TLS).
- A reboot with no package change: a change set with empty `added`/`removed` must update the running kernel (Task 7 `a_kernel_only_change_updates_the_running_kernel`).

---

## Repository 1: openvibes-protocol

### Task 1: `InventoryChanges`, `inventory_resync`, fingerprint vectors

**Files:**
- Create: `schemas/v1/inventory-changes.schema.json`, `fixtures/v1/inventory-changes/{valid.json,valid-kernel-only.json,invalid-missing-base-sha256.json,invalid-uppercase-sha256.json}`, `fixtures/v1/platform-error/valid-inventory-resync.json`, `vectors/inventory-fingerprint.json`
- Modify: `schemas/v1/platform-error.schema.json`, `tools/validate.py`, `spec/contracts-v1.md`, `PLAN.md`, and the platform spec amendment (Task 5 carries the file; note it here in the PR body)

- [ ] **Step 1: The failing check.** Add to `tools/validate.py` before the summary line:

```python
    # The inventory fingerprint (protocol P11): each vector's digest must be
    # the SHA-256 of the canonical JSON the contract defines.
    for vector in json.loads((ROOT / "vectors/inventory-fingerprint.json").read_text()):
        checked += 1
        if fingerprint(vector["inventory"]) != vector["sha256"]:
            print(f"FAIL fingerprint vector {vector['name']}")
            failures += 1
```

and at module level:

```python
def fingerprint(inventory: dict) -> str:
    """spec/contracts-v1.md, "Inventory fingerprint"."""
    import hashlib

    def compact(value) -> str:
        return json.dumps(value, separators=(",", ":"), ensure_ascii=False)

    records = sorted(
        {
            compact(
                [
                    p["manager"], p["name"], p.get("epoch", 0), p["version"],
                    p.get("release", ""), p.get("arch", ""),
                    p.get("source"), p.get("source_version"),
                ]
            )
            for p in inventory["packages"]
        }
    )
    os = inventory["os"]
    text = "[{},{},[{}]]".format(
        compact([os["id"], os["version_id"]]),
        compact(inventory.get("running_kernel")),
        ",".join(records),
    )
    return hashlib.sha256(text.encode()).hexdigest()
```

Run: `.venv/bin/python tools/validate.py` (create the venv first if missing: `python3 -m venv .venv && .venv/bin/pip install -r tools/requirements.txt`).
Expected: FAIL with `FileNotFoundError` for `vectors/inventory-fingerprint.json`.

- [ ] **Step 2: Vectors.** `vectors/inventory-fingerprint.json`:

```json
[
  {
    "name": "fedora, as inventory-report/valid.json",
    "inventory": {
      "os": { "id": "fedora", "version_id": "44" },
      "running_kernel": "6.17.4-300.fc44.x86_64",
      "packages": [
        { "manager": "rpm", "name": "bash", "version": "5.2.37", "release": "1.fc44", "epoch": 0, "arch": "x86_64", "vendor": "Fedora Project" },
        { "manager": "rpm", "name": "kernel-core", "version": "6.17.4", "release": "300.fc44", "arch": "x86_64" },
        { "manager": "rpm", "name": "kernel-core", "version": "6.17.7", "release": "300.fc44", "arch": "x86_64" }
      ]
    },
    "sha256": "0aec6f76ae2bd8749130718bc52381e8517e9f652e9315cec4275b3651bda505"
  },
  {
    "name": "no kernel, no packages",
    "inventory": { "os": { "id": "debian", "version_id": "13" }, "packages": [] },
    "sha256": "cf8b1a5076db80106dff407963b7c3fe6090665cc998065ece281a6b07ea316c"
  },
  {
    "name": "dpkg: unordered, a duplicate after normalisation (epoch 0 = absent, vendor ignored), sources, non-ASCII",
    "inventory": {
      "os": { "id": "debian", "version_id": "13" },
      "running_kernel": "6.12.48+deb13-amd64",
      "packages": [
        { "manager": "dpkg", "name": "zlib1g", "version": "1.3.dfsg", "release": "3.1", "arch": "amd64", "source": "zlib", "source_version": "1:1.3.dfsg-3.1" },
        { "manager": "dpkg", "name": "bash", "version": "5.2.37", "release": "1", "epoch": 0, "arch": "amd64" },
        { "manager": "dpkg", "name": "bash", "version": "5.2.37", "release": "1", "arch": "amd64", "vendor": "ignored" },
        { "manager": "dpkg", "name": "libc6", "version": "2.41", "release": "12", "arch": "amd64", "source": "glibc" },
        { "manager": "dpkg", "name": "café", "version": "1", "arch": "all" }
      ]
    },
    "sha256": "0cdc5d5f0b04c13ec1b8423ded68b49897575085f7db12210fd1b9b360b3acc5"
  }
]
```

Run the validator. Expected: the three vectors pass (the digests were computed with this exact function).

- [ ] **Step 3: Schema and fixtures.** `schemas/v1/inventory-changes.schema.json`:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://github.com/openvibes-project/openvibes-protocol/schemas/v1/inventory-changes.schema.json",
  "title": "InventoryChanges",
  "description": "Online route (P11): what changed since the inventory the platform last acknowledged for this agent, sent to POST /v1/inventory/changes. The platform applies it only if its stored fingerprint equals base_sha256 and the result's fingerprint equals sha256; otherwise 409 inventory_resync and the agent sends the full InventoryReport. added and removed together hold at most 50,000 packages.",
  "type": "object",
  "required": ["schema_version", "agent_id", "base_sha256", "sha256", "os", "collected_at_unix_ms", "added", "removed"],
  "properties": {
    "schema_version": { "$ref": "common.schema.json#/$defs/schemaVersion" },
    "agent_id": { "$ref": "common.schema.json#/$defs/identifier" },
    "base_sha256": { "type": "string", "pattern": "^[0-9a-f]{64}$", "description": "Fingerprint of the inventory the platform last acknowledged." },
    "sha256": { "type": "string", "pattern": "^[0-9a-f]{64}$", "description": "Fingerprint after applying the changes." },
    "os": { "$ref": "inventory-report.schema.json#/properties/os" },
    "running_kernel": { "$ref": "inventory-report.schema.json#/properties/running_kernel" },
    "collected_at_unix_ms": { "$ref": "common.schema.json#/$defs/unixMs" },
    "added": { "type": "array", "maxItems": 50000, "items": { "$ref": "inventory-export.schema.json#/$defs/package" } },
    "removed": { "type": "array", "maxItems": 50000, "items": { "$ref": "inventory-export.schema.json#/$defs/package" } }
  }
}
```

(Match `additionalProperties` to `inventory-report.schema.json`: it sets none, so none here.)

Fixtures:
- `valid.json`: `agent.1`, `base_sha256` = the first vector's digest, `sha256` = `"b" * 64`, os `fedora 44`, the kernel from `valid.json`, `collected_at_unix_ms` 1790000700000.
  - `added`: `[{rpm bash 5.2.38 1.fc44 x86_64}]`
  - `removed`: `[{rpm bash 5.2.37 1.fc44 epoch 0 x86_64}]`
- `valid-kernel-only.json`: the same with `added: []`, `removed: []`, and `running_kernel` `6.17.7-300.fc44.x86_64`.
- `invalid-missing-base-sha256.json`: `valid.json` without `base_sha256`.
- `invalid-uppercase-sha256.json`: `valid.json` with `sha256` = `"B" * 64`.

`platform-error.schema.json`:
- `enum` becomes `["identity_revoked", "inventory_resync"]`;
- description: "Optional body of a 401 or 403 (`identity_revoked` makes an agent discard its identity), or of a 409 from `POST /v1/inventory/changes` (`inventory_resync`: send the full inventory)".

Fixture `platform-error/valid-inventory-resync.json`: `{"schema_version": 1, "code": "inventory_resync"}`.

- [ ] **Step 4: Contract text.** `spec/contracts-v1.md`:
  - **Route table:** add the row `/v1/inventory/changes | required | InventoryChanges | 204; 409 PlatformError inventory_resync`.
  - **After the `InventoryReport` paragraph, a section "Inventory changes (P11)":**
    - the rules from the Global Constraints above (fingerprint, 409/404 behaviour, limits, the half rule, base kept only after a 2xx);
    - an update is one `removed` plus one `added`;
    - `os` and `running_kernel` are always sent;
    - a `removed` package the host does not have, or an `added` one it has, is a resync.
  - **A section "Inventory fingerprint":** the exact definition, a pointer to `vectors/inventory-fingerprint.json`, and the note that it replaces the digest agents used before P11 (one full report after upgrading).
  - **A sentence under compression:** both inventory endpoints take `Content-Encoding: gzip`; the 8 MiB limit applies to the compressed body and to its expansion.
  - **Limits table:** the inventory document row names both endpoints.

  `PLAN.md`:
  - message table row `11 | InventoryChanges | agent → ingest | online | /v1/inventory/changes, mTLS | todo | todo`;
  - section `### P11: Inventory changes and compression (user, 2026-09-27)` with checkboxes for spec/schema (checked in this PR), agent and platform.

- [ ] **Step 5: Run.**

Run: `.venv/bin/python tools/validate.py`
Expected: `… fixtures checked, 0 failures`, including 4 new `inventory-changes` fixtures, 1 new `platform-error` fixture and 3 vectors.

- [ ] **Step 6: Commit, push, PR.** Commit "Protocol P11: inventory changes, inventory_resync, fingerprint vectors". Push `inventory-changes` and open the PR "Protocol P11: send only inventory changes, gzip-compressed"; its Validation section gives the validator output. Merge only with the user's approval. The agent task pins this branch's head commit, which stays reachable after a merge commit.

---

## Repository 2: openvibes-agent

### Task 2: core: fingerprint, changes, `InventoryChanges`, `inventory_resync`

**Files:**
- Create: `crates/openvibes-core/src/inventory.rs`
- Modify: `crates/openvibes-core/{Cargo.toml,src/lib.rs,src/export.rs,src/contracts.rs}`, `crates/openvibes-core/tests/` (the fixture test file that lists message directories; find it with `grep -rln inventory-export crates/*/tests`), `protocol` submodule → Task 1's commit, `docs/components/openvibes-core.md`

**Interfaces — Produces:**

```rust
// inventory.rs, re-exported from lib.rs
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NormalizedPackage { pub manager: String, pub name: String, pub epoch: u32, pub version: String,
    pub release: String, pub arch: String, pub source: Option<String>, pub source_version: Option<String> }
impl From<&InstalledPackage> for NormalizedPackage;
impl serde::Serialize for NormalizedPackage;   // as the 8-element array
pub fn inventory_fingerprint(os: &OsRelease, running_kernel: Option<&str>,
    packages: impl IntoIterator<Item = NormalizedPackage>) -> [u8; 32];
pub fn hex(digest: &[u8; 32]) -> String;                 // lowercase
pub fn digest_from_hex(text: &str) -> Option<[u8; 32]>;  // 64 lowercase hex only
pub fn inventory_changes(base: &[InstalledPackage], current: &[InstalledPackage])
    -> (Vec<InstalledPackage>, Vec<InstalledPackage>);   // (added, removed), by normalized record
// export.rs
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InventoryChanges { pub schema_version: SchemaVersion, pub agent_id: Identifier,
    pub base_sha256: String, pub sha256: String, pub os: OsRelease,
    #[serde(default, skip_serializing_if = "Option::is_none")] pub running_kernel: Option<String>,
    pub collected_at_unix_ms: i64, pub added: Vec<InstalledPackage>, pub removed: Vec<InstalledPackage> }
impl Validate for InventoryChanges;
// contracts.rs: PlatformErrorCode::InventoryResync  (serde "inventory_resync")
```

- [ ] **Step 1: Worktree.** `git -C openvibes-agent worktree add ../openvibes-agent-changes -b inventory-changes origin/main`, then `git submodule update --init` and the git identity. `git -C protocol fetch && git -C protocol checkout <Task 1 head>`.

- [ ] **Step 2: Failing tests.** Add at the bottom of `inventory.rs` (the file otherwise holds only its doc comment and `use` lines):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[derive(serde::Deserialize)]
    struct Vector {
        name: String,
        inventory: Inventory,
        sha256: String,
    }
    #[derive(serde::Deserialize)]
    struct Inventory {
        os: OsRelease,
        running_kernel: Option<String>,
        packages: Vec<InstalledPackage>,
    }

    #[test]
    fn the_fingerprint_matches_the_protocol_vectors() {
        let text = include_str!("../../../protocol/vectors/inventory-fingerprint.json");
        let vectors: Vec<Vector> = serde_json::from_str(text).unwrap();
        assert_eq!(vectors.len(), 3);
        for vector in vectors {
            let inventory = vector.inventory;
            let digest = inventory_fingerprint(
                &inventory.os,
                inventory.running_kernel.as_deref(),
                inventory.packages.iter().map(NormalizedPackage::from),
            );
            assert_eq!(hex(&digest), vector.sha256, "{}", vector.name);
            assert_eq!(digest_from_hex(&vector.sha256), Some(digest));
        }
        assert_eq!(digest_from_hex(&"A".repeat(64)), None, "lowercase only");
        assert_eq!(digest_from_hex("00"), None);
    }

    fn package(name: &str, version: &str) -> InstalledPackage {
        serde_json::from_value(serde_json::json!({
            "manager": "rpm", "name": name, "version": version, "release": "1.fc44", "arch": "x86_64"
        }))
        .unwrap()
    }

    #[test]
    fn changes_are_whole_records() {
        let base = [package("bash", "5.2.37"), package("gone", "1"), package("same", "1")];
        let mut vendor = package("same", "1");
        vendor.vendor = Some("Fedora Project".into()); // not part of the record
        let current = [package("bash", "5.2.38"), vendor, package("new", "2")];
        let (added, removed) = inventory_changes(&base, &current);
        let names = |list: &[InstalledPackage]| {
            list.iter().map(|p| format!("{}-{}", p.name, p.version)).collect::<Vec<_>>()
        };
        assert_eq!(names(&added), ["bash-5.2.38", "new-2"]);
        assert_eq!(names(&removed), ["bash-5.2.37", "gone-1"]);
        assert_eq!(inventory_changes(&current, &current), (vec![], vec![]));
    }
}
```

In `export.rs` tests (or the crate's existing contract test file), add:

```rust
#[test]
fn inventory_changes_are_bounded_together() {
    let package: InstalledPackage =
        serde_json::from_str(r#"{"manager":"rpm","name":"p","version":"1"}"#).unwrap();
    let mut changes: InventoryChanges = serde_json::from_str(include_str!(
        "../../../protocol/fixtures/v1/inventory-changes/valid.json"
    ))
    .unwrap();
    assert!(changes.validate(ResourceLimits::V1).is_ok());
    changes.added = vec![package.clone(); 25_000];
    changes.removed = vec![package; 25_001];
    assert!(changes.validate(ResourceLimits::V1).is_err(), "50,001 together");
}
```

Add `"inventory-changes" => accepts::<InventoryChanges>` to the protocol-fixture test's match.

Run: `cargo test -p openvibes-core`
Expected: FAIL to compile (`inventory_fingerprint`, `InventoryChanges` missing).

- [ ] **Step 3: Implement.** `Cargo.toml` of core: `serde_json.workspace = true`, `sha2.workspace = true` under `[dependencies]`. `inventory.rs`:

```rust
//! The inventory fingerprint and change sets (protocol P11). Both sides
//! compute the fingerprint over the normalised package record the platform
//! stores, so the platform can check a change set against what it holds.

use std::collections::BTreeMap;

use serde::{Serialize, Serializer};
use sha2::{Digest, Sha256};

use crate::{InstalledPackage, OsRelease, PackageManager};

/// A package as the fingerprint and the platform see it: `vendor` dropped,
/// absent epoch 0, absent release and arch empty.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NormalizedPackage {
    pub manager: String,
    pub name: String,
    pub epoch: u32,
    pub version: String,
    pub release: String,
    pub arch: String,
    pub source: Option<String>,
    pub source_version: Option<String>,
}

impl From<&InstalledPackage> for NormalizedPackage {
    fn from(package: &InstalledPackage) -> Self {
        Self {
            manager: match package.manager {
                PackageManager::Rpm => "rpm",
                PackageManager::Dpkg => "dpkg",
            }
            .to_owned(),
            name: package.name.clone(),
            epoch: package.epoch.unwrap_or(0),
            version: package.version.clone(),
            release: package.release.clone().unwrap_or_default(),
            arch: package.arch.clone().unwrap_or_default(),
            source: package.source.clone(),
            source_version: package.source_version.clone(),
        }
    }
}

/// The contract's record: an eight-element JSON array.
impl Serialize for NormalizedPackage {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        (
            &self.manager,
            &self.name,
            self.epoch,
            &self.version,
            &self.release,
            &self.arch,
            &self.source,
            &self.source_version,
        )
            .serialize(serializer)
    }
}

/// SHA-256 of `[[os.id, os.version_id], running_kernel, [record, …]]` in
/// compact JSON, records deduplicated and sorted by their JSON text
/// (contracts-v1, "Inventory fingerprint").
#[must_use]
pub fn inventory_fingerprint(
    os: &OsRelease,
    running_kernel: Option<&str>,
    packages: impl IntoIterator<Item = NormalizedPackage>,
) -> [u8; 32] {
    // Strings, integers and nulls always serialize.
    let mut records: Vec<String> = packages
        .into_iter()
        .map(|package| serde_json::to_string(&package).unwrap_or_default())
        .collect();
    records.sort_unstable();
    records.dedup();
    let head = serde_json::to_string(&(os.id.as_str(), os.version_id.as_str())).unwrap_or_default();
    let kernel = serde_json::to_string(&running_kernel).unwrap_or_default();
    let text = format!("[{head},{kernel},[{}]]", records.join(","));
    Sha256::digest(text.as_bytes()).into()
}
```

Then:

```rust
/// Lowercase hex.
#[must_use]
pub fn hex(digest: &[u8; 32]) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The digest `hex` wrote; `None` for anything but 64 lowercase hex digits.
#[must_use]
pub fn digest_from_hex(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 || !text.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return None;
    }
    let mut digest = [0; 32];
    for (index, byte) in digest.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(digest)
}

/// `(added, removed)` from `base` to `current`, compared by normalised
/// record: an update is one removed and one added.
#[must_use]
pub fn inventory_changes(
    base: &[InstalledPackage],
    current: &[InstalledPackage],
) -> (Vec<InstalledPackage>, Vec<InstalledPackage>) {
    let index = |list: &[InstalledPackage]| -> BTreeMap<NormalizedPackage, InstalledPackage> {
        list.iter().map(|p| (NormalizedPackage::from(p), p.clone())).collect()
    };
    let (old, new) = (index(base), index(current));
    let added = new.iter().filter(|(k, _)| !old.contains_key(*k)).map(|(_, p)| p.clone()).collect();
    let removed = old.iter().filter(|(k, _)| !new.contains_key(*k)).map(|(_, p)| p.clone()).collect();
    (added, removed)
}
```

`lib.rs`: `mod inventory;` and `pub use inventory::{NormalizedPackage, digest_from_hex, hex, inventory_changes, inventory_fingerprint};` plus `InventoryChanges` in the `export` re-export.

`contracts.rs` `PlatformErrorCode`: add

```rust
    /// The platform's stored inventory differs from a change set's base, or
    /// the result's fingerprint differs: send the full inventory (P11).
    InventoryResync,
```

`export.rs`: add `InventoryChanges` (fields as in Interfaces, documented like `InventoryReport`) and

```rust
fn validate_sha256(field: &'static str, value: &str) -> Result<(), ValidationError> {
    if crate::digest_from_hex(value).is_some() {
        Ok(())
    } else {
        Err(ValidationError::new(field, "must be 64 lowercase hex digits"))
    }
}

impl Validate for InventoryChanges {
    fn validate(&self, limits: ResourceLimits) -> Result<(), ValidationError> {
        validate_version(self.schema_version)?;
        validate_sha256("base_sha256", &self.base_sha256)?;
        validate_sha256("sha256", &self.sha256)?;
        validate_unix_ms("collected_at_unix_ms", self.collected_at_unix_ms)?;
        validate_kernel(self.running_kernel.as_deref())?;
        if self.added.len() + self.removed.len() > limits.inventory_items {
            return Err(ValidationError::new("added", "added and removed hold too many packages together"));
        }
        self.added
            .iter()
            .chain(&self.removed)
            .try_for_each(|package| package.validate(limits))
    }
}
```

- [ ] **Step 4: Run.** `cargo test -p openvibes-core`. Expected: PASS, including every protocol fixture and the three vectors.

- [ ] **Step 5: Docs and commit.** `docs/components/openvibes-core.md`: an "Inventory fingerprint and changes (P11)" section with the functions and the definition. Commit "Core: P11 fingerprint, change sets, InventoryChanges" (with the submodule bump).

### Task 3: transport: gzip, `/v1/inventory/changes`, 404 and 409

**Files:**
- Modify: `Cargo.toml` (workspace `flate2`), `crates/openvibes-transport/{Cargo.toml,src/client.rs,tests/platform.rs}`, `crates/openvibes-testkit/{Cargo.toml,src/lib.rs}`, `docs/components/openvibes-transport.md`, `docs/components/openvibes-testkit.md`

**Interfaces — Produces:**

```rust
// client.rs
pub enum TransportError { …, NotFound, InventoryResync }   // Display: "the platform does not offer this endpoint", "the platform asks for the full inventory"
impl PlatformClient {
    pub fn report_inventory(&self, report: &InventoryReport) -> Result<(), TransportError>;           // now gzip
    pub fn report_inventory_changes(&self, changes: &InventoryChanges) -> Result<(), TransportError>; // gzip; 404 → NotFound, 409 inventory_resync → InventoryResync
}
// testkit
pub struct Seen { pub path: String, pub body: Vec<u8>, pub client_cert: bool, pub content_encoding: Option<String> }
impl Seen { pub fn decoded_body(&self) -> Vec<u8>; }   // gunzips when content_encoding is gzip
```

- [ ] **Step 1: Testkit.**
  - Record the `content-encoding` header (lowercased value, trimmed) in `Seen`.
  - Add `decoded_body()` using `flate2::read::GzDecoder`.
  - This is test infrastructure, so there is no separate test: it is proven by Step 2's tests.

- [ ] **Step 2: Failing tests** in `tests/platform.rs`.
  - Change `inventories_may_exceed_one_mib_and_nothing_else_may` to assert `seen.recv().unwrap().decoded_body().len() > 1024 * 1024`. The wire body is now small.
  - Add:

```rust
fn changes() -> openvibes_core::InventoryChanges {
    serde_json::from_str(include_str!(
        "../../../protocol/fixtures/v1/inventory-changes/valid.json"
    ))
    .unwrap()
}

/// Both inventory endpoints are gzip-compressed (P11); nothing else is.
#[test]
fn inventories_are_sent_gzip_compressed() {
    let pki = Pki::new();
    let (url, seen) = serve(
        pki.server_config(false, false),
        vec![Box::new(|_: &Seen| status(204)), Box::new(|_: &Seen| status(204))],
    );
    let client = PlatformClient::new(&config(&url, &pki), None).unwrap();
    let report = big_inventory(3_000);
    client.report_inventory(&report).unwrap();
    client.report_inventory_changes(&changes()).unwrap();
    for (seen, path) in seen.iter().take(2).zip(["/v1/inventory", "/v1/inventory/changes"]) {
        assert_eq!(seen.path, path);
        assert_eq!(seen.content_encoding.as_deref(), Some("gzip"));
        assert!(seen.body.len() < seen.decoded_body().len() / 5, "compressed");
    }
}

/// 409 with `inventory_resync` and 404 are the change set's own answers;
/// other refusals stay as before, and 404 elsewhere is still `Rejected`.
#[test]
fn a_change_set_learns_resync_and_missing_endpoint() {
    let pki = Pki::new();
    let resync = serde_json::json!({"schema_version": 1, "code": "inventory_resync"});
    let (url, _) = serve(
        pki.server_config(false, false),
        vec![
            Box::new(move |_: &Seen| Reply { status: 409, ..json(&resync) }),
            Box::new(|_: &Seen| status(409)),
            Box::new(|_: &Seen| status(404)),
            Box::new(|_: &Seen| status(404)),
        ],
    );
    let client = PlatformClient::new(&config(&url, &pki), None).unwrap();
    assert_eq!(client.report_inventory_changes(&changes()), Err(TransportError::InventoryResync));
    assert_eq!(client.report_inventory_changes(&changes()), Err(TransportError::Rejected), "409 without the code");
    assert_eq!(client.report_inventory_changes(&changes()), Err(TransportError::NotFound));
    assert_eq!(client.report_inventory(&big_inventory(1)), Err(TransportError::Rejected), "404 on /v1/inventory");
}
```

(If `Reply` has non-public fields that stop `..json(&resync)`, build `Reply { status: 409, headers: "", body: serde_json::to_vec(&resync).unwrap(), stall: false }`; `Reply` is imported already.)

Run: `cargo test -p openvibes-transport --test platform`
Expected: FAIL to compile (`report_inventory_changes`, `content_encoding`).

- [ ] **Step 3: Implement.**
  - **Dependencies:** workspace `flate2 = { version = "1.1.10", default-features = false, features = ["rust_backend"] }`; `flate2.workspace = true` in transport and testkit.
  - **`client.rs`:**
    - `const INVENTORY: &str = "/v1/inventory"; const CHANGES: &str = "/v1/inventory/changes";`
    - `report_inventory_changes` calls `self.post(changes, CHANGES).map(drop)`.
  - **In `send`:**
    - `let inventory = path == INVENTORY || path == CHANGES;`
    - the size check uses `inventory_document_bytes` for both paths;
    - for inventory paths, gzip the body (level 6) and check the compressed length against the same limit (`InvalidRequest` if over);
    - add `.header("content-encoding", "gzip")` for them;
    - before the status match:

```rust
        let resync = status == 409
            && path == CHANGES
            && body.as_ref().ok().and_then(|body| serde_json::from_slice::<PlatformError>(body).ok())
                .is_some_and(|error| error.validate(self.limits).is_ok()
                    && error.code == PlatformErrorCode::InventoryResync);
```

    - then the match arms `404 if path == CHANGES => Err(TransportError::NotFound)` and `409 if resync => Err(TransportError::InventoryResync)`, before the final `_`;
    - `fn gzip(bytes: &[u8]) -> Result<Vec<u8>, TransportError>` uses `flate2::write::GzEncoder` with `Compression::new(6)`; errors map to `InvalidRequest`;
    - add the two `Display` texts.

- [ ] **Step 4: Run.** `cargo test -p openvibes-transport && cargo test -p openvibes-testkit`. Expected: PASS.

- [ ] **Step 5: Docs and commit.**
  - `openvibes-transport.md`: the changes endpoint, gzip on both inventory paths, the two new errors.
  - `openvibes-testkit.md`: `content_encoding` and `decoded_body`.
  - Commit "Transport: gzip inventories, the P11 changes endpoint".

### Task 4: agent service: base, changes or full, fallbacks

**Files:**
- Modify: `crates/openvibes-agent/{src/service.rs,tests/service.rs}`, `docs/components/openvibes-agent.md`
- If `service.rs` passes 500 lines, move the inventory state and functions into `src/inventory.rs` (`pub(crate)`), keeping `Service`'s fields.

**Interfaces — Consumes:** Task 2's `inventory_fingerprint`, `hex`, `NormalizedPackage`, `inventory_changes`, `InventoryChanges`; Task 3's `report_inventory_changes`, `TransportError::{NotFound, InventoryResync}`, `Seen::decoded_body`.

Behaviour (Global Constraints). State added to `Service`:
- `inventory_base: Option<InventoryBase>`, with `#[derive(Serialize, Deserialize)] struct InventoryBase { os: OsRelease, running_kernel: Option<String>, packages: Vec<InstalledPackage> }`;
- `changes_unsupported: bool`.

Files in the state directory:
- `INVENTORY_BASE = "inventory-base.json"`, read bounded to `inventory_document_bytes + 1`;
- kept only if it parses, holds at most `inventory_items` packages, and its fingerprint equals the value in `inventory.sha256`.

- [ ] **Step 1: Update the existing tests for gzip.**
  - `requested()` returns `(seen.path.clone(), seen.decoded_body())`.
  - Other direct uses of `seen.body` that parse JSON move to `decoded_body()`.
  - Expect the existing inventory tests to still pass after Step 3. The first report is a full `/v1/inventory`, because there is no base yet.

- [ ] **Step 2: Failing tests** (append to `tests/service.rs`; all `#[cfg(target_os = "linux")]`, since they read the real package database):

```rust
use openvibes_core::{InstalledPackage, NormalizedPackage, OsRelease, hex, inventory_fingerprint};

/// Rewrites the stored base as if the host had one package less and one
/// more than now, with a matching `inventory.sha256`; returns the digest.
fn fake_base(state: &Path) -> (String, String, String) {
    let base: serde_json::Value =
        serde_json::from_slice(&fs::read(state.join("inventory-base.json")).unwrap()).unwrap();
    let os: OsRelease = serde_json::from_value(base["os"].clone()).unwrap();
    let kernel = base["running_kernel"].as_str().map(str::to_owned);
    let mut packages: Vec<InstalledPackage> = serde_json::from_value(base["packages"].clone()).unwrap();
    let dropped = packages.remove(0);
    packages.push(serde_json::from_value(serde_json::json!(
        {"manager": "rpm", "name": "openvibes-test-gone", "version": "1"})).unwrap());
    let digest = hex(&inventory_fingerprint(&os, kernel.as_deref(),
        packages.iter().map(NormalizedPackage::from)));
    fs::write(state.join("inventory-base.json"), serde_json::to_vec(&serde_json::json!(
        {"os": os, "running_kernel": kernel, "packages": packages})).unwrap()).unwrap();
    fs::write(state.join("inventory.sha256"), &digest).unwrap();
    (digest, dropped.name, "openvibes-test-gone".into())
}

#[cfg(target_os = "linux")]
#[test]
fn changes_follow_the_first_full_report() {
    let pki = Arc::new(Pki::new());
    let dir = scratch("inventory-changes");
    let (url, seen) = serve(pki.server_config(false, false), vec![
        issue(&pki, 10_000_000),
        Box::new(|_: &Seen| status(204)), // heartbeat
        Box::new(|_: &Seen| status(204)), // full inventory
        Box::new(|_: &Seen| status(204)), // heartbeat (restart)
        Box::new(|_: &Seen| status(204)), // changes
    ]);
    let config = write_config(&dir, &pki, &url, "");
    let state = dir.join("state");
    let mut service = Service::open(load_config(&config).unwrap()).unwrap();
    service.scan_if_due(0).unwrap();
    service.tick(0).unwrap();
    let first: Vec<String> = requested(&seen).into_iter().map(|(p, _)| p).collect();
    assert_eq!(first, ["/v1/enroll", "/v1/heartbeat", "/v1/inventory"]);
    assert!(state.join("inventory-base.json").exists(), "base kept after the 2xx");
    let real = fs::read_to_string(state.join("inventory.sha256")).unwrap();
    drop(service);
    let (base, dropped, gone) = fake_base(&state);
    let mut service = Service::open(load_config(&config).unwrap()).unwrap();
    service.scan_if_due(3_600_000).unwrap();
    service.tick(3_600_000).unwrap();
    let sent = requested(&seen);
    assert_eq!(sent.iter().map(|(p, _)| p.as_str()).collect::<Vec<_>>(), ["/v1/heartbeat", "/v1/inventory/changes"]);
    let changes: serde_json::Value = serde_json::from_slice(&sent[1].1).unwrap();
    assert_eq!(changes["base_sha256"], base.as_str());
    assert_eq!(changes["sha256"], real.trim());
    assert_eq!(changes["added"].as_array().unwrap().len(), 1);
    assert_eq!(changes["added"][0]["name"], dropped.as_str());
    assert_eq!(changes["removed"][0]["name"], gone.as_str());
    assert_eq!(fs::read_to_string(state.join("inventory.sha256")).unwrap().trim(), real.trim());
}

#[cfg(target_os = "linux")]
#[test]
fn a_resync_or_an_old_platform_gets_the_full_report() {
    let pki = Arc::new(Pki::new());
    let dir = scratch("inventory-resync");
    let resync = serde_json::json!({"schema_version": 1, "code": "inventory_resync"});
    let (url, seen) = serve(pki.server_config(false, false), vec![
        issue(&pki, 10_000_000),
        Box::new(|_: &Seen| status(204)), // heartbeat
        Box::new(|_: &Seen| status(204)), // full
        Box::new(|_: &Seen| status(204)), // heartbeat (restart)
        Box::new(move |_: &Seen| openvibes_testkit::Reply { status: 409, ..json(&resync) }),
        Box::new(|_: &Seen| status(204)), // full, same tick
        Box::new(|_: &Seen| status(204)), // heartbeat (restart)
        Box::new(|_: &Seen| status(404)), // changes: an older platform
        Box::new(|_: &Seen| status(204)), // full, same tick
    ]);
    let config = write_config(&dir, &pki, &url, "");
    let state = dir.join("state");
    let mut service = Service::open(load_config(&config).unwrap()).unwrap();
    service.scan_if_due(0).unwrap();
    service.tick(0).unwrap();
    let _ = requested(&seen);
    for at in [3_600_000, 7_200_000] {
        drop(service);
        let _ = fake_base(&state);
        service = Service::open(load_config(&config).unwrap()).unwrap();
        service.scan_if_due(at).unwrap();
        assert_eq!(service.tick(at).unwrap().inventory_error, None, "no error for a fallback");
        let paths: Vec<String> = requested(&seen).into_iter().map(|(p, _)| p).collect();
        assert_eq!(paths, ["/v1/heartbeat", "/v1/inventory/changes", "/v1/inventory"]);
    }
}
```

"404 remembered until restart" cannot be driven through the service without changing the host's packages while it runs, so it is a unit test of the decision. Keep the choice in a free function, `fn changes_to_send(unsupported: bool, base: Option<&InventoryBase>, acked: Option<&str>, pending: &PendingInventory, report: &InventoryReport) -> Option<InventoryChanges>`, and test it in `service.rs`'s (or `inventory.rs`'s) `#[cfg(test)]` module:
- with a base whose packages differ by one from `pending` and `acked` equal to the base's fingerprint, it returns `Some` when `unsupported` is `false` and `None` when it is `true`;
- it returns `None` when `acked` differs from the base's fingerprint.

```rust
#[cfg(target_os = "linux")]
#[test]
fn a_corrupt_base_means_a_full_report() {
    let pki = Arc::new(Pki::new());
    let dir = scratch("inventory-corrupt-base");
    let (url, seen) = serve(pki.server_config(false, false), vec![
        issue(&pki, 10_000_000),
        Box::new(|_: &Seen| status(204)), Box::new(|_: &Seen| status(204)), // heartbeat, full
        Box::new(|_: &Seen| status(204)), Box::new(|_: &Seen| status(204)), // heartbeat, full
    ]);
    let config = write_config(&dir, &pki, &url, "");
    let state = dir.join("state");
    let mut service = Service::open(load_config(&config).unwrap()).unwrap();
    service.scan_if_due(0).unwrap();
    service.tick(0).unwrap();
    let _ = requested(&seen);
    drop(service);
    fake_base(&state);
    fs::write(state.join("inventory-base.json"), b"{\"os\": trunc").unwrap();
    let mut service = Service::open(load_config(&config).unwrap()).unwrap();
    service.scan_if_due(3_600_000).unwrap();
    service.tick(3_600_000).unwrap();
    let paths: Vec<String> = requested(&seen).into_iter().map(|(p, _)| p).collect();
    assert_eq!(paths, ["/v1/heartbeat", "/v1/inventory"]);
}

#[cfg(target_os = "linux")]
#[test]
fn large_changes_are_sent_in_full_and_no_base_before_a_2xx() {
    let pki = Arc::new(Pki::new());
    let dir = scratch("inventory-large-changes");
    let (url, seen) = serve(pki.server_config(false, false), vec![
        issue(&pki, 10_000_000),
        Box::new(|_: &Seen| status(204)), Box::new(|_: &Seen| status(503)), // heartbeat, full fails
        Box::new(|_: &Seen| status(204)), Box::new(|_: &Seen| status(204)), // heartbeat, full
        Box::new(|_: &Seen| status(204)), Box::new(|_: &Seen| status(204)), // heartbeat (restart), full
    ]);
    let config = write_config(&dir, &pki, &url, "");
    let state = dir.join("state");
    let mut service = Service::open(load_config(&config).unwrap()).unwrap();
    service.scan_if_due(0).unwrap();
    service.tick(0).unwrap();
    assert!(!state.join("inventory-base.json").exists(), "no base without a 2xx");
    service.tick(60_000).unwrap();
    assert!(state.join("inventory-base.json").exists());
    drop(service);
    // A base with nothing in common with the host: changes > half the report.
    let base: serde_json::Value =
        serde_json::from_slice(&fs::read(state.join("inventory-base.json")).unwrap()).unwrap();
    let os: OsRelease = serde_json::from_value(base["os"].clone()).unwrap();
    let count = base["packages"].as_array().unwrap().len();
    let packages: Vec<InstalledPackage> = (0..count).map(|i| serde_json::from_value(serde_json::json!(
        {"manager": "rpm", "name": format!("other-{i}"), "version": "1"})).unwrap()).collect();
    let digest = hex(&inventory_fingerprint(&os, None, packages.iter().map(NormalizedPackage::from)));
    fs::write(state.join("inventory-base.json"), serde_json::to_vec(&serde_json::json!(
        {"os": os, "running_kernel": null, "packages": packages})).unwrap()).unwrap();
    fs::write(state.join("inventory.sha256"), &digest).unwrap();
    let _ = requested(&seen);
    let mut service = Service::open(load_config(&config).unwrap()).unwrap();
    service.scan_if_due(3_600_000).unwrap();
    service.tick(3_600_000).unwrap();
    let paths: Vec<String> = requested(&seen).into_iter().map(|(p, _)| p).collect();
    assert_eq!(paths, ["/v1/heartbeat", "/v1/inventory"]);
}
```

Run: `cargo test -p openvibes-agent --test service inventory`
Expected: FAIL. No base file is written yet; `/v1/inventory/changes` is never sent.

- [ ] **Step 3: Implement** in `service.rs` (or `src/inventory.rs`, as ruled):
  - **`refresh_inventory`:** the digest becomes `hex(&inventory_fingerprint(&os, running_kernel.as_deref(), packages.iter().map(NormalizedPackage::from)))`. Keep the sort, for a stable full report.
  - **`open`:** after reading the ack, `inventory_base = read_inventory_base(&state_dir.join(INVENTORY_BASE), inventory_acked.as_deref())`. This reads at most `inventory_document_bytes + 1` bytes, parses `InventoryBase`, checks `packages.len() <= inventory_items`, and recomputes the fingerprint; it returns `None` on any mismatch or error.
  - **`report_inventory`:** after the existing dedupe and back-off checks:

```rust
        let client = PlatformClient::new(transport, Some(&enrollment.identity));
        let full = |client: &PlatformClient| client.report_inventory(&report);
        let changes = changes_to_send(self.changes_unsupported, self.inventory_base.as_ref(),
            self.inventory_acked.as_deref(), pending, &report);
        let sent = client.and_then(|client| match changes {
            Some(changes) => match client.report_inventory_changes(&changes) {
                Err(TransportError::InventoryResync) => full(&client),
                Err(TransportError::NotFound) => {
                    self.changes_unsupported = true;
                    full(&client)
                }
                other => other,
            },
            None => full(&client),
        });
```

(If the borrow checker objects to assigning `self.changes_unsupported` inside the closure, return a flag from the closure and set the field after it.)

`changes_to_send` (the free function tested above; `report` supplies `agent_id`, `os`, kernel and time) returns `None` when:
- `changes_unsupported` is set;
- there is no base, or the acknowledged digest is absent;
- the changes are larger than half the full report, measured as `serde_json::to_vec(&changes).len() * 2 > serde_json::to_vec(report).len()`.

Otherwise it builds `InventoryChanges` from `inventory_changes(&base.packages, &pending.packages)`, with `base_sha256` = the acknowledged digest, `sha256` = `pending.sha256`, and the pending `os`, kernel and time.

On `Ok(())`:
1. write `inventory-base.json` with `write_private` from the pending inventory, then `inventory.sha256` as today;
2. set `inventory_base`.

Any other error keeps today's handling (refused / back-off).

- [ ] **Step 4: Run.** `cargo test -p openvibes-agent`. Expected: PASS: every existing test (gzip decoded in `requested`) and the four new ones.

- [ ] **Step 5: Docs, gate, PR.**
  - **Docs:** in `openvibes-agent.md`, the base file, the choice between changes and full, and the fallbacks.
  - **Gate:** `testing.md` §4 for the agent (fmt, clippy `-D warnings -F unsafe-code`, doc, `cargo test --locked --workspace --all-features`, `cargo audit --deny warnings`, with `flate2` new).
  - **Commit:** "Agent: send inventory changes after the first full report".
  - **PR:** push and open "Agent P11: inventory changes and gzip".
  - Merge only with the user's approval, after the protocol PR.

---

## Repository 3: openvibes-platform

### Task 5: repin; wire uses the contract fingerprint

**Files:**
- Modify: `Cargo.toml` (the three agent pins → Task 4's head, repinned to the agent merge commit before merging), `Cargo.lock`, `protocol` submodule → Task 1's commit, `crates/platform-store/src/{wire.rs,inventory.rs}`, `crates/openvibes-ingest/src/delivery.rs`, `crates/openvibes-admin/src/import.rs`, the ingest protocol-fixture test, `docs/specs/2026-09-27-inventory-changes-design.md` (§3 amended to the Global Constraints definition)

**Interfaces — Produces:**
- `PackageRow` derives `PartialOrd, Ord, Hash`.
- `PackageRow::normalized(&self) -> NormalizedPackage`.
- `impl From<&NormalizedPackage> for PackageRow`.
- `wire::inventory(os: &OsRelease, running_kernel: Option<&str>, packages: &[InstalledPackage]) -> Result<(Vec<PackageRow>, [u8; 32]), StoreError>`: rows are deduplicated normalized records; the digest is `inventory_fingerprint`.
- `wire::package_rows(packages: &[InstalledPackage]) -> Vec<PackageRow>`: deduplicated normalized.

- [ ] **Step 1: Failing test** in `wire.rs` tests, replacing `inventory_digest_ignores_package_order`:

```rust
    #[test]
    fn the_inventory_digest_is_the_contract_fingerprint() {
        let text = include_str!("../../../protocol/vectors/inventory-fingerprint.json");
        let vectors: Vec<serde_json::Value> = serde_json::from_str(text).unwrap();
        for vector in vectors {
            let inventory = &vector["inventory"];
            let os: OsRelease = serde_json::from_value(inventory["os"].clone()).unwrap();
            let packages: Vec<InstalledPackage> =
                serde_json::from_value(inventory["packages"].clone()).unwrap();
            let (rows, digest) = super::inventory(&os, inventory["running_kernel"].as_str(), &packages).unwrap();
            assert_eq!(openvibes_core::hex(&digest), vector["sha256"].as_str().unwrap());
            let again = openvibes_core::inventory_fingerprint(&os, inventory["running_kernel"].as_str(),
                rows.iter().map(PackageRow::normalized));
            assert_eq!(again, digest, "the stored rows give the same fingerprint");
        }
    }
```

Run: `cargo test -p platform-store --lib wire`. Expected: FAIL. The digest differs (old formula) and `normalized` is missing.

- [ ] **Step 2: Implement.**
  - **Repin:** agent rev → Task 4's head, then `cargo update -p openvibes-core -p openvibes-transport -p openvibes-rules`. Move the protocol submodule to Task 1's commit.
  - **`inventory.rs`:** `PackageRow` gains the derives, `normalized()` (epoch via `u32::try_from(self.epoch).unwrap_or(0)`) and `From<&NormalizedPackage>` (epoch via `i32::try_from(p.epoch).unwrap_or(0)`, the known ceiling).
  - **`wire.rs`:**
    - `package_rows` = `packages.iter().map(NormalizedPackage::from).collect::<BTreeSet<_>>().iter().map(PackageRow::from).collect()`;
    - `inventory` returns `(package_rows(packages), inventory_fingerprint(os, running_kernel, packages.iter().map(NormalizedPackage::from)))`.
  - **Callers:** update `delivery.rs` and `admin/src/import.rs` (no `&mut`).
  - **Ingest protocol-fixture test:** add `"inventory-changes" => accepts::<InventoryChanges>`.
  - **Spec:** amend §3 of the P11 spec to the exact definition, with the reason (the platform stores normalized records).

- [ ] **Step 3: Run.** `eval "$(scripts/test-db.sh)"; cargo test -p platform-store -p openvibes-ingest -p openvibes-admin`. Expected: PASS. Existing inventory tests store and compare rows; the digest change is invisible to them.

- [ ] **Step 4: Commit** "Store: the P11 inventory fingerprint; pin the P11 agent".

### Task 6: agent server: gzip bodies, the changes path, 409

**Files:**
- Modify: `crates/platform-agent-server/{Cargo.toml,src/request.rs,src/limits.rs,src/error.rs,src/lib.rs}`, `docs/components/platform-agent-server.md`

**Interfaces — Produces:**
- `pub const INVENTORY_PATHS: [&str; 2] = ["/v1/inventory", "/v1/inventory/changes"];`
- `body_limit(path)` returns `MAX_INVENTORY_BYTES` for both paths, and so does the inventory deadline in `bound`.
- `pub fn decoded_body<'a>(headers: &axum::http::HeaderMap, body: &'a [u8], limit: usize) -> Result<std::borrow::Cow<'a, [u8]>, ApiError>`
- `ApiError::Resync` → 409 with `PlatformError { code: InventoryResync }`.

- [ ] **Step 1: Failing tests** (in `request.rs`):

```rust
#[cfg(test)]
mod tests {
    use std::io::Write;

    use axum::http::{HeaderMap, HeaderValue, header::CONTENT_ENCODING};

    use super::{ApiError, decoded_body};

    fn gzip(bytes: &[u8]) -> Vec<u8> {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::new(6));
        encoder.write_all(bytes).unwrap();
        encoder.finish().unwrap()
    }

    fn encoded(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_ENCODING, HeaderValue::from_str(value).unwrap());
        headers
    }

    #[test]
    fn gzip_and_plain_bodies_are_read() {
        assert_eq!(&*decoded_body(&HeaderMap::new(), b"{}", 10).unwrap(), b"{}");
        assert_eq!(&*decoded_body(&encoded("identity"), b"{}", 10).unwrap(), b"{}");
        assert_eq!(&*decoded_body(&encoded("GZIP"), &gzip(b"{\"a\":1}"), 10).unwrap(), b"{\"a\":1}");
    }

    #[test]
    fn a_bomb_a_broken_stream_and_other_encodings_are_refused() {
        let bomb = gzip(&vec![0; 9 * 1024 * 1024]);
        assert!(bomb.len() < 64 * 1024, "small on the wire");
        assert_eq!(decoded_body(&encoded("gzip"), &bomb, 8 * 1024 * 1024).unwrap_err(), ApiError::BadRequest);
        assert_eq!(decoded_body(&encoded("gzip"), b"not gzip", 10).unwrap_err(), ApiError::BadRequest);
        assert_eq!(decoded_body(&encoded("br"), b"{}", 10).unwrap_err(), ApiError::BadRequest);
    }
}
```

(If `ApiError` lacks `PartialEq`/`Debug`, derive them in `error.rs`.)

Run: `cargo test -p platform-agent-server --lib request`. Expected: FAIL to compile.

- [ ] **Step 2: Implement.**
  - **Dependencies:** `flate2 = { version = "1.1.10", default-features = false, features = ["rust_backend"] }` in `platform-agent-server`.
  - **`request.rs`:**

```rust
/// An inventory body as sent: gzip (`Content-Encoding: gzip`, P11) or
/// plain. Decompresses as a stream and refuses more than `limit` bytes of
/// output, so a small body cannot make the server allocate more.
pub fn decoded_body<'a>(
    headers: &axum::http::HeaderMap,
    body: &'a [u8],
    limit: usize,
) -> Result<std::borrow::Cow<'a, [u8]>, ApiError> {
    use std::io::Read;
    let encoding = headers
        .get(axum::http::header::CONTENT_ENCODING)
        .map(|value| value.to_str().map_err(|_| ApiError::BadRequest))
        .transpose()?
        .map(str::trim);
    match encoding {
        None => Ok(body.into()),
        Some(value) if value.eq_ignore_ascii_case("identity") => Ok(body.into()),
        Some(value) if value.eq_ignore_ascii_case("gzip") => {
            let mut out = Vec::new();
            flate2::read::GzDecoder::new(body)
                .take(u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1))
                .read_to_end(&mut out)
                .map_err(|_| ApiError::BadRequest)?;
            if out.len() > limit {
                return Err(ApiError::BadRequest);
            }
            Ok(out.into())
        }
        Some(_) => Err(ApiError::BadRequest),
    }
}
```

  - `body_limit` uses `INVENTORY_PATHS.contains(&path)`.
  - `limits.rs` `bound`: the deadline check likewise.
  - `error.rs`: `Resync` → `(StatusCode::CONFLICT, Json(PlatformError { schema_version: V1, code: PlatformErrorCode::InventoryResync }))`.
  - `lib.rs`: re-export `decoded_body` and `INVENTORY_PATHS`.

- [ ] **Step 3: Run.** `cargo test -p platform-agent-server`. Expected: PASS.

- [ ] **Step 4: Docs and commit.** `platform-agent-server.md`: `decoded_body`, the two inventory paths, 409. Commit "Agent server: gzip inventory bodies, resync answer".

### Task 7: store and ingest: `POST /v1/inventory/changes`

**Files:**
- Modify: `crates/platform-store/src/inventory.rs` (split out the row writes shared with `replace`), `crates/openvibes-ingest/{Cargo.toml,src/delivery.rs,src/server.rs,tests/inventory.rs,tests/support/mod.rs}`, `docs/components/{openvibes-ingest.md,platform-store.md}`, `docs/sizing.md`

**Interfaces — Produces:**

```rust
// platform-store inventory.rs
pub enum ChangesOutcome { Stored, Resync }
#[allow(clippy::too_many_arguments)]
pub async fn apply_changes(client: &mut Client, agent_id: &str, os: &OsRelease, running_kernel: Option<&str>,
    added: &[PackageRow], removed: &[PackageRow], base: [u8; 32], expected: [u8; 32], now: DateTime<Utc>)
    -> Result<ChangesOutcome, StoreError>;
// ingest delivery.rs
pub(crate) async fn inventory_changes(State, AuthenticatedAgent, HeaderMap, Bytes) -> Result<StatusCode, ApiError>;
```

- [ ] **Step 1: Test helpers.**
  - `support/mod.rs`: rename the body of `raw_tls` to `raw_tls_with(…, extra_headers: &str)`, which inserts `extra_headers` (each ending in `\r\n`) after `Content-Type`; `raw_tls` calls it with `""`.
  - Add `World::raw_encoded(&self, path, body, encoding, client) -> Option<(u16, String)>`, which passes `format!("Content-Encoding: {encoding}\r\n")`.
  - Add `flate2` as a dev-dependency of `openvibes-ingest`.

- [ ] **Step 2: Failing tests** in `tests/inventory.rs` (they reuse `enrolled`, `package`, `report`, `send`, `stored`):

```rust
fn digest(report: &InventoryReport) -> String {
    openvibes_core::hex(&openvibes_core::inventory_fingerprint(
        &report.os,
        report.running_kernel.as_deref(),
        report.packages.iter().map(openvibes_core::NormalizedPackage::from),
    ))
}

fn changes(base: &InventoryReport, next: &InventoryReport) -> openvibes_core::InventoryChanges {
    let (added, removed) = openvibes_core::inventory_changes(&base.packages, &next.packages);
    openvibes_core::InventoryChanges {
        schema_version: SchemaVersion::V1,
        agent_id: next.agent_id.clone(),
        base_sha256: digest(base),
        sha256: digest(next),
        os: next.os.clone(),
        running_kernel: next.running_kernel.clone(),
        collected_at_unix_ms: next.collected_at_unix_ms,
        added,
        removed,
    }
}

async fn send_changes(world: &World, chain: &[String], key: &str,
    changes: openvibes_core::InventoryChanges) -> Result<(), TransportError> {
    let transport = world.transport();
    let (chain, key) = (chain.to_vec(), key.to_owned());
    blocking(move || {
        let identity = ClientIdentity::from_pem(&chain, &key).unwrap();
        PlatformClient::new(&transport, Some(&identity)).unwrap().report_inventory_changes(&changes)
    })
    .await
}

#[tokio::test]
async fn changes_are_applied_when_base_and_result_match() {
    let world = World::start().await;
    let (agent, chain, key) = enrolled(&world).await;
    let first = report(&agent, vec![package("bash", "5.2.37"), package("openssl", "3.5.1")]);
    send(&world, &chain, &key, first.clone()).await.unwrap();
    let next = report(&agent, vec![package("bash", "5.2.38"), package("openssl", "3.5.1")]);
    send_changes(&world, &chain, &key, changes(&first, &next)).await.unwrap();
    assert_eq!(stored(&world, &agent).await, ["bash-5.2.38", "openssl-3.5.1"]);
    let sha: Vec<u8> = world.db().await
        .query_one("SELECT inventory_sha256 FROM agents WHERE agent_id = $1", &[&agent])
        .await.unwrap().get(0);
    assert_eq!(openvibes_core::hex(&sha.try_into().unwrap()), digest(&next));
    world.stop().await;
}

#[tokio::test]
async fn a_wrong_base_or_result_is_a_resync_and_nothing_changes() {
    let world = World::start().await;
    let (agent, chain, key) = enrolled(&world).await;
    let first = report(&agent, vec![package("bash", "5.2.37")]);
    send(&world, &chain, &key, first.clone()).await.unwrap();
    let next = report(&agent, vec![package("bash", "5.2.38")]);
    let good = changes(&first, &next);
    let mut wrong_base = good.clone();
    wrong_base.base_sha256 = "0".repeat(64); // e.g. a digest stored before P11
    let mut wrong_result = good.clone();
    wrong_result.sha256 = "0".repeat(64);
    let mut missing = good.clone();
    missing.removed = vec![package("never-installed", "1")];
    let mut present = good.clone();
    present.added.push(package("bash", "5.2.37"));
    present.removed.clear();
    for bad in [wrong_base, wrong_result, missing, present] {
        assert_eq!(send_changes(&world, &chain, &key, bad).await, Err(TransportError::InventoryResync));
        assert_eq!(stored(&world, &agent).await, ["bash-5.2.37"]);
    }
    world.stop().await;
}

#[tokio::test]
async fn a_kernel_only_change_updates_the_running_kernel() {
    let world = World::start().await;
    let (agent, chain, key) = enrolled(&world).await;
    let mut first = report(&agent, vec![package("kernel-core", "6.17.7")]);
    first.running_kernel = Some("6.17.4-1.fc44.x86_64".into());
    send(&world, &chain, &key, first.clone()).await.unwrap();
    let mut next = first.clone();
    next.running_kernel = Some("6.17.7-1.fc44.x86_64".into());
    let set = changes(&first, &next);
    assert!(set.added.is_empty() && set.removed.is_empty());
    send_changes(&world, &chain, &key, set).await.unwrap();
    let kernel: Option<String> = world.db().await
        .query_one("SELECT running_kernel FROM agents WHERE agent_id = $1", &[&agent])
        .await.unwrap().get(0);
    assert_eq!(kernel.as_deref(), Some("6.17.7-1.fc44.x86_64"));
    world.stop().await;
}

#[tokio::test]
async fn plain_bodies_still_work_and_bombs_and_unknown_encodings_do_not() {
    use std::io::Write;
    let world = World::start().await;
    let (agent, chain, key) = enrolled(&world).await;
    let chain = chain.concat();
    let client = Some((chain.as_str(), key.as_str()));
    let plain = serde_json::to_vec(&report(&agent, vec![package("bash", "5.2.37")])).unwrap();
    assert_eq!(world.raw("/v1/inventory", &plain, client).await.map(|r| r.0), Some(204), "a pre-P11 agent");
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::new(6));
    encoder.write_all(&vec![b' '; 9 * 1024 * 1024]).unwrap();
    let bomb = encoder.finish().unwrap();
    for path in ["/v1/inventory", "/v1/inventory/changes"] {
        assert_eq!(world.raw_encoded(path, &bomb, "gzip", client).await.map(|r| r.0), Some(400), "{path}");
        assert_eq!(world.raw_encoded(path, &plain, "br", client).await.map(|r| r.0), Some(400), "{path}");
    }
    world.stop().await;
}
```

Also:
- extend the existing busy test (the one that fills the inventory slots and expects 503) so a request to `/v1/inventory/changes` is also refused while the slots are full;
- in `an_inventory_report_is_stored_and_replaced`, nothing changes: the real client now sends gzip, which covers "gzip accepted".

Run: `eval "$(scripts/test-db.sh)"; cargo test -p openvibes-ingest --test inventory`
Expected: the new tests FAIL. The changes endpoint answers 404 (`NotFound`), and the bomb gets 400 on `/v1/inventory` only by accident (JSON parse). Record which assertion fails.

- [ ] **Step 3: Implement.**
  - **`inventory.rs`:** move `replace`'s version insert and link insert into:
    - `async fn insert_versions(transaction: &Transaction<'_>, rows: &[PackageRow]) -> Result<(), StoreError>`;
    - `async fn link(transaction, agent_id, rows) -> Result<(), StoreError>`;
    - `async fn finish(transaction, agent_id, os_id, os_version, running_kernel, sha256, now)`, which does the `UPDATE agents`, `pg_notify` and commit.

    `replace` calls all three. Then:

```rust
/// Applies a change set (protocol P11) under the host's row lock: only if
/// the stored fingerprint is `base`, every removed row is present, every
/// added row absent, and the result's fingerprint is `expected`. Anything
/// else is `Resync` and nothing is written.
#[allow(clippy::too_many_arguments)]
pub async fn apply_changes(
    client: &mut Client,
    agent_id: &str,
    os: &OsRelease,
    running_kernel: Option<&str>,
    added: &[PackageRow],
    removed: &[PackageRow],
    base: [u8; 32],
    expected: [u8; 32],
    now: DateTime<Utc>,
) -> Result<ChangesOutcome, StoreError> {
    let transaction = client.transaction().await?;
    let stored: Option<Vec<u8>> = transaction
        .query_one("SELECT inventory_sha256 FROM agents WHERE agent_id = $1 FOR UPDATE", &[&agent_id])
        .await?
        .get(0);
    if stored.as_deref() != Some(base.as_slice()) {
        return Ok(ChangesOutcome::Resync);
    }
    let rows = transaction
        .query(
            "SELECT v.manager, v.name, v.epoch, v.version, v.release, v.arch, v.source, v.source_version
             FROM host_packages h JOIN package_versions v ON v.id = h.package_version_id
             WHERE h.agent_id = $1",
            &[&agent_id],
        )
        .await?;
    let mut set: BTreeSet<PackageRow> = rows
        .iter()
        .map(|row| PackageRow {
            manager: row.get(0), name: row.get(1), epoch: row.get(2), version: row.get(3),
            release: row.get(4), arch: row.get(5), source: row.get(6), source_version: row.get(7),
        })
        .collect();
    if !removed.iter().all(|row| set.remove(row)) || !added.iter().all(|row| set.insert(row.clone())) {
        return Ok(ChangesOutcome::Resync);
    }
    let result = openvibes_core::inventory_fingerprint(os, running_kernel, set.iter().map(PackageRow::normalized));
    if result != expected {
        return Ok(ChangesOutcome::Resync);
    }
    insert_versions(&transaction, added).await?;
    unlink(&transaction, agent_id, removed).await?;
    link(&transaction, agent_id, added).await?;
    finish(transaction, agent_id, os.id.as_str(), os.version_id.as_str(), running_kernel, expected, now).await?;
    Ok(ChangesOutcome::Stored)
}
```

  - **`unlink`:** `DELETE FROM host_packages h USING package_versions v, unnest($2::text[], $3::text[], $4::int[], $5::text[], $6::text[], $7::text[], $8::text[], $9::text[]) AS r(manager, name, epoch, version, release, arch, source, source_version) WHERE h.agent_id = $1 AND h.package_version_id = v.id AND (v.manager, v.name, v.epoch, v.version, v.release, v.arch) = (r.manager, r.name, r.epoch, r.version, r.release, r.arch) AND v.source IS NOT DISTINCT FROM r.source AND v.source_version IS NOT DISTINCT FROM r.source_version`, with the columns built as `replace` builds them.
  - **Dropping the transaction without committing rolls it back**, which covers every `Resync` return.
  - **`delivery.rs`:** the full handler gains `headers: HeaderMap` and parses `decoded_body(&headers, &body, MAX_INVENTORY_BYTES)?`. The new handler:

```rust
/// `POST /v1/inventory/changes` (protocol P11): applies a change set to the
/// authenticated agent's inventory, or answers 409 `inventory_resync`.
pub(crate) async fn inventory_changes(
    State(state): State<AppState>,
    AuthenticatedAgent(agent_id): AuthenticatedAgent,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, ApiError> {
    let body = platform_agent_server::decoded_body(&headers, &body, platform_agent_server::MAX_INVENTORY_BYTES)?;
    let changes: InventoryChanges =
        platform_agent_server::parse_with_limit(&body, platform_agent_server::MAX_INVENTORY_BYTES)?;
    if changes.agent_id.as_str() != agent_id {
        return Err(ApiError::BadRequest);
    }
    let (Some(base), Some(expected)) = (
        openvibes_core::digest_from_hex(&changes.base_sha256),
        openvibes_core::digest_from_hex(&changes.sha256),
    ) else {
        return Err(ApiError::BadRequest);
    };
    let mut client = state.pool.get().await.map_err(|_| ApiError::Unavailable)?;
    match inventory::apply_changes(
        &mut client,
        &agent_id,
        &changes.os,
        changes.running_kernel.as_deref(),
        &wire::package_rows(&changes.added),
        &wire::package_rows(&changes.removed),
        base,
        expected,
        Utc::now(),
    )
    .await?
    {
        inventory::ChangesOutcome::Stored => Ok(StatusCode::NO_CONTENT),
        inventory::ChangesOutcome::Resync => Err(ApiError::Resync),
    }
}
```

  - **`server.rs`:** route `/v1/inventory/changes` with the same `DefaultBodyLimit` and `inventory_slot` layers as `/v1/inventory`. Build both from one helper, `fn inventory_route(handler, state)`, so they cannot drift.

- [ ] **Step 4: Run.** `cargo test -p openvibes-ingest` (all test files) and `cargo test -p platform-store`. Expected: PASS.

- [ ] **Step 5: Docs and commit.**
  - `openvibes-ingest.md`: the route, 409, gzip, shared slots.
  - `platform-store.md`: `apply_changes`.
  - `docs/sizing.md`: the measured sizes from spec §1, and that a change set is a few KB.
  - Commit "Ingest: POST /v1/inventory/changes".

### Task 8: end to end, plan, gate, PR

**Files:**
- Modify: `scripts/systemd-e2e.sh`, `openvibes-protocol/PLAN.md` (P11 agent and platform ticked, in a small follow-up protocol commit or PR after both merge)

- [ ] **Step 1: e2e.** After the step `the agent's inventory is stored (protocol P8)`, add:

```bash
# P11: a package change reaches the platform as a change set, not a full
# report. `rpm -e --justdb` drops tar from the package database only (its
# files stay); the restarted agent scans at once and sends the difference.
in_c 'rpm -q tar' >/dev/null 2>&1 || fail "the e2e image has no tar package to remove"
in_c 'rpm -e --justdb --nodeps tar && systemctl restart openvibes-agent' || fail "change the agent's inventory"
wait_for "the agent sent inventory changes (protocol P11)" 120 \
    'journalctl -u openvibes-ingest -o cat | grep -q "\"endpoint\":\"/v1/inventory/changes\".*\"status\":204"'
[[ $($SQL "SELECT count(*) FROM host_packages h JOIN package_versions v ON v.id = h.package_version_id WHERE v.name = 'tar'") == 0 ]] ||
    fail "the platform still lists tar after the change set"
ok "a package change arrives as inventory changes"
```

If `tar` is not in the image, pick any package `rpm -qa` lists that no later step needs, and rule it in the ledger.

- [ ] **Step 2: Gate.** Rebase on `origin/main`, then run `testing.md` §2 in order (test DB, `build-console.sh`, fmt, `check-names.sh`, clippy, doc, `cargo test --locked --workspace --all-features`, `cargo audit --deny warnings`). The systemd e2e needs the full RPM set that CI builds: say so in the PR body and watch that job.

- [ ] **Step 3: PR.** Push `inventory-changes` and open "Platform P11: inventory changes and gzip".
  - Before asking to merge, repin the agent to the agent PR's merge commit once that merges (one commit, as with the M1 limits work).
  - Merge only with the user's approval, after protocol and agent.
  - Then tick P11 in the protocol's `PLAN.md` (a follow-up protocol PR).
