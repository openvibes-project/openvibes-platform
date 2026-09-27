# Larger inventories — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:executing-plans (native) or superpowers:subagent-driven-development. Steps use checkboxes.

**Goal:** Hosts with up to 50,000 packages send and export their inventory and keep their package facts; an inventory that cannot be sent is not retried every minute.

**Architecture:** Protocol first (two new V1 limits, schema `maxItems` 50,000), then the agent (limits, validation, collector cap, `package.names` exception, per-path transport body limit, no retry of a refused inventory), then the platform (8 MiB body on `/v1/inventory` only, at most 4 inventories at once, admin import of large inventory files).

**Tech Stack:** Rust (agent, platform), JSON Schema + Python validator (protocol), axum.

**Spec:** `docs/specs/2026-09-27-inventory-limits-design.md` (approved 2026-09-27).

## Global Constraints

- `inventory_items = 50_000`; `inventory_document_bytes = 8_388_608`. Every other V1 limit unchanged (`document_bytes` 1 MiB, `fact_list_items` 10,000).
- `inventory_items` applies to: `InventoryReport.packages`, `InventoryExport.packages`, `collect_packages`, and the `package.names` fact only.
- `inventory_document_bytes` applies to: the `/v1/inventory` request body (agent send, platform accept) and `InventoryExport` files (agent write, admin import). Nothing else.
- Platform: at most 4 inventory requests in progress; the fifth gets 503 (`Busy`).
- Agent: an inventory refused locally (over the limit / invalid) or by a 4xx is remembered by digest and not resent until the digest changes, logged once; network errors and 5xx are retried next tick.
- Order: protocol PR → agent PR (pins protocol) → platform PR (pins agent); each merged with the user's approval.
- Files under 500 lines; docs in the same PR; commits end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`; `CARGO_NET_GIT_FETCH_WITH_CLI=true`; agent checks with `--locked`.

## Review Focus

- A 503 from the platform (busy, the 4-inventory cap): the agent retries on the next tick and does **not** mark the inventory refused (Task 3 test with a mock answering 503 then 204).
- An inventory that shrinks back under the limit after being refused: its new digest is sent (Task 3 test).
- A findings or heartbeat body between 1 and 8 MiB: still refused on the agent and the platform (Task 3 transport test; Task 4 platform test).
- An 8 MiB inventory from 4+ agents at once: the fifth concurrent request gets 503 and memory stays bounded (Task 4 test).
- A `FindingExport` file between 1 and 8 MiB given to `openvibes-admin import`: refused as "larger than 1 MiB" (Task 4 test).

---

### Task 1: Protocol (openvibes-protocol)

**Files:** `schemas/v1/inventory-report.schema.json`, `schemas/v1/inventory-export.schema.json` (`packages.maxItems`), `spec/contracts-v1.md` (limits table, `InventoryReport` and `### Inventory Export` text), `tools/validate.py` (generated large documents), `PLAN.md`.

- [ ] **Step 1:** Branch `inventory-limits`. In `tools/validate.py`, inside `main()` just before the `print(f"{checked} fixtures checked…")` line, add a generated check (no multi-MB fixtures in git):

```python
    # Generated, not checked in: inventories at the package limits.
    base = json.loads((ROOT / "fixtures/v1/inventory-report/valid.json").read_text())
    report = Draft202012Validator(schemas["inventory-report"], registry=registry)
    for count, expect_valid in [(10_001, True), (50_000, True), (50_001, False)]:
        document = dict(base, packages=[dict(base["packages"][0], name=f"p{i}") for i in range(count)])
        valid = report.is_valid(document)
        checked += 1
        if valid != expect_valid:
            print(f"FAIL generated inventory-report with {count} packages: valid={valid}")
            failures += 1
```

- [ ] **Step 2:** `python3 tools/validate.py` (venv from `tools/requirements.txt`) → FAIL: 10,001 and 50,000 invalid.
- [ ] **Step 3:** Set `"maxItems": 50000` for `packages` in both inventory schemas. In `contracts-v1.md`: the limits table gains `inventory_items | 50,000 | packages in InventoryReport and InventoryExport, and the package.names fact` and `inventory_document_bytes | 8 MiB | one InventoryReport body or InventoryExport file`; the inventory texts say "up to 50,000 packages" and "bounded by `inventory_document_bytes` (8 MiB) instead of the 1 MiB document limit"; add: "A platform may answer 503 when it is busy; an agent retries then. A refused inventory (4xx) is not resent until it changes." `PLAN.md`: under P8 add `- [x] Larger inventories: 50,000 packages, 8 MiB (M1 limits review, 2026-09-27).`
- [ ] **Step 4:** `python3 tools/validate.py` → all pass.
- [ ] **Step 5:** Commit `Larger inventories: 50,000 packages, 8 MiB`; push; PR; user approval; merge.

### Task 2: Agent limits and validation (openvibes-agent, `openvibes-core`)

**Files:** `crates/openvibes-core/src/limits.rs`, `src/export.rs` (`InventoryReport`, `InventoryExport` validate), `src/contracts.rs` (`validate_fact`), tests in `crates/openvibes-core/tests/` (the existing limits test file; `grep -ln fact_list_items crates/openvibes-core/tests`), `protocol` submodule → Task 1 merge.

**Interfaces — Produces:** `ResourceLimits::V1.inventory_items: usize = 50_000`, `ResourceLimits::V1.inventory_document_bytes: usize = 8_388_608`; `pub const PACKAGE_NAMES: &str = "package.names"` in `openvibes-core` (used by the collector and `validate_fact`).

- [ ] **Step 1:** Branch `inventory-limits`; pin the submodule. Tests:

```rust
#[test]
fn inventories_take_up_to_50000_packages() {
    let package: InstalledPackage =
        serde_json::from_str(r#"{"manager":"rpm","name":"p","version":"1"}"#).unwrap();
    let mut report: InventoryReport = serde_json::from_str(
        r#"{"schema_version":1,"agent_id":"agent.1","os":{"id":"fedora","version_id":"44"},"collected_at_unix_ms":1,"packages":[]}"#,
    ).unwrap();
    report.packages = vec![package.clone(); 50_000];
    report.validate(ResourceLimits::V1).unwrap();
    report.packages.push(package);
    assert!(report.validate(ResourceLimits::V1).is_err());
}

#[test]
fn package_names_is_the_only_fact_list_above_10000() {
    let names: Vec<String> = (0..20_000).map(|i| format!("p{i:05}")).collect();
    let set = |key: &str| FactSet {
        schema_version: SchemaVersion::V1,
        scan_id: Identifier::new("scan.1").unwrap(),
        collected_at_unix_ms: 1,
        facts: vec![Fact {
            key: Identifier::new(key).unwrap(),
            source: Identifier::new("packages").unwrap(),
            value: FactValue::StringList(names.clone()),
        }],
        errors: Vec::new(),
    };
    assert!(set("package.names").validate(ResourceLimits::V1).is_ok());
    assert!(set("process.names").validate(ResourceLimits::V1).is_err());
}
```

Also the `InventoryExport` twin of the first test: the same body parsed as an `InventoryExport` (`install_id` instead of `agent_id`, plus `scanner_version`).
- [ ] **Step 2:** `cargo test --locked -p openvibes-core` → FAIL (no field / 10,001 refused).
- [ ] **Step 3:** Add the two fields to `ResourceLimits` (doc comments: "Packages in one inventory (protocol P8, M1 review)", "Bytes of one inventory body or export file"), values in `V1`. `InventoryReport`/`InventoryExport` validate: `self.packages.len() > limits.inventory_items`. `validate_fact`: `let max = if fact.key.as_str() == PACKAGE_NAMES { limits.inventory_items } else { limits.fact_list_items };`. Any place that checks `limits ≤ V1` field by field (`grep -rn 'V1\.' crates/*/src`) includes the new fields.
- [ ] **Step 4:** `cargo test --locked --workspace` → PASS (fixtures included).
- [ ] **Step 5:** Commit `Core: inventory limits (50,000 packages, 8 MiB)`.

### Task 3: Agent collector, transport, service, export

**Files:** `crates/openvibes-collectors/src/packages.rs` (cap), `crates/openvibes-transport/src/client.rs` (per-path body limit; 5xx → `Unavailable`), `crates/openvibes-agent/src/service.rs` (refused inventory not resent; export limit), tests: `crates/openvibes-collectors/tests/` (packages), `crates/openvibes-transport/tests/platform.rs`, `crates/openvibes-agent/tests/` (inventory send against the testkit mock platform; find the existing inventory test with `grep -ln report_inventory crates/openvibes-agent/tests`).

**Interfaces — Produces:** `TransportError::Unavailable` (5xx); `Rejected` now means non-2xx other than 401/403 and 5xx.

- [ ] **Step 1:** Tests:
  - collectors: a synthetic dpkg status with 11,000 packages (the dpkg parser's test helper writes a status file; reuse it) → `collect_packages` Ok with 11,000; `package_facts` gives `package.names` with 11,000 entries.
  - transport: against the mock platform, `report_inventory` with a 2 MB body is sent (mock records it); `deliver` of a findings batch serialising over 1 MiB is refused locally (`InvalidRequest`); a mock answering 503 yields `Unavailable`, 400 yields `Rejected`.
  - agent: mock answers 400 to `/v1/inventory` → first tick sends once, next two ticks send nothing; after the inventory changes (new package in the synthetic source, or by setting the pending inventory in the test) it is sent again. Mock answers 503 then 204 → sent on tick 1 and tick 2, acked after tick 2.
  - agent export: an inventory of 9,000 synthetic packages (~1.2 MB) is written.
- [ ] **Step 2:** Run each → FAIL.
- [ ] **Step 3:** Implement:
  - `collect_packages`: `packages.len() > limits.inventory_items`.
  - transport `send(request, path)`: `let max = if path == "/v1/inventory" { self.limits.inventory_document_bytes } else { self.limits.document_bytes };` for the request body; response body limit stays `document_bytes`. Status mapping: `500..=599 => Err(TransportError::Unavailable)` before the catch-all. Update every `match` on `TransportError` in the agent (`grep -rn 'TransportError::Rejected' crates`) so `Unavailable` is handled like `Rejected` was for delivery backoff (transient), and document the variant.
  - service `report_inventory`: new field `inventory_refused: Option<String>` (digest); skip when `== Some(pending.sha256)`; on `Err(InvalidRequest | Rejected)` set it and log once (`eprintln!` as the service logs today: "openvibes-agent: the platform refused this inventory (N packages); it is sent again when it changes"); on other errors return the error as today (retried next tick).
  - export: `write_export` takes a `max_bytes` argument; inventory uses `inventory_document_bytes`, findings `document_bytes`; the "exceeds the 1 MiB document limit" message names the right limit.
- [ ] **Step 4:** `cargo fmt --all --check && cargo clippy --locked --workspace --all-targets --all-features -- -D warnings -F unsafe-code && cargo test --locked --workspace --all-features` → PASS.
- [ ] **Step 5:** Docs: `docs/components/openvibes-collectors.md`, `openvibes-transport.md`, `openvibes-agent.md` (limits and the no-retry rule); `docs/plan/initial-implementation.md` M1: tick "Review the concrete limits against representative endpoint inventories" with a one-line result. Commit `Agent: inventories up to 50,000 packages; no retry of a refused inventory`; push; PR; user approval; merge.

### Task 4: Platform (openvibes-platform)

**Files:** `crates/platform-agent-server/src/{request.rs, limits.rs, serve.rs}`, `crates/openvibes-ingest/src/{server.rs, delivery.rs}` (inventory route limit and semaphore), `crates/openvibes-admin/src/import.rs`, tests in `crates/openvibes-ingest/tests/` (the inventory delivery test file), `crates/platform-store/tests/inventory.rs`, `crates/openvibes-admin/tests/import.rs`; `Cargo.toml` agent pin → Task 3 merge.

**Interfaces — Produces:** `platform_agent_server::MAX_INVENTORY_BYTES: usize = 8 * 1024 * 1024`; `parse_with_limit<T>(body, limit)`; ingest `AppState.inventory_slots: Arc<Semaphore>` (4).

- [ ] **Step 1:** Tests:
  - ingest: an authenticated `/v1/inventory` with ~7 MB (52,000 packages would exceed; use 45,000 packages with long names to reach ~7 MB) → 204 and stored; 8 MiB + 1 declared → 400; `/v1/findings` with 1 MiB + 1 → 400 (unchanged); with the 4 slots held (test hook: acquire the semaphore from the test's `AppState`), `/v1/inventory` → 503.
  - store: `inventory::replace` with 50,000 packages → `Stored`, `host_packages` count 50,000.
  - admin import: a 5 MB `InventoryExport` file → `inventory accepted (N packages)`; a 2 MB `FindingExport` → `refused: larger than 1 MiB`.
- [ ] **Step 2:** Run → FAIL.
- [ ] **Step 3:** Implement:
  - `request.rs`: `pub const MAX_INVENTORY_BYTES`; `parse_with_limit(body, limit)`; `parse` calls it with `MAX_BODY_BYTES`.
  - `limits.rs` `bound`: `let max = if request.uri().path() == "/v1/inventory" { MAX_INVENTORY_BYTES } else { MAX_BODY_BYTES };` for the declared length.
  - `serve.rs`: keep `DefaultBodyLimit::max(MAX_BODY_BYTES)` globally; in ingest `server.rs`, `.route("/v1/inventory", post(...).layer(DefaultBodyLimit::max(MAX_INVENTORY_BYTES)))` so only that route reads up to 8 MiB.
  - `delivery.rs::inventory`: `let _slot = state.inventory_slots.clone().try_acquire_owned().map_err(|_| ApiError::Busy)?;` first; `parse_with_limit(&body, MAX_INVENTORY_BYTES)`.
  - `import.rs`: read cap `ResourceLimits::V1.inventory_document_bytes`; after kind detection, a `FindingExport` whose bytes exceed `document_bytes` → `larger than 1 MiB`; an `InventoryExport` over `inventory_document_bytes` → `larger than 8 MiB`.
- [ ] **Step 4:** `eval "$(scripts/test-db.sh)"; cargo test -q --workspace` and clippy → PASS.
- [ ] **Step 5:** Docs: `platform-agent-server.md` (per-route limit), `openvibes-ingest.md` (inventory limit, 4 at once, 503), `openvibes-admin.md` (import sizes), `docs/sizing.md` (50,000-package hosts). Commit `Ingest and import: inventories up to 8 MiB, 4 at once`; push; PR; user approval; merge. Workspace `status.md`/`decisions.md`; board: M1 limits review done.
