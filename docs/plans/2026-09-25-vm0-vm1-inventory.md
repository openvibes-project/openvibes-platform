# VM0–VM1: Inventory Reports — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:executing-plans (native, as for SP2 and M6a). Steps use checkboxes.

**Goal:** Agents report OS and package inventory on change; ingest stores it compactly and notifies. VM2 (matching) builds on this.

**Architecture:** Protocol P8 first (`InventoryReport`, `POST /v1/inventory`), then the agent (os-release collector, change detection, send), then the platform (migration, store module, ingest route, NOTIFY).

**Spec:** `docs/specs/2026-09-25-vulnerability-management-design.md` §4–§6.

## Global Constraints

- Protocol first; agent and platform pin the merged protocol.
- Limits: 10,000 packages, 1 MiB document; identifiers bounded as V1.
- Agent sends only when the canonical SHA-256 of (os, sorted packages) differs from the last acknowledged one; never local-only; never without `packages`.
- Platform: next free migration number at merge; `openvibes_ingest` gains only the rights it uses (insert/select on `package_versions`, insert/delete/select on `host_packages`, update of the new `agents` columns).
- Commits end with the Claude co-author trailer; component docs updated in the same change.

## Review Focus

- A report for another agent: 400, nothing stored (Task 4 test).
- Identical report twice: second is a no-op, no NOTIFY (Task 4 test).
- Kernel-style duplicates (same name, several versions installed): all stored (Task 3 test).
- An agent whose first send fails: retried next tick, not lost (Task 2 test).
- 10,000-package report under 1 MiB accepted; 10,001 refused (Task 1 fixtures, Task 4 test).

### Task 1 (VM0): Protocol P8
- [ ] Fixtures first under `fixtures/v1/inventory-report/`: `valid.json`, `valid-no-packages.json`, `invalid-missing-os.json`, `invalid-os-id-with-space.json`, `invalid-negative-time.json`; validator fails on the schema's absence (RED).
- [ ] `schemas/v1/inventory-report.schema.json` reusing `InstalledPackage` from the inventory-export schema; spec section "Inventory report"; route table row; PLAN.md P8. `python3 tools/validate.py` green. PR, merge on the user's approval.

### Task 2 (VM0): Agent
- [ ] `openvibes-core`: `InventoryReport` and `OsRelease` types with `Validate`; fixture test covers `inventory-report` (RED on missing type, GREEN).
- [ ] `openvibes-collectors::os_release()` with parser tests (quotes, comments, missing keys, fallback path).
- [ ] Transport `PlatformClient::report_inventory`.
- [ ] Service: after a scan with packages enabled, compute hash; in tick, send if differs from the stored acknowledged hash (state directory file `inventory.sha256`, 0600); store on 2xx; retry otherwise. Tests with the testkit: sends once, not again unchanged, again after a change, retries after 503, never local-only, never without packages. Heartbeat capability `inventory.packages`.
- [ ] Measure hash cost on this host; docs.

### Task 3 (VM1): Store
- [ ] Migration (next number): columns on `agents`, `package_versions`, `host_packages`, grants. Store tests as `openvibes_ingest` (RED first): replace inventory, duplicates (kernels), identical skipped, role rights.
- [ ] `platform_store::inventory::{replace, InventoryOutcome::{Stored, Unchanged}}` with `NOTIFY inventory_changed`.

### Task 4 (VM1): Ingest route
- [ ] `/v1/inventory` tests first: 204 stored, 204 unchanged, 400 other agent, 400 over limit, 401/403 as other routes, NOTIFY observed by a listener.
- [ ] Route, docs (`openvibes-ingest.md`, `platform-store.md`), pin bump to the agent merge, integration: the real agent's inventory arrives (`scripts/integration-agent.sh` check: `host_packages` count > 100 for the agent).
