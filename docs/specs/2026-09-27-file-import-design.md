# File import (protocol P3b) — design

Status: approved by the user, 2026-09-27. Platform sub-project 3
(architecture §9). Server side of the local-only route (protocol P3,
contracts `Local-Only Export`).

## 1. Decisions (the user, 2026-09-27)

- An imported host gets **findings and vulnerability matching**, like an
  enrolled host. `InventoryExport` therefore gains the operating system
  (protocol change first).
- Operators import with **`openvibes-admin import`** on the platform host,
  not through a network endpoint. The architecture's "ingest: later file
  import" moves to the admin CLI.
- An imported host is **its own host, keyed by `install_id`**, marked
  imported everywhere. A claimed `agent_id` in a file is a label only; an
  import never updates or authenticates an enrolled agent (decision
  2026-09-23, "Export provenance").

Out of scope: linking an imported host to the same machine after it
enrolls (enrollment carries no `install_id`), signed exports (a later
schema version), a watched drop directory, an import endpoint.

## 2. Protocol change (openvibes-protocol, first)

`InventoryExport` gains two optional fields, with the same shape and
rules as in `InventoryReport`:

- `os`: `{ id, version_id }` from os-release;
- `running_kernel`: `uname -r`, pattern `^[A-Za-z0-9._+~^-]{1,128}$`.

Both optional so files from agents before this change stay valid. The
contracts document gains the import rules:

- One imported host per `install_id`.
- Findings are idempotent on `finding_id` (existing rule).
- The inventory with the newest `collected_at_unix_ms` wins; an older or
  equal one is ignored, so importing files in any order gives the same
  result.
- An inventory without `os` is stored but not matched for
  vulnerabilities.
- `agent_id` and `hostname` in a file are labels, never identity.

New fixtures: `inventory-export/valid-os.json` (with `os` and
`running_kernel`), `invalid-os-missing-version.json`,
`invalid-bad-kernel.json`. The agent's `export` writes both fields from
the same collection the online inventory report uses (agent PR, pin the
new protocol commit).

## 3. Storage (migration 0015)

Imported hosts are rows in `agents`, so everything keyed by agent
(current findings, `host_packages`, `vulnerabilities`,
`host_vulnerability_counts`, `agent list`, the console) works unchanged.

- `agents.status` also allows `imported`; `agent_id` also allows
  `^import\.[A-Za-z0-9._:-]{1,128}$` (`import.` + the `install_id`).
- New nullable column `claimed_agent_id text`: the `agent_id` a file
  named, shown as a label.
- For an imported row: `enrolled_at` = first import time, `last_seen_at`
  = the newest file time (`exported_at` or `collected_at`),
  `scanner_version` and `hostname` from the newest file.
- An imported row has no certificates and no token uses. Agent
  authentication maps a certificate's SAN to an `agent.<uuid>` id, so an
  `import.` row can never authenticate, renew, fetch rules, or be
  revoked. Ingest and distribution need no change.

Migration numbering: console PR #29 also adds migrations. Whichever
merges second renumbers its own files.

## 4. `openvibes-admin import PATH...`

- `PATH` is a file or a directory; a directory imports its `*.json`
  files (not recursive), in name order.
- Per file: refuse above 1 MiB before reading it all; decode JSON; tell
  the kind by its members (`findings` → `FindingExport`, `packages` →
  `InventoryExport`); validate with the same protocol types and limits as
  `FindingBatch` and `InventoryReport` (schema version, identifiers, NUL
  refusal, counts, bounds).
- **FindingExport:** upsert the imported `agents` row; store findings
  through the same store code as online delivery with `origin = 'import'`
  and `authenticated = false`; update current findings the same way.
  Findings already present are counted, not re-stored.
- **InventoryExport:** upsert the row; if newer than the stored
  inventory, replace `host_packages`, set `os_id`/`os_version_id` and
  `running_kernel`, and `NOTIFY inventory_changed` so `openvibes-vulns`
  matches the host (within a second, as online).
- Each file is one transaction; a refused file does not stop the others.
- Output: one line per file, e.g.
  `openvibes-export-…json: imported 12 findings (3 already present)`,
  `…: inventory accepted (412 packages)`, `…: older inventory ignored`,
  `…: refused: <reason>`; then a total. Exit code 1 if any file was
  refused, else 0.
- One `audit_log` entry per run: the paths, and counts of files, findings,
  inventories and refusals.
- Runs as the admin database role; no new role or privilege.

## 5. Visibility

- `agent list` shows imported hosts with status `imported` and their
  claimed `agent_id` if any; `agent list --imported` shows only them.
- `agent show ID` works for `import.` ids.
- `agent revoke` on an imported host is refused: "imported hosts have no
  identity to revoke".
- `vulns summary|list|show` include imported hosts unchanged.
- Note for Codex (console): `agents.status` has a third value,
  `imported`, and `claimed_agent_id` exists.

## 6. Failure behaviour

- Invalid, oversized, unknown-kind or unreadable files are refused with a
  reason; nothing from that file is stored.
- A database error aborts that file's transaction and the run continues;
  the error counts as a refusal.
- Re-running an import is always safe (idempotent findings, newest-wins
  inventory).

## 7. Testing

- Protocol: fixtures validated by the protocol's schema tool and by the
  agent's and platform's fixture tests.
- Store (PostgreSQL): re-import stores nothing new; an older inventory is
  ignored and a newer one replaces; a file claiming an enrolled
  `agent_id` leaves that agent, its findings and inventory untouched;
  an inventory without `os` is stored and not matched.
- Admin CLI integration: mixed directory (good, oversized, invalid,
  unknown kind) gives the expected lines and exit code 1; audit entry
  written; `agent revoke import.…` refused.
- End to end under systemd (existing CI job): a local-only agent runs
  `export`, the files are imported, and `vulns list --host import.…`
  shows an open vulnerability from the offline feed.

## 8. Delivery

1. Protocol PR: schema fields, contract text, fixtures, `PLAN.md` P3b.
2. Agent PR: export writes `os` and `running_kernel`; pin protocol.
3. Platform PR: this spec, plan, migration 0015, store, CLI, docs
   (`docs/components/openvibes-admin.md`, platform-store page), e2e step;
   pin agent.

Each merges with the user's approval.
