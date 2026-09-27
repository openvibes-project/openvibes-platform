# Inventory changes and compression (protocol P11) — design

Status: idea approved by the user, 2026-09-27 ("send changes after the
first time, keep full visibility"); written spec awaiting review. Builds on
the larger inventory limits (`2026-09-27-inventory-limits-design.md`),
which stay: the first report and every full resend must still fit.

## 1. Why

Agents already send an inventory only when it changes, but then send all
of it. Measured on a Fedora 44 workstation (3,613 packages):

| Sent | Size |
|---|---|
| full inventory today | 472 KB |
| full inventory, gzip | 45 KB |
| changes after a 150-package `dnf upgrade` | about 35 KB, a few KB with gzip |
| changes after one package update | 0.4 KB |

A TeX Live workstation's full inventory is several MB. Changes plus
compression make every report after the first small, on the wire and in
the platform's work, without the platform ever holding less than the full
list.

## 2. Decisions

- **The platform always holds the complete list.** Changes are applied to
  it and checked against the agent's fingerprint; any mismatch makes the
  agent send the full list once. Visibility never depends on deltas being
  right.
- **Changes are a new endpoint, `POST /v1/inventory/changes`**; the full
  report stays `POST /v1/inventory`, unchanged. An older platform answers
  404 to the new endpoint and the agent falls back to full reports.
- **Compression is `Content-Encoding: gzip`** on both inventory endpoints,
  always used by agents that support P11; the platform also accepts
  uncompressed bodies (older agents).
- **Export files stay full and uncompressed** (offline import, readable by
  people).
- Findings, heartbeats and rule bundles are unchanged ("fewer repeat
  findings" is a separate roadmap item).

## 3. The fingerprint (a contract)

Today the agent and the platform each compute an inventory digest the same
way in code; P11 makes it a contract, because both sides must agree byte
for byte:

`sha256` = SHA-256 of the compact JSON array `[os, running_kernel,
packages]`, where `running_kernel` is `null` when absent and `packages` is
sorted by each package's own compact JSON text, members in schema order,
absent optional members omitted. Test vectors (inventory → hex digest) are
fixtures in the protocol repository.

## 4. `InventoryChanges` (new document)

```json
{
  "schema_version": 1,
  "agent_id": "agent.…",
  "base_sha256": "…",
  "sha256": "…",
  "os": {"id": "fedora", "version_id": "44"},
  "running_kernel": "6.17.4-300.fc44.x86_64",
  "collected_at_unix_ms": 1790000000000,
  "added": [ { package as in InventoryReport } ],
  "removed": [ { package as in InventoryReport } ]
}
```

- `base_sha256`: the fingerprint of the last inventory the platform
  acknowledged for this agent; `sha256`: the fingerprint after applying the
  changes. `os` and `running_kernel` are always sent (tiny), so an OS or
  kernel change needs no special case.
- A package is identified by its whole record: an update is one `removed`
  (old version) and one `added` (new version). `added` + `removed` together
  at most `inventory_items`; body at most `inventory_document_bytes`.

**Platform:** under the host's row lock, if the stored digest equals
`base_sha256`, apply the changes to the stored package set, compute the
fingerprint of the result, and store it (same path as a full report,
including the `inventory_changed` notification) only if it equals
`sha256`. Otherwise answer **409** with `PlatformError` code
`inventory_resync`; nothing is stored. A `removed` package the host does not
have, or an `added` one it already has, is also a resync.

**Agent:** keeps the last acknowledged inventory (the package list and its
fingerprint) in its state directory, private, next to today's
`inventory.sha256`. When the inventory changes it sends changes if it has an
acknowledged base, else the full report. It sends the full report instead
when the platform answers 409 (`inventory_resync`) or 404 (an older
platform: remembered until restart), or when the changes would be larger
than half of the full report (cheaper and simpler to resend).

## 5. Compression limits

- Agent: gzip level 6; a compressed body is at most
  `inventory_document_bytes` before compression and after.
- Platform: decompresses as a stream and refuses (400) a body that expands
  past `inventory_document_bytes` (8 MiB) or whose compressed size exceeds
  it; the 4-at-once inventory limit counts both endpoints. So a small
  compressed body cannot make the platform allocate more than 8 MiB.
- New dependency: `flate2` with the pure-Rust `miniz_oxide` backend, in the
  agent's transport and the platform's agent server.

## 6. Testing

- Protocol: `InventoryChanges` schema fixtures; fingerprint test vectors.
- Agent: fingerprint matches the vectors; changes computed from two
  inventories (update, add, remove, OS change); full report on no base, on
  409, on 404, and when changes exceed half; gzip bodies; the stored base
  survives a restart and is written only after an acknowledgement.
- Platform: changes applied with matching base and result (stored,
  notified); wrong base, wrong result, removing a missing package → 409 and
  nothing stored; gzip accepted, a gzip bomb (small body expanding past
  8 MiB) refused with 400; uncompressed full reports still accepted.
- End to end (systemd): an agent updates a package in its container and
  the platform's inventory follows through `/v1/inventory/changes`.

## 7. Delivery

After the larger-limits work: protocol P11 PR → agent PR → platform PR,
each merged with the user's approval. Platform first is also safe: agents
without P11 keep sending full reports.
