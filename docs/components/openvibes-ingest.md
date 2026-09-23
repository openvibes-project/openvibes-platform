# openvibes-ingest

The agent-facing, receive-only service on port **18423** (protocol P1 and
P2). Design: [`../specs/2026-09-23-ingest-subproject-design.md`](../specs/2026-09-23-ingest-subproject-design.md),
sections 3 and 6.

## Run

`openvibes-ingest [--config /etc/openvibes/ingest.toml]`. Logs are JSON on
stderr (journald).

## Configuration

Strict TOML (unknown keys refused), absolute paths only:

| Key | Default | Range |
|---|---|---|
| `listen` | required | agent-facing TLS address |
| `health_listen` | required | loopback address for `/health`, `/ready` |
| `server_certificate_file`, `server_key_file` | required | server chain (leaf first) and key |
| `client_ca_file` | required | CA whose client certificates are accepted |
| `issuing_certificate_file`, `issuing_key_file` | required | intermediate that signs agent certificates |
| `database_url` | required | the `openvibes_ingest` role |
| `client_certificate_days` | 30 | 1 to 365 |
| `max_in_flight` | 4096 | at least 1 |
| `finding_retention_days` | 90 | 1 to 36500; match `openvibes-admin maintenance` |
| `request_timeout_seconds` | 10 | 1 to 300; TLS handshake and request headers |

## TLS and authentication

- TLS 1.3 only (ring). ALPN `http/1.1`. No redirects anywhere.
- A client certificate is optional at the handshake (enrollment has none),
  but one that does not chain to `client_ca_file` fails the handshake.
- Authenticated endpoints need a certificate whose **serial and key hash**
  are recorded for an agent: unknown → 401; agent revoked → 403 with
  `PlatformError { identity_revoked }` (the only source of that code).

## Enrollment and renewal

- `POST /v1/enroll` (no client certificate): `EnrollmentRequest`. The token
  is hashed with `platform_pki::enrollment_token_sha256`; unknown, expired,
  revoked, malformed, or used-up tokens → 401. The CSR must pass
  `check_csr` (P-256, empty subject, valid signature) → else 400. A retry
  with the same token and the same key returns the same identity and chain.
  Response: `EnrollmentResponse` with `agent.<uuid>`, leaf + intermediate,
  and the leaf expiry.
- `POST /v1/renew` (authenticated): `RenewalRequest`; issues a certificate
  for the requesting agent's own id and records it. Earlier certificates
  keep working until they expire. A revoked agent gets `identity_revoked`.

## Heartbeats and findings

- `POST /v1/heartbeat` (authenticated): `Heartbeat`; its `agent_id` must be
  the authenticated agent's (else 400). Stores version and capabilities,
  writing `last_seen_at` at most every 5 minutes. 204.
- `POST /v1/findings` (authenticated): `FindingBatch`, attributed to the
  authenticated agent. A finding observed more than 5 minutes in the future
  fails the whole batch (400, nothing stored). Findings older than
  `finding_retention_days` are acknowledged but not stored. The rest are
  stored in one transaction (duplicates skipped) and every finding in the
  batch is acknowledged, including ones stored before.
- Any database error, on any endpoint, is 503 and acknowledges nothing. A
  finding whose day has no partition also ends as 503 and a
  `findings not stored` log line; `openvibes-admin maintenance` keeps the
  window covered. Ingest never creates partitions.

## Load control and logging

- Bodies over 1 MiB → 400 (never read past the limit).
- TLS handshake and request headers must arrive within
  `request_timeout_seconds`; silent clients are dropped.
- More than `max_in_flight` concurrent requests → 503 for the extra ones.
- One JSON log line per request on stderr: `endpoint`, `status`,
  `latency_ms`, and (inside the request span) `agent_id` once
  authenticated. Bodies, tokens, CSRs, and certificates are never logged.

## Health

On `health_listen` (plain HTTP, loopback): `/health` → 200 while the process
runs; `/ready` → 200 only if the database is reachable at the expected
schema version, else 503.

## Status

All four endpoints, load control, and logging are built (PM3). PM4 adds
RPM packaging and the cross-repository test with the real agent binary.

## Protocol fixtures

`tests/protocol_fixtures.rs` runs every fixture in the pinned `protocol/`
submodule through the `openvibes-core` types, and `tests/contract.rs` runs
the request fixtures through ingest's own parsing and validation layer.

## Test

```sh
eval "$(scripts/test-db.sh)"
CARGO_NET_GIT_FETCH_WITH_CLI=true cargo test --locked -p openvibes-ingest
```

`tests/support/mod.rs` builds a database, a PKI, and the real server
in-process; `raw()` sends hand-made HTTPS requests, with or without a
client certificate.
