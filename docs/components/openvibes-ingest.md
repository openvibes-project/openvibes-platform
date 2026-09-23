# openvibes-ingest

The agent-facing, receive-only service on port **18423** (protocol P1 and
P2). Design: [`../specs/2026-09-23-ingest-subproject-design.md`](../specs/2026-09-23-ingest-subproject-design.md),
sections 3 and 6.

## Run

`openvibes-ingest [--config /etc/openvibes/ingest.toml]`. Logs are JSON on
stderr (journald).

On SIGINT (ctrl-c; the unit's `KillSignal`) it stops accepting, closes idle
connections, lets requests in flight finish (at most
`request_timeout_seconds`), then exits 0.

## Configuration

Strict TOML (unknown keys refused), absolute paths only:

| Key | Default | Range |
|---|---|---|
| `listen` | required | agent-facing TLS address |
| `health_listen` | required | loopback address for `/health`, `/ready`; any other address is refused |
| `server_certificate_file`, `server_key_file` | required | server chain (leaf first) and key |
| `client_ca_file` | required | CA whose client certificates are accepted |
| `issuing_certificate_file`, `issuing_key_file` | required | intermediate that signs agent certificates |
| `database_url` | required | the `openvibes_ingest` role |
| `client_certificate_days` | 30 | 1 to 365 |
| `max_in_flight` | 4096 | at least 1 |
| `finding_retention_days` | 90 | 1 to 36500; match `openvibes-admin maintenance` |
| `request_timeout_seconds` | 10 | 1 to 300; TLS handshake, request headers, and each whole request |
| `max_connections` | 1024 | 1 to 65536; keep below the process's file limit (`LimitNOFILE`) |
| `database_pool_size` | 16 | 1 to 1024 |

## TLS and authentication

- TLS 1.3 only (ring). ALPN `http/1.1`. No redirects anywhere.
- A client certificate is optional at the handshake (enrollment has none),
  but one that does not chain to `client_ca_file` fails the handshake. An
  **expired** (or not yet valid) certificate that otherwise chains is let
  through, so the platform can answer at the HTTP level as the protocol
  requires: 401, or 403 `identity_revoked` if its agent is revoked.
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
  the authenticated agent's (else 400). Stores version, capabilities, and the
  optional `hostname` (a spoofable operator label, never identity), writing
  at most every 5 minutes unless the hostname changed; an absent hostname
  keeps the stored one. 204.
- `POST /v1/findings` (authenticated): `FindingBatch`, attributed to the
  authenticated agent. A finding observed more than 5 minutes in the future
  fails the whole batch (400, nothing stored). Findings older than
  `finding_retention_days` are acknowledged but not stored. The rest are
  stored in one transaction (duplicates skipped) and every finding in the
  batch is acknowledged, including ones stored before.
- Any database error, on any endpoint, is 503 (`unavailable`) and
  acknowledges nothing; it is logged as a warning inside the request span
  (endpoint, and `agent_id` once authenticated), never with SQL or the
  connection string. A
  finding whose day has no partition also ends as 503 and a
  `findings not stored` log line; `openvibes-admin maintenance` keeps the
  window covered. Ingest never creates partitions.

## Load control and logging

- Accepted sockets set `TCP_NODELAY`: without it every request waited about
  40 ms for the client's delayed ACK (found by the PM5 load test).
- Bodies over 1 MiB → 400 (never read past the limit).
- The TLS handshake, the request headers, and each whole request (body
  included) must finish within `request_timeout_seconds`; otherwise the
  connection is dropped or the request gets 408, and its slot is freed.
- More than `max_in_flight` concurrent requests → 503 (`busy`) for the extra
  ones, logged as a request with status 503 but no database warning.
- At most `max_connections` connections are accepted at once; the rest wait
  in the kernel backlog. Accept errors (e.g. out of file descriptors) back
  off instead of spinning.
- Database waits, connects, and recycles are bounded to 5 s and every
  statement to 10 s, so a hung database yields 503, not hangs.
- One JSON log line per request on stderr: `endpoint`, `status`,
  `latency_ms`, and (inside the request span) `agent_id` once
  authenticated. Bodies, tokens, CSRs, and certificates are never logged.

## Capacity

About 1,000 req/s (the spec target) holds at p99 under 10 ms on a
12-core desktop; see [load.md](load.md) for the measured results.

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

The `integration_bundle` example (`cargo run -p openvibes-ingest --example
integration_bundle -- OUT_FILE`) writes a signed two-rule test bundle for
`scripts/integration-agent.sh` and prints its public key. It is test-only
(a published seed, the same as the agent's tests) and never shipped.
