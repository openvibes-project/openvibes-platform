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

## Health

On `health_listen` (plain HTTP, loopback): `/health` → 200 while the process
runs; `/ready` → 200 only if the database is reachable at the expected
schema version, else 503.

## Status

TLS, authentication, health, and configuration are built. Endpoints:
enroll and renew (PM3 task 4), heartbeat and findings (task 5), load
control and logging (task 6).

## Protocol fixtures

`tests/protocol_fixtures.rs` runs every fixture in the pinned `protocol/`
submodule through the `openvibes-core` types.

## Test

```sh
eval "$(scripts/test-db.sh)"
CARGO_NET_GIT_FETCH_WITH_CLI=true cargo test --locked -p openvibes-ingest
```

`tests/support/mod.rs` builds a database, a PKI, and the real server
in-process; `raw()` sends hand-made HTTPS requests, with or without a
client certificate.
