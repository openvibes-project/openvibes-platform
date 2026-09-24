# Sub-project 1: Ingest Service, Admin CLI, Built-in PKI, Storage

Status: draft for review, 2026-09-23. Architecture context:
[`2026-09-23-platform-architecture-design.md`](2026-09-23-platform-architecture-design.md).

## 1. Goal and Exit Criteria

Build the server side of protocol milestones **P1 (online ingest)** and **P2
(identity lifecycle)**, installable as RPM packages on Fedora.

Done when, on a Fedora host with PostgreSQL from Fedora's packages:

1. A real `openvibes-agent` binary (built at a pinned revision) enrolls with a
   token issued by `openvibes-admin`, sends heartbeats, delivers findings
   exactly once, restarts and reconnects, renews its certificate, is revoked
   (receives `identity_revoked`), and re-enrolls with a new token.
2. Every valid protocol fixture for these endpoints is accepted and every
   invalid one refused with 400.
3. All failure-path tests in section 8 pass.
4. A load test has recorded throughput and p99 latency for the target of about
   1,000 requests per second on one ingest instance, on stated hardware.

Out of scope: distribution, file import, agent health reports (heartbeat
`health` is ignored until sub-project 4), admin API, web UI, RBAC, corporate
CA modes 2 and 3 (mode 2 needs no code, but is not tested here), containers.

## 2. Workspace

```
openvibes-platform/
  Cargo.toml                  workspace; openvibes-core as a git dependency
  crates/platform-config/     bounded TOML loading
  crates/platform-store/      PostgreSQL pool, migrations, all queries
  crates/platform-pki/        CSR checks, certificate issuing, CA loading
  crates/openvibes-ingest/    agent-facing mTLS service
  crates/openvibes-admin/     operator CLI
  migrations/                 numbered SQL files
  packaging/rpm/              spec file, systemd units, sysusers, tmpfiles
  scripts/                    integration and load test drivers
```

Conventions copied from the agent: `#![forbid(unsafe_code)]`, clippy `-D
warnings`, `clippy.toml` bans `std::process::Command` and TLS verification
bypasses, `Cargo.lock` committed, every CI action pinned to a commit SHA.

CI needs read access to the private agent repository (for `openvibes-core` and
the integration test) and to the protocol repository (fixtures). One
fine-grained, read-only token covering both is stored as a platform secret and
used verbatim.

## 3. Configuration

`/etc/openvibes/ingest.toml`, `deny_unknown_fields`, absolute paths only,
64 KiB cap:

```toml
listen = "0.0.0.0:18423"
health_listen = "127.0.0.1:18480"          # /health, /ready; loopback only
server_certificate_file = "/etc/openvibes/tls/ingest.crt"   # chain, leaf first
server_key_file = "/etc/openvibes/tls/ingest.key"
client_ca_file = "/etc/openvibes/pki/intermediate.crt"      # accepted client issuers
issuing_certificate_file = "/etc/openvibes/pki/intermediate.crt"
issuing_key_file = "/var/lib/openvibes-ingest/intermediate.key"   # 0600, ingest user
database_url = "postgresql:///openvibes?host=/run/postgresql&user=openvibes_ingest"
client_certificate_days = 30
max_in_flight = 4096                        # above this: 503
finding_retention_days = 90
request_timeout_seconds = 10               # TLS handshake, headers, whole request
max_connections = 1024                     # keep below LimitNOFILE
database_pool_size = 16
```

`openvibes-admin` reads `/etc/openvibes/admin.toml` (database URL for the
admin role, CA file paths only when a `ca` command is run).

## 4. Data Model (migration 0001)

```
agents            agent_id text PK ('agent.' + UUIDv4), status ('active'|'revoked'),
                  enrolled_at, revoked_at, last_seen_at, scanner_version, capabilities text[]
certificates      serial bytea PK (16 random bytes), agent_id FK, spki_sha256 bytea,
                  not_before, not_after, issued_at, chain_pem text
enrollment_tokens token_id uuid PK, token_sha256 bytea UNIQUE, label, created_at,
                  created_by, expires_at, max_uses int (default 1), revoked_at
token_uses        token_id FK, spki_sha256 bytea, agent_id FK, serial FK, used_at,
                  PK (token_id, spki_sha256)
findings          PARTITION BY RANGE (observed_day date):
                  finding_id text, observed_day date, observed_at timestamptz,
                  agent_id, scan_id, rule_id, rule_version bigint, severity, confidence,
                  message, evidence text[], received_at, origin ('online'),
                  authenticated bool, PK (finding_id, observed_day)
current_findings  PK (agent_id, rule_id): last_finding_id, rule_version, severity,
                  first_observed_at, last_observed_at
audit_log         id bigserial, at, actor (OS user or service), action, target, result,
                  detail jsonb (never secrets)
schema_version    version int
```

Roles: `openvibes_ingest` may read and write agents, certificates,
enrollment_tokens (read, plus the use count), token_uses, findings,
current_findings, and insert audit_log. `openvibes_admin` owns the schema.

## 5. PKI (built-in mode)

- `ca init-root --out DIR`: root key and self-signed certificate, P-256,
  10 years, path length 1. Intended for an offline machine; the key never
  goes onto a platform host.
- `ca sign-intermediate --root DIR --csr FILE` or `--out DIR`: intermediate,
  2 years (never past the root's expiry), path length 0, key usage
  certificate and CRL signing (CRLs are not issued: revocation is a database
  state).
- `ca import-intermediate CHAIN`: records the chain; the key stays a file.
- `ca issue-server NAME --san DNS|IP...`: server certificate, 90 days, from
  the intermediate.
- Client certificates (at enrollment and renewal): subject empty, SAN URI
  `openvibes:agent:<agent_id>`, extended key usage client auth, validity from
  now to `client_certificate_days`, serial 16 random bytes.
- CSR checks before issuing: valid PKCS#10 signature, P-256 public key, empty
  subject, size within the V1 document limit. Requested extensions are
  ignored; the platform sets every extension itself.

## 6. Ingest Endpoints

Every request: body at most 1 MiB, parsed into the `openvibes-core` type and
validated against V1 limits, else 400 without echoing input. No redirects.
TLS 1.3 only; a client certificate is optional at the handshake (enrollment
has none) and required per endpoint below. A certificate that does not chain
to `client_ca_file` fails the handshake.

**Authentication of mTLS requests:** look up the presented leaf's serial in
`certificates`, check the public-key hash matches, then the agent's status.
Unknown certificate: 401. Revoked agent: 403 with
`PlatformError{identity_revoked}`. Nothing else ever returns that code.

| Endpoint | Behaviour |
|---|---|
| `POST /v1/enroll` (no client certificate) | Hash the token; look it up. Unknown, expired, or revoked token: 401. If a `token_uses` row exists for this token and the CSR's public-key hash, return the same identity (the stored chain): the protocol's retry rule. Otherwise, if uses are exhausted: 401. Else, in one transaction: create agent, issue certificate, record the use and certificate, write audit entry. Return `EnrollmentResponse`. |
| `POST /v1/renew` | Check the CSR, issue a certificate for the requesting agent's own `agent_id` with the new key, record it. Earlier certificates stay valid until they expire. |
| `POST /v1/heartbeat` | Update `last_seen_at`, `scanner_version`, `capabilities` at most once per 5 minutes per agent. 204. |
| `POST /v1/findings` | Every finding's agent is the authenticated agent. One bad finding never fails the batch (protocol P5): a finding observed more than 1 hour in the future, older than the retention window, with an unrepresentable value, or for a day without a partition is acknowledged and listed in `rejected_findings` with a reason. The rest: one transaction, insert with `ON CONFLICT DO NOTHING`, upsert `current_findings` where newer. After commit, return `DeliveryAcknowledgement` naming every finding in the batch. On any database error: 503, nothing acknowledged. |

**Load control.** A global in-flight limit returns 503 above `max_in_flight`;
per-connection request and header timeouts; database pool sized in config.
The agent's jittered backoff spreads reconnect bursts.

**Logs.** Structured (JSON) to journald: endpoint, status, agent_id, latency.
Tokens, CSRs, certificates, and finding text are never logged.

**Health.** `health_listen` serves `/health` (process alive) and `/ready`
(database reachable, schema version matches, CA loaded).

## 7. Admin CLI

```
openvibes-admin migrate | status | maintenance
openvibes-admin ca init-root | sign-intermediate | import-intermediate | issue-server
openvibes-admin token create --expires 7d [--uses 1] [--label TEXT] | list | revoke ID
openvibes-admin agent list [--offline] [--revoked] | show ID | revoke ID
```

- `token create` prints the token once (32 random bytes, base64url) and
  stores only its SHA-256.
- `agent revoke` sets the status; the agent's next request gets
  `identity_revoked`.
- `maintenance` creates the next seven daily finding partitions and drops
  those older than the retention window; run by a systemd timer.
- `status` reports database and schema version, partition range, agents
  active, offline (no heartbeat for 15 minutes; `last_seen_at` is written at
  most every 5 minutes), revoked, and token counts.
- Every command writes an `audit_log` entry with the invoking OS user. The CLI
  is local break-glass access: whoever can run it with the admin database
  role has full rights.

## 8. Tests

- **Store:** against a real PostgreSQL (a throwaway cluster in a temporary
  directory locally; a PostgreSQL service in CI).
- **Fixtures:** every protocol fixture for enroll, renew, heartbeat, findings,
  acknowledgement, and platform error, through the real handlers.
- **Failure paths:** unknown, expired, revoked, and exhausted tokens; token
  reuse with a different key (401) and with the same key (same identity);
  renewal cannot change `agent_id`; unknown certificate (401); certificate
  from another CA (handshake failure); revoked agent (403 plus
  `identity_revoked`); body over 1 MiB (400); future-dated finding (refused alone, acknowledged with `future_observation`);
  database unavailable (503, nothing acknowledged); duplicate batch
  (acknowledged, stored once); in-flight limit (503).
- **Cross-repo integration** (`scripts/integration-agent.sh`): starts
  PostgreSQL and ingest on localhost, builds the agent at the pinned revision,
  and runs the exit-criteria sequence in section 1.
- **Load** (`scripts/load`): a generator using the agent's transport crate to
  simulate N agents: heartbeats every 60 s, a finding batch every hour.
  Reports requests per second, p50 and p99 latency, and database CPU.

## 9. Packaging

`packaging/rpm/openvibes-platform.spec` builds `openvibes-ingest` and
`openvibes-admin`. Each ships a systemd unit (`NoNewPrivileges`,
`ProtectSystem=strict`, `PrivateTmp`, restricted address families
`AF_INET AF_INET6 AF_UNIX`), a sysusers entry for its service user, and
tmpfiles for its state directory. A `openvibes-maintenance.timer` runs
`openvibes-admin maintenance` daily.

## 10. Milestones

| # | Milestone | Exit |
|---|---|---|
| PM0 | Workspace, CI, pinned `openvibes-core`, fixture tests | CI green |
| PM1 | `platform-store`, migration 0001, `admin migrate` and `status` | schema applies; store tests pass |
| PM2 | `platform-pki` built-in mode; `admin ca`, `token`, `agent` | issued chains validate; tokens stored only as hashes |
| PM3 | Ingest endpoints with all failure-path tests | section 8 fixture and failure tests pass |
| PM4 | RPM packaging; cross-repo integration test on Fedora | section 1 items 1 to 3 hold |
| PM5 | Load test | section 1 item 4 recorded |

## 11. Protocol Housekeeping

- `openvibes-protocol/PLAN.md` still shows the agent side of P3 as open; the
  agent implemented it (local-only mode and `export`). Tick those items.
- Record in `PLAN.md` that the ingest side of P1 and P2 is in progress in
  `openvibes-platform`.
