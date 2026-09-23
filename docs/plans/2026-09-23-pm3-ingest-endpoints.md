# PM3: Ingest Endpoints — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `openvibes-ingest` serves `/v1/enroll`, `/v1/renew`, `/v1/heartbeat`, and `/v1/findings` over TLS 1.3 with per-request mTLS authentication, and the agent's real client enrolls, delivers, renews, and is revoked against it.

**Architecture:** `openvibes-ingest` = config + rustls server (TLS 1.3 only, client certificate optional at the handshake, required per endpoint) + an accept loop that hands each connection to an `axum` router with the peer's leaf certificate attached. All database work goes through new `platform-store::ingest` functions; all certificate work through `platform-pki`. A loopback-only health listener serves `/health` and `/ready`.

**Tech Stack:** Rust 1.95, tokio 1, axum 0.8.9, hyper 1.11 + hyper-util 0.1.20, tokio-rustls 0.26.5, rustls 0.23.45 (ring, TLS 1.3 only), tower 0.5, tracing 0.1 + tracing-subscriber 0.3 (JSON), serde_json; tests use the agent's `openvibes-transport` (same pinned revision as `openvibes-core`) as the real client.

**Spec:** `docs/specs/2026-09-23-ingest-subproject-design.md` sections 3 (config), 6 (endpoints, load control, logs, health), 8 (tests), 10 (PM3 exit: "section 8 fixture and failure tests pass"). Protocol: `protocol/spec/contracts-v1.md` ("Platform HTTP API", status handling).

## Global Constraints

- PM0–PM2 constraints still apply (toolchain, lints, `--locked`, trailer, component docs in the same change, `CARGO_NET_GIT_FETCH_WITH_CLI=true`, `scripts/test-db.sh`).
- TLS 1.3 only (ring provider). Client certificates must chain to `client_ca_file`; one that does not **fails the handshake**. No certificate is allowed at the handshake; endpoints decide.
- Request bodies at most 1 MiB; parse into the `openvibes-core` type and `validate(ResourceLimits::V1)`, else **400** with a fixed body that never echoes input. No redirects anywhere.
- mTLS authentication: leaf serial (16 bytes) **and** SPKI SHA-256 must match a `certificates` row. Unknown → **401**. Agent revoked → **403** with `PlatformError { code: identity_revoked }`; nothing else ever returns that code.
- Tokens hash exactly as in `openvibes-admin`: strict base64url (no padding) decode, then SHA-256 of the 32 bytes, via one shared helper.
- `agent_id` is `agent.` + a lowercase UUID; validated before `issue_client`.
- `client_certificate_days` 1–365; `max_in_flight` ≥ 1; `finding_retention_days` 1–36500. Findings more than 5 minutes in the future fail the batch (400); findings older than the retention window are acknowledged without storing.
- A database error on any endpoint is **503** and acknowledges nothing.
- Logs: JSON to stderr (journald), fields endpoint, status, agent_id, latency_ms. Tokens, CSRs, certificates, and finding text are never logged.
- The ingest database role `openvibes_ingest` must be sufficient for every query it runs (tested with `SET ROLE`).

## Review Focus

- A retried enrollment with the same token and key returns the **same** identity; with another key after the last use, 401; two concurrent enrollments with a single-use token yield one identity. (Task 2, Task 4.)
- A certificate whose serial matches but whose key differs (or the reverse) is 401, never accepted. (Task 3.)
- A duplicate findings batch is acknowledged in full and stored once; a batch with one future-dated finding stores nothing. (Task 5.)
- The database going away mid-run yields 503 on every endpoint, never a partial acknowledgement or a panic. (Task 5.)
- Oversized bodies, slow clients, and exceeding `max_in_flight` are refused without exhausting the process. (Task 6.)

---

### Task 1: Shared token hashing and agent-id validation

**Files:** Create `crates/platform-pki/src/token.rs`; modify `crates/platform-pki/src/{lib.rs,client.rs}`, `crates/openvibes-admin/src/token.rs`; tests in `crates/platform-pki/tests/token.rs`; update `docs/components/platform-pki.md`.

**Produces:** `platform_pki::enrollment_token_sha256(token: &str) -> Option<[u8; 32]>` (`None` unless the input is exactly 43 base64url characters decoding to 32 bytes); `platform_pki::is_agent_id(id: &str) -> bool` (`^agent\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`); `issue_client` returns `PkiError::InvalidAgentId` for anything else.

- [ ] **Step 1:** Failing tests: a token produced the admin way (32 random bytes, `URL_SAFE_NO_PAD`) hashes to SHA-256 of the bytes; padded, 42/44-character, standard-alphabet (`+`/`/`), whitespace-wrapped, and empty inputs return `None`; `is_agent_id` accepts `agent.00000000-0000-4000-8000-000000000001` and rejects uppercase, missing prefix, `a/b?c#d`, and 1 KiB strings; `issue_client` with a bad id is `InvalidAgentId`.
- [ ] **Step 2:** Run: FAIL. Implement (add `base64` to `platform-pki`); make `openvibes-admin token create` call `enrollment_token_sha256(&token)` instead of hashing the bytes itself (its tests must stay green).
- [ ] **Step 3:** Run pki and admin tests: PASS. Docs. Commit: `Share token hashing and validate agent ids`.

### Task 2: `platform-store::ingest`

**Files:** Create `crates/platform-store/src/ingest.rs`, `crates/platform-store/tests/ingest.rs`; update `docs/components/platform-store.md`. No migration: schema 2 already grants everything below (verified by the role test).

**Produces** (every function takes `&platform_store::Client`; times are `DateTime<Utc>`):
```rust
pub struct TokenRow { pub token_id: String, pub expires_at: DateTime<Utc>, pub max_uses: i32, pub revoked: bool }
pub async fn token_by_hash(client, sha256: [u8; 32]) -> Result<Option<TokenRow>, StoreError>;
pub struct Identity { pub agent_id: String, pub chain_pem: Vec<String>, pub not_after: DateTime<Utc> }
pub enum Enrolled { New(Identity), Existing(Identity), Exhausted }
/// In one transaction under pg_advisory_xact_lock(hashtext(token_id)):
/// an existing token_uses row for (token_id, spki) returns Existing; uses >= max_uses returns
/// Exhausted; otherwise `issue(agent_id)` is called with a fresh `agent.<uuid>` and the agent,
/// certificate, token use, and an audit row ("enroll", target agent_id) are inserted.
pub async fn enroll(client: &mut Client, token_id: &str, spki_sha256: [u8; 32], now,
    issue: impl FnOnce(&str) -> Result<IssuedCert, StoreError>) -> Result<Enrolled, StoreError>;
pub struct IssuedCert { pub serial: [u8; 16], pub spki_sha256: [u8; 32], pub not_before, pub not_after, pub chain_pem: Vec<String> }
pub async fn add_certificate(client, agent_id: &str, cert: &IssuedCert, now) -> Result<(), StoreError>;
pub enum Authenticated { Active(String /* agent_id */), Revoked, Unknown }
pub async fn authenticate(client, serial: &[u8], spki_sha256: [u8; 32]) -> Result<Authenticated, StoreError>;
pub async fn heartbeat(client, agent_id: &str, version: &str, capabilities: &[String], now) -> Result<bool /* written */, StoreError>;
pub struct StoredFinding { /* all Finding fields + agent_id + observed_at DateTime */ }
pub async fn store_findings(client: &mut Client, agent_id: &str, findings: &[StoredFinding], now) -> Result<u64 /* newly stored */, StoreError>;
```
`chain_pem` is stored as a JSON array string. `heartbeat` writes only if `last_seen_at` is null or older than 5 minutes. `store_findings`: one transaction, `INSERT … ON CONFLICT DO NOTHING`, then `current_findings` upsert keeping the newest `last_observed_at` and the earliest `first_observed_at`.

- [ ] **Step 1:** Failing tests (every test first runs `migrate`, then `SET ROLE openvibes_ingest` on the connection it hands to the function under test):
  - enroll new → `New`, rows in agents, certificates, token_uses, audit_log; same token + same key → `Existing` with the identical chain; single-use token + another key → `Exhausted`;
  - two concurrent `enroll` calls (two pooled connections, `tokio::join!`) with a single-use token and different keys → exactly one `New`, one `Exhausted`;
  - `authenticate`: right serial+key → `Active`; right serial, wrong key → `Unknown`; unknown serial → `Unknown`; after `agents::revoke` → `Revoked`;
  - `heartbeat` twice within 5 minutes → `true`, `false`; version stored;
  - `store_findings` of 3 → 3; same batch again → 0 and `count(*)` still 3; `current_findings` holds one row per rule with the newest `last_observed_at`.
- [ ] **Step 2:** Run: FAIL. Implement. **Step 3:** PASS; docs; commit `Add the ingest queries`.

### Task 3: Ingest config, TLS server, authentication, health

**Files:** `crates/openvibes-ingest/src/{main.rs,config.rs,tls.rs,server.rs,auth.rs,health.rs,error.rs}`, `crates/openvibes-ingest/tests/{support/mod.rs,tls.rs}`; workspace deps for axum, hyper, hyper-util, tokio-rustls, rustls, tower, tracing, tracing-subscriber, serde_json, and dev-dep `openvibes-transport` (git, same rev as `openvibes-core`); `docs/components/openvibes-ingest.md`.

**Produces:** `IngestConfig` (spec section 3 keys, `deny_unknown_fields`, all ranges validated); `pub async fn serve(config: IngestConfig, shutdown: impl Future) -> Result<(), IngestError>` binding `listen` and `health_listen`; an axum extractor `PeerCertificate(Option<CertificateDer<'static>>)` and `AuthenticatedAgent(String)` that performs the mTLS check (401/403 as in Global Constraints).

`tests/support/mod.rs` builds a complete test world: throwaway database (as in the store tests, migrated), PKI (root, intermediate, server certificate for `127.0.0.1`) in a temp dir, a config on free ports, the server spawned on the test runtime, and helpers: `enroll_token(uses)`, `raw_tls(path, body, client_cert: Option<…>) -> (status, body)` using tokio-rustls + a hand-written HTTP/1.1 request, and an `openvibes_transport::TransportConfig` pointing at the server.

- [ ] **Step 1:** Failing tests: a TLS 1.2-only client is refused; a client certificate from another CA fails the handshake; no certificate completes the handshake; `/v1/heartbeat` without a certificate → 401; with a certificate issued by the intermediate but not recorded → 401; `/health` → 200 and `/ready` → 200 on the loopback listener; `/ready` → 503 after the test database is dropped; config with `client_certificate_days = 0`, a relative path, or an unknown key is refused.
- [ ] **Step 2:** Run: FAIL. Implement: rustls `ServerConfig` with a TLS 1.3-only ring provider and `WebPkiClientVerifier::builder(roots).allow_unauthenticated()`; accept loop with a 10 s handshake timeout per connection, spawning a hyper-util connection per client with the peer leaf in the request extensions; router with no redirect layers.
- [ ] **Step 3:** PASS; docs; commit `Serve TLS 1.3 with per-request mTLS authentication`.

### Task 4: `/v1/enroll` and `/v1/renew`

**Files:** `crates/openvibes-ingest/src/{enroll.rs,renew.rs}`, `crates/openvibes-ingest/tests/enroll.rs`; docs.

- [ ] **Step 1:** Failing tests, all through the **real agent client** (`PlatformClient::new(&transport, None)?.enroll(&token, &HostKey::generate()?)`, in `spawn_blocking`): enroll returns an `agent.<uuid>` id, a two-certificate chain, and `expires_at_unix_ms` ≈ now + 30 days; the chain verifies against the intermediate; retry with the same token and the same `HostKey` (its CSR sent twice) → same `agent_id` and chain; another key after the only use → 401; unknown, expired, and revoked tokens → 401; malformed token string → 401; CSR with a subject → 400. Renew with the issued identity → a new certificate whose response `agent_id` is the requesting agent's, recorded (2 certificates for the agent), and the old one still authenticates until it expires; renew by a revoked agent → 403 `identity_revoked` (the transport maps it to `TransportError::IdentityRevoked`).
- [ ] **Step 2:** Run: FAIL. Implement: enroll = parse → `enrollment_token_sha256` → `token_by_hash` (absent, expired, revoked → 401) → `check_csr` (error → 400) → `store::ingest::enroll` with the issuer from `issuing_certificate_file`/`issuing_key_file` loaded once at start → response. Renew = `AuthenticatedAgent` → `check_csr` → `issue_client` → `add_certificate` → response.
- [ ] **Step 3:** PASS; docs; commit `Add enrollment and renewal`.

### Task 5: `/v1/heartbeat` and `/v1/findings`

**Files:** `crates/openvibes-ingest/src/{heartbeat.rs,findings.rs}`, `crates/openvibes-ingest/tests/delivery.rs`; docs.

- [ ] **Step 1:** Failing tests via the real client after enrollment: heartbeat → 2xx and `last_seen_at` set; heartbeat with another agent's `agent_id` → 400; deliver 3 findings → acknowledgement names all 3, stored once; deliver the same batch again → all 3 acknowledged, still 3 rows; a batch containing one finding observed 10 minutes in the future → 400 and nothing stored; a finding older than the retention window → acknowledged, not stored; revoked agent → `TransportError::IdentityRevoked` on both endpoints; drop the database (`DROP DATABASE … WITH (FORCE)`) → heartbeat, findings, renew, and enroll all return 503 (raw requests), and the process keeps serving `/health`.
- [ ] **Step 2:** Run: FAIL. Implement. Ingest never creates partitions (`openvibes-admin maintenance` owns them and keeps the whole retention window covered); if a finding's day has no partition the insert fails, the batch gets 503, and the log says `missing partition`.
- [ ] **Step 3:** PASS; docs; commit `Add heartbeats and finding delivery`.

### Task 6: Load control, contract layer, logging

**Files:** `crates/openvibes-ingest/src/{limits.rs,log.rs}`, `crates/openvibes-ingest/tests/{limits.rs,contract.rs}`; docs.

- [ ] **Step 1:** Failing tests: a 1 MiB + 1 body → 400 without reading it all; a client that opens TLS and sends nothing is dropped after the header timeout (10 s, configurable in tests); with `max_in_flight = 1` and one request held open, a second gets 503; `tests/contract.rs` passes every `valid*` protocol fixture for enrollment-request, renewal-request, heartbeat, and finding-batch through the request **parsing and validation layer** (`parse::<T>(bytes)` → `Ok`) and every `invalid*` one → the 400 path (full end-to-end acceptance of fixtures is impossible: their CSRs and tokens are placeholders); a captured log line for a failed enrollment contains `endpoint`, `status`, `latency_ms` and not the token or CSR text.
- [ ] **Step 2:** Run: FAIL. Implement with a `tokio::sync::Semaphore` (`try_acquire` → 503), hyper-util header read timeout, axum body limit, and a `tracing` layer.
- [ ] **Step 3:** Run the whole workspace: PASS; docs; commit `Bound load and log without secrets`.

## Exit (PM3)

CI green; section 8 fixture and failure-path tests pass; the agent's real client completes enroll → heartbeat → deliver → renew → revoke (`identity_revoked`) against `openvibes-ingest`. PM4 packages it as RPM and runs the real agent binary against it on Fedora.
