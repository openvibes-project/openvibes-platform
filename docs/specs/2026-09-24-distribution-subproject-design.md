# Sub-project 2: Distribution Service

**Status: approved by the user on 2026-09-24.** Drafted overnight on
2026-09-24; the user chose the recommended option for every question in
section 11 and then approved the spec as a whole. Next: the implementation
plan (DM0 to DM4).

- Architecture context:
  [`2026-09-23-platform-architecture-design.md`](2026-09-23-platform-architecture-design.md),
  sections 3, 4, 5 and 9 (item 2).
- Protocol: `openvibes-protocol/spec/contracts-v1.md` ("Rule Distribution")
  and `PLAN.md` P4.
- Shape and conventions follow sub-project 1:
  [`2026-09-23-ingest-subproject-design.md`](2026-09-23-ingest-subproject-design.md).

## 1. Goal and Exit Criteria

Build the server side of protocol milestone **P4 (rule distribution)**:
- a separate service that serves offline-signed rule bundles to enrolled
  agents over mTLS;
- the admin CLI commands that manage trusted rule-signing keys and publish
  bundles.

It is installable as an RPM next to ingest.

Done when, on a Fedora host with PostgreSQL from Fedora's packages:

1. **The real agent follows published bundles.** The agent is built at a
   pinned revision, configured with `distribution_url`, and enrolled through
   ingest. It then:
   - fetches a bundle published with `openvibes-admin`, scans with it, and
     delivers the findings;
   - picks up a newer published version at its next scan;
   - keeps its last accepted bundle when the service is down or serves a
     refused envelope.
2. **Protocol fixtures:** every protocol fixture for `RuleBundleRequest` and
   `SignedRuleEnvelope` is handled as the contract says. Unknown rule set →
   404, nothing newer → 204, newer → 200 with the exact signed bytes.
3. **Failure paths:** all failure-path tests in section 8 pass.
4. **Load:** a load run has recorded throughput and p99 at the burst rate in
   section 8, on stated hardware.

Out of scope:
- the console's rule-set pages. The console later reuses this schema; see
  Q2.
- rule authoring and the detection-rules repository;
- trust-root rotation (protocol open question 6);
- agent health reporting of rule-set versions (sub-project 4);
- corporate issuing CA mode 3.

## 2. What Already Exists

- **Contract:** `RuleBundleRequest { schema_version, rule_set_id,
  current_version? }` → `200` with a `SignedRuleEnvelope` (byte for byte as
  signed), `204` when nothing is newer, and `404` for an unknown rule set.
  Status handling, including `identity_revoked`, is the same as ingest.
- **Agent side (done):** before every scan, the agent asks once per
  configured rule set. It verifies each envelope with its own locally
  configured trusted keys and rollback floor, and keeps its last accepted
  bundle on any refusal or failure.
  - Assignment is local: the service cannot add, remove, or re-scope rule
    sets. It can at worst withhold updates or serve refused bundles.
- **Platform:** ingest's TLS 1.3 server, mTLS authentication (serial plus
  SPKI hash against `certificates`, revoked agent → 403), request limits,
  JSON logs, health listener, RPM packaging, and the integration and load
  harnesses.

## 3. Workspace

```
crates/platform-agent-server/   NEW (Q1): TLS config, expiry-tolerant client verifier,
                                authenticated-agent extractor, limits, logging,
                                accept loop with drain, health, extracted from ingest
crates/openvibes-distribution/  NEW: the service (lib + thin binary)
crates/platform-store/          + rules module, migration 0006
crates/openvibes-admin/         + `rules` commands
packaging/rpm/                  + openvibes-distribution subpackage, unit, sysusers
scripts/integration-agent.sh    + distribution steps
scripts/load/                   + distribution mode
```

`openvibes-admin` gains a dependency on the agent's `openvibes-rules` crate,
pinned to the same revision as `openvibes-core`. The platform then verifies
envelopes with exactly the agent's loader.

## 4. Configuration

`/etc/openvibes/distribution.toml`, with the same rules as `ingest.toml`:
strict keys, absolute paths, 64 KiB cap.

```toml
listen = "0.0.0.0:18424"
health_listen = "127.0.0.1:18481"
server_certificate_file = "/etc/openvibes/tls/distribution.crt"   # chain, leaf first
server_key_file = "/etc/openvibes/tls/distribution.key"
client_ca_file = "/etc/openvibes/pki/intermediate.crt"
database_url = "postgresql:///openvibes?host=/run/postgresql&user=openvibes_distribution"
max_in_flight = 4096
request_timeout_seconds = 10
max_connections = 1024
database_pool_size = 16
```

The service holds no issuing key and no rule-signing key.

## 5. Data Model (migration 0006)

```
rule_sets        rule_set_id text PK (Identifier), created_at, retired_at
rule_trust_keys  rule_set_id FK, issuer_key_id text, public_key bytea (32, Ed25519),
                 added_at, removed_at; PK (rule_set_id, issuer_key_id)
rule_bundles     rule_set_id FK, version bigint, envelope bytea (exact signed bytes),
                 envelope_sha256 bytea, issuer_key_id, created_at_ms, expires_at_ms,
                 published_at, published_by; PK (rule_set_id, version)
```

- The **current bundle** of a rule set is its highest `version`. There is no
  mutable pointer, so publishing is a single insert.
- **Roles:**
  - `openvibes_distribution`: `SELECT` on `agents`, `certificates`,
    `rule_sets` and `rule_bundles`, and nothing else (Q5).
  - `openvibes_ingest`: no access to the rule tables.
- **Envelope size:** at most the protocol's `document_bytes` (1 MiB).

## 6. Admin CLI

```
openvibes-admin rules trust add RULE_SET ISSUER_KEY_ID PUBLIC_KEY_B64URL
openvibes-admin rules trust list [RULE_SET] | remove RULE_SET ISSUER_KEY_ID
openvibes-admin rules publish FILE
openvibes-admin rules list | show RULE_SET | retire RULE_SET
```

`publish` runs `openvibes-rules`' loader on the file against the rule set's
currently trusted keys, then stores the exact bytes in one transaction. It
checks that:
- the signature is valid and the issuer is trusted;
- the envelope is not expired (Q3);
- the version is above the current one.

Re-publishing the same version with the same bytes is idempotent. The same
version with different bytes is refused, with the same semantics as the
console's planned `409`. Every command is audited, with the rule set, the
version, and the envelope digest as target.

## 7. Distribution Service

- `POST /v1/rule-bundle`, client certificate required. The agent is
  authenticated exactly as in ingest, and a revoked agent gets 403
  `identity_revoked`.
- **Responses:**
  - 200 with the envelope bytes (`application/json`) when
    `current_version` is absent or below the current version;
  - 204 when it is at or above it;
  - 404 for an unknown or retired rule set (Q7);
  - 400 for a malformed body;
  - 503 on a database error.
- **Query and caching:** one indexed query per request, with no cache (Q6).
  At 50,000 agents with 3 rule sets and hourly scans that is about
  42 req/s on average.
- **Load control, logging and health:** load control is identical to ingest:
  1 MiB body limit, `max_in_flight`, request deadline, connection cap,
  `TCP_NODELAY`, and draining on SIGINT. Logs are one JSON line per
  request. The health listener serves `/health` and `/ready`, with a schema
  check.
- **Replicas:** the service is stateless and read-only, so replicas can sit
  behind an L4 load balancer.

## 8. Tests

- **Store:** the rules module against a real PostgreSQL, run as the
  least-privilege roles.
- **Publish:** these cases are refused:
  - an untrusted issuer, a bad signature, an expired envelope;
  - a version equal to or below the current one, with different bytes
    (idempotent with the same bytes);
  - an oversized file;
  - a removed trust key.
- **Service:**
  - the contract statuses above, and exact-byte equality of the served
    envelope;
  - revoked agent → 403, unknown certificate → 401, a certificate from
    another CA → handshake failure;
  - body over 1 MiB → 400, database down → 503;
  - in-flight limit → 503.
- **Fixtures:** every `rule-bundle-request` and `signed-rule-envelope`
  protocol fixture.
- **Cross-repo integration:** extend `scripts/integration-agent.sh`. The real
  agent fetches v1 and delivers the findings it produces. Publishing v2 makes
  the next scan use it. Stopping distribution keeps the agent on v2 with
  scans continuing, and a revoked agent is told `identity_revoked` by
  distribution.
- **Load:** the generator's distribution mode. The burst case is every agent
  scanning at once after a publish; the target is 1,000 req/s at 200 KB
  envelopes on one instance (Q9).

## 9. Packaging

- `openvibes-distribution` RPM subpackage, with a hardened unit identical to
  ingest's (no writable paths, `KillSignal=SIGINT`), sysusers entry
  `openvibes_distribution` (named like its PostgreSQL role), and
  `/etc/openvibes/distribution.toml` at 0640 root:openvibes_distribution.
- **Server certificate:** its own, issued with `ca issue-server` like
  ingest's.
- **Firewall:** 18424/tcp.

## 10. Milestones

| # | Milestone | Exit |
|---|---|---|
| DM0 | Extract `platform-agent-server` from ingest (Q1) | ingest suite, integration, and load unchanged and green |
| DM1 | Migration 0006, store rules module, `admin rules` | publish tests pass; exact bytes stored |
| DM2 | `openvibes-distribution` with all failure-path tests | section 8 service and fixture tests pass |
| DM3 | RPM subpackage; integration with the real agent | section 1 items 1 to 3 hold |
| DM4 | Distribution load run | section 1 item 4 recorded |

Protocol housekeeping: tick P4 "Distribution service" in `PLAN.md` at the end
of DM3.

## 11. Questions (resolved 2026-09-24)

Each question lists the options with the recommendation, marked **R**. The
user chose **R** for every question, and each carries a **Resolved** line.

**Q1. Share the agent-facing server code with ingest?** **Resolved: R.**
- (a) **R** Extract it into a `platform-agent-server` crate first (DM0).
  Distribution then gets ingest's TLS, authentication, limits, drain and
  Nagle fixes for free, and a fix in one place fixes both services.
- (b) Copy the modules into distribution. Faster to start, but two copies of
  security-critical code drift.
- (c) Serve distribution from the ingest binary on a second port. That
  contradicts the architecture's "one binary per module".

**Q2. Who owns the rule schema: this sub-project or the console?** **Resolved: R.**
Codex's console technical design (branch `console`, section 14, item 6)
plans "rule sets, trusted public keys, and exact signed bundle versions" as a
later migration.
- (a) **R** Distribution defines them here in migration 0006. The console
  reuses the tables and the store functions when it implements its
  rule-set pages. Record this in `decisions.md` so Codex sees it.
- (b) The console defines them and distribution waits. That blocks
  sub-project 2 on the console.
- (c) Each defines its own. Duplicated truth.

**Q3. Expired and nearly expired envelopes.** **Resolved: R.**
- (a) **R** `publish` refuses an expired envelope and warns when it expires
  within 7 days. The service serves the current bundle regardless (agents
  refuse expired ones themselves). `rules list` shows each set's expiry.
- (b) The service also stops serving expired bundles (404 or 204). It hides a
  problem the agent already handles, and changes the contract meaning of
  404.

**Q4. What removing a trust key does.** **Resolved: R.**
- (a) **R** It blocks future publishes signed by that key. A bundle already
  published keeps being served and is flagged in `rules list`. The
  authoritative trust is each agent's own configured keys; the platform's
  copy is a publish-time guard.
- (b) Removing the key also withdraws its bundles. That surprises operators
  mid-rotation and still leaves agents on their last accepted bundle.

**Q5. Record which agent fetched which version?** **Resolved: R.**
- (a) **R** Not in this sub-project: the service stays read-only.
  Sub-project 4's heartbeat `health` carries rule-set versions, which is the
  agent's own truth.
- (b) Write a last-fetch row per agent and rule set: a write on every read,
  and a second, weaker source of truth.

**Q6. Cache envelopes in memory?** **Resolved: R.**
- (a) **R** No cache at first. The query is one index lookup; measure in DM4
  and add a cache only if the burst target needs it.
- (b) An in-memory cache invalidated by `LISTEN/NOTIFY`: faster, with more
  moving parts.

**Q7. Retiring a rule set.** **Resolved: R.**
- (a) **R** `rules retire` stops serving the set (404, audited) and keeps
  every stored byte. Agents keep their last accepted bundle and retry each
  scan.
- (b) Serve 204 forever after retirement: indistinguishable from "nothing
  newer".
- (c) No retirement in this sub-project.

**Q8. Where publishing happens in the first release.** **Resolved: R.**
- (a) **R** CLI only (`openvibes-admin rules publish`). The console adds its
  upload route later on the same store functions.
- (b) Wait for the console. That leaves no way to publish until sub-project 5.

**Q9. Distribution load target.** **Resolved: R.**
- (a) **R** 1,000 req/s with 200 KB envelopes on one instance: every agent
  of a 50,000-host fleet scanning within about a minute after a publish.
- (b) Only the average (about 42 req/s). It hides the burst.

**Q10. Server certificate: shared with ingest, or its own?** **Resolved: R.**
- (a) **R** Its own (`distribution.crt`). The services may sit on different
  hosts or names, and each key is readable only by its own service user.
- (b) One certificate with both names. One file, but two service users need
  the same key.
