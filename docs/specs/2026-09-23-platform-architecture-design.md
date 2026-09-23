# OpenVIBES Platform Architecture

Status: draft for review, 2026-09-23. Companion spec for the first
sub-project: [`2026-09-23-ingest-subproject-design.md`](2026-09-23-ingest-subproject-design.md).

## 1. Purpose and Scope

The platform receives what OpenVIBES agents collect, stores it, gives agents
their signed rules, and lets operators manage agents and read results. The
agent and the wire protocol already exist (`openvibes-agent`,
`openvibes-protocol`); the platform implements the server side of that
protocol and must honour every obligation in `openvibes-protocol/PLAN.md`.

Target: one organisation running **1,000 to 50,000 hosts**. At 50,000 agents a
once-a-minute heartbeat alone is about 830 mutually authenticated requests per
second, so the agent-facing services scale horizontally from the start.

This document fixes module boundaries, storage, trust, and deployment for the
whole platform. Each module is then designed and built as its own sub-project.

## 2. Design Principles

1. **Secure by default, configurable to fit an organisation.** Every setting
   (CA mode, server certificates, authentication, retention) has a safe
   default. No option weakens the authorisation checks described below.
2. **Modular.** Each module is its own binary with one purpose, its own system
   user, and least-privilege database access. Modules communicate only through
   PostgreSQL and the documented protocols.
3. **The protocol is the contract.** Anything exchanged with agents, including
   files a platform generates for agents, is specified in
   `openvibes-protocol` first and tested against its fixtures on both sides.
4. **Separate trust domains.** Agents authenticate only with mTLS on the
   agent ports. Humans authenticate only on the admin API and UI port. Neither
   credential works in the other domain.
5. **No silent data loss.** Agents buffer while the platform is unavailable;
   whatever an agent drops is counted and reported.

## 3. Modules

| Module | Binary | Port | Role | Sub-project |
|---|---|---|---|---|
| Ingest | `openvibes-ingest` | 18423 | Enrollment, renewal, heartbeats and health, finding delivery; later file import | 1 |
| Admin CLI | `openvibes-admin` | none | Local operator tool: CA, tokens, agents, rules, migrations, maintenance | 1 |
| Distribution | `openvibes-distribution` | 18424 | Serves offline-signed rule bundles (`/v1/rule-bundle`) | 2 |
| Admin API and web UI | `openvibes-console` | 443 | Human access, RBAC, deployment packages | later |
| Correlation | `openvibes-correlation` | none | Works from stored findings and inventory | later |
| CMDB sync | `openvibes-cmdb` | none | Third-party inventory and CMDB integration | later |

Shared library crates in the same Cargo workspace: `platform-store` (the only
crate that touches PostgreSQL), `platform-pki` (certificate issuing, no
network), `platform-config` (bounded TOML with the agent's rules). The
platform depends on the agent repository's `openvibes-core` crate, pinned by
git revision, so both sides enforce identical contract types, validation, and
V1 resource limits.

Stack: Rust (toolchain, lints, and CI conventions as in the agent), `tokio`,
`axum`, `rustls` (TLS 1.3 only), PostgreSQL.

## 4. Storage

One PostgreSQL database. Per-module roles with least privilege; for example
distribution may only read rule bundles. Schema changes are versioned SQL
migrations applied by `openvibes-admin migrate`; services refuse to start on
an unknown schema version.

- Identity: agents, certificates, enrollment tokens and their uses.
- Findings: a history table partitioned by day of `observed_at` (retention by
  dropping partitions, default 90 days) plus a current-state table per agent
  and rule.
- Agent health: the latest health report per agent.
- Distribution: rule bundles exactly as signed, plus the public keys trusted
  for each rule set.
- Audit log: append-only record of every privileged action and login, retained
  for 365 days by default under an administrator-configurable global policy;
  the first release includes permission-gated, audited CSV export.

Expected volume with today's agent (every scan re-reports its matches): up to
1 M findings per hour at 50,000 hosts, about 10 GB/day. Planned mitigation, a
separate protocol change: report when a match starts and ends instead of on
every scan. A columnar store for history remains an option if analytics
outgrow PostgreSQL.

## 5. Trust and PKI

All keys ECDSA P-256. Three CA modes behind one issuing boundary in
`platform-pki`:

1. **Built-in (default).** An offline OpenVIBES root (10 years) signs an
   intermediate (2 years) kept on the ingest host, readable only by the
   ingest service user. Agents pin the root.
2. **Corporate subordinate.** The organisation's CA signs the OpenVIBES
   intermediate. No platform code differs. Agents should pin the OpenVIBES
   intermediate: pinning a corporate root means any server certificate that
   CA issues for the ingest hostname is trusted by agents.
3. **Corporate issuing.** The platform forwards each validated CSR to the
   organisation's CA over a standard enrollment protocol (EST, RFC 7030,
   first). Affects only enrollment and renewal.

Server certificates for the agent ports are a separate setting and may come
from the corporate PKI in any mode.

**Authorisation never rests on the CA alone.** A client certificate is
accepted only if its serial and public-key hash are recorded for an active
agent. Any other certificate, whoever issued it, is refused. Revocation is a
database state change visible to every ingest replica at once; no CRL or OCSP.

Rule-signing keys never reach the platform. Distribution serves envelopes
signed offline; the admin CLI verifies them against the rule set's trusted
public keys before storing. Rule trust-key management remains CLI-only in the
first release.

## 6. Human Access and RBAC (planned sub-project)

- Authentication: local username and password first, provisioned and recovered
  through the audited local CLI, with Argon2id, generic failures, rate limiting,
  and temporary lockout. OIDC (Entra ID, Okta, Keycloak, Authentik, Google
  Workspace, ADFS), SAML 2.0, and TOTP/WebAuthn are later adapters over the
  same server-side session and RBAC boundary. First-release service accounts
  use hashed, expiring API tokens bound to a role.
- Authorisation: deny by default. Fine-grained permissions (for example
  `agents.read`, `agents.revoke`, `tokens.create`, `rules.upload`,
  `findings.read`, `packages.create`, `ca.manage`, `rbac.manage`); roles are
  permission sets (built-in Viewer, Analyst, Operator, Admin, plus custom);
  bindings attach a role to a user or an identity-provider group, scoped to
  the whole platform or to an asset group of hosts selected by tag. One
  middleware enforces the permission each endpoint declares.
- Manual exact tags provide first-release asset grouping. CMDB integration may
  automate the source later without changing the access semantics.
- Analyst triage is a first-release, audited human workflow kept separate from
  immutable detector observations and detector truth. Its states are Open,
  Investigating, Mitigated, Accepted Risk, and False Positive; re-observation
  reopens completed states according to the version/expiry contract.
- Every privileged action and login is written to the audit log.
- Until the admin API exists, `openvibes-admin` is local break-glass access:
  running it on a platform host grants full rights, and every command is
  audited with the OS user that ran it.

## 7. Planned Capabilities with Design Hooks

- **Hostname label.** Authenticated heartbeats carry an optional OS-reported
  hostname. PM3 stores/indexes the latest present value for operators; it is
  mutable and spoofable, and never identity or authorisation input.
- **Agent health reporting.** Heartbeats gain an optional `health` object
  (queue depth and oldest age, dropped counts, local storage errors, last
  scan and collector errors, rule-set versions and expiry). Compatible within
  schema version 1. The platform flags unhealthy and offline agents; an agent
  with no heartbeat for 15 minutes (well above the 5-minute `last_seen`
  write throttle) is offline, and many agents going silent at once points at
  the platform.
- **Rotating agent queue.** A full agent queue currently refuses new findings.
  It will instead drop the oldest pending findings, count them, and report the
  count, so agent storage stays small and current.
- **Deployment packages.** The console builds an agent installer plus a
  generated deployment profile (platform and distribution addresses, root CA,
  enrollment token, rule sets and their public keys, scan interval, proxy).
  Needs: multi-use, expiring enrollment tokens (a protocol change; the data
  model plans for it now), the agent configuration format promoted to a
  protocol contract, and per-OS agent installers (agent Milestone 6).
- **File import** of `FindingExport` and `InventoryExport` (protocol P3),
  stored as imported and unauthenticated.

## 8. Deployment

Order of support: native RPM packages with systemd first (Fedora), then
container images with Compose, then Helm. Services are static binaries driven
by config files so all three share the same artefacts. One RPM spec builds a
subpackage per service, each with a system user and a hardened unit like the
agent's. Ingest replicas sit behind an L4 (TCP passthrough) load balancer so
each replica terminates TLS and sees client certificates. Each service
exposes loopback-only `/health` and `/ready`.

## 9. Sub-project Order

1. Ingest service, admin CLI, built-in PKI, storage (protocol P1 and P2).
2. Distribution service (P4 server side).
3. File import (P3 server side).
4. Agent health reporting and rotating queue (protocol, agent, platform).
5. Admin API, RBAC, and web UI.
6. Deployment packages, multi-use tokens, deployment-profile contract.
7. Corporate issuing CA (mode 3).
8. Correlation and CMDB sync.
9. Containers, Compose, Helm.
