# VM2: Fedora Advisories and Matching — Implementation Plan

> **For agentic workers:** superpowers:executing-plans (native). Steps use checkboxes.

**Goal:** Turn stored inventories into vulnerability records from Fedora security advisories, first from an imported feed file (VM2a), then fetched hourly by a service (VM2b).

**Spec:** `docs/specs/2026-09-25-vulnerability-management-design.md` §2, §6–§8.

## Global Constraints

- Migration 0008 (next free on main; renumber if the console lands first).
- New role `openvibes_vulns`: owns advisory, vulnerability, and feed tables; reads `agents` (os columns), `package_versions`, `host_packages`; nothing else.
- New dependencies, justified in the spec: `quick-xml` (streaming XML), `ruzstd` (pure-Rust zstd); VM2b adds an HTTPS client.
- Parsing is streaming and bounded (default 512 MiB open, 64 MiB compressed); only `type="security"` updates are kept; `src` packages ignored.
- RPM version order is exact (rpmvercmp), tested against RPM's own vectors.
- A failed import or fetch never deletes existing advisories.

## Review Focus

- Kernel-style: several installed versions; only those below the fixed EVR count (Task 3 test).
- `noarch` fixed package matches any host arch (Task 3 test).
- Epoch beats version (`1:1.0` > `0:2.0`) (Task 1 vectors).
- A host fixed by an upgrade: record gets `fixed_at`; a downgrade reopens it (Task 3 test).
- An advisory whose packages the host does not have creates nothing (Task 3 test).

### Task 1 (VM2a): `rpmvercmp` in a new crate `openvibes-vulns`
- [ ] Tests first from RPM's `rpmvercmp` vectors (tilde, caret, alnum segments, leading zeros, epochs), then the implementation.

### Task 2 (VM2a): updateinfo parser
- [ ] Trimmed real Fedora 44 fixture (3 security + 1 bugfix update; a CVE only in the description; `src` and `noarch` packages; `severity` None). Tests first: security only, CVEs from reference titles and description (deduplicated), severity mapping, fixed packages without `src`, size cap enforced. Then streaming parser over `quick-xml`, input through optional `ruzstd` decoder.

### Task 3 (VM2a): store and matching
- [ ] Migration 0008 and `platform_store::vulns`: `replace_advisories(source, os_id, os_version, advisories)`, `match_release(os_id, os_version)` / `match_host(agent_id)` using the Rust comparator on candidate rows, lifecycle upsert, `summary`, `list`, `show`. Tests first as `openvibes_vulns`, covering the Review Focus.

### Task 4 (VM2a): admin commands
- [ ] `feeds import FILE --source fedora-<rel>-<arch>`, `feeds status`, `vulns summary|list|show`, audited. Tests first (CLI tests against a fixture file and a stored inventory). Docs.

### Task 5 (VM2b): the service
- [ ] Config, metalink → repomd → updateinfo download with checksum verification (tests with a local HTTPS test server serving fixture files), hourly schedule, LISTEN `inventory_changed` → `match_host`, health on 18483, `feed_sources` state. Then RPM subpackage and the end-to-end offline check (VM3).
