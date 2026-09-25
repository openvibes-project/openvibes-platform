# Other distributions via OSV.dev — Implementation Plan

> **For agentic workers:** superpowers:executing-plans (native). Steps use checkboxes.

**Goal:** Match Debian, Ubuntu, Rocky Linux and AlmaLinux hosts against OSV.dev, with "no fix available" shown.

**Spec:** `docs/specs/2026-09-25-osv-distributions-design.md` (approved 2026-09-25).

## Global Constraints

- Protocol first: P10 (optional `source`, `source_version` on `InstalledPackage`) lands in `openvibes-protocol`, then the agent, then the platform pins it.
- Migration 0013; one new dependency (`zip`, deflate only, on `flate2`).
- Version order is exact per format: RPM (built) and dpkg (new, cross-checked against `dpkg --compare-versions`).
- Light: no full re-download on each check; NVD backfill only for CVEs of open vulnerabilities.
- Every milestone is its own PR with green CI; docs in the same change.

## Review Focus

- A Debian binary whose `Source:` carries its own version (`Source: foo (1.2-3)`) is matched by that source version, not its binary version (D0, D3 tests).
- Several binaries of one source at different versions: the newest decides, as with RPM (D3 test).
- `introduced` above the installed version: not affected (D3 test).
- A record whose `affected[]` spans releases only touches the host's release (D2 test).
- Over 5,000 changed records falls back to the release's `all.zip` (D4 test).

### D0: protocol P10 and the agent
- [x] (protocol #12, agent #11; amended for RPM: protocol #13, agent #12)
- [x] Protocol: schema and spec for `source`, `source_version`; valid and invalid fixtures.
- [ ] Agent: the dpkg collector reads `Source:` (name, and version in parentheses when present); tests on a real Debian status file excerpt; the report carries them; docs.

### D1: dpkg version order
- [x] (platform #27) `dpkgver::compare` with dpkg's own test vectors; cross-check of a few thousand real version pairs against `dpkg --compare-versions` in a Debian container; an example binary like `vercmp`.

### D2: OSV parser, store, Rocky and Alma (with D3 in one change)
- [x] `osv::parse` over trimmed real Rocky, Alma, Debian and Ubuntu records; migration 0013 (`introduced`, `last_affected`, nullable fixed, name kind); advisory ids `ID/source`; import of an `all.zip` filtered to releases; Rocky and Alma matching through the RPM path; tests first.

### D3: Debian and Ubuntu matching
- [x] Group installed binaries by source; newest source version; ranges with `introduced`, `fixed`, `last_affected`; "no fix available" rows; `vulns list`/`summary` show it; tests first; a real Debian 12 dump against a real status file.

### D4: fetching, NVD scope, CLI, docs
- [x] First import from `all.zip`; hourly `modified_id.csv` (ETag) and changed records; fallback over 5,000; host release mapping; `feeds import FILE --source debian-12`; NVD backfill limited to open vulnerabilities' CVEs; local-server tests; a live check; component docs.

### D5: scale check (and no-fix storage per package version, spec §8)
- [x] The scale example with a Debian package list and the Debian 12 dump; results in `docs/sizing.md`.
