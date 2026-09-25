# Other distributions via OSV.dev — design

Status: approved by the user, 2026-09-25. Extends the vulnerability management
spec (`2026-09-25-vulnerability-management-design.md`) beyond Fedora.

## 1. Decisions (the user, 2026-09-25)

- First milestone: **Debian, Ubuntu, Rocky Linux, AlmaLinux**. Alpine
  later (it needs an apk collector in the agent and apk version order).
- Vulnerabilities without a fixed version are **shown, labelled "no fix
  available"**, and ranked by the same priority.
- Unchanged principles: light (no full mirrors), exact version order per
  package format, lifecycle records, offline import, quiet by default.

## 2. Facts checked (2026-09-25)

| | Agent reads | OSV download | Names | Version order |
|---|---|---|---|---|
| Debian | dpkg | `Debian:12/all.zip` 43 MB, 29,492 records (CVE-* plus DSA-*) | **source** packages (`?arch=source`) | dpkg |
| Ubuntu | dpkg | `Ubuntu:24.04:LTS/all.zip` 142 MB | **source** packages; `ecosystem_specific.binaries` lists binaries | dpkg |
| Rocky | RPM | `Rocky Linux/all.zip` 5 MB, all releases (no per-release file) | binary packages | RPM (built) |
| AlmaLinux | RPM | `AlmaLinux/all.zip` 6 MB, all releases | binary packages | RPM (built) |

- Base URL `https://osv-vulnerabilities.storage.googleapis.com/`; every
  file has an ETag.
- `<Ecosystem>/modified_id.csv` (per ecosystem, not per release; Debian
  3.4 MB, Ubuntu 3.4 MB, 68,607 lines) lists `modified,id`, newest first.
- `<Ecosystem>/<id>.json` serves one record.
- One Debian record covers every release (`affected[]` per
  `Debian:11`, `Debian:12`, …). Of 5,000 Debian CVE records, 15,430
  affected entries had a fix and 427 (about 3%) had none. Severity:
  Debian `ecosystem_specific.urgency`; Ubuntu `severity[]` (CVSS vector
  and Ubuntu priority); Rocky and Alma in the summary ("Critical: …").
- The agent's dpkg collector does not report a package's source name or
  source version; dpkg's status file has them (`Source:`, optionally with
  a version in parentheses; absent when equal to the binary's).

## 3. Scope

1. **Protocol P10:** `InstalledPackage` gains optional `source` and
   `source_version` (dpkg only; omitted when equal to the binary's). The
   agent reports them.
2. **dpkg version order** in `openvibes-vulns`: epoch, upstream, revision;
   `~` before everything, letters before non-letters. Tested with dpkg's
   own vectors and cross-checked against `dpkg --compare-versions` in a
   Debian container, as RPM was against `rpm.vercmp`.
3. **OSV adapter:** parse OSV 1.x JSON records; keep `affected[]` entries
   for the releases hosts run; `ECOSYSTEM` ranges with `introduced`,
   `fixed` and `last_affected` events; CVE ids from the id, `aliases`,
   `upstream` and `related`.
4. **Store:** advisories keyed by record and release (`CVE-2024-1234
   /debian-12`), since one OSV record spans releases; `advisory_packages`
   gains `introduced` and `last_affected`, and `fixed` may be absent;
   a package entry says which name it matches (binary, or source).
   Migration 0013.
5. **Matching:** unchanged for RPM (Rocky, Alma: binary name, RPM order).
   Debian and Ubuntu: a host's installed binaries are grouped by source
   name (from P10; the binary's own name when absent) and the newest
   source version decides. Affected when `introduced` ≤ installed and
   installed < `fixed` (or ≤ `last_affected`); with no fix, a
   vulnerability is open with `"fixed": null`.
6. **Fetching:** a release's first import downloads its `all.zip`
   (Rocky and Alma: the ecosystem's, filtered to the releases hosts run).
   Later checks, hourly as today, read `modified_id.csv` with its ETag and
   fetch only records changed since the last check, one by one; over
   5,000 changes the release is re-downloaded instead. Offline: `feeds
   import FILE --source debian-12` takes an `all.zip`. New dependency: a
   zip reader (the `zip` crate, deflate only, via the `flate2` already
   used); entries are read one by one with a size cap.
7. **Host releases:** from os-release, `debian` 12 → `Debian:12`,
   `ubuntu` 24.04 → `Ubuntu:24.04:LTS` (or without `:LTS`, as OSV names
   it), `rocky` 9.4 → `Rocky Linux:9`, `almalinux` 9.4 → `AlmaLinux:9`.
8. **Severity** mapped onto the existing scale: critical; important
   (high); moderate (medium); low (low, negligible, unimportant);
   unrated. KEV, EPSS, NVD and EUVD enrichment apply through the CVE ids
   unchanged.
9. **NVD scope:** Debian 12 alone names about 29,000 CVEs, which would take
   48 hours to backfill without a key. NVD backfill is limited to CVEs of
   **open** vulnerabilities (still thousands at most); the hourly
   last-modified query keeps them current.
10. **CLI:** `vulns list` shows `no fix available` instead of
    `installed -> fixed`; `vulns summary` counts them on their own line.

## 4. Out of scope

Alpine (next milestone); other OSV ecosystems (language packages);
Red Hat and SUSE (OSV has them; later, same adapter).

## 5. Milestones

| # | Milestone | Exit |
|---|---|---|
| D0 | Protocol P10; agent reports dpkg source and source version | fixtures; agent tests on a real Debian status file |
| D1 | dpkg version order | dpkg vectors; cross-check in a Debian container |
| D2 | OSV parser; migration 0013; Rocky and Alma import and matching | parser tests on trimmed real records; real Rocky 9 dump imported |
| D3 | Debian and Ubuntu matching by source; "no fix available" | matching tests; real Debian 12 dump against a real Debian status file |
| D4 | Fetching (all.zip first, then modified_id.csv); NVD scope; CLI; docs | local-server tests; live check; systemd e2e unchanged |
| D5 | Scale check with a Debian fleet | `docs/sizing.md` |

## 6. Risks

- **OSV record quality varies by distribution;** the tests use trimmed
  real records for each.
- **Ubuntu's first import is 142 MB per release.** It is a one-time
  download per release; later checks are the change list plus the
  changed records.
- **`last_affected` without `fixed`:** versions up to it are affected and
  no fixed version is named, so such a vulnerability is open and labelled
  "no fix available"; a newer installed version is not affected.

## 7. Amendments found while building D2 (2026-09-25)

Checked against real systems; each changes the design above.

- **OSV's per-release files are frozen.** `Debian:12/all.zip`,
  `Ubuntu:24.04:LTS/all.zip`, `Alpine:v3.20/all.zip` and the rest were last
  modified in October 2024. Only the whole-ecosystem files are current
  (Debian 73 MB, Ubuntu 757 MB, Rocky 5 MB, Alma 6 MB), so imports read
  those and keep the host's release. Ubuntu's first import is therefore a
  757 MB download (streamed, not stored); later checks use the change
  list (D4).
- **Rocky Linux names source RPMs** (`systemd` for `systemd-libs`);
  AlmaLinux names binaries. Protocol P10 is amended so RPM packages report
  their `SOURCERPM` name too, and Rocky is matched by source like Debian
  and Ubuntu (RPM order).
- **One record kind per distribution:** Debian `DEBIAN-CVE-*`, Ubuntu
  `UBUNTU-CVE-*`, Rocky `RLSA-*`, Alma `ALSA-*`. Notices that repeat them
  (DSA, DLA, DTSA, USN), legacy `CVE-*` ids and bug-fix advisories are
  skipped, so nothing is listed twice.
- **`unimportant` (Debian) and `negligible` (Ubuntu) are skipped:** the
  distributions mean "not a security problem in practice", and their own
  tools hide them. Quiet by default.
- **Results on real systems:**
  - Rocky 9.8 (151 packages): 40 of `dnf updateinfo --security`'s 40
    advisories, none extra.
  - Debian 12 (136 packages): all 156 CVEs `debsecan` lists, plus 8 more
    that Debian's security tracker marks vulnerable in bookworm (`no-dsa`)
    and `debsecan` omits.
