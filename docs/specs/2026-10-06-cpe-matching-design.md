# CPE matching from NVD applicability data

Status: implemented (step 3 of `2026-10-06-vulnerability-confidence-design.md`).
Requested 2026-10-06. Written from real NVD API 2.0 responses
(CVE-2024-3094, CVE-2024-6387, CVE-2023-38545).

## Why

Fedora hosts are flagged only from Fedora's released advisories. A CVE with
no released update yet is invisible. Red Hat's Security Data API does not
cover Fedora (checked: none of the `package_state` entries of 60 recent CVEs
names it), so the usable source is NVD's own applicability data: which
upstream product and versions each CVE affects.

## What NVD gives us

Each CVE has `configurations[].nodes[].cpeMatch[]`:
`{vulnerable, criteria: "cpe:2.3:a:haxx:libcurl:*:...", versionStartIncluding,
versionStartExcluding, versionEndIncluding, versionEndExcluding}`. A node
without version bounds names one exact version in `criteria`
(`cpe:2.3:a:tukaani:xz:5.6.1:*:...`). Seen in practice: a CVE can list dozens
of unrelated products (netapp, microsoft); some configurations are `AND`
pairs (firmware plus hardware, application plus OS); NVD often lists
distributions explicitly (`o:fedoraproject:fedora:37`).

## Design

1. **Store a slim table**, not NVD's JSON: `cve_applicability(cve_id, part,
   vendor, product, version_start, start_inclusive, version_end,
   end_inclusive, exact_version, lists_fedora)`, filled while the existing NVD
   sync reads pages, for **application (`a`) products only**, `vulnerable =
   true`, from single `OR` nodes. `AND` configurations are skipped in this
   step (counted, shown in the source's status). Rejected CVEs are skipped.
   Only products matching a package name any host reports (or a curated alias)
   are kept, so the table stays small. A full NVD crawl is about 140 pages, 2,000
   a page: 14 minutes unkeyed, 1.5 minutes with a key. Needs a migration
   (next free number; check `main`, whoever merges second renumbers).
2. **Package to product mapping**, a curated alias table in code
   (`libcurl` and `curl` to `curl`/`libcurl`, `openssl-libs` to `openssl`,
   `python3` to `python`, ...), else a package's source-package name or its
   own name equal to the CPE product (case-insensitive, `_` and `-` equal).
   Vendor is ignored (CPE vendors are unreliable) but recorded as evidence.
3. **Version test.** The package's upstream version (the RPM `version`, not the
   release) is compared with the bounds using the RPM version order. Fedora
   rebases rather than backports for most packages, so this is a fair test;
   Fedora-specific patches are why the confidence stays below advisory-grade.
4. **Advisory wins.** If any Fedora advisory for the host's release names the
   CVE, the CPE finding is not created: the advisory path decides (open if the
   host is behind, closed if fixed). CPE only reports what no advisory
   covers, so it never contradicts Fedora.
5. **Confidence** (shown with the 0 to 100 % bar, below 50 hidden by the
   filter): exact product-name match and version in range 60; match through an
   alias 55; exact single-version CPE 55; plus 15 when NVD itself lists
   `fedoraproject:fedora` at the host's release; never above 75. The
   console's "How this was matched" shows the CVE, the CPE, the range and the
   installed version.
6. **Lifecycle.** Findings are keyed by host and CVE, shown as "no fix
   yet" with the mapping evidence, and closed when a Fedora advisory for the
   CVE appears (then the advisory finding takes over) or when the installed
   version leaves the range.
7. **Scope of this change.** Fedora hosts only. Debian, Ubuntu, Rocky and
   Alma already track unfixed CVEs through OSV.

## As built

- Own tables (migration 0039): `cve_applicability` (ranges),
  `cve_applicability_products` (the products kept) and `cpe_findings` (one row
  per installed package version, release and CVE, so a fleet's shared package
  versions are evaluated once). They are separate from `vulnerabilities` on
  purpose: no existing count, host flag, case or assistant answer changes.
- The crawl reads NVD by last-modified windows from 2010 with its own sync
  point (`nvd-cpe`); a product that appears later restarts it. Findings are
  recomputed after every feed check and every crawl (hourly by default).
- The console shows them only when the list asks for a minimum confidence of
  75 or less (the vulnerabilities view hides everything under 80 unless
  "Lower confidence" is on), as `CPE:<CVE>:<product>` advisories marked
  "Possible". They cannot be added to a case.
- Not done: findings have no closed history (they disappear when no longer
  true); `AND` configurations; exclusive range starts; other distributions.

## Decided

- CPE findings do not count in "open vulnerabilities" totals (the user,
  2026-10-06): shown separately and by filter, so the existing counts keep
  meaning "a distribution says so".
- Notifications and cases: unchanged; CPE findings cannot be added to a case.
- `AND` configurations: skipped now; revisit with real false-negative counts.

## Test plan

Real NVD fixtures (the three CVEs above, trimmed), the RPM-version range
edge cases (inclusive and exclusive bounds, `*` bounds, epochs ignored),
alias mapping, advisory suppression, lifecycle, and a live check against
Fedora 44 reporting how many CPE-only findings appear and a sample of them.
