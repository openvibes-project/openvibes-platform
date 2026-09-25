# openvibes-vulns

## Purpose

Vulnerability management (spec
`docs/specs/2026-09-25-vulnerability-management-design.md`): Fedora security
advisories matched against the package inventories agents report, and each
CVE enriched with CISA KEV (exploited in the wild) and FIRST EPSS (likelihood
of exploitation) so the vulnerabilities to patch first come first. The crate is
the offline core used by `openvibes-admin feeds import` and the
`openvibes-vulns` service that fetches feeds.

## Interfaces

- `rpmver::{rpmvercmp, compare_evr}` — RPM version order, exactly: RPM's own
  test vectors pass, and the `vercmp` example agrees with `rpm.vercmp` on
  4,000 real version and release pairs.
- `updateinfo::{read, read_zstd}` — streaming parse of Fedora's
  `updateinfo.xml[.zst]`: security advisories only; CVEs from reference
  titles and descriptions; severity (`None` → unrated); fixed binary
  packages (`src` dropped); a hard size cap after decompression.
- `matching::{match_release, match_host, evaluate}` — a host is affected
  when its **newest** installed version of a fixed package's name, with a
  compatible architecture (same, or either side `noarch`), is lower than the
  fixed version. For the running kernel (`kernel`, `kernel-core`,
  `kernel-modules*`), when the host reports it (protocol P9): an installed
  fix that is not yet running keeps the vulnerability open with
  `reboot_needed` and the running version in its package entry; a reboot
  into the fix closes it with the next inventory.
- `repodata::{metalink, updateinfo_location}` — Fedora's mirror list (the
  current `repomd.xml` digest first, then alternates for lagging mirrors;
  https then http mirrors) and repository index (updateinfo location under
  `repodata/`, digest, size).
- `fetch::{Fetcher, check}` — metalink over HTTPS (plain HTTP only on an
  exact loopback host) → a mirror whose `repomd.xml` has the current digest
  (an alternate only when no mirror has it, so checks never flip between
  versions) → updateinfo verified against `repomd.xml` → import. Unchanged
  content is not downloaded. Live on Fedora's mirrors: first check ~1.6 s
  (2 MB), later checks report unchanged.
- `service::run(config, health, shutdown)` — the daemon: checks every
  Fedora release its hosts report at start and every interval, and
  re-matches a host within a second of ingest's `inventory_changed`
  notification (dedicated LISTEN connection, reconnecting every 30 s).
- `feed::import(client, source, content, now)` — parse (plain or zstd by
  magic bytes), store advisories, record the feed state, re-match the
  release. A failure is recorded on the feed and changes nothing else.
- `enrich::{parse_kev, parse_epss, import}` (VM4) — KEV catalog JSON
  (entries without a valid CVE id or date skipped; `Known` ransomware use)
  and EPSS CSV, gzip or plain (score date from the header comment; any bad
  row refuses the file; 128 MiB open cap). `import` stores them in
  `cve_enrichment` and records the source (`kev`, `epss`) in
  `feed_sources`. Real files (2026-09-24): KEV 1,723 entries parse in 3 ms;
  EPSS 378,567 scores parse in 95 ms (`examples/enrich_parse.rs`).
- `fetch::check_enrichment(client, fetcher, source, url, now)` — sends the
  stored ETag: a 304 or a body identical to the last import is unchanged.
  Live: first run KEV 0.19 s, EPSS 4.2 s (378k rows upserted, 42 MB
  table); later runs 304 in under 0.1 s each, also through EPSS's
  redirect. The service checks both every interval, after the feeds.
- `enrich::{parse_nvd, parse_euvd}` (VM5) — an NVD `cves/2.0` page: the
  newest CVSS version scored (4.0, 3.1, 3.0, 2.0), within it NVD's own
  over a CNA's; CWE ids deduplicated; the English description (4 KiB
  cap). An EUVD search page: one record per CVE alias of each entry.
  2,000 real NVD records parse in 98 ms.
- `sources::sync_nvd(client, nvd, now)` — NVD is kept **only for CVEs
  advisories name** (Fedora 44 names 944; a full mirror would be 1.8 GB):
  each run asks for what changed since the last one (last-modified
  windows of at most 120 days, 2,000 a page, each finished window saved
  as the sync point), then one by one for named CVEs not yet seen (up to
  1,000 a run; CVEs NVD does not know are asked again after 7 days).
  Requests are 6 s apart, 0.6 s with an API key (NVD's limits); any error
  (403, 429, network) stops the run, keeps what was done, and the next run
  resumes. Runs in its own task, so pacing never delays re-matching. Live:
  10 real CVEs backfilled in 56 s; the first fill of Fedora 44 takes about
  95 min, 10 min with a key.
- `sources::check_euvd(client, fetcher, url, page_size, now)` — EUVD's
  exploited list, page by page (live: 1,735 CVEs, 18 pages, 6 s); an
  unchanged list is not re-imported. Checked every interval with KEV and
  EPSS.
- **Priority** (spec §9), computed when read by `platform_store::vulns`:
  exploited (a CVE on KEV or EUVD's list) first, then the highest EPSS
  percentile among the advisory's CVEs, then severity, then the highest
  CVSS, then oldest first. Advisories without a scored CVE come after
  scored ones.

## Configuration

`openvibes-vulns [--config PATH]`, default `/etc/openvibes/vulns.toml`
(unknown keys refused):

```toml
database_url = "postgresql:///openvibes?host=/run/postgresql&user=openvibes_vulns"
health_listen = "127.0.0.1:18483"      # loopback only
check_interval_minutes = 60            # 15 to 1440
metalink_url = "https://mirrors.fedoraproject.org/metalink?repo=updates-released-f{release}&arch={arch}"
arch = "x86_64"                        # its feed lists every architecture's fixes
# proxy_url = "http://proxy.example:3128"
max_download_bytes = 67108864
kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
epss_url = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
nvd_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
# nvd_api_key_file = "/etc/openvibes/nvd.key"   # mode 0600 or stricter
euvd_url = "https://euvdservices.enisa.europa.eu/api/search"
```

`kev_url`, `epss_url`, `nvd_url` and `euvd_url` must be HTTPS; an empty
value turns that source off (offline platforms import files with
`openvibes-admin feeds import FILE --source kev|epss|nvd|euvd`). The NVD
key file must not be readable by group or others, holds one key, and the
key is sent only in the `apiKey` header, never logged.

Packaged as the `openvibes-vulns` RPM with its unit and user
`openvibes_vulns` ([packaging.md](packaging.md)).

## Failure behaviour

- Unreadable or oversized feed: `ImportError::Parse`, recorded as the
  feed's `last_error`; stored advisories and vulnerabilities are kept.
- Reloading a feed never deletes advisories or vulnerability history.
- A failed check (network, digest mismatch, unreadable content) is logged
  and recorded as the feed's `last_error`; other releases are still
  checked and the next interval retries.
- A bad KEV or EPSS download (unreachable, not the expected format, a bad
  row, oversized) is recorded on its source; the stored enrichment is kept.
  A CVE that leaves the KEV catalog loses its mark on the next import;
  EPSS scores are only added or updated. The same holds for EUVD (a CVE
  leaving its exploited list loses the mark) and NVD (a failed run keeps
  its sync point and resumes).
- A release is matched in batches of 500 hosts (`MATCH_BATCH`; one query
  and one transaction each; 10,000 hosts re-matched in 38 s). A feed is
  recorded as current only after its match succeeds; a failed match is
  recorded as the feed's error and retried by the next check.
- After storing a feed's advisories the import runs `ANALYZE` on the
  advisory tables, so matching right after it is planned with current
  statistics (scale check, `docs/sizing.md`: 10,000 hosts imported and
  matched in 32 s).
- `/ready` is 503 while the database is unreachable or at another schema.
- **Compared with `dnf`:** checked on this Fedora 44 host against the real
  feed (385 advisories, 3,622 packages, import and match 0.47 s), matching
  found 2 of the 3 advisories `dnf advisory list --security` lists. The
  third was a kernel whose fix was installed while the host still ran the
  previous kernel. With the running kernel reported (protocol P9) it is
  open as "fix installed, reboot needed". Agents before P9 report no
  kernel, and the installed fix counts for them.

## Test

Scale check (`examples/scale.rs`, VM spec §10): N synthetic hosts with a
real package list, stored and matched against a real feed; see the usage
in the file and the results in `docs/sizing.md`.

```sh
eval "$(scripts/test-db.sh)"
cargo test -p openvibes-vulns   # rpmvercmp, parser (real trimmed F44 fixture), matching and lifecycle,
                                # KEV/EPSS parsing (trimmed real files), import, conditional fetch, priority
```
