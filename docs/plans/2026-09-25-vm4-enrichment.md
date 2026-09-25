# VM4: KEV and EPSS Enrichment, Priority — Implementation Plan

> **For agentic workers:** superpowers:executing-plans (native). Steps use checkboxes.

**Goal:** Mark each CVE that is exploited in the wild (CISA KEV) and how likely it is to be exploited (FIRST EPSS), and sort open vulnerabilities so the ones to patch first come first, with the reason shown.

**Spec:** `docs/specs/2026-09-25-vulnerability-management-design.md` §6, §8, §9.

## Facts checked on 2026-09-25

- KEV: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`,
  1.7 MB JSON, 1,723 entries (`cveID`, `dateAdded`, `dueDate`,
  `knownRansomwareCampaignUse` = `Known`/`Unknown`); sends `ETag`.
- EPSS: `https://epss.empiricalsecurity.com/epss_scores-current.csv.gz`
  (302 to the dated file), 2.6 MB gzip, 11 MB CSV, 378,568 CVEs. First
  line `#model_version:…,score_date:2026-09-24T12:00:20Z`, then
  `cve,epss,percentile`; sends `ETag`.

## Global Constraints

- Migration 0010: `cve_enrichment` (spec §6, KEV and EPSS columns now,
  NVD and EUVD columns in VM5); `feed_sources.etag`. Role `openvibes_vulns`
  writes both.
- Every CVE EPSS scores is stored (378k small rows), so an advisory
  imported later is enriched at once, without waiting for the next EPSS
  change.
- One new dependency: `flate2` (pure-Rust backend) for the EPSS gzip.
- Sources are checked every interval with `If-None-Match`: an unchanged
  source costs one 304. Each source's URL is configurable; an empty URL
  turns it off (offline platforms import files instead).
- Parsing is bounded (download cap, 128 MiB open for EPSS); a bad
  download changes nothing and is recorded on the source.
- Priority is computed at query time (spec §9): exploited (KEV) first,
  then the highest EPSS percentile among the advisory's CVEs, then
  severity, then first seen. `vulns list` shows why.

## Review Focus

- An advisory with several CVEs takes the strongest signal of any of them (Task 3 test).
- A CVE dropped from KEV loses its KEV mark on the next import (Task 2 test).
- A 304 or an identical body re-imports nothing (Task 4 test).
- A malformed or oversized download keeps the previous enrichment (Tasks 1, 4 tests).
- Reboot-needed rows keep their own place: not counted as open or exploited in the summary (Task 3 test).

### Task 1: parsers
- [ ] Trimmed real fixtures (`kev.json`, `epss.csv.gz`). Tests first: KEV
  entries with dates and ransomware flag, invalid CVE ids skipped; EPSS
  score date from the header comment, plain or gzip, values outside 0..1
  refused, size cap. Then `enrich::{parse_kev, parse_epss}`.

### Task 2: store and import
- [ ] Migration 0010 and `platform_store::enrichment::{replace_kev,
  replace_epss}` (bulk, one transaction; KEV clears CVEs no longer listed).
  `enrich::import(client, source, content, now)` records the source in
  `feed_sources` (`kev`, `epss`). Tests first as `openvibes_vulns`. EPSS
  full-size import timed.

### Task 3: priority
- [ ] `vulns::list` orders by priority and returns KEV (due date,
  ransomware) and the top EPSS; `summary` counts exploited open ones.
  `vulns list` shows `exploited (KEV, due …, ransomware)` and
  `EPSS 0.94 (top 1%)`. Tests first (store and CLI).

### Task 4: fetching and CLI
- [ ] Config `kev_url`, `epss_url` (HTTPS; empty turns off); the service
  checks both each interval with the stored `ETag`. `feeds import FILE
  --source kev|epss`. Tests against a local server (200, 304, same body,
  bad body). Docs, packaged `vulns.toml`.
