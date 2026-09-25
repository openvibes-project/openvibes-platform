# openvibes-vulns

## Purpose

Vulnerability management (spec
`docs/specs/2026-09-25-vulnerability-management-design.md`): Fedora security
advisories matched against the package inventories agents report. The crate is
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
  fixed version.
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
```

Packaged as the `openvibes-vulns` RPM with its unit and user
`openvibes_vulns` ([packaging.md](packaging.md)).

## Failure behaviour

- Unreadable or oversized feed: `ImportError::Parse`, recorded as the
  feed's `last_error`; stored advisories and vulnerabilities are kept.
- Reloading a feed never deletes advisories or vulnerability history.
- A failed check (network, digest mismatch, unreadable content) is logged
  and recorded as the feed's `last_error`; other releases are still
  checked and the next interval retries.
- `/ready` is 503 while the database is unreachable or at another schema.
- **Known difference from `dnf`:** checked on this Fedora 44 host against
  the real feed (385 advisories, 3,622 packages, import and match 0.47 s),
  matching found 2 of the 3 advisories `dnf advisory list --security`
  lists. The third is a kernel update whose fixed version is installed
  while the host still runs the previous kernel (no reboot yet); `dnf`
  flags it because older kernels remain installed, this crate counts the
  fix as installed. Reporting "fix installed, reboot needed" needs the
  agent to report the running kernel (planned).

## Test

```sh
eval "$(scripts/test-db.sh)"
cargo test -p openvibes-vulns   # rpmvercmp, parser (real trimmed F44 fixture), matching and lifecycle
```
