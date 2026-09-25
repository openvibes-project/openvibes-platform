# openvibes-vulns

## Purpose

Vulnerability management (spec
`docs/specs/2026-09-25-vulnerability-management-design.md`): Fedora security
advisories matched against the package inventories agents report. VM2a (this
crate so far) is the offline core used by `openvibes-admin feeds import`;
VM2b adds the service that fetches feeds hourly.

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
- `feed::import(client, source, content, now)` — parse (plain or zstd by
  magic bytes), store advisories, record the feed state, re-match the
  release. A failure is recorded on the feed and changes nothing else.

## Configuration

None yet (VM2b adds `/etc/openvibes/vulns.toml`).

## Failure behaviour

- Unreadable or oversized feed: `ImportError::Parse`, recorded as the
  feed's `last_error`; stored advisories and vulnerabilities are kept.
- Reloading a feed never deletes advisories or vulnerability history.
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
