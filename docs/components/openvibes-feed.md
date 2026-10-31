# openvibes-feed

## Purpose

The mirror side of the signed vulnerability-data feed (format:
openvibes-protocol `spec/feed-v1.md`; design:
`docs/specs/` air-gap feed spec, approved 2026-10-30). One host that can
reach the internet fetches what the platforms of a site need, signs it, and
publishes it as a static tree. Platforms read that tree through one URL, or
a bundle of it is carried into an air-gapped network and imported with
`openvibes-admin feeds import-bundle`. Sites with internet access keep
fetching directly; nothing changes for them.

It needs no database and no platform services. It is a separate command so a
DMZ host does not carry the platform. (It links the platform's fetch and
format code, so the downloads, size limits and proxy handling are exactly the
vulnerability service's.)

## Commands

| Command | Does |
|---|---|
| `openvibes-feed keygen KEY_FILE --feed-id ID --key-id K` | writes an Ed25519 key (mode 0600, never overwritten) and prints the feed id, key id, public key, fingerprint and the `feeds trust add` line to run on each platform. Compare the fingerprint there |
| `openvibes-feed build --out DIR --key KEY_FILE [--sources LIST] [--valid-days N]` | fetches the configured upstreams, stores each file as `DIR/blobs/<sha256>`, signs the manifest, and writes `DIR/feed.json` last (atomically). Prints one line per file (`new`, `unchanged`, `kept from an earlier build`, `FAILED`) and exits non-zero if any source failed, after publishing what it has |
| `openvibes-feed bundle DIR --out FILE.tar` | packs a built tree (`feed.json` first, then its blobs) into a new tar for carrying across an air gap |

`--sources` takes `fedora-<release>-<arch>`, `debian`, `ubuntu`, `rocky-linux`,
`almalinux`, `kev`, `epss`, `euvd`. A smaller bundle is a smaller feed: build
the sources an air-gapped site runs into their own directory, then bundle it.
Serving `DIR` is the site's job (any static web server).

## How a build works

- **Unchanged files are reused.** KEV, EPSS and OSV are asked with the ETag of
  the last build (a 304 keeps the blob); Fedora's updateinfo is compared by the
  digest `repomd.xml` names. EUVD's pages are merged into one response.
- **The sequence** is the larger of the last sequence plus one and the Unix
  time, so it always grows, also for a second tree built later with the same
  key. `created_at` is now and `expires_at` is `valid_days` later (default 7).
- **A source that fails** keeps its earlier file (with its old `fetched_at`)
  and the build exits non-zero; a source with no earlier file is left out. A
  build with no files at all publishes nothing.
- **Verified before published.** The feed is checked with the platform's own
  verifier before `feed.json` is renamed into place.
- **Blobs of the last two manifests are kept** so a reader that fetched the
  previous `feed.json` can still finish; older ones are removed.
- State between builds is `DIR/state.json` (ETags and the files last
  published); remove it to start over.

## Configuration

`/etc/openvibes/feed.toml` (or `--config`); every key is optional, a missing
file means the defaults. The builder has no database, so the releases the
site runs are listed here:

```toml
fedora = ["fedora-44-x86_64"]               # empty: no Fedora
osv_releases = ["debian-12", "ubuntu-24.04", "rocky-9", "almalinux-9"]
# proxy_url = "http://proxy.example:3128"
# valid_days = 7                            # 1 to 30
# metalink_url, osv_url, kev_url, epss_url, euvd_url: as in vulns.toml;
# "" leaves a source out
```

## Not here yet

Slim NVD files (step 3b), the RPM, user and daily timer (step 3c), and the
platform's own mirror sync and console views (steps 4 and 5).

## Test

`cargo test -p openvibes-feed`: a build against a local upstream (first build,
reuse by 304, a failing source, a subset tree), the result verified as a
platform verifies it, and a bundle unpacked by the platform's reader.
