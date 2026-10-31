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
`almalinux`, `kev`, `epss`, `euvd`, `nvd`. A smaller bundle is a smaller feed: build
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
- **NVD is carried in full, as slim year files.** The builder reads NVD's API by
  last-modified windows of up to 120 days, exactly as the platform's own sync does,
  and keeps one gzip file per CVE year (`nvd-2024.json.gz`): per CVE the newest CVSS,
  weakness ids, the English description (4 KiB) and the application ranges the
  platform matches (single `OR` nodes, `vulnerable` only; `AND` pairs, negated nodes
  and exclusive starts are left out, as the platform leaves them out today) and an
  `os` list of every operating system NVD marks affected (`vendor:product:version`,
  at most 256, sorted; the platform uses the Fedora entries today). The
  first read is about 210 requests, so roughly 20 minutes unkeyed (6 s apart, 0.6 s
  with a key) and about 45 MB gzipped in all; later builds read only what NVD changed
  since and rewrite only the years that changed. Progress is saved after every
  window in `DIR/nvd-state.json`, so an interrupted first read resumes. **NVD joins the
  feed only once a first read has reached the present**, so a platform never imports half
  of it; until then the build says so and the other sources publish as usual. If NVD is
  unreachable later, the files from the last finished read stay in the feed. Version
  bounds are cut to 64 bytes as the API sync cuts them, a range the platform's reader
  would refuse is left out, and every year file is read back with the platform's own
  parser before it is kept, so a file the platform refuses is never published. During
  a first read, superseded year blobs pile up (a few GB) until the build ends and
  prunes them.
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
# metalink_url, osv_url, kev_url, epss_url, euvd_url, nvd_url: as in vulns.toml;
# "" leaves a source out
# nvd_api_key_file = "/var/lib/openvibes-feed/nvd.key"   # asks NVD every 0.6 s, not 6 s
```

## The package (the mirror)

The `openvibes-feed` RPM is only for the mirror machine; no other package
needs it and the platform never creates a key. It installs its own account
`openvibes-feed`, the config above, and a **daily timer that is enabled at
install** (by preset) but idle: the service only runs once the signing key
exists. State is `/var/lib/openvibes-feed/` (mode 0755; the key in it is
0600): `feed.key` and the tree `site/` for a web server to serve.

```sh
sudo -u openvibes-feed openvibes-feed keygen /var/lib/openvibes-feed/feed.key \
    --feed-id mysite --key-id k1      # prints what each platform must trust
sudoedit /etc/openvibes/feed.toml     # list the releases the site runs
sudo systemctl start --no-block openvibes-feed   # first build now; later ones run daily
journalctl -fu openvibes-feed         # follow it (the first NVD read takes about 20 minutes)
```

Run `build` and `bundle` by hand as `sudo -u openvibes-feed openvibes-feed ...`:
run as root they leave root-owned files and lock in the tree, and the next
timer run then fails. **Remove everything** in Setup also stops, disables and
removes this package when it is installed, and deletes its signing key.

`build` and `bundle` take a lock on `site/.build.lock`: a second one started
while one runs stops with "another build or bundle is running" and writes
nothing, so the timer and a hand-run build never race. The lock file is not
part of the feed.

## Serving the tree

The tree is plain files; any static web server works. Its root must be
`/var/lib/openvibes-feed/site` and never `/var/lib/openvibes-feed`, which also
holds the signing key. The files in `site/` are world-readable; the key sits
in the parent directory with mode 0600, so keep the root exactly `site/`.
Two examples:

```sh
# nginx: root /var/lib/openvibes-feed/site; autoindex off;
# On an SELinux host, label the tree for the web server first:
sudo semanage fcontext -a -t httpd_sys_content_t '/var/lib/openvibes-feed/site(/.*)?'
sudo restorecon -R /var/lib/openvibes-feed/site
# any host, for a quick test:
python3 -m http.server 8080 --directory /var/lib/openvibes-feed/site
```

Platforms read the tree through the mirror URL once step 4 lands; until then,
`openvibes-admin feeds import-bundle` takes either the tree directory or a
bundle `.tar`.

## Not here yet

The platform's own mirror sync and console views (steps 4 and 5).

## Test

`cargo test -p openvibes-feed`: a build against a local upstream (first build,
reuse by 304, a failing source, a subset tree; NVD read by windows from a fake
API, only the changed year rewritten), the result verified as a
platform verifies it, a bundle unpacked by the platform's reader, and a second build
or bundle refused while the tree's lock is held.

`scripts/systemd-e2e.sh` (the "End to end under systemd" CI job) installs the
RPM next to a running platform: the timer is enabled and waiting, the service
is skipped without a key, and with one the sandboxed service builds a feed from
a local upstream that the platform verifies and imports from the tree and from
a bundle.
