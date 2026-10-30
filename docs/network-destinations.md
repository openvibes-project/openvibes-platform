# Network destinations (egress)

Everything the platform may connect to on the internet, so a firewall or proxy
team can decide what to allow. Checked against `main` on 2026-10-30 (code and
configuration read; no live fetches made).

Agents never go to the internet for OpenVIBES: they talk only to the platform
(ingest 18423, distribution 18424, both inbound to the platform). Only the
platform host makes outbound calls, and only the ones below. All use HTTPS
(port 443) except where noted.

## 1. While the platform runs

| # | What for | Program | Host(s) | Pattern | Setting that moves or turns it off |
|---|---|---|---|---|---|
| 1 | Fedora advisories (updateinfo) | `openvibes-vulns` | `mirrors.fedoraproject.org`, then **a mirror it names** (see [section 3](#3-the-fedora-mirror-problem)) | metalink, then `repomd.xml` and `updateinfo.xml.zst` (~2 MB) from one mirror; hourly, a download only when the index changed | `metalink_url` |
| 2 | Debian, Ubuntu, Rocky, Alma advisories | `openvibes-vulns` | `osv-vulnerabilities.storage.googleapis.com` | per release; first sync downloads the ecosystem's `all.zip` (Ubuntu ~760 MB, Debian ~73 MB, Rocky ~5 MB), later syncs fetch only changed records | `osv_url` (`""` = off) |
| 3 | Exploited in the wild | `openvibes-vulns` | `www.cisa.gov` | one small JSON, conditional (ETag) | `kev_url` |
| 4 | Likelihood of exploitation | `openvibes-vulns` | `epss.empiricalsecurity.com` (redirects) | ~40 MB gzip, conditional | `epss_url` |
| 5 | CVSS, weakness, description, affected ranges | `openvibes-vulns` | `services.nvd.nist.gov` | per-CVE and windowed requests, paced 6 s apart (0.6 s with an API key); first fill of Fedora 44 about 95 min | `nvd_url`, `nvd_api_key_file` |
| 6 | Exploited list | `openvibes-vulns` | `euvdservices.enisa.europa.eu` | about 18 pages | `euvd_url` |
| 7 | "Newer release available" on About | `openvibes-console` | `api.github.com` (platform and agent `releases/latest`) | two requests, cached 6 h (15 min after a failure), 4 s timeout; a failure is shown as "unavailable", nothing else is affected | none yet |
| 8 | Reference lookups (opt in, off by default) | `openvibes-fetch` | `api.osv.dev`, `bodhi.fedoraproject.org`, and the admin's own SearXNG if level 2 is on | one request per assistant question | Settings › Assistant › Internet lookups; `proxy_url` in `fetch.toml` |

Rows 1 to 6 use `proxy_url` from `vulns.toml` (or the console setting) when it
is set. The `openvibes-fetch` service has its own `proxy_url`. Row 7 has no
setting of its own; I did not check whether it follows a proxy set in the
service's environment.

Nothing else is outbound at run time. Rules are signed offline by the operator
and published by the console to its own database, and the ATT&CK data is only
read by a development script.

## 2. Installing and updating

| What for | Host(s) |
|---|---|
| `install.sh`, the OpenVIBES dnf repository and its key | `openvibes-project.github.io` |
| Package files and release notes | `github.com` (release assets and pages), `api.github.com` |
| Fedora packages (PostgreSQL and dependencies) and OS updates | Fedora's repositories through the same metalink mirrors as row 1 (`mirrors.fedoraproject.org` and the mirror it names); your own dnf configuration decides |
| The assistant's model (optional, 2.7 GB) | `huggingface.co` (and the CDN it redirects to) |
| llama.cpp for the assistant | built into the `openvibes-llm` package, nothing fetched on the host |

An install with **no** network at all uses the offline kit
([offline-kit.md](components/offline-kit.md)): one signed tar of about 95 MB
holding the platform, the rule sets and the Fedora packages they need. The
model is carried in separately.

## 3. The Fedora mirror problem

Row 1 cannot be written down as a list of hostnames. `mirrors.fedoraproject.org`
answers with a metalink: the current digest of `repomd.xml` and a list of third
party mirrors, which differs by location and time. `openvibes-vulns` takes the
first mirror that serves the current digest, so the host that carries your data
may change between runs. dnf (OS updates, installs) has the same property.

What this means today:

- **Allowing hostnames is not enough** for Fedora data. Either the proxy lets
  the platform reach any HTTPS or HTTP mirror, or Fedora data has to come from
  somewhere else.
- **`metalink_url` is not a mirror address.** It must return a metalink XML
  document, over HTTPS (HTTP only on loopback, for tests). Setting it to one
  mirror's directory does not work. A site that wants a fixed mirror has to
  serve its own metalink, whose `repomd.xml` digest is current; a static file
  would go stale each time Fedora publishes.
- **Air-gapped alternative:** download `updateinfo.xml.zst` on a connected
  machine and import it (section 5).
- The OSV, KEV, EPSS, NVD and EUVD rows are fixed hostnames and can be
  allowed one by one. NVD is the chatty one.

A single destination for all of this is the subject of the air-gap feed
proposal (`planning/airgap-data-feed-proposal-2026-10-30.md`); this page
describes what exists now.

## 4. Allowing it through a proxy

Set `proxy_url = "http://proxy.example:3128"` in `/etc/openvibes/vulns.toml`
(or Settings › General › Vulnerability feeds) and, if the assistant's lookups
are on, in `/etc/openvibes/fetch.toml`. The proxy must allow the hosts in
sections 1 and 2 that apply, with these sizes in mind:

- first Ubuntu sync about 760 MB, first EPSS download about 40 MB;
- no request needs any other port than 443 (HTTP only if the metalink lists a
  plain-HTTP mirror and the proxy allows it);

To turn a source off instead of allowing it, set its URL to `""` in the same
place (rows 2 to 6; the same line in `vulns.toml` documents this for KEV and
EPSS).

## 5. No network: import by hand

On a connected machine, download the file; carry it to the platform; import it
with `openvibes-admin feeds import FILE --source SOURCE`, which re-matches
immediately and audits the import. Sources: `fedora-<release>-<arch>`
(`updateinfo.xml[.zst]`), `rocky-N`, `almalinux-N`, `debian-N`, `ubuntu-YY.MM`
(the ecosystem's OSV `all.zip`), `kev`, `epss`, `nvd` (an API response page)
and `euvd`. See [openvibes-admin.md](components/openvibes-admin.md) for the
exact lines. Imported files are not signed: whoever carries the file vouches
for it, and the console does not yet show how old the data is. `feeds status`
lists each source's last check.

## 6. Quick list for a firewall request

```
mirrors.fedoraproject.org      + the Fedora mirrors it names (see section 3)
osv-vulnerabilities.storage.googleapis.com
www.cisa.gov
epss.empiricalsecurity.com
services.nvd.nist.gov
euvdservices.enisa.europa.eu
api.github.com                 (About page only; optional)
api.osv.dev, bodhi.fedoraproject.org   (assistant lookups only; optional)
openvibes-project.github.io, github.com, huggingface.co   (install and updates only)
```
