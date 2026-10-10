# openvibes-fetch

Purpose: the one component that makes outbound requests for the console
assistant's opt-in internet lookups (one process per request). This page
covers the wire protocol, the query filter, and level 1 (OSV and Bodhi
references), level 2 (web search through the admin's SearXNG) and the
systemd units.

## Protocol (`protocol.rs`)

Request, one JSON object, tagged by `kind`:

```json
{"user":"alex","kind":"reference","id":"CVE-2026-1234"}
{"user":"alex","kind":"search","query":"openssh 9.8 regression"}
```

Response, tagged by `result`:

```json
{"result":"ok","source":"osv.dev","items":[{"title":"..","snippet":"..","url":".."}]}
{"result":"refused","code":"blocked"}
```

`source` is `osv.dev`, `bodhi.fedoraproject.org` (Fedora IDs) or the
SearXNG `host[:port]`. Refusal codes: `off`, `blocked`, `invalid`,
`unavailable`, `too_large`.

## Filter (`filter.rs`)

- `is_public_id(id)`: level-1 identifiers only. Uppercase prefix of 2-8
  letters, `-`, at least 3 digits, then another `-` or `:` part (so `CVE-2026`
  is not an ID); only `[A-Za-z0-9:-]`, at most 64 characters.
- `check_query(query, deny)`: level-2 web search. Lowercases the query (and
  each deny term) and refuses (`blocked`) when it is over 200 characters;
  contains `://`, `scheme:/`, `scheme:\` or a percent-encoded `%XX`;
  contains full-width characters (U+FF00-U+FFEF) or non-ASCII digits; contains
  a deny term (agent IDs, host and user names, internal domains) as a whole
  word (not embedded in a longer `[a-z0-9]` word, so user `al` does not block
  "algorithm", host `db` does not block "mongodb", but `web-01.corp.example`
  and `mail.corp.example` are caught); or contains an address. Addresses are
  found by scanning maximal runs of address characters, whatever surrounds
  them (`root@10.0.0.5`, `ip:10.0.0.5`, `10.0.0.5-10.0.0.9`): IPv4 (four
  parts of at most 255, so `126.0.6478.126` is a version, but a version such
  as `1.2.3.4` is refused), IPv6 (also `fe80::`, `::1`, `fe80::1%eth0`,
  bracketed), MAC (`:` or `-` separated, or Cisco `aabb.ccdd.eeff`).
  Defanged forms (`10[.]0[.]0[.]5`, `(.)`, `[dot]`) are normalised first;
  Mathematical Alphanumeric Symbols are refused like full-width characters;
  a deny term is a word; a Windows path `c:\\dir` is not a URL.
  Plain words such as `www.example.org` or `std::vector` are not refused.

## Process contract (`main.rs`)

`openvibes-fetch [--config /etc/openvibes/fetch.toml]` serves one connection
(systemd `Accept=yes`): reads one JSON request from stdin (at most 8 KiB;
more or malformed is `invalid`), reads the setting and deny list from
PostgreSQL, writes one JSON response to stdout, exits 0. One journal line to
stderr: user, kind and ID or query, outcome; never response text. A database
or proxy failure answers `unavailable`. Deadlines: the stdin read and the
whole answer each have 20 s (stdin timeout: `invalid`, then exit; answer
timeout: `unavailable`); the HTTP call is bounded by its own 10 s timeout.
The deadline is `openvibes_fetch::DEADLINE`; the console waits 25 s, longer,
so even a timeout answer reaches it. A client that hung up is no error (the
write's EPIPE is ignored, exit 0). The systemd unit also sets
`RuntimeMaxSec=30` and `CollectMode=inactive-or-failed`.

Config `fetch.toml` (unknown keys rejected): `database_url`, optional
`proxy_url` (set by hand), optional `platform_domain` (written by Setup's
console step: the public origin's host). That host, and its parent when the
parent still has a dot (`example.com` for `vibes.example.com`, not `lan` for
`vibes.lan`), join the deny list (`FetchConfig::platform_names`).

The deny list from PostgreSQL holds agent IDs, host names and the first
label of every dotted host name (`web-01` for `web-01.corp.example`),
console user names and the internal domains.

`outside.rs` holds what the model sees of a lookup (the `[web:N]` data
shape and the fixed notes), shared by the console and the evaluation.

## Packaging (`packaging/rpm/openvibes-fetch.*`)

- `openvibes-fetch.socket`: `/run/openvibes-fetch/fetch.sock`, 0660
  `root:openvibes-console`, `Accept=yes`, `MaxConnections=8` (systemd refuses a ninth concurrent
  connection; the console then answers with the unreachable note). Enabled by a preset (`80-`, before Fedora's `90-default` disable-all).
- `openvibes-fetch@.service`: one instance per connection as user
  `openvibes-fetch`, stdin/stdout on the socket, stderr to the journal,
  `RuntimeMaxSec=30`, `CollectMode=inactive-or-failed`, no capabilities, `ProtectSystem=strict`, seccomp,
  `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`.
- Failure: no database or no outbound network answers `unavailable`; a
  missing `fetch.toml` exits non-zero with one stderr line.
- Test: `scripts/check-rpm.sh` (units, modes); `scripts/systemd-e2e.sh`
  (level 1 with no outbound answers `unavailable` within 15 s, level 0
  answers `off`). SELinux is not tested in CI (the container is not
  enforcing). Verified in the lab on 2026-10-10 (Fedora 44 VM, enforcing,
  0.2.9 packages of this branch, real network): level 1 (OSV) and level 2
  (SearXNG on loopback, Test connection, a search refused as `blocked`)
  gave no AVC denial (`ausearch -m avc,user_avc,selinux_err` empty). Each
  request runs as `system_u:system_r:unconfined_service_t:s0` (like the
  console and `llama-server`); the socket is `var_run_t`. So the fetch
  service needs no SELinux module of its own; it is no more confined
  than the console.
- Hardening beyond the signer's: `ProtectProc=invisible`, `ProcSubset=pid`,
  `PrivateIPC=yes`, `RemoveIPC=yes`, `IPAddressDeny=link-local multicast`
  (blocks the cloud metadata address; loopback stays open for a proxy).
- Setup enables and starts the socket with the console when the package is
  installed; an offline kit without the package skips it with a note.
- A client must keep reading until the reply (`socat -t 25`): the default
  0.5 s linger drops a reply that takes longer, and the process then ends on
  a broken pipe.

## Level 2 (`searxng.rs`)

- `search` at level 2 runs `check_query` first (`blocked`, no request), then
  GETs `{searxng_url}/search?q=<percent-encoded>&format=json` (a trailing `/`
  on the stored URL is ignored). No stored URL: `unavailable`.
- Allowlist: `Client::with_searxng(url)` adds exactly the prefix
  `{url}/search?` for that process (so plain `http://` works only for the
  validated private SearXNG URL); every other URL still needs the fixed hosts.
  Same limits as level 1 (no redirects, 256 KiB, 10 s).
- The stored URL is validated again here with the console's save-time rule
  (`searxng::valid_url`, shared): `https://` any host, `http://` only on
  localhost, loopback, RFC 1918 or `fc00::/7` literals, no user info, `?`,
  `#` or whitespace, valid port. Invalid: `unavailable`, no request.
- Proxy: a SearXNG with a plain `http://` URL or a loopback/private IP
  literal host is reached directly (a second proxy-less agent for that
  prefix), never through `proxy_url`, so the query and the internal address
  stay on the LAN. OSV and Bodhi keep the proxy.
- Extraction: `results[]`, at most 5 with an `http://` or `https://` URL
  (`javascript:`, `data:` ... dropped), title cut to 200, snippet (`content`)
  to 300, URL to 500 characters. `source` is the SearXNG `host[:port]`.
  Not JSON or no `results`: `unavailable`.
- Test: `tests/serve.rs` with `tests/fixtures/searxng-openvibes.json` (12
  results, one 900-character snippet, one `javascript:` URL; synthetic).

## Level 1 (`serve.rs`, `http.rs`, `osv.rs`, `bodhi.rs`)

- Level 0: `off`, no request made. An ID failing `is_public_id`: `invalid`.
  `search` is `off` below level 2 (see Level 2 above).
- `FEDORA-...` goes to `https://bodhi.fedoraproject.org/updates/{id}`, every
  other ID to `https://api.osv.dev/v1/vulns/{id}`. The URL is built only from
  a checked ID and its host must be on the allowlist, else `unavailable`.
- Limits: connect 5 s, total 10 s, no redirects (a 3xx or any non-200 is
  `unavailable`), body over 256 KiB `too_large` (read through `take(256 KiB + 1)`), non-JSON or unexpected JSON
  `unavailable`. A reference ID also passes `check_query` against the deny
  list (`blocked`), since a well-formed ID can carry a host name. Proxy from `proxy_url`.
- Extraction is by JSON path only. OSV: one item (title `id: first summary
  line`; snippet: summary, else details, cut to 1,000 characters, plus
  `package: fixed in a, b` per affected package with a `package.name`; git
  commit ranges give no versions here), then up to 5 `https://` reference
  URLs as further items titled `reference`. Bodhi: `update.title`,
  `update.notes` cut to 1,000 characters plus `fixed in` the `builds[].nvr`.
  A record without `affected` is fine. Each fixed version and NVR is cut to
  100 characters, the fixed-versions text to 400, and the whole snippet stays
  within 1,000 characters (the summary gives way). Cuts fall on character
  boundaries.

## Residual risks

A lexical filter cannot catch integer or hex IPv4 notations (`167772165`,
`0x0a000005`), short or spaced IPv4 forms, other-script look-alikes
(Cyrillic `е`), a non-breaking hyphen in a host name, or deliberate encoding (spelled-out digits, base64). The
filter stops accidental leaks and the common forms; it is not a defence
against a model told to smuggle data out.

## Test

`cargo test -p openvibes-fetch`. `tests/serve.rs` drives `serve::handle` with a
fake `Http` and real OSV/Bodhi responses saved in `tests/fixtures/`; `tests/http.rs` tests the real client against a
loopback listener (redirect, oversize, 500).
