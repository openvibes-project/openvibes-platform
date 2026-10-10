# openvibes-fetch

Purpose: the one component that makes outbound requests for the console
assistant's opt-in internet lookups (one process per request). This page
covers the wire protocol, the query filter, and level 1 (OSV and Bodhi
references). Web search and the systemd units are added later.

## Protocol (`protocol.rs`)

Request, one JSON object, tagged by `kind`:

```json
{"user":"alex","kind":"reference","id":"CVE-2026-1234"}
{"user":"alex","kind":"search","query":"openssh 9.8 regression"}
```

Response, tagged by `result`:

```json
{"result":"ok","source":"nvd","items":[{"title":"..","snippet":"..","url":".."}]}
{"result":"refused","code":"blocked"}
```

Refusal codes: `off`, `blocked`, `invalid`, `unavailable`, `too_large`.

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
The systemd unit also sets `RuntimeMaxSec` (Task 7).

Config `fetch.toml` (unknown keys rejected): `database_url`, optional
`proxy_url`.

## Level 1 (`serve.rs`, `http.rs`, `osv.rs`, `bodhi.rs`)

- Level 0: `off`, no request made. An ID failing `is_public_id`: `invalid`.
  `search` is `off` below level 2 and `unavailable` at level 2 until web
  search is built.
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
