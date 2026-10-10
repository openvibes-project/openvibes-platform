# openvibes-fetch

Purpose: the one component that makes outbound requests for the console
assistant's opt-in internet lookups (one process per request). This page
covers what exists so far: the wire protocol and the query filter (pure, no
I/O). The network, limits and unit are added later.

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

## Residual risks

A lexical filter cannot catch integer or hex IPv4 notations (`167772165`,
`0x0a000005`), short or spaced IPv4 forms, other-script look-alikes
(Cyrillic `е`), a non-breaking hyphen in a host name, or deliberate encoding (spelled-out digits, base64). The
filter stops accidental leaks and the common forms; it is not a defence
against a model told to smuggle data out.

## Test

`cargo test -p openvibes-fetch`
