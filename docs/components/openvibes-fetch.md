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
- `check_query(query, deny)`: level-2 web search. Lowercases the query and
  refuses (`blocked`) when it is over 200 characters, contains `://`,
  contains any deny term as a substring (agent IDs, host and user names,
  internal domains; the caller passes them lowercase; a substring match also
  covers FQDNs and mixed case), or has a token that is an IPv4 address
  (optional `:port`), an IPv6 address (also in brackets) or a MAC address
  (`:` or `-`). Tokens split on whitespace and `,;()"'[]<>=/`. Plain words
  such as `www.example.org` or `9.8.1` are not refused.

## Test

`cargo test -p openvibes-fetch`
