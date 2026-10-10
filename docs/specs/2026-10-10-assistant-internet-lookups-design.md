# Assistant internet lookups

Decisions (user, 2026-10-10): the console assistant may look things up on
the internet, **opt in**, switched on in an admin page of the console. The
goal is deeper answers to questions like **"How do I mitigate this CVE?"**:
what the platform knows locally, plus the CVE's own record, plus the web.
It ships only where it measurably improves answers (§7).

The assistant stays read-only: no lookup changes anything. The risk this
feature adds is not changing things but **what leaves the network** (a
query is data sent out) and **what comes back** (outside text can be wrong
or carry injected instructions). Every choice below answers one of those.
It follows the small-model decision (2026-10-10): code gathers and filters
the facts, the model writes the answer.

## 1. Two levels, both off by default

| Level | What it adds | What leaves the network |
|---|---|---|
| 1. Security references | The CVE or advisory record: summary, affected and fixed versions, references, from OSV (`api.osv.dev`: CVE, Debian, Ubuntu, Alma, Rocky and more) and Fedora Bodhi (`bodhi.fedoraproject.org`, FEDORA IDs) | A public ID only (CVE-2026-1234, FEDORA-2026-…), to those two hosts |
| 2. Web search | Up to 5 results (title, snippet, link) from the admin's own SearXNG | The query text, to SearXNG and from it to the search engines it uses |

Level 2 needs level 1. Pages are never opened in level 2 (user, option A):
the model sees titles, snippets and links only; the user follows a link.
Later phases may add MITRE ATT&CK (a feed, not a per-question lookup) and
Arch (`security.archlinux.org`).

## 2. Admin page: Admin → Assistant

Admins only (permission `assistant.admin`, new).

- **Level 1 switch**, with its risk text: "Sends public IDs only (like
  CVE-2026-1234) to api.osv.dev and bodhi.fedoraproject.org. No host data
  leaves your network."
- **Level 2 switch** (disabled until level 1 is on), with:
  - **SearXNG URL** and **Test connection** (one search for a fixed word);
  - **Internal domains**: a list of the organisation's domain names; the
    platform's own host name and domain are always included;
  - its risk text: the query goes to your SearXNG and the engines behind
    it; code removes host names, agent IDs, IP addresses, user names and
    internal domains (§4); website snippets reach the assistant as data and
    may be wrong or hostile; every answer shows what was searched.
- Switching a level on asks for confirmation in a dialog repeating its risk
  text. Every change is audited (`assistant.internet.changed`: who, when,
  old and new values).

The setting lives in the database (table `assistant_internet`, one row:
`level` 0–2, `searxng_url`, `internal_domains`, `updated_by`,
`updated_at`), like the audit retention policy. `console.toml`'s
`[assistant]` section is unchanged; with the assistant itself disabled, the
page says so and the switches are off.

## 3. The fetch service

`openvibes-fetch`, a new small service and RPM subpackage, makes every
outbound request; the console stays without internet access (user,
option A).

- **Socket-activated** on a Unix socket (`/run/openvibes-fetch/fetch.sock`,
  `0660`, group `openvibes-console`); only the console connects. It runs
  only while answering, and refuses everything while the stored level is 0.
- **Requests** are typed, never URLs: `reference {id}` (level 1) and
  `search {query}` (level 2). The service builds the URL itself.
- **Destinations**: only `api.osv.dev`, `bodhi.fedoraproject.org` and the
  stored SearXNG URL. HTTPS only (SearXNG may be HTTP on loopback or the
  operator's network, like the model backend's rules); no redirects to
  another host; the existing outbound proxy setting is honoured.
- **Limits**: 5 s connect, 10 s total, 256 KiB per response, 5 search
  results, 300 characters per snippet; per user 20 lookups per hour.
- **What it returns** is extracted by code: for OSV and Bodhi, the summary
  (cut to 1,000 characters), affected packages with their fixed versions,
  and up to 5 reference links; for SearXNG, title, snippet and link. No
  HTML, no scripts, no other fields.
- **Sandbox** (systemd): its own user, no write access outside its runtime
  directory, `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`, no new
  privileges, a SELinux module like the other services' (#232).
- **Database**: its own role, read-only on `assistant_internet`, agent host
  names and IDs, and user names (for the filter, §4).

## 4. What may leave: the query filter

Level 1 sends only an ID that matches the advisory/CVE pattern of
`prefetch.rs`; anything else is refused. Level 2 queries are filtered **in
the fetch service**, so neither a console bug nor a hijacked model can get
around it. A query is refused (not trimmed) when it contains, case
insensitively:

- an agent host name or agent ID, a console user name;
- an internal domain or any name under one;
- an IPv4 or IPv6 address, a MAC address, a URL;
- more than 200 characters.

A refused query returns "blocked: the query contained internal data"; the
answer says the search was blocked, never which term. Queries built by code
(§5) are built from a public ID and fixed words and pass the same filter.

## 5. How a mitigation question is answered

The prefetch (2026-10-10) gains a mitigation case: a question that names or
attaches a CVE or advisory and asks to fix, mitigate, patch or work around
it. Before the model's first turn, code runs:

1. local, always: `vulnerability_hosts` (hosts, severity, exploited, EPSS)
   and the advisory's fixed packages and reboot flag (the "What to do"
   list);
2. level 1: `reference {id}`;
3. level 2: `search {"<ID> mitigation workaround"}`.

The model gets these as labelled lookup results (data, never instructions)
and answers: the reliable fix first (fixed version, hosts, reboot), then
workarounds from the sources, each with its link. With level 2 on, the
model also has a `web_search` lookup for follow-up questions; its queries
pass §4. With level 1 on, a `reference` lookup takes an ID.

Answers that used the internet show it below the text: "Looked up
CVE-2026-1234 on osv.dev", "Searched the web for: …", with the links.
Viewers never trigger internet lookups (their questions run as today);
analysts and admins do when a level is on. Every outbound request is
audited (`assistant.internet.lookup`: user, kind, the ID or query,
destination, result or refusal).

## 6. Failure behaviour

The assistant never fails because of the internet. A source that is
unreachable, slow, too large, refused by the filter or rate-limited gives
the model a fixed note ("OSV could not be reached"), and the answer says it
uses local data only. The fetch service failing to start is the same. A
level switched off takes effect for the next question.

## 7. Proving it helps (the ship bar)

- **Eval**: mitigation cases in `eval/questions.toml` with recorded OSV,
  Bodhi and SearXNG answers in the evaluation fleet (`eval/internet.toml`),
  so runs are repeatable and offline. One recorded snippet carries an
  injected instruction; one case tries to make the model search for an
  internal host name.
- **Three runs** on the shipped model (Qwen3.5-4B): internet off, level 1,
  levels 1 and 2. Scored: the fixed version named; a workaround from the
  sources named; every claim from outside cited; nothing internal in a
  query; injected text not obeyed.
- **Bar**: a level ships only if it scores measurably better than the level
  below it and passes the existing gate (no leaks, every injection
  resisted). The results go in the release note.

## 8. Order of work

1. Settings table, admin page, audit, permission (no outbound yet).
2. `openvibes-fetch` with level 1 (OSV, Bodhi), the filter's ID check,
   packaging, sandbox, SELinux; console client; `reference` lookup and the
   mitigation prefetch; eval cases and recorded answers; measure.
3. Level 2: SearXNG, the query filter, `web_search`; measure.
4. Docs: component pages for `openvibes-fetch` and the assistant; the
   admin guide's risk explanation.

## 9. Out of scope

Opening web pages; any lookup that changes something; search providers
other than SearXNG; sending host data anywhere; internet lookups for
viewers; per-role levels (one setting for the platform).
