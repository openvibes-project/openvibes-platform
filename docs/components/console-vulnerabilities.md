# console-vulnerabilities (the Vulnerabilities list and a vulnerability's page)

The console's Vulnerabilities list (`/vulnerabilities`, approved screen 25)
and a vulnerability's page (`/vulnerabilities/{key}`, screen 26), from roles
step 5b (spec §10.3 and its "Plan rulings, 2026-10-22 (step 5b)", plan
`docs/superpowers/plans/2026-10-22-roles-5b-vulnerabilities-pages.md`). One
row and one page per CVE; an advisory without a CVE has its own. Triage is
still saved per host and advisory. They are built from the shared list and
detail pieces in [console-web.md](console-web.md#shared-list-and-detail-pieces),
like the Alarms pages ([console-alarms.md](console-alarms.md)).

## Interfaces

- `GET /api/v1/vulnerability-list`: the list, filtered, counted, sorted and
  paged (`crates/openvibes-console/src/vulnerabilities/list_page.rs`, store
  `vuln_list.rs`), with `vulnerabilities.read`.
- `GET /api/v1/vulnerabilities/{key}/summary`: the page above the Hosts
  table; `GET /api/v1/vulnerabilities/{key}/hosts?segment=&offset=&limit=`:
  the Hosts table (`src/vulnerabilities/page.rs`, store `vuln_summary.rs`,
  `vuln_hosts.rs`, `vuln_related.rs`), with `vulnerabilities.read`.
- `POST /api/v1/vulnerabilities/bulk`: Set state, Assign, Reopen and Add to
  case ([Bulk](#bulk)).
- `GET|POST|DELETE /api/v1/saved-views`, `GET|PUT /api/v1/list-columns/vulnerabilities`
  ([saved-views.md](saved-views.md)).
- `GET /api/v1/vulnerabilities` (the older per-advisory list) is unchanged.
  The dashboards' List tile still reads it with the old flags
  (`exploited`, `reboot`, `nofix`, `lowconf`; `views/lists/filters.ts`), not
  the new route's `signal`.
- The demo mirrors the routes: `src/demo/routes/vulnList.ts`,
  `vulnSummary.ts` and `cveFacts.ts`.

## CVE grouping

- **The key** is the CVE id, or the advisory id for an advisory without
  CVEs. A row's pairs are every host and advisory pair in reach whose
  advisory names that CVE: fixable pairs, pairs with no fix yet, and, under
  the Lower confidence signal only, CPE matches.
- One advisory naming several CVEs (a Fedora update) gives several rows that
  share its pairs: triage on one shows on the others, and each row's
  `also_covers` names the others (at most 10) for the confirmation.
- One CVE named by several advisories (Fedora and Debian) is one row listing
  them all as its covering advisories.
- Severity is the worst covering advisory's; the title is the one with the
  most hosts in reach; the assignee is One when exactly one person is
  assigned among the open pairs (others may be unassigned), Several(n) for n
  people, None when no open pair is assigned.

## The list (screen 25)

One row per CVE: `views/investigate/Vulnerabilities.tsx`
over `GET /api/v1/vulnerability-list`, with the shared FilterBar (Severity,
State, Signals, Package, Group, Assignee, and Host and Advisory as chips
only while set), SummaryLine ("N open on N hosts · N known exploited · N
with a due date · N without a fix · N unassigned"), Columns (page
`vulnerabilities`; Severity and Advisory never hidden), saved views and
paging by offset. Columns: Severity; Advisory (the title a real link to
`/vulnerabilities/{key}`, Exploited, Lower confidence, the CVE id);
Package ("fixed in V", "fixed in n versions" or "no fix yet"); CVSS; EPSS;
Hosts ("n open of m" and a bar named "n open of m hosts"); Due (CISA's
date, amber within 30 days, red when overdue); Assignee. URL sorts
`severity`, `cvss`, `epss`, `hosts` (the API's `open`) and `due`; none is
the API's priority order. Old addresses keep their meaning in place
(`vulnerabilitiesQuery` in `app/location.ts`, applied by `redirect`):
`exploited`, `reboot`, `nofix` and `lowconf=true` become one `signal`
(the first in that order wins), and old sorts no column has go. Views
the old list kept in this browser (`openvibes.v2.views./vulnerabilities`)
are imported once with the same mapping.

## The page (screen 26)

Rulings 7–12: `views/investigate/vulnerability/` at `/vulnerabilities/{key}`, one per
CVE (or per advisory without a CVE), over
`GET /api/v1/vulnerabilities/{key}/summary` and its paged `/hosts`. The
header has Set state ▾, Assign ▾ and Add to case (each covering
advisory's open hosts in reach, `{advisory_id, open_only: true}`; the
confirmation says how many open hosts change, that hosts without a fix
are left as they are, and names the other CVEs the advisories cover),
Ask about this (`header.advisory_id`, the covering advisory with the
most hosts; not offered when that is a `CPE:` version-range match) and ⋯ (Export, a CSV of its hosts; Copy link), each only
with its `can` flag; Set state and Assign go when nothing is open. The
status shows Known exploited from `header.exploited` (KEV or EUVD); the
CVE id links to NVD; CISA's due date is a banner below the header
(`DetailPage`'s `banner`). Tiles: open on
(to the Hosts card), fix available, EPSS, CVSS. Left: What to do (the
fixed build per distribution, reboot), Details (advisories, published,
confidence, vector, CWE, description), History. Right: Hosts
(`?segment=` All, Open, Mitigated, Resolved, an unknown value read as
All; `?offset=` paging by 50; ticks send `{agent_id, advisory_id}`
pairs, Reopen included; a pair with no triage (no fix or a version-range
match, which say why, or fixed by an update) has no tick; each row shows
the open cases holding the pair, "Reboot needed" next to its state when
the fix waits for one, and when it was first seen (hidden on narrow
screens), as the old panel did; without `vulnerabilities.triage` but
with `can.add_to_case`, each such pair has its own Add to case, since the
bulk route needs triage even to add to a case) and Related (open alarms
on its hosts, cases, the same packages' other CVEs, each package linking
to `/vulnerabilities?package=NAME&state=all`). `Reach.tsx` holds the
confirmation text the list and the header share. The summary resolves the
key: an advisory naming one CVE is replaced by that CVE's address, one
naming several by `/vulnerabilities?advisory=ID&state=all`
(`nav.replace`), so history keeps no dead entry. The advisory panel is
gone: `nav.open({kind: "advisory"})`, `ObjectLink` and
`?open=advisory:ID` go to the page (`pagePath` and `redirect` in
`app/location.ts`). Tests: `vulnerability/VulnPage.test.tsx`,
`e2e/demo/vuln-page.spec.ts`.

What to do counts, per distribution, every pair that is not fixed:
mitigated, accepted and false-positive pairs are counted too, since they
still need the fixed build. History shows state changes and notes; assignee
changes are not stored, so it has none. Lower-confidence pairs show on the
page only when the CVE has no other pairs, as on the list.

## Bulk

`POST /api/v1/vulnerabilities/bulk` takes items `{advisory_id}` (a CVE row
acts through its covering advisories; the advisory expands to its hosts in
reach) or `{agent_id, advisory_id}` (that pair, as asked). An advisory-wide
`state` close or `assign` changes only open pairs: no triage row, or an
accepted risk whose expiry has passed, counts as open, and fixed pairs are
never expanded. Mitigated, accepted and false-positive pairs are not
expanded either, so they keep their note and assignee and do not count
toward the 10,000-item cap (a widespread CVE with few open hosts still
changes); an advisory with no open pair left comes back in `skipped` with
reason `not open`. Hosts out
of the actor's reach are never touched. A reopen (`state: open`) is the
exception: it reopens the closed pairs and skips the open ones ("already
open"). Triage on one CVE row shows on its sibling rows, which share the
advisory's pairs.

An item may add `open_only: true` (default false; only on vulnerability
items, refused elsewhere as `invalid_items`). The Vulnerabilities list sends
it on every row, so with the Host chip set (`{agent_id, advisory_id,
open_only}`) a close or assign still changes only that host's open pair and
answers `not open` when it is closed; a named pair without it changes as asked
(the page's Hosts table). A reopen ignores it. Store:
`bulk_triage::vulnerabilities_open_only` (`vulnerabilities` is the same
with no flags).

Pairs with no fix yet cannot be triaged (triage needs a `vulnerabilities`
row): their Hosts rows have no tick, and the confirmation counts only
triageable open hosts.

In the web, a ticked list row sends each of its covering advisories (`{advisory_id,
open_only: true}`, plus `agent_id` with the Host chip) but `CPE:` matches; the server changes only their open pairs
(the closed ones are not reached) and skips pairs with no fix. A row with no fix
(`fixed.kind` none) or only `CPE:` advisories sends nothing and is left out of the
confirmation's counts; a selection of only such rows offers no Set state, Assign
or Add to case. There is no Reopen
there. `BulkBar`'s `confirm` puts what a change reaches in the Set state
dialog and makes Assign ask first too: "Changes up to N open hosts. Hosts
without a fix yet are left as they are…" and the other CVEs those
advisories also cover. A vulnerability change refreshes every
`/api/v1/vulnerabilit…` read, the list included.

## The store

### The list (`vuln_list::vuln_list`)

`vuln_list(client, &VulnQuery, &AgentScope, actor_id, today) -> VulnListPage`:
one statement returns one row per CVE (or per advisory without a CVE), the
total, the count for every value of every filter with the other filters
applied, and the summary line (roles spec §10.3; step 5b rulings 2–6).
A row's pairs are the host and advisory pairs in the `vulnerabilities.read`
scope whose advisory names that CVE: fixable ones (`vulnerabilities`), ones
without a fix (`version_vulnerabilities` through `host_packages`, on hosts
of the advisory's release) and, with the `lowconf` signal only, CPE matches
(`cpe_findings`, keyed `CPE:<cve>:<product>`) and fixable pairs mapped
below confidence 80 (`vulns/confidence.rs`); without it those are left out.
A pair's state: fixed is `resolved`, an accepted risk past `today` is
`open`, no triage row is `open`; pairs without a fix are never triaged.

Filters (one value each, all combining): state (a row matches when one of
its pairs is in it; `All` is every state), severity (the worst covering
advisory's), signal (`exploited`, `due30`: KEV due within 30 days of
`today`, overdue included, `nofix`, `reboot`, `lowconf`), package name,
group and host (they narrow the pairs a row counts), advisory (rows of the
CVEs it names) and assignee (`Assignee` from `alarm_list`; state and
assignee must hold on the same pair). Search `q` matches the key, the
covering advisory ids, the title and the package names. Sorts: priority
(exploited, EPSS percentile, severity, CVSS), severity, CVSS, EPSS, open
pairs and due; nulls last, ties by key in the same direction.

Each row: title of the covering advisory with the most pairs, worst
severity, KEV/EUVD, due, CVSS and EPSS of the CVE, package names, the fixed
version (`One`, `Several(n)` or `None`), open and total pairs, reboot, the
covering advisories, `also_covers` (other CVEs those advisories name, at
most 10) and the assignee summary (`One` when exactly one person is
assigned among the open pairs, others perhaps unassigned; `Several(n)`;
`None`). Counts: per state, severity, signal, the 50
package names with the most rows (plus the chosen one when in reach),
groups (by a per-host group bit mask, rows with a pair on a member host),
me, unassigned and people. The summary counts rows with an open pair over
every filter but the state's: open rows, hosts, exploited, with a due date,
without a fix, with no open pair assigned.

How: the fixable pairs in reach are counted per advisory, state and
assignee in one parallel pass (hosts, group side and group mask come from
the stored membership, `console_host_group_membership`, in a subquery
written in place: a CTE would keep the scan serial). Package names and
fixed versions are those of the pairs (ruling 2): an advisory with one
(name, fixed) entry in `advisory_packages` gives it to every pair, one
with several (a Fedora bundle, OSV ranges) is read from the `packages` of
its pairs in reach on the chosen group side, through
`vulnerabilities_advisory` (schema 62); the package filter and counts use
the same names. Pairs without a fix are counted through host profiles
(hosts with the same affected package versions, by fingerprint), so the
27 M no-fix pairs of the sizing fleet are never expanded. A host that also
has an unfixed fixable row for that advisory holds one pair, the fixable
one: those hosts are counted per profile, group side and mask class and
taken out of the profile's counts and masks; once the fixable row is
fixed, a package still without a fix is an open pair again. Everything
else reads that small cube. Timing (console-read.md): 1.90 s at full
reach, 1.53 s scoped, within ruling 13's 2 s. Tests: `tests/vuln_list.rs`,
`tests/vuln_list_pairs.rs`; the timing in `tests/vuln_list_timing.rs`.

### The page (`vuln_summary`, `vuln_hosts`, `vuln_related`)

`vuln_summary(client, key, &PageScopes, today) -> Lookup<VulnPageSummary>`
and `vuln_hosts(client, key, &AgentScope, HostSegment, offset, limit, today)
-> Lookup<VulnHostsPage>` (step 5b rulings 2, 7, 9, 12). The key resolves
first: a CVE is its page; an advisory with one CVE answers as that CVE
(`key` is the CVE); an advisory without CVEs is its own page; an advisory
with several answers `Lookup::SeveralCves` (sorted) when a pair is in
reach; a `CPE:` key, an unknown key and a key with no pair in the
`vulnerabilities.read` scope are `Lookup::Missing`. The pairs follow the
list (`vuln_summary_sql::pairs`, reusing `vuln_list_sql`'s `PAIR_STATE` and
`LOW_CONFIDENCE`) but are expanded host by host, as one key has few:
fixable rows, no-fix packages of the host's release (one pair per host and
advisory while a fixable row is unfixed), and the CVE's CPE matches.
Lower-confidence pairs count only when the key has no other, as the list
shows them only under their signal. The summary is one statement returning
JSON: header (title and id of the advisory with most pairs, worst severity,
names, fixed versions, open and total, assignee of open pairs, exploited
as the list's (KEV or EUVD), KEV due and ransomware), tiles (fix: `All`, `Some(n, m)` distributions or `None`; EPSS,
CVSS), what to do per distribution (OS id and version: its advisory with
most pairs, that advisory's names and fixed versions, hosts not fixed,
reboot), details (advisories, earliest issue date, confidence min/max with
the least sure basis from `vulns::confidence`, CVSS vector, CWE,
description), the last 50 triage changes on hosts in reach (newest first,
actor's display name), `also_covers` and `agents` (hosts in reach).
`vuln_related` adds the Related card: open alarms on those hosts that
`PageScopes::alarms` reaches (top three and total), open cases holding a
pair whose host `PageScopes::cases` reaches, and other keys in reach on the
same package names (via `advisory_packages`) per worst severity;
`reaches_any(client, agents, scope)` answers the page's `can` flags. The
Hosts table sorts by host name, agent id and advisory; segments are
`open`, `mitigated` and `resolved` (fixed, accepted risk, false positive),
each pair in one, `all` their sum; `triage_version` is null where triage
does not apply (a no-fix or CPE pair, or one fixed by an update, which bulk
never expands); `reboot_needed` (unfixed, fix installed, reboot pending)
and `first_seen` (the earliest sighting of the pair) come with each row. Tests: `tests/vuln_summary.rs`.

Timing of the page's summary for a kernel-sized CVE seen by a scoped viewer:
[console-read.md](console-read.md#acceptance-measurement).

A dashboard List tile on Vulnerabilities still reads `GET /api/v1/vulnerabilities`
(advisory rows), so its link says "Open list (N advisories)": the list it
opens counts CVEs, and the two numbers differ.

## Upgrading

The advisory panel became the vulnerability's page, and list rows are now
CVEs, not advisories. Old links and saved addresses redirect:
`?open=advisory:ID` goes to the CVE's page (or the advisory's own page when
it names no CVE, or the list filtered by the advisory when it names
several), and old list URLs keep their filters (`exploited`, `reboot`,
`nofix` and `lowconf=true` become `signal`; the first wins). Views saved in
the browser move to the person's account the first time they open
Vulnerabilities. Popped-out advisory windows are dropped. A bulk close or
assign on a CVE row no longer lists each closed pair as `not open` in
`skipped`: closed pairs are left out of the action (and of the cap). See
[console-web.md](console-web.md#upgrading).

## Failure behaviour

- The list answers 400 `invalid_query` naming the parameter, 401 signed
  out, 403 without `vulnerabilities.read`, 503 when the store fails. A
  refused or failed load shows the error box; the last page stays on screen
  while the next loads.
- The page's routes add 404 `vulnerability_not_found` for a missing key or
  one with no pair in reach (out-of-reach hosts are never counted or named),
  and 409 `advisory_has_several_cves` (listing them), which the web turns
  into the filtered list.
- Bulk changes skip pairs out of reach and report the rest as `skipped`
  with their reason.

## How to test

- Store: `tests/vuln_list.rs`, `tests/vuln_list_pairs.rs`,
  `tests/vuln_summary.rs`, `tests/bulk_triage.rs`; timing (ignored, run
  explicitly): `cargo test -p platform-store --test vuln_list_timing -- --ignored --nocapture`.
- Console HTTP: `crates/openvibes-console/tests/vuln_list_http.rs`,
  `vuln_page_http.rs`.
- Unit: `views/investigate/Vulnerabilities.test.tsx`,
  `views/investigate/vulnerability/VulnPage.test.tsx`,
  `demo/routes/vulnList.test.ts`, `demo/routes/vulnSummary.test.ts`.
- Demo e2e (`npm run test:e2e:demo`): `e2e/demo/vuln-list.spec.ts`,
  `e2e/demo/vuln-page.spec.ts`.
- Live e2e (`scripts/test-console-e2e.sh`): `e2e/live/vulnerabilities.spec.ts`,
  a team lead's list holds only their hosts' CVEs, its counts agree with
  the rows, and one host's state set on a CVE's page moves the row's
  "n open of m" and its sibling CVE's.
