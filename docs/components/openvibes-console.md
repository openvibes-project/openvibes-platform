# openvibes-console

The human-facing OpenVIBES web application and versioned administration API.
It is a same-origin React/TypeScript application embedded in an Axum service.
The approved product and technical contracts are in
[`../specs/2026-09-23-console-product-design.md`](../specs/2026-09-23-console-product-design.md)
and
[`../specs/2026-09-23-console-technical-design.md`](../specs/2026-09-23-console-technical-design.md).

The console owns browser assets, `/api/v1`, local human authentication,
server-side sessions, RBAC enforcement, and service-account API
authentication. It does not accept agent credentials, implement agent
protocol endpoints, sign rules, operate CA private keys, edit host
configuration, or control system services. Local host administration belongs
to `openvibes-admin tui`.

## Status

The design is approved. C0–C5 are implemented; PR #29 merged on 2026-09-27.
The vulnerability and grouped-finding API and UI work is implemented on the
follow-up branch. It adds scoped fleet summaries, prioritized vulnerability
views, CVE enrichment, grouped rule views, endpoint inspection, and atomic
bulk triage. The merge-readiness check still requires the complete local gate,
browser E2E, and CI/review confirmation for the final commit.
C3 local authentication is
implemented through pre-auth, login, session validation/refresh, logout, and
password hash upgrade. When both `database_url` and `public_origin` are set,
the executable connects to PostgreSQL, requires schema version 26, and serves
the authenticated router. Otherwise it serves the C0 development router,
where `/api/v1/session` remains fail-closed. The authenticated router now
serves permission-checked, SQL-scoped agent summary, list, detail, and
certificate routes (the agent summary also carries `platform_version`, the
console's own version: the Agents view marks agents older than it, since
agent and platform release together. It is readable by every signed-in
role, being in the packages anyway, so nothing admin-only belongs next to
it), plus finding summary, latest, history, and grouped rule
reads. Vulnerability summary, prioritized list, and advisory/CVE detail are
available under the caller's `vulnerabilities.read` scope. Access
control has a global read inventory for roles, bindings, and asset groups,
plus CSRF-protected local-user role binding changes and audited asset-group
selector management. Enrollment-token, service-account, and signed rule-bundle
read/preview/publish flows are available through the console API and UI;
private signing and trust-key management remain local CLI operations.
Global audit event search and retention-policy
reads/updates are available; `/audit` provides a filtered, cursor-paginated
activity screen without exposing event details or request source metadata.
Global `audit.export` users can download the exact visible filters as bounded
CSV; the export audit event records only filters, row count, and digest.
`GET`/`PUT /api/v1/assistant-internet` (permission `assistant.admin`, global
scope, `If-Match`, Origin and CSRF on writes) read and change the assistant's
internet-lookup setting: level 0 off, 1 fetch pages, 2 fetch pages and search
through SearXNG. The SearXNG URL must be `https://`, or `http://` only on
loopback or a private address; level 2 requires it. Domains must be lowercase
names (at most 50). Each change writes an `assistant.internet.changed` audit
row; `platform_domain` (the public origin's host) is always filtered. An
unreadable setting counts as level 0.
The Administer menu's Assistant page (`/assistant-settings`, `assistant.admin`)
switches the two levels: "Look up security references" and "Search the web"
(enabled only while level 1 is on). Turning a level on opens a confirmation
dialog repeating its risk text; level 2 also asks for the SearXNG URL and
stays disabled until it is an http(s) URL. Turning off needs no confirmation.
A textarea holds the internal domains, one per line, beside the always-included
platform domain. When `/api/v1/assistant/status` says the assistant is
unavailable the page says so and the switches are off. The Test connection
button is not built yet. The demo serves the setting from memory.
The first-account bootstrap and account recovery CLI is available through
`openvibes-admin user`. The embedded UI has a login form, session gate, and
sign-out action, and its production Overview, Agents, Findings, Audit, and
Access control pages use authenticated APIs. Agent detail also provides a
reason-required revoke operation; the store enforces the effective global or
asset-group scope in SQL and commits revocation with its audit row.
Enrollment-token listing, one-time secret creation with idempotent retries,
and audited revocation are available through global `tokens.read`,
`tokens.create`, and `tokens.revoke` capabilities. The token secret is stored
only as the same SHA-256 digest used by ingest, and is never repeated on a
replayed create response. The opt-in local assistant uses the `assistant.use`
capability plus the caller's current agent and finding read scopes. Its model
can call only bounded agent, finding, vulnerability, and rule lookups, each
within the caller's permission for that console page; browser history is in memory
and prompts and responses are omitted from audit and logs. See
[`console-assistant.md`](console-assistant.md).

The C1 seeded read slice is
implemented: a
loopback-only Axum process with separate public and health routers, an embedded
React shell, exact static-asset routing, enforced security headers, locked
frontend tooling, checked Rust-generated OpenAPI, and CI build validation.
One checked frontend contract now supplies the browser-route and public-asset
inventory to both Rust and TypeScript, and the production output carries a
SHA-256 build stamp over the exact source inputs and generated files.
The shell uses native platform interaction primitives: a Popover API help menu
with arrow-key navigation, a modal `<dialog>` with focus return, and the native
theme `<select>`. They pass the target CSP and axe checks in the real-browser
suite without adding a component dependency.
The supplied logo references are represented by reviewed, self-contained
transparent SVG paths: a compact mark and light- and dark-surface wordmarks.
The expanded shell follows the active theme while the compact shell, favicon,
and application manifest use the mark. ImageMagick deterministically renders
the committed 32, 192, and 512 pixel PNG derivatives from that SVG source.
Production data routes remain unavailable until their later milestones
provide SQL-enforced authorisation. The C1 `dev-seed` feature exposes a synthetic read-only API
only on the loopback development router; it is not part of the production
OpenAPI snapshot or package. The seeded API also supplies deterministic
vulnerability and grouped-finding data so both pages can be reviewed locally. It does not serve
alarms or cases; those are reviewed with the in-browser demo or against a database.

### Vulnerability review and X-M7 grouped findings

`GET /api/v1/vulnerabilities/summary`, `/vulnerabilities`, and
`/vulnerabilities/advisories/{advisory_id}` require `vulnerabilities.read`.
Every query applies the caller's asset scope in SQL before returning records.
The summary reports severity, affected hosts, exploited advisories, no-fix
matches, and reboot-needed hosts, plus `feed_last_imported_at` (RFC 3339,
null until an advisory feed has imported: then zero counts mean "not set
up", not "nothing found"). The bounded prioritized list uses the same
ranking as `vulns list`; host, advisory, severity, CVE, and fixed-state filters
are available, with exploited and reboot-needed filters applied before the
store's fleet row cap. Host names that match multiple visible hosts are refused
with their visible IDs; an agent ID selects one exact host. Advisory details
return CVE enrichment only if at least one affected host is visible to the
caller.

`GET /api/v1/compliance/groups` shows each rule set and rule once in the recent
window, after scope filtering. Its endpoint route pages visible current
reporters with a cursor-bound window (the response's `since` is reused for
subsequent pages) and can include older matches on request. Triage counts are
typed by state in OpenAPI. `~unknown` represents
pre-P6 findings with no rule set. `POST .../triage` accepts at most 100
endpoint/version pairs and performs one all-or-nothing state transition.
Stale selections return 412 and no endpoint is updated. Imported rows are
labelled with their installation ID and remain limited to global readers.

The web console's Vulnerabilities and Findings views
([console-web.md](console-web.md)) own the two read experiences. They render API priority and provenance as supplied,
link host/advisory views, preserve opaque cursors, disable triage for readers,
and send mutations with the session CSRF token. The demo server supplies
synthetic API models for these routes.

### Installed software (assets v1, `src/software.rs`)

All three need `agents.read` and are scoped like the agents. A scoped
caller's counts include only hosts in the scope, and a host or package no
visible host has is a 404. Revoked agents are not hosts and never count;
imported hosts do. "Fixable vulnerable" means an open
vulnerability **with a fix** naming the package on that host;
vulnerabilities without a fix (thousands on a Debian host) are left out
and stay in the Vulnerabilities view.

- The agent list and detail (`AgentView`) also carry `os_id`, `os_version`
  and `running_kernel` from the last inventory, and `inventory_at` (the
  time the software list is "as of"). Each is null until an inventory
  arrives.
- `AgentView.rule_sets` lists the rule sets the agent reported in its latest
  health report (`id`, `version`, `expires_at_ms`, `refused`), and
  `rule_sets_at` is when that report was written. Both are empty or null for
  an agent that has not sent a health report. The Host page's Rule sets
  section shows them, flags a set behind the published version (when the
  user holds `rules.read`) and a refused bundle.
- `AgentView.alarms` (`AgentAlarmsView`: `state` `on`/`off`, `source`
  `ebpf`/`audit`, `reason`, `text`, `fix` in words, `command` to copy when
  there is one, `fault`) is the host's threat-alarm status from the same
  report (`platform_store::alarms_status`); absent before a report and for
  hosts that are not online. Codes and words are on the platform-store page.
- `GET /api/v1/agents/{agent_id}/packages`: the host's packages by name
  (manager, name, epoch, version, release, arch, `fixable_vulnerable`).
  `q` is a case-insensitive substring of the name (at most 128 bytes).
- `GET /api/v1/software`: one row per (manager, name) over visible hosts,
  by name, with `hosts`, `versions` (distinct epoch/version/release) and
  `fixable_vulnerable_hosts`, plus the package's open advisories on visible
  hosts: `advisories` (distinct, fixable or not), `no_fix_advisories`,
  `worst_severity` and `exploited` (KEV or EUVD). Filters are `q`,
  `fixable=true` and `multiple_versions=true` (more than one version in
  use on visible hosts).
- `GET /api/v1/software/{manager}/{name}`: the versions in use (most hosts
  first, each with its `advisories` count), the open `advisories` on the
  package (most urgent first: exploited, EPSS, severity, CVSS; each with
  CVEs, hosts affected and `fixed_in`, absent while there is no fix; at
  most 200) and a page of the hosts that have it (hostname, version, arch,
  last contact, `fixable_vulnerable`). Advisories come from the hosts'
  matches (fixable) and from the package versions the hosts have (no fix);
  no migration is involved.

Cursors are opaque (base64url JSON of the keyset), and `limit` is 1–100
(default 50). Measured on 1,000 hosts × 2,000 packages with 50 k open
vulnerabilities: a software page takes ~235 ms, the `fixable` filter
~365 ms, a 100-host scope 78 ms, and one host's packages 6 ms
(`platform-store` test `measure_the_fleet_aggregate_on_1000_hosts`).

### Open ports and running services (P15, `src/ports.rs`)

Assets v2, from each agent's `HostServices` report (stored by ingest in
`host_listeners` and `host_services`, replaced per report). Reads need
`agents.read` and are scoped like agents; fleet counts leave revoked
hosts out.

- `GET /api/v1/agents/{agent_id}/services`: the host's listeners (exposed
  first, then by port: protocol, address, port, `exposed`, and the owning
  `service`/`program` where the agent saw it) and services (unit,
  programs, processes, `run_as`), with `reported_at` and `owners`
  (`complete`, or `partial` when some owners were not visible: see the
  agent's opt-in `owners.conf`), and `refused_at`/`refused` when ingest
  refused the host's last report since the last good one (`too_large`,
  `invalid`, `wrong_agent`; the Ports and Services tabs then say so above
  the older lists). 404 outside the caller's scope.
- `GET /api/v1/ports`: one row per (protocol, port) with `hosts`,
  `exposed_hosts` and up to 8 owning services; `exposed=true` keeps ports
  exposed on at least one host.
- `GET /api/v1/services`: one row per unit with `hosts`.
- `GET /api/v1/ports/{protocol}/{port}` and `GET /api/v1/services/{unit}`:
  the visible, non-revoked hosts that listen on the port (once per bound
  address: `address`, `exposed`, `service`/`program`) or run the unit
  (`programs`, `processes`, `run_as`), with `hostname` and
  `last_seen_at`. They are keyset-paged by hostname like a package's
  hosts (`limit` 1–100, default 50; opaque `cursor`). An unknown
  protocol, a port outside 1–65535 or a bad cursor is 400; 404 when no
  visible host has it. The fleet Ports and Services rows open these as
  panels, each host linking to its Host page.
- The host view also carries `truncated`: the agent cut a list to the
  protocol limits. The Ports and Services tabs then say "some ports (or
  services) not listed" in their "As of" line.

The fleet lists are not paged: distinct ports and units across a fleet
stay in the low thousands.

### Live agent presence (`src/presence.rs`)

- `GET /api/v1/agents/events` (`agents.read`): a `text/event-stream`. It sends
  `event: presence` when the fleet's online set changed (a host came online or
  went offline), a keep-alive comment every 20 s, and closes after 60 s (the
  browser reconnects, which re-checks its session). Events carry no data: the
  browser rereads the scoped agent endpoints. One shared task compares
  `online_fingerprint` every 5 s, only while a stream is open. Not in the
  OpenAPI snapshot (it is not JSON).

### Threat alarms (P14, `src/alarms.rs`)

- `GET /api/v1/alarms` (`alarms.read`): newest `last_seen` first, scoped
  to the caller's agents; filters `agent_id`, `rule_id`, `severity`,
  `state`, `suppressed` (closed-by-suppression alarms are hidden unless
  true); keyset cursor on `(last_seen, id)`, `limit` 1–100. A resend moves
  `last_seen`, so the list is a live view.
- **Live in the web app** (`web/src/app/liveAlarms.ts`): while the tab is
  visible and the user has `alarms.read`, the app asks for the newest
  active alarm (`limit=1`) every 5 s. A change refreshes alarm views; an
  alarm whose `first_seen` is newer than any seen so far shows a toast and
  recounts the active alarms for the menu (an older alarm repeating only
  refreshes). No websocket; one small request per poll, paused while
  the tab is hidden. The poll sends `X-OpenVIBES-Background: 1`, and such
  requests are checked as usual but never extend the session's 30-minute
  idle expiry, so an unattended console still signs out.
- **Menu counts** (#117): Findings (open findings), Alarms (active, red) and
  Vulnerabilities show a count beside their menu item when non-zero, capped
  at "99+", only for what the user may read. The alarm count is one
  background page of 100, refreshed when the newest alarm changes.
- `GET /api/v1/alarms/{id}` (`alarms.read`): the alarm with its process and
  ancestors (masked args, as the agent sent them) and triage; ETag is the
  triage version. `{id}` is the platform's id, never the agent's
  `alarm_id`. Outside the scope is 404.
- `PUT /api/v1/alarms/{id}/triage` (`alarms.triage`, CSRF, `If-Match`):
  any of the four states to any other (open, mitigated, accepted risk,
  false positive; `investigating` is retired, triage v2); completed states
  need a note, accepted risk a future expiry; 412 stale, 409 for a retired
  state, 428 without `If-Match`. Audited as `alarm.triage.changed` with a
  history row.
- `GET /api/v1/alarm-suppressions` (`alarms.read`): active suppressions
  the caller may see: `host` ones on agents in scope; `program` and
  `command` ones (they apply on every host) only with global scope.
- `POST /api/v1/alarm-suppressions` (`alarms.suppress`, CSRF): `{alarm_id,
  scope, note}`; the rule, agent, program and args hash are derived from
  that alarm, never typed in. `program`/`command` need global scope (403
  `global_scope_required`). It applies to alarms stored from now on.
- `DELETE /api/v1/alarm-suppressions/{id}` (`alarms.suppress`, CSRF): sets
  `removed_at`; the row stays as history. Both changes are audited
  (`alarm.suppression.created` / `.removed`).
- Alarms are not offered to the assistant in P14.

Draft site rules (`rule_drafts.rs`; need `rules.write`, global scope; the
`site` findings set and the `site-alarms` alarm set only, else 404):

- `GET /api/v1/rules/coverage` (global `rules.read`): MITRE ATT&CK
  coverage (protocol P18, spec `2026-10-09-attack-coverage-design.md`):
  tactics in matrix order with their derived kill-chain phase, and every
  rule of each live set's current bundle (verified with the set's trusted
  keys, at its own creation time) plus the site's drafts, each with its
  pairs resolved against the bundled release. The test-trigger rules are
  left out; a set whose bundle does not verify is named in
  `unverified_sets`.
- `GET /api/v1/attack` (global `rules.read`): the bundled ATT&CK release
  (`data/attack-enterprise.json`, built by `scripts/attack-data.py` from
  MITRE's STIX at a pinned version; 19.2 today) for the editor's picker.
- `GET /api/v1/rule-drafts/{set}`: the set's drafts, by rule id. Drafts
  carry `attack`; checking refuses a pair that is not in the bundled
  release or a technique under a tactic it does not belong to.
- `POST /api/v1/rule-drafts/{set}/{rule_id}/check` (CSRF):
  `{title, severity, confidence, expression, finding_message, programs?}`
  returns `{ok, problems: [{field, message}]}`. The checks are the agent's
  own: `RuleSet::validate`, `openvibes_rules::check_rule` (the loader's
  static check of the CEL expression) and, for alarm rules, the restricted-set
  caps (one to eight distinct programs per rule, 32 per set), the same
  numbers the rule signer enforces.
- `PUT /api/v1/rule-drafts/{set}/{rule_id}` (CSRF): saves a draft that
  passes the checks (422 with the problems otherwise). A rule's `version`
  is 1 when new, unchanged when the save changes nothing, and one more
  otherwise. At most 512 drafts per set. Audited (`rule_draft.saved`).
- `DELETE /api/v1/rule-drafts/{set}/{rule_id}` (CSRF): 204; audited
  (`rule_draft.deleted`).

- `GET /api/v1/rule-drafts/{set}/changes` (`rules.write`): the drafts
  against the published set: added, changed, removed, unchanged count.
- `POST /api/v1/rule-drafts/{set}/publish` (`rules.upload`, CSRF; body
  `{password}`): sends the drafts, the user's name and the password to the
  rule signer's socket (`/run/openvibes-signer/sign.sock`; the signer checks
  the password and `rules.upload` itself, rate-limits and keeps its audit),
  verifies the returned envelope against the set's trusted keys like any
  upload, and stores it (audited as a bundle publish). 201 `{version,
  expires_at_ms, rules}`. Refusals: 403 wrong password or not allowed, 409
  no drafts or nothing changed, 422 over a limit, 429 locked out or hourly
  limit, 503 signer unreachable.

- `POST /api/v1/rule-drafts/site/{rule_id}/test` (`rules.write`, CSRF; body
  `{agent_id, rule}`): runs the typed rule, saved or not, on the facts the
  platform can rebuild for the host (`package.names`, `package.count` and
  the `port.{tcp,udp}.*` facts from its listeners) with the agent's own
  evaluator. The rule is signed with a key made for the call and loaded
  back through the agent's loader, so the evaluator sees what an agent
  would. Result `match` (with the evidence keys), `no_match`, `unavailable`
  (a fact the platform doesn't hold, such as `process.names`, or a host
  that never reported its listeners) or `failed`. Alarm rules answer 422:
  they run on process starts, which the platform doesn't hold.

- `GET /api/v1/site-rules/fleet` (`rules.write`, global): for `site` and
  `site-alarms`, how many hosts are current, behind, refused the bundle, or
  don't list the set (from each host's last health report), the hosts that
  are not current in either set (up to 200), how many hosts have sent no
  report yet (in no count), and the two `[[rule_sets]]` blocks to paste into
  an agent's `agent.toml` when the platform trusts a key for both sets.
  Before the first publish a host that lists a set counts as current.

A draft reaches an agent only once published this way.

## Interfaces

The production service has two HTTP surfaces:

| Surface | Routes | Contract |
|---|---|---|
| Public HTTPS | `/`, known browser routes, `/assets/*`, `/auth/*`, `/api/v1/*` | Same-origin web UI and human/service-account API. Unknown API, auth, and asset paths are real 404 responses and never receive the SPA index. |
| Loopback health listener | `/health`, `/ready` | Liveness and dependency/schema readiness only; never exposed by the public router. |

The JSON API uses closed request validation, bounded bodies, RFC Problem
Details-style errors with stable codes, and opaque keyset cursors. Every public
response carries an `X-Request-ID`; structured request logs include that ID,
method, matched route template, and status without query strings or bodies.
Mutations use idempotency keys or
ETag/`If-Match` where replay or stale edits matter. Rust DTOs generate the
checked OpenAPI snapshot, which generates the committed browser TypeScript
contract. The production build checks both snapshot and generated-client drift
before Vite runs.

`GET /api/v1/session` defines the current-human-session contract: principal,
authentication method and level, effective permission/scope pairs, CSRF value,
and idle/absolute expiry. In C0 mode it returns
`503 authentication_unavailable`; the authenticated C3 router returns a
database-validated session or generic `401`. It never manufactures an
anonymous or implicitly privileged session. Service-account bearer tokens
cannot use this browser-session route.

Collection DTOs use opaque cursors with a default limit of 50, maximum limit
of 100, and a 2,048-byte cursor bound. Response envelopes contain typed items,
an optional next cursor, and an RFC 3339 generation time. Agent, certificate,
latest-finding, and finding-history response schemas are generated into OpenAPI
and the TypeScript client; the seeded API reuses those DTOs. Agent fields match
the stored schema, including optional hostname/heartbeat data and multiple
certificate records. Finding fields include confidence, evidence, scan ID,
receive time, and authenticated origin. Implemented agent and finding reads
resolve current permission scopes for each request and apply asset-group
selectors in SQL before pagination or aggregation. Access-control, audit,
enrollment, service-account, rule-set, triage, and agent-revocation operations
use authenticated, permission-checked routes with transactional audit records.

Dashboards (`/api/v1/dashboards`, `/api/v1/dashboards/{id}`,
`/api/v1/dashboards/{id}/sharing`, `/api/v1/me/home`) belong to browser
users: any signed-in user keeps their own, sees those shared with a role they
hold, and chooses a home; service-account bearer tokens get 403. See
[console-dashboards.md](console-dashboards.md).

Cases (`/api/v1/cases` and below) are read with `cases.read` and changed with
`cases.manage` (new in schema 35; Analyst and Admin, both agent-scoped, so a
scoped user sees and adds only what their asset groups cover). They are
browser-session only like dashboards; service-account bearer tokens get 403.
A case the caller cannot see answers 404. See
[console-cases.md](console-cases.md).

Count history (`GET /api/v1/metrics/history?metric=<id>&days=7|30|90|365`,
default 30) returns one catalogued count per UTC day, summed over the hosts
the caller may see. Each metric needs the read permissions listed in
[count-history.md](count-history.md); a missing one is 403, and so is a metric
spanning kinds (alarms, vulnerabilities, compliance) when the caller's scopes
for them differ. An unknown `metric` or other `days` is 422 (`unknown_metric`,
`invalid_days`); both are validated before authentication, so bad input gets
422 even unauthenticated. Today is always the live value; stored rows dated today or
later are not served, and days without a stored row are absent, not zero.

Most exposed hosts (`GET /api/v1/metrics/top-hosts?limit=1..10`, default 6)
returns `{items: [{agent_id, hostname, serious, open}]}`, the hosts with the
most critical and high problems across alarms, vulnerabilities and
compliance findings. A `limit` outside 1 to 10 is 422 `invalid_metric_query` with field code `invalid_limit`.
The caller needs `alarms.read`, `vulnerabilities.read` and `compliance.read`
with one common scope; a missing permission, or scopes that differ, is 403.
A caller limited to asset groups sees only hosts in those groups. Ranking
and counting rules are in [count-history.md](count-history.md).

The implemented production UI covers sign-in, overview, agents, findings,
enrollment, service accounts, rule sets, access control, audit, and
latest-finding analyst triage with version-checked updates. Fedora 44 RPM
installation, upgrade preservation, direct TLS, Unix proxy peer enforcement,
and systemd sandboxing pass the C5 integration run. CA and rule-trust-key
administration remain CLI-only.

Imported installations use the Agents view with a distinct Imported status.
Detail shows the `install_id`, import timestamps, and file-reported scanner
version, labels the identity unauthenticated, and never offers certificate,
tag, or revoke actions. Hostnames remain operator labels and are not treated as
unique identities; hostname-based vulnerability lookup must refuse ambiguous
matches while exact installation IDs remain addressable.

## Configuration


### Bulk triage and the detail view (triage v2, `src/bulk.rs`, `src/triage_detail.rs`)

Spec `docs/specs/2026-10-10-bulk-triage-design.md` (#237, #239, #240).

- `POST /api/v1/{alarms,compliance,vulnerabilities}/bulk` (CSRF): `{action,
  state?, note?, accepted_until?, assignee?, case_id? | new_case_title +
  new_case_severity?, items[]}`, 1 to 10,000 items, each fitting its list
  (alarms `{id}`; compliance `{rule_set_id, rule_id, agent_id?}`;
  vulnerabilities `{advisory_id, agent_id?}`; without a host, every host in
  scope). Actions: `state` (a close needs a note, accepted risk its
  expiry; a close reaching hosts through their rule or advisory skips
  those already closed, so their decision stays), `assign`, `case` (an
  open case or a new one; an item in another open case is skipped, and no
  new case opens when nothing is left) and, for alarms, `suppress` (one `program`
  suppression per distinct rule and program). Needs the kind's triage
  permission (`alarms.triage`, `compliance.triage`,
  `vulnerabilities.triage`), plus `cases.manage` for `case` and
  `alarms.suppress` for `suppress`. Answers `{changed, skipped[{id,
  reason}], case_id?, case_number?}`: items out of scope, gone or refused
  are listed, never silently changed. One audit row per action
  (`alarm.bulk_triage`, `finding.bulk_triage`,
  `vulnerability.bulk_triage`), one history row per item.
- `PUT /api/v1/vulnerabilities/advisories/{advisory}/hosts/{agent}/triage`
  (`vulnerabilities.triage`, CSRF, `If-Match`, version 0 when never
  triaged): one host's vulnerability triage. Vulnerability rows (list and
  advisory detail) carry `triage_state`, `triage_version` and
  `assigned_to`; the advisory detail lists up to 2,000 hosts.
- `GET /api/v1/triage-history?kind=alarm&id=` (or
  `kind=compliance&rule_set_id=&rule_id=`, `kind=vulnerability&advisory_id=`):
  the newest 200 triage changes on hosts in scope, behind the kind's read
  permission. The detail view's History tab.
- `GET /api/v1/cases/active-items?kind=` (`cases.read`): the alarm,
  finding or vulnerability refs in open cases the caller can see, with the
  case number, for the lists' case badges.
- Failure behaviour: a refused request (count, fields, action, permission)
  changes nothing; once accepted, each item is its own transaction, so a
  database error mid-way leaves the items before it changed (their history
  and audit say so).
- Tests: `tests/bulk_http.rs` (permission, CSRF, the note rule, items that
  do not fit, one open case per item, advisory expansion, version 0, the
  History tab, case badges).

### Current

`openvibes-console [--config PATH]` reads `/etc/openvibes/console.toml` by
default: strict TOML (unknown keys refused). The health listener must be a
distinct loopback address. `transport_mode` explicitly selects `development`,
`direct_tls`, or `reverse_proxy`. Development mode is loopback-only. Direct TLS
requires both absolute `server_certificate_file` and `server_key_file` paths
and permits a non-loopback public listener. Optional `database_url` and
`public_origin` must be provided together; HTTP origins must be loopback, while
HTTPS origins are required for direct TLS and reverse proxy. For example:

```toml
development_listen = "127.0.0.1:8443"   # the development web listener
health_listen = "127.0.0.1:18482"       # /health and /ready
transport_mode = "development"
database_url = "postgresql:///openvibes?host=/run/postgresql" # optional
public_origin = "http://localhost:8443" # required with database_url
```

`update_check` (default `true`) lets the About page ask GitHub for the latest
release; set it to `false` on hosts that must make no outbound connections
(see [`console-about.md`](console-about.md)).

`[agent_install]` (`platform`, `ingest_port` 18423, `distribution_port` 18424,
`root_cert_file` `/etc/openvibes/pki/root.crt`) says where agents reach the
platform; Setup writes it. With it, `GET /api/v1/agent-package` (global
`tokens.create`, session or token, audited as `agent_package.downloaded`)
returns `openvibes-agent-install.sh`: one script that installs and enrolls an
agent the same way on every host, so no `agent.toml` is made per agent. It
carries the standing fleet token (the console role can read
`standing_token_secret` since migration 0038), the root CA fingerprint, and
`--rules` / `--alarm-rules` for the sets the platform serves.
`GET /api/v1/agent-command` (same permission and checks, audited as
`agent_command.viewed`, `no-store`) returns `{command}`: the same install as
one line to copy, token inline, what `openvibes-admin agent command` prints.
The Enrollment page's "Add a host" section (install walkthrough, 2026-10-08:
hosts are added from the console) has two buttons: "Install package"
(the download) and "Copy CLI install" (copies that command; it is not shown,
being long and holding the token), while a standing token exists and the user
holds global `tokens.create`; without `[agent_install]` both routes answer
404, without a standing token `no_standing_token`. The script file holds the token:
keep it private, and revoke the standing token to rotate it.

A non-loopback address, equal addresses, unpaired auth fields, non-loopback
origin, unpaired TLS paths, relative TLS paths, or malformed file is refused at startup ("invalid console
configuration"), and `run` refuses a listener that is not loopback even if
bound elsewhere. TLS PEM files are capped at 1 MiB, must contain a valid
certificate chain and key, and are checked before serving; handshakes are TLS
1.3 only with a 10-second deadline. Startup checks that the database is already at schema 23; it
never runs migrations. The database URL is redacted from `Debug`. Authenticated
requests must use the configured Host authority or, with direct TLS, any name
the server certificate covers (its DNS and IP subjectAltNames at the listen
port; the bare name too on 443), so the console opens by IP over a VPN or as
`localhost` through a tunnel. Any other `Host` gets a 421 page linking to
`public_origin`, in the sign-in page's look and plain words (#81); its
stylesheet and wordmarks (`/misdirected/page.css`, `wordmark-light.svg`,
`wordmark-dark.svg`: fixed files, no data) load under any `Host`, since the
console's CSP allows no inline style and every other path is refused there. Plain http on the TLS port gets a `301` to `https://` on the
same `Host` when that is a served name, else to `public_origin` (never to a
name the console does not serve), instead of TLS bytes. The e2e fixture uses
18490/18491, clear of ingest's 18480 and distribution's 18481.

Reverse-proxy mode requires authenticated database configuration and a
canonical HTTPS `public_origin`. It uses either a loopback TCP listener with
1–64 unique loopback `trusted_proxy_addresses`, or a Unix socket with an
absolute `unix_socket_file` and 1–64 unique `trusted_proxy_uids`. The TCP and
Unix trust lists are mutually exclusive. Requests from other peers are
rejected. Unix sockets are created mode 0660; the proxy user must be able to
traverse the parent directory and belong to the socket's group. The proxy must
preserve the configured Host authority and append its observed client address
to `X-Forwarded-For`. The console uses the final address for source-address
login throttling only after authenticating the immediate proxy peer; absent or
malformed final values leave the per-account throttle in effect.
HSTS is set for both direct TLS and reverse-proxy responses.

### Development seed (C1)

Run the API with `cargo run -p openvibes-console --example seeded_server
--features dev-seed` (defaults to loopback ports 18490/18491), then run
`npm run dev` from `crates/openvibes-console/web` for the Vite UI; with
`?live=1` the Vite server proxies API requests to the seeded API. API
requests accept the demo-only `x-openvibes-dev-persona` and
`x-openvibes-dev-mode` headers (the API contract tests send them; the web
console has its own in-browser demo instead). The persona names use the
same built-in role resolver as C3, with a fixed demo asset-group binding for
`scoped_operator`. Data is deterministic and synthetic; the 50,000-agent mode
returns bounded pages and never loads all rows into the browser. These
temporary routes are intentionally absent from the production OpenAPI
contract until the database-backed C2/C3 routes exist.

### Deployment and packaging (C5)

The production service uses strict, bounded TOML; unknown keys and relative
key/certificate paths are refused. Its deployment constraints are:

- direct TLS 1.3 termination is available with a configured server certificate
  chain and private key; TLS responses include HSTS;
- reverse-proxy mode is explicit and requires a canonical external HTTPS
  origin plus an allow-list of trusted proxy peers (loopback TCP addresses or
  Unix effective UIDs);
- Host checks accept the configured external origin and, with direct TLS, the
  certificate's names; a browser `Origin` must be `https://` plus the `Host`
  the request came to, so one served name is still cross-origin to another
  (session cookies are `__Host-`, one per name); for login throttling,
  the final `X-Forwarded-For` address is trusted only from an allow-listed
  proxy, including when the proxy appends its observed client address;
- plaintext proxy upstreams may bind only to loopback or a Unix socket;
  non-loopback upstreams remain TLS protected;
- the health listener must be loopback-only;
- the production PostgreSQL connection uses the least-privilege
  `openvibes-console` role;
- session lifetimes, request limits, password hashing, export limits, and the
  private CSV spool are bounded configuration rather than browser choices.

The systemd unit creates `/run/openvibes-console` as a service-owned runtime
directory and removes it when the service stops. In Unix proxy mode, the
configured peer UIDs are checked using kernel peer credentials. Development
uses a loopback-only seeded server; the `dev-seed` implementation and its
conspicuous banner are never included in the production RPM.

The offline RPM build script validates the caller-supplied cache digest,
builds the embedded UI and release binary without network access, creates an
isolated `target/rpm-console` rpmbuild tree, and emits the package there. CI
installs that RPM after platform migrations inside Fedora 44 with systemd as
PID 1, then checks readiness, HTTPS delivery, response security headers, the
systemd seccomp and `NoNewPrivs` settings, Unix proxy access for allowed and
disallowed peer UIDs, no Node.js runtime dependency, and upgrade preservation
of local configuration, TLS files, the local account, and its active session.

## Failure behaviour

**Now (C0, C1, and the C3 local-auth slice):**

- The development listener answers only loopback `Host` names (`localhost`,
  `127.0.0.1`, `[::1]`, any port); any other `Host` gets 421, so a
  DNS-rebinding page cannot read it. Requests without `Host` pass.
- Authenticated runtime startup refuses absent/unreachable databases and any
  schema version other than 24; it does not migrate. The configured Host
  authority (and, with direct TLS, the certificate's names) is enforced for
  authenticated requests; a wrong one gets a no-store 421 page with the
  console's address, still without any data, so DNS rebinding reads nothing. Login uses trusted socket
  peer information from the capped listener. In reverse-proxy mode, the final
  `X-Forwarded-For` address from an allow-listed proxy is used for source-address
  throttling; other forwarded headers are ignored.
- Login, logout, pre-auth, session refresh, and password-hash upgrade persist
  through `platform-store` transactions. Login failures have a generic shape;
  password work has a four-operation concurrency bound.
- The embedded UI requests the current session without caching, gates
  application routes unless that request succeeds, obtains one-use pre-auth
  state before enabling local login, and sends logout with the synchronizer
  CSRF token. It never reads the opaque session cookie. Navigation entries are
  shown only when the current session has a matching read capability (and
  global scope where required); direct navigation to a restricted page shows
  an access-denied screen. The loopback seeded demo applies the same visibility
  rules to its selected persona. API handlers remain the authorization boundary.
- The full Content Security Policy is enforced on every public response,
  including `frame-ancestors 'none'`; `X-Frame-Options: DENY` is also set.
- A wrong method on an API route is a 405 Problem Details response with
  `Cache-Control: no-store`, like every API error.
- The public and development routers cap extractor request bodies at 1 MiB,
  request handling at 15 seconds, and in-flight requests at 128 per process.
  The public TCP or Unix listener accepts at most 256 concurrent connections
  and the health listener accepts at most 16; excess connections wait in the
  OS accept queue until a slot opens.
- Problem Details errors log their request ID, stable code, and HTTP status;
  request fields and secret values are not logged.
- An `embedded-ui` build fails if the shared route/public-asset contract,
  generated frontend manifest, SPA entry, exact public-file inventory, or a
  referenced embedded asset is missing or inconsistent. It also refuses a
  stale build stamp whose sorted input/output inventory or SHA-256 digest does
  not match the files being embedded.
- Frontend tests refuse brand SVGs with scripts, animation, embedded raster,
  external references, text/fonts, or background rectangles, and verify the
  PNG signatures, alpha channel, and declared dimensions.
**Implemented runtime behavior:**

- In authenticated mode, `/ready` is refreshed every five seconds using a
  bounded database connection and schema-version check. It returns 503 on
  timeout, database failure, or schema drift; `/health` remains a
  process-liveness check.
- Development mode and its synthetic seeded routes remain loopback-only. They
  cannot access production state. Production data and control-plane routes
  require database-backed authentication; there is no permissive production
  authentication mode.
- In authenticated mode, `/api/v1/session` validates the database session and
  resolves active role bindings on every request.
- API failures are bounded Problem Details responses and never expose SQL,
  credentials, tokens, certificates, IdP payloads, or authorisation detail.
- Authorisation is applied in database queries before aggregation, filtering,
  and pagination. An object outside the caller's asset scope looks absent.
- A mutation whose audit append fails rolls back. Token plaintext is shown
  once and cannot be recovered afterward.
- Direct TLS 1.3, trusted loopback-TCP proxying, and UID-allow-listed Unix
  socket proxying are available. Other proxy peers are rejected. Forwarded
  headers are ignored; the Fedora systemd integration covers the direct TLS
  package path and Unix-socket peer-UID enforcement.

## Build and test

The reproducible production sequence renders the PNG brand derivatives with
ImageMagick, exports Rust OpenAPI, checks snapshot/client drift, performs the
locked frontend install and checks, runs Vite, generates the content-derived
build stamp, validates embedded assets, then builds the Rust `embedded-ui`
release. The Rust build script reads the checked frontend contract and verifies
the stamp but never invokes a package manager.

Run `scripts/build-console-brand-assets.sh` alone after an intentional change
to `web/public/brand/openvibes-mark.svg`. It accepts ImageMagick 7 (`magick`) or
ImageMagick 6 (`convert`); CI installs ImageMagick explicitly. The SVG files are
the reviewed sources and the generated PNG files are committed so offline
packaging has no hidden artwork input.

`scripts/build-console-npm-cache.sh OUTPUT_DIR` creates a separate
`linux-x64` cache artefact named by the SHA-256 of `package-lock.json`, plus a
checksum sidecar. It contains npm's content-addressed cache, the lock digest,
and the target platform, but no `node_modules`. The networked cache-preparation
stage is separate from packaging. `scripts/check-console-npm-cache.sh ARCHIVE`
checks the sidecar, allow-lists archive paths, refuses links and special files,
confirms the current lock digest and platform, then runs `npm ci --ignore-scripts --offline`
and a Vite build in a scratch directory. Packaging extraction also requires an
independently pinned digest from trusted RPM source metadata:
`scripts/check-console-npm-cache.sh ARCHIVE CACHE_DIR EXPECTED_SHA256`.
`scripts/build-console.sh
--offline-cache-dir CACHE_DIR` then checks the lock digest/platform again,
verifies npm's cache, and runs npm in offline mode. When the host permits an
unprivileged network namespace, npm commands also run under `unshare -rn`;
restricted CI kernels may only enforce npm's offline cache. The first package
target is Fedora Linux x86_64, so caches for other platforms are deliberately
distinct. Console RPM source metadata
supplies the expected archive digest independently of the archive and its
sidecar. The one-argument checker mode used in CI validates corruption only.

Build the Fedora x86_64 console package with:

```sh
scripts/build-console-rpm.sh "$CACHE_ARCHIVE" "$EXPECTED_SHA256"
```

The script verifies the pinned source cache, runs the frontend package checks
and build with networking disabled, builds the Rust binary with Cargo offline,
and packages it through `packaging/rpm/openvibes-console.spec`. RPM `%check`
verifies the expected cache digest again. The resulting service is disabled
until the operator provisions its database and certificate.

For a network-isolated package build, persist the validated cache and pass it
to the frontend build:

```sh
scripts/check-console-npm-cache.sh "$CACHE_ARCHIVE" target/console-npm-cache/extracted "$EXPECTED_SHA256"
scripts/build-console.sh --offline-cache-dir target/console-npm-cache/extracted
```

For the current C0 foundation, run:

```sh
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings -F unsafe-code
cargo doc --locked --workspace --all-features --no-deps
cargo test --locked --workspace --all-features
scripts/build-console.sh
archive=$(scripts/build-console-npm-cache.sh target/console-npm-cache)
scripts/check-console-npm-cache.sh "$archive"
scripts/test-console-e2e.sh
cargo run --locked -p openvibes-console --bin export_openapi -- \
  --check docs/api/console-v1.openapi.json
```

`export_openapi` has no `embedded-ui` dependency. With no arguments it writes
deterministic pretty JSON to stdout; `--check PATH` fails on snapshot drift.
Run `npm --prefix crates/openvibes-console/web run generate:api` after an
intentional API change; `scripts/build-console.sh` fails if the generated
browser contract does not match the snapshot.

Current frontend verification includes strict type checking, linting, unit
tests, dependency audit, production asset generation, and Rust-side embedded
asset tests. `scripts/test-console-e2e.sh` runs Playwright in Chromium,
Firefox and WebKit against the real console binary with the embedded UI and
its production CSP, on a throwaway PostgreSQL database; it covers sign-in,
every view, CSP violations, third-party requests, triage, dashboards and axe
([console-web.md](console-web.md#how-to-test)). The seeded server is
test-only and is not the production binary. Later contract tests
exercise the complete Axum router first against deterministic seeded data and
then against PostgreSQL. Security coverage expands from the current route
fall-through, cache-header, and CSP checks to session/CSRF handling, object
scope, audit atomicity, trusted proxies, secret redaction, and bounded CSV
export.

## Upgrade notes

Console: rule results are now "compliance findings". API paths moved from
`/api/v1/findings/*` to `/api/v1/compliance/*`; permissions `findings.read` /
`findings.triage` are now `compliance.read` / `compliance.triage` (roles and
saved dashboards are migrated; update scripts). Migration 43 changes stored
data: run Update, which takes a backup. The agent wire protocol and the ingest
API (`/v1/findings`) keep the name "findings".

Also renamed: the cases API's item kind `finding` is now `compliance_finding`
(stored items are migrated; sending `finding` is refused with 422
`invalid_kind`); the problem code `finding_not_found` is now
`compliance_finding_not_found`; the page `/findings` is now `/compliance`
(old links and saved views carry over).
