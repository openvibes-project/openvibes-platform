# console-web (the console's web interface)

The React application in `crates/openvibes-console/web`, embedded in the
`openvibes-console` binary and RPM. It was designed as "console v2"
(approved by the user on 2026-09-28) and replaced the first interface (v1)
on 2026-09-28; v1 remains in git history.
Design: [2026-09-28-console-v2-design.md](../superpowers/specs/2026-09-28-console-v2-design.md).

## Purpose

Show everything, without page changes for details:

- **Inspector:** any object (agent, finding, advisory, token, rule set,
  service account, audit event, user) opens in a panel beside the list.
- **Panel stack:** links inside a panel stack further panels, with a
  breadcrumb. The stack is in the URL (`?open=kind:id`, repeated), so
  Back, reload and shared links restore it.
- **Floating windows:** any panel pops out into a window that can be dragged,
  resized, minimised and docked back.
- **Assistant dock:** open from any view (Ctrl+J). It takes the open object as
  context, and its citations open objects in the inspector.
- **Command palette** (Ctrl+K): searches views, actions, recent objects,
  hosts, advisories/CVEs and findings.
- **Lists:** saved views per viewer, keyboard navigation (j/k, Enter, x, /),
  and one table component for every list. Compact rows can be switched on
  per viewer.
- **Sign-in:** `/login` shows local sign-in (pre-auth CSRF, password-manager
  autocomplete, generic errors), or home when already signed in. Every other
  route asks `GET /api/v1/session` first and shows sign-in on 401. Sign out
  POSTs `/auth/v1/logout` with the session CSRF token.
- **Views** (the same set v1 had):
  - findings with bulk triage and a 14-day trend of reporting hosts;
  - vulnerabilities by advisory, with CVEs, EPSS and KEV;
  - agents, with tags and revocation;
  - enrollment tokens;
  - rule sets, with signed-bundle preview and publish;
  - access: roles, bindings and asset groups;
  - service accounts, with tokens issued once;
  - audit log, with ranges, CSV export and retention.
- **Triage** (finding panel, `panels/triage.ts`): select one host or many,
  then set state, assignee (an analyst or admin username), note and, for
  accepted risk, the date it is accepted until (end of that local day).
  The state list follows the server's workflow (open → investigating →
  mitigated, accepted risk or false positive; closed states stay), limited
  to states every selected host can reach. Mitigated, accepted risk and
  false positive need a note. With one host selected, the form loads and
  shows its saved triage first (fields stay disabled until it arrives).
  A stale selection (412) reloads the list. The Hosts table shows each
  host's assignee and, for accepted risk, the date it is accepted until
  (marked expired once past), and a `fixed <date>` badge (`about` when
  approximate) for a host whose agent reported the match ended (P13).

## Dashboards

The console opens on a dashboard ([console-dashboards.md](console-dashboards.md)).

- **Home:** the built-in Overview (read-only, rebuilt from widgets; its
  header keeps the greeting) until a user picks another with the pin button.
  `/` shows the home dashboard, and `/dashboards/{id}` shows a specific one
  (`/dashboards/overview` is the built-in).
- **Switcher:** Built-in, Mine and Shared with me, plus New dashboard.
  Dashboards also appear in the Ctrl+K palette.
- **Edit mode** (own dashboards only; built-in and shared ones offer
  "Duplicate to edit"):
  - drag a tile's header to move it and its corner to resize it; tiles
    below are pushed down;
  - with a tile focused, arrows move it, Shift+arrows resize it, Delete
    removes it and Enter opens its settings;
  - Add widget opens the gallery in the inspector, and widget settings open
    there too.
- **Saving:** Save sends the version (`If-Match`). If someone else saved
  first, the editor offers "Reload theirs" or "Save as a copy" and keeps
  your edits. Leaving with unsaved changes asks first.
- **Unsaved drafts** are kept per tab (`sessionStorage`,
  `openvibes.v2.draft.{id}`) while you edit. After a lost session, a reload
  or a crash, the dashboard offers to Restore or Discard them. Save, Cancel
  or a confirmed leave clears them.
- **Undo:** removing a tile (button or Delete) shows an Undo bar. In edit
  mode, a screen-reader hint on each tile describes its keys.
- **Widgets:** Number, Breakdown, Needs attention, List (any list view with
  its filters), Trend, Most exposed hosts, and Note (plain text; only
  whole `https://` words become links).
  - Each tile loads data with the viewer's own permissions.
  - A tile the viewer's role can't read says so.
  - A tile that fails to render doesn't take the dashboard down.
- **The rail** is icons until hovered or focused, then opens over the page
  (its width and negative margin animate together, so the page never moves
  while it opens; e2e "opening the rail over the page never moves the
  page"), or stays open when pinned, which narrows the page.
- **Phones:** tiles stack in reading order, number tiles two to a row
  (titles wrap rather than truncate), the greeting sits above its buttons,
  and editing is hidden, "Edit" and "Duplicate to edit" included (the
  dashboard menu says "Editing needs a wider screen"). Below 720px the rail is a bottom bar in which every
  destination fits (icons only, each link keeps its name for screen
  readers); tables wrap long names, and Agents drops Last heartbeat below
  480px so host names fit.
- **Menu:**
  - Duplicate, Rename and Delete;
  - Share with role (owner with `dashboards.share`);
  - Set as home.
- **The demo** (preview and dev only) keeps dashboards and home choices in the browser's
  `localStorage` (`openvibes.v2.demo.dashboards`).

## Threat alarms (P14)

- **Alarms** (`/alarms`, `g m`, `alarms.read`): newest first; severity,
  message with `parent → program`, host, count, triage, last seen. Resolved
  and suppressed alarms are hidden unless their chips are on; the empty
  state explains the auditd / `process_events` requirement. The list loads
  the newest 100 with the filters sent to the API (`state=active` by
  default) and **Load 100 more**; the text filter applies to what is
  loaded. Each row has a **Quiet…** choice (with `alarms.suppress`): this
  host, or (global scope only) this program or this exact command on any
  host. Choosing does nothing until the inline confirmation, which names
  what it quiets and asks why; confirming closes that alarm as a false
  positive (through investigating) and creates the suppression.

**Site rules** (`/site-rules`, with `rules.write`) lists the site's own
compliance rules and alarm rules (drafts) with New rule. A rule opens in
the inspector as a form (id for a new rule, title, severity, confidence,
for alarms the programs, expression, message). As you type, the server's
check (the agent's own loader) shows what is wrong beside the field, and
Save draft stays off until the rule passes. Delete asks first. Rules saved
here are drafts. Under each table, Publish lists what changed against the
published set; with the user's password typed again the rule signer signs
the set and the platform publishes it (needs `rules.upload`). A compliance
rule's panel can also be tested against one host: it runs on the packages
and listening ports the platform holds and says match, no match or
unavailable (a rule over anything else, such as running processes, is
unavailable here). A Hosts section at the bottom of Site rules counts the
hosts running each set (current, behind, refused, not set up), lists the
ones that aren't current, and shows the `[[rule_sets]]` lines to paste into
an existing agent's `agent.toml`.
- **Alarm panel** (`alarm`): the process tree top-down (ancestors, then the
  process: program, masked command line, uid and euid when they differ,
  working directory, pid), rule and versions, first/last seen, count, and
  the triage bar (findings workflow). Choosing false positive offers
  "Don't alarm on this again" with the same scopes.
- **Alarm suppressions** (`/alarm-suppressions`, `g q`): who, when and
  why, Remove (kept as history on the server); a row opens the matching
  alarms.
- Alarms are not offered to the assistant (no "Ask about" on the panel).
- The demo serves alarms and suppressions with the server's rules
  (scoped persona, workflow, global-only program/command).

## Cases

One place for an investigation ([console-cases.md](console-cases.md); spec
[2026-10-04-console-cases-design.md](../specs/2026-10-04-console-cases-design.md)).
A case gathers hosts, alarms, findings, vulnerabilities on a host and
software, with notes and a timeline. It does not replace those views, and
triage on alarms and findings stays as it is.

- **Cases** (`/cases`, `g c`, `cases.read`): C-number, title, severity,
  status (a closed case also says how it ended), assignee, items with the
  count that still need an outcome, and last change. Chips: Open,
  Investigating, Closed, Include closed (the default list shows open and
  investigating), the four severities, Assigned to me and Unassigned. The
  chips and severity go to the API; the text filter (title, `C-104`,
  assignee) applies to what is loaded. **New case** (with `cases.manage`)
  opens a form in the inspector. A row opens the case.
- **Case panel** (`case`, id is the case's UUID, `case:new` is the form):
  - the header shows number, title, status, severity, assignee and how many
    items are unresolved;
  - with `cases.manage`, title, severity and assignee (a picker from
    `/cases/assignees`, plus Assign to me) save together with the version
    (`If-Match`). Status moves open to investigating and back, and **Close
    case…** asks for the resolution, a note and, for accepted risk, the date
    it is accepted until (the case reopens then). It lists the alarms,
    findings and vulnerabilities that still need an outcome and stays
    disabled until the rules are met (`panels/cases.ts`, `closeProblems`).
    A closed case offers **Reopen**;
  - **Items**: each row shows its kind, title, severity and host and opens
    that object's own panel (alarm `alarm:<id>`, finding `finding:<rule
    set>/<rule>`, vulnerability `advisory:<advisory>`, host `agent:<id>`,
    software `package:<manager>/<name>`). Alarms, findings and
    vulnerabilities take an outcome: resolved (offered only while the
    evidence is gone), false positive or accepted risk (a note is required).
    Hosts and software need none. **Remove** and **Add item** (kind and
    pasted id) work on open cases;
  - **Notes** (plain text) and the **Timeline**, newest first, with who did
    what.
  - Without `cases.manage` the panel is read-only.
- **Add to case** (`panels/AddToCase.tsx`, with `cases.manage`): a button on
  the alarm panel, on each host row of a finding and of an advisory, on the
  host panel and its vulnerabilities, and on the software panel. Its dialog
  asks `/cases/for-item` first. An alarm, finding or vulnerability that is
  already in an open case shows that case (a link) and offers nothing else,
  because it can be in one at a time; a host or software lists the cases
  that hold it and can join another. Otherwise pick an open case or **New
  case…**, which opens one with the item.
- **Refusals**: a stale version (412) reloads the case and says someone else
  changed it; an item in another open case (409) names that case when the
  server does; a case closed or an outcome the evidence does not allow shows
  the server's message.
- **The demo** (`demo/cases.ts`) serves the same routes, JSON, status codes
  and rules as the server: filters, `If-Match`, exclusivity, close rules,
  outcomes decided by the demo's own alarms and findings (mitigating an alarm
  in the Alarm panel makes "resolved" available for it), the visibility rule
  for a scoped viewer, and accepted risk that reopens when its date passes.
  It starts with four cases over real demo objects (an SSH and shell
  investigation, an exploited advisory on three hosts, web servers starting
  shells, and a closed one) and keeps cases in `localStorage`
  (`openvibes.v2.demo.cases`). Analyst and admin hold `cases.read` and
  `cases.manage`; the viewer and operator have neither.

## Assets v1 (hosts and software)

- **Hosts** (`/agents`, the former Agents view): a row opens the **Host
  page** (the `agent` panel): Findings, Vulnerabilities, **Alarms** (active
  ones), **Software** (the host's packages, filtered on the server by name
  and "Fix available", 200 at a time) and Details (identity, system and
  running kernel, "software as of", tags, certificates). The list, panel and
  host export call `last_seen_at` **Last heartbeat**. Its hover text
  says agents send one about every minute and a host is online within three
  minutes of the last. Online and offline changes show up without a reload:
  `app/livePresence.ts` keeps `GET /api/v1/agents/events` open (a fetch marked
  background, so it does not extend the session) and refetches the agent
  views, at most every two seconds, when the server reports a change.
- **Software** (`/software`, `g w`): packages across the caller's hosts with
  hosts, versions (highlighted when more than one is in use), open
  advisories (worst severity, count, no-fix count, an Exploited flag) and
  hosts with a fix available; the name filter and the "Fix available" and
  "Multiple versions" chips go to the API; Load 100 more. A row opens the
  `package` panel: versions in use with host share and advisory count, the
  open advisories (each opens the advisory) and the hosts.
- "Fix available" means an open vulnerability that has a fix (quiet by
  default; no-fix ones stay in Vulnerabilities).
- On a phone, Software sits under More (`phoneMore`), so the bar keeps five
  labelled slots.

## Interfaces

- **Entry:** `web/index.html` → `src/main.tsx` → `shell/App.tsx`.
- **Browser routes:** every view's path, `/login` and
  `/dashboards/{dashboard_id}`, listed in `web/frontend-contract.json` for
  the server's router; `app/frontendContract.test.ts` keeps the two in step.
- **`app/registry.tsx`:** declares every view (path, icon, group, required
  permissions, shortcut) and object kind (panel). A new module is one entry
  in each.
- **`app/location.ts`:** URL ↔ state (view, panel stack, filters); tested.
- **`api/client.ts`:** `request`, `load` (cached by path), `invalidate(prefix)`
  after mutations, and the `useResource`/`useAllPages` hooks. Live requests
  send the session cookie, plus `x-csrf-token` on mutations.
- **`app/source.ts`:** picks live or demo data. An installed build (`npm run
  build`, embedded in the RPM) is always live, and the demo code is left out
  of its bundle.
- **`demo/server.ts`:** (preview and dev builds only) an in-browser implementation of the endpoints v2 uses,
  over deterministic synthetic data (`demo/data.ts`). It follows the wire
  types and the permission model, with personas viewer, analyst, operator,
  scoped operator and admin. Tested.
- **Types:** from the OpenAPI client (`src/api/generated.ts`, generated by
  `npm run generate:api`), via `api/types.ts`.

## Configuration

| Setting | Where | Effect |
|---|---|---|
| `VITE_DEMO=true` | build env | includes the demo (`npm run build:demo`, the Pages preview); without it the build is live only |
| `?demo=1` / `?live=1` | URL | in dev and demo builds, switches the source for this browser session; ignored by an installed build |
| `CONSOLE_BASE` | build env | public path (`/openvibes-platform/` on Pages; `/` by default) |
| `CONSOLE_URL` | dev env | proxy target for `/api` and `/auth` (default `http://127.0.0.1:18490`) |

Per-viewer conveniences go in browser storage and are never needed for
correctness:
- theme (`openvibes.theme`);
- saved views;
- rail pinned;
- inspector width;
- windows;
- recent objects;
- assistant open state;
- demo persona.

## Failure behaviour

- **401 on the session:** shows the sign-in form. Another failure shows
  "not reachable" (with a link to the demo in preview and dev builds).
- **Failed request:** its view or panel shows the API's problem title, plus
  a hint for 403 and for network errors.
- **Empty service accounts:** the list explains what accounts are for and
  gives a next step appropriate to the viewer's create permission.
- **Mutation errors:** shown inline or as a toast. A 409 on triage reloads
  the data.
- **Unknown panel kinds and views:** they show an explanation instead of
  failing.

## How to test

```sh
cd crates/openvibes-console/web
npm ci --ignore-scripts      # no dependency install scripts; esbuild's binary is an optional dependency
npm run lint && npm run typecheck
npm test                     # location, client, table, source, contract, demo server, demo cases, case rules
npm run test:e2e:demo        # demo build: smoke, dashboards + axe (both themes), Chromium and Firefox
npm run dev                  # http://127.0.0.1:5174 with demo data; add ?live=1 for CONSOLE_URL
```

From the repository root, `scripts/test-console-e2e.sh` (needs
`OPENVIBES_TEST_DATABASE_URL`, e.g. `eval "$(scripts/test-db.sh)"`,
`psql` and `openssl`) builds the embedded UI and runs `e2e/live` against the real console
in Chromium, Firefox and WebKit. `scripts/console-e2e-server.sh` prepares a
fresh `ov_console_e2e` database (migrate, users alex/admin and sam/analyst,
imported findings for six hosts) and starts the console on
`https://127.0.0.1:18490` with direct TLS 1.3 (a throwaway self-signed
certificate; WebKit keeps the `__Host-` Secure session cookie only over
HTTPS) and its production CSP. The tests check sign-in, every
view (no error, no CSP violation, no third-party request), `/login` and
retired `/assistant`, bulk triage, one host's accepted risk with an
assignee and date (refused for an unknown assignee, shown again on
reselect), a dashboard shared with a role and seen
read-only, and axe in both themes.
The live tests also check the service accounts empty state on a fresh server
and the Access and Audit filtered empty states at narrow widths in light and
dark themes. Access keeps asset groups visible when no people match; Audit
distinguishes an empty date range from filters that hide existing events.

The `Console demo preview` workflow (`console-demo-pages.yml`) runs lint,
types, unit tests and the demo end-to-end tests on pull requests; on pushes
to `main` it also builds the demo and publishes it to GitHub Pages
(https://openvibes-project.github.io/openvibes-platform/). A failing check
stops the deploy. The main CI workflow runs the live tests.

## Host export (#119)

The Host page's **Export** button lets the user pick sections (details,
findings, alarms, vulnerabilities, software, ports, services; only those
their role may read) and saves one CSV with the columns `section, name,
detail, state, severity, extra`. The browser fetches each section through
the same scoped API as the Host page (at most 50,000 rows per section, above what Compare can handle, so its "use Export" advice holds).
Cells are quoted, and a leading `= + - @` is prefixed with `'` so a
spreadsheet never runs it as a formula (`ui/csv.ts`, unit-tested).
