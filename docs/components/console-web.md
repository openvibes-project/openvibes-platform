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
  - agents, with labels, host groups and revocation;
  - enrollment tokens;
  - rule sets, with signed-bundle preview and publish, and where each assignable set runs ([rule-set assignment](rule-set-assignment.md#console-screens));
  - settings: General (typed settings that save as they change, with the
    approvers named and Recent changes; needs `settings.manage`), people,
    roles and host groups;
  - service accounts, with tokens issued once; roles are shown by name, and
    the new-account picker offers only roles inside the creator's own access
    (`fitsShare`, as for people);
  - audit log, with ranges, CSV export and retention.
- **Host hardening** (`views/investigate/host/HostHardening.tsx`): the host page's Hardening
  row, "Hardening facts unavailable" warning and "Not assigned" badge; see
  `rule-set-assignment.md`.
- **Triage** (triage v2, `panels/triage/triage.ts`, `panels/triage/bulk.ts`,
  `panels/triage/BulkBar.tsx`): four states (open, mitigated, accepted risk, false
  positive), any to any other; every close needs a note, accepted risk an
  expiry (90 days by default, at most a year, to the end of that local
  day). The Alarms, Compliance and Vulnerabilities lists and a detail
  view's Hosts tab select rows (checkbox, shift-click range, `x` on the
  cursor row; the header box selects the rows on screen, then a bar offers
  every row the filter matches, up to 10,000; `ui/selection.ts`). The
  triage actions (#253) are the same in a panel header and in the bulk bar
  at the bottom of a list: **Set state** (a menu, `ui/Menu.tsx`: Mitigate,
  Accept risk, False positive, and Suppress for alarms in bulk; like
  `Select`, it follows its button on scroll and closes only once the button
  is off screen, `inView` in `ui/select.ts`), **Reopen
  N closed** (only when the selection holds closed items; applied at once),
  the **assignee** (the console's `Select` drawn as a button, with search,
  "Assign to me" and "Unassigned" on top; applied on pick) and **Add to
  case**. A state or a case opens one dialog whose confirm button names the
  count; the toast says what changed, what was already so ("unchanged") and
  why the rest was skipped. A selected finding or advisory row acts on its
  hosts in scope; a close leaves the hosts already closed alone, a reopen
  the ones already open. Rows in an open case show
  its badge (`panels/cases/CaseBadge.tsx`). Vulnerabilities count open hosts
  and hide advisories triaged everywhere unless Include resolved is on.
- **Detail template** (`panels/triage/TriageDetail.tsx`): a finding and an advisory
  share one layout (an alarm is a page, [console-alarms.md](console-alarms.md)): the triage actions on the panel header's
  actions line (a finding or advisory: "Set state: N open", acting on its
  open hosts), a short summary, then the console's underline tabs
  (`Tabs`). Findings and advisories: Hosts (a `DataTable` with a state
  filter, selection and the bulk bar, never cut off), Evidence, History.
  The Hosts table shows each
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
  - Add widget opens the gallery in the inspector (each widget type has its
    own icon), and widget settings open there too (the tile's pencil, or
    Enter). A new widget goes to the first free spot in the grid.
- **Saving:** Save sends the version (`If-Match`). If someone else saved
  first, the editor offers "Reload theirs" or "Save as a copy" and keeps
  your edits. Leaving with unsaved changes asks first.
- **Unsaved drafts** are kept per tab (`sessionStorage`,
  `openvibes.v2.draft.{id}`) while you edit. After a lost session, a reload
  or a crash, the dashboard offers to Restore or Discard them. Save, Cancel
  or a confirmed leave clears them.
- **Undo:** removing a tile (button or Delete) shows an Undo bar. In edit
  mode, a screen-reader hint on each tile describes its keys.
- **Widgets:** eight types: Number, Breakdown, Needs attention, List (any
  list view with its filters), Trend, Most exposed hosts, Graph, and Note
  (plain text; only whole `https://` words become links).
  - Each tile loads data with the viewer's own permissions.
  - A tile the viewer's role can't read says so.
  - A tile that fails to render doesn't take the dashboard down.
- **Number tile:** one count from the catalogue
  ([count-history.md](count-history.md)). Settings: Count, Trend (Off, 7, 30
  or 90 days) and, with a trend, Line (smooth or stepped).
  - With a trend it shows a sparkline and the change over the period
    ("+3", "−2", "no change"). When the history starts later than the
    period asks, the change adds "vs N d ago".
  - A count that spans kinds (Critical, High: alarms, vulnerabilities and
    compliance) has no tile link, because it has no single list. Fine
    print under the number shows each part ("2 alarms · 1 vulnerability ·
    0 compliance"), and each part links to its own list.
  - A vulnerability count reads "Not set up" until the first vulnerability
    feed import.
- **Graph widget:** 1 to 4 counts as lines (Count 1 to 4, no repeats; add
  and remove in settings), over 7, 30, 90 or 365 days (default 30), smooth
  or stepped. Colours come from a four-colour palette (`--series-1` to
  `--series-4`, tuned for light and dark). "Show as table" swaps the chart
  for a day-by-count table, and "Show as chart" swaps back. The role rule:
  the viewer needs the read permission of every chosen count, otherwise the
  tile says "Not available with your role". With fewer than two days of
  history the tile says "Collecting since <day>" instead of a line ("No
  data yet" when there is none).
- **Breakdown sources:** a bar and a legend, each segment linking to its
  list.
  - Active alarms by severity: critical, high, medium, low, and an
    info segment computed as the Active alarms count minus the four
    severities.
  - Vulnerabilities by severity.
  - Compliance findings by severity.
  - Hosts by status.
  - Vulnerabilities say "Vulnerability scanning is not set up" before
    the first feed import.
- **Needs attention** shows at most 1 to 20 items, most urgent first.
  Kinds (each can be switched off):
  - active threat alarms, medium and above;
  - exploited vulnerabilities, grouped by advisory;
  - serious: open critical and high vulnerabilities that are not
    exploited (`exploited=false`), grouped by advisory, the 20 advisories
    on most hosts kept. When the server cut the list short, the host count
    reads "N+ hosts";
  - open critical and high compliance findings;
  - hosts that stopped reporting.
- **Most exposed hosts:** settings Count (All kinds or Vulnerabilities only) and Hosts (1 to 10, default 6).
  - All kinds ranks hosts by critical and high problems across alarms,
    vulnerabilities and compliance findings, from
    `GET /api/v1/metrics/top-hosts`. It needs the three read permissions
    and one shared scope; otherwise the tile says "Not available with your
    role — choose Vulnerabilities only".
  - Vulnerabilities only ranks hosts by open vulnerabilities.
- **The built-in Overview** (read-only; "Duplicate to edit" makes a copy):
  - top row, four Number tiles with a 30-day trend: Active alarms,
    Critical (all kinds), High (all kinds), Exploited vulnerabilities;
  - middle: Needs attention (alarms, exploited, serious, compliance,
    stale; 14 items) beside Vulnerabilities by severity, Compliance
    findings by severity and Most exposed hosts (7, all kinds);
  - bottom row, three Number tiles: Fleet · online, Fleet · stale,
    Fleet · need a reboot.
- **The rail** is icons until hovered or focused, then opens over the page
  (its width and negative margin animate together, so the page never moves
  while it opens; e2e "opening the rail over the page never moves the
  page"), or stays open when pinned, which narrows the page.
- **Phones:** tiles stack in reading order, number tiles two to a row
  (titles wrap rather than truncate), the greeting sits above its buttons,
  and editing is hidden, "Edit" and "Duplicate to edit" included (the
  dashboard menu says "Editing needs a wider screen"). Below 720px the rail is a bottom bar in which every
  destination fits (icons only, each link keeps its name for screen
  readers); tables wrap long names, and Hosts keeps only Host and Last
  heartbeat below 600px so host names fit.
- **Menu:**
  - Duplicate, Rename and Delete;
  - Share with role (owner with `dashboards.share`): only the roles the
    owner holds (`GET /api/v1/roles?held=true`), shown and confirmed by name;
  - Set as home.
- **The demo** (preview and dev only) keeps dashboards and home choices in the browser's
  `localStorage` (`openvibes.v2.demo.dashboards`).

## Console controls

The console draws its own controls (`web/src/ui`); the browser's native
select popups, radios, spinners and checkboxes cannot be themed, so none is
used.

- **Select** (`Select.tsx`, logic in `select.ts`): a combobox button and a
  listbox popup. Options are flat or in groups (a group has a heading), each
  with an optional hint and a `disabled` flag. Above 8 enabled options a
  search box filters the list, and typing a character on the closed button
  opens it with that search. Arrow keys, Enter, Escape and Tab work; only one
  Select is open at a time; the popup closes when its button scrolls out of
  view. A stored value that is not among the options is shown as a selected
  extra at the top of the list (labelled by `unknownLabel`) and stays
  selected until the user picks something else. Clicks inside the popup
  never reach a wrapping `<label>`.
- **SelectField** (`Field.tsx`): a captioned Select. It is a `div`, never a
  `<label>` around a Select; the Select carries its own `aria-label`.
- **Segmented** (`Segmented.tsx`): a button row for two to four choices, a
  `radiogroup` where the arrows move and wrap. An unknown stored value is
  added as an extra, selected segment.
- **Switch** (`Switch.tsx`): an on/off row, label left and track right; the
  whole row is a `role="switch"` button.
- **Checkbox and number input:** `input.checkbox` is a drawn box (the tables'
  selection columns use it); `input.input[type=number]` has no spinner.
  Under `forced-colors: active` the segments, switch track, checkbox and
  focus ring use system colours with visible borders.
- **The guard** (`ui/no-native-controls.test.ts`): a vitest scan of every
  `.tsx` under `src` that fails on a native `<select>`, a radio, a checkbox
  without `className="checkbox"` or a number input without `className="input"`.
  Its documented exception list is empty; an exception is a
  `"file:line reason"` entry.

### Filter catalogue

`views/lists/filters.ts` holds one catalogue per list (Compliance, Vulnerabilities,
Hosts, Audit log): each filter is a flag (one fixed value) or a choice (a
list of values), and each parameter holds one value. The list views build
their chip bars from it and the List widget editor offers the same filters,
so the two cannot drift. Runtime extras (compliance rule sets, counts) stay
in the views.

### Widget editors

The inspector's editors (`dashboards/settings.tsx`) use only those controls:

- **Number:** Count (grouped Select with search), Trend (Segmented: Off, 7,
  30, 90 d) and, with a trend, Line.
- **Graph:** one Select per count (a dot shows its line colour; counts
  already chosen are disabled in the others), "Add a count" up to four,
  Period and Line as Segmented.
- **Breakdown:** the source as Segmented (Alarms, Vulnerabilities,
  Compliance, Hosts).
- **Needs attention:** one Switch per kind (the last one on cannot be
  switched off) and "Show at most" (5, 8, 10, 15).
- **List:** the list, its filters as removable chips with an "Add filter"
  Select (a choice filter then asks for its value; picking a value for a
  used filter replaces the old one), and Rows (5, 8, 10, 15). Only the
  catalogue's filters are offered: runtime rule-set filters are not, but a
  stored `set=` parameter shows as a chip and is kept. Changing the list
  drops the filters the new list does not support, or whose value it does not offer.
- **Trend:** the compliance rule, grouped by rule set and labelled
  "<latest message> · <rule id>" (the API has no rule title), and Days (7,
  14, 30). Without `compliance.read` the list is empty.
- **Most exposed hosts:** Count (All kinds, Vulnerabilities only) and Hosts
  (3, 6, 10).
- **Note:** plain text.
- **Unknown stored values** (a day count, a rule, a list, an attention kind
  the editor does not offer) are shown as selected extras and saved back
  unchanged, never silently replaced. A stored rule missing from the loaded
  rules reads "<id> (not found)", or "<id> (could not load)" if loading
  failed.

## Threat alarms (P14)

- **Alarms** (`/alarms`, `g m`, `alarms.read`), an alarm's page
  (`/alarms/{id}`) and the suppress form (approved screen 12): see
  [console-alarms.md](console-alarms.md).

**Site rules** (`/site-rules`, with `site_rules.read`) lists the site's own
compliance rules and alarm rules (drafts) with New rule. A rule opens in
the inspector as a form (id for a new rule, title, severity, confidence,
for alarms the programs, expression, message). As you type, the server's
check (the agent's own loader) shows what is wrong beside the field, and
Save draft stays off until the rule passes. Delete asks first. Rules saved
here are drafts. Under each table, Publish lists what changed against the
published set; with the user's password typed again the rule signer signs
the set and the platform publishes it (needs `site_rules.publish`). A compliance
rule's panel can also be tested against one host (with `site_rules.test`;
a host outside the user's `hosts.read` reach is not found): it runs on the packages
and listening ports the platform holds and says match, no match or
unavailable (a rule over anything else, such as running processes, is
unavailable here). A Hosts section at the bottom of Site rules counts the
hosts the user may see running each set (current, behind, refused, not set up), lists the
ones that aren't current, and shows the `[[rule_sets]]` lines to paste into
an existing agent's `agent.toml`.
- **Coverage** (`/coverage`, `g t`, global `rules.coverage.read`): an ATT&CK
  matrix (tactics as columns, covered techniques with rule counts; empty
  tactics stay as visible gaps) above the rule list. Chips: Kill chain
  (the same cells grouped into the seven phases), Findings, Alarms, Include
  drafts. A cell or tactic filters the list; "N rules are not mapped"
  lists the unmapped. The matrix scrolls sideways inside its own box on
  narrow screens. Logic in `views/operate/coverage.ts` (tested).
- Rule panels show a rule's ATT&CK pairs as chips that open Coverage
  filtered to them; the site-rule editor adds pairs with a searchable
  picker (one option per technique and tactic).
- **Alarm suppressions** (`/alarm-suppressions`, `g q`; approved screen 14,
  `views/operate/AlarmSuppressions.tsx` and `SuppressionRow.tsx`), in the
  shared layout. Left: By status (Waiting / Active with expired / Rejected,
  counts linking to their cards) and Recent changes: the newest eight
  `alarm.suppression.*` audit lines of 30 days (`action_prefix`), each
  with its suppression number and who (named from `/api/v1/users` with
  `access.read`, else the id), shown with `audit.read` only; while loading,
  empty or failed the card says so in words. Right: one card per
  status; each row shows the program, What/Where/For chips, the quoted
  reason, "asked by … · when", "Would have closed N alarms in the last 7
  days" on waiting rows ("at least N" when capped), the status badge (a
  rejection with its reason) and Open alarm. Actions by flag: Approve and
  Reject… with an inline required reason (`can_decide`), Withdraw
  (`can_withdraw`), Remove… with a confirm (`can_remove`), and Ask again…
  (rejected rows with an alarm, for `alarms.suppress`) opening the
  suppress form prefilled from the row (alarm, what, where, for, reason);
  when the row's group is gone or outside the asker's reach (or all hosts
  is), the form starts at this host and says "The group this was for
  isn't one you can choose; pick where it applies." Every action button's
  accessible name names the row's program ("Approve /usr/bin/sh"). Each action is busy until it
  returns, shows errors in `role=alert`, reloads the list, the menu count
  and recent changes, and toasts "Saved · recorded in the audit log"; a
  row that moves to another card keeps focus, and a row that leaves
  hands focus to its card. The menu item counts the waiting requests the
  viewer can decide (`GET /api/v1/alarm-suppressions?state=waiting`,
  fetched only with `alarms.suppressions.approve`; `app/menuCount.ts`).
- The demo serves alarms and suppressions with the server's rules
  (`demo/suppressions.ts`): the approval setting from Settings › General,
  waiting/active/rejected/withdrawn/removed states, every refusal code,
  the per-row flags, options, `would_close` over the reader's reach,
  For counted from activation, close-on-activation of the source alarm
  when the where covers it,
  group rows matched with `demo/hostGroups.ts`, and a group's delete
  withdrawing its waiting rows and removing its active ones (counted in
  the delete preview's `suppressions_ended`). Rows are kept in browser
  storage, so a request made as one persona waits for another; rows read
  back are checked field by field (`validRow`) and malformed ones dropped.

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
  assignee) applies to what is loaded. **New case** (with `cases.write`)
  opens a form in the inspector. A row opens the case.
- **Case panel** (`case`, id is the case's UUID, `case:new` is the form):
  - the header shows number, title, status, severity, assignee and how many
    items are unresolved;
  - with `cases.write`, title, severity and (with `cases.assign`) assignee (a picker from
    `/cases/assignees`, plus Assign to me) save together with the version
    (`If-Match`). Status moves open to investigating and back, and **Close
    case…** asks for the resolution, a note and, for accepted risk, the date
    it is accepted until (the case reopens then). It lists the alarms,
    findings and vulnerabilities that still need an outcome and stays
    disabled until the rules are met (`panels/cases/cases.ts`, `closeProblems`).
    A closed case offers **Reopen**;
  - **Items**: each row shows its kind, title, severity and host and opens
    that object's own panel or page (alarm: its page `/alarms/<id>`, finding `finding:<rule
    set>/<rule>`, vulnerability `advisory:<advisory>`, host: its page,
    software `package:<manager>/<name>`). Alarms, findings and
    vulnerabilities take an outcome: resolved (offered only while the
    evidence is gone), false positive or accepted risk (a note is required).
    Hosts and software need none. **Remove** and **Add item** (kind and
    pasted id) work on open cases;
  - **Notes** (plain text) and the **Timeline**, newest first, with who did
    what.
  - Without `cases.write` the panel is read-only.
- **Add to case** (`panels/cases/AddToCase.tsx`, with `cases.write`): a button on
  an alarm's page (Details, and a command seen once), on each host row of a finding and of an advisory, on the
  host page and its top vulnerabilities, and on the software panel. Its dialog
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
  on its page makes "resolved" available for it), the visibility rule
  for a scoped viewer, and accepted risk that reopens when its date passes.
  It starts with four cases over real demo objects (an SSH and shell
  investigation, an exploited advisory on three hosts, web servers starting
  shells, and a closed one) and keeps cases in `localStorage`
  (`openvibes.v2.demo.cases`). As on the server, anyone holding
  `cases.read` can be assigned, and setting or changing an assignee needs
  `cases.assign` (403 otherwise): Analyst has `cases.write` but not
  `cases.assign`, Administrator has both, the operators have no cases.

## Assets v1 (hosts and software)

- **Hosts and the host page** (`/hosts`, `/hosts/{id}`): see
  [console-hosts.md](console-hosts.md).
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

## Shared list and detail pieces

Built once for every list and detail page (roles spec §10.3; approved
screens 16 and 17, and the shared layout). Hosts is the first user; the
other list pages move to them in step 5. `ui/ViewHeader.tsx` keeps working
for the pages not yet moved; its saved views stay in the browser.

- **FilterBar** (`ui/list/FilterBar.tsx`): the search box (`q` in the URL
  250 ms after the last key, at once on Enter or blur, and only onto the
  list's own URL: leaving the page drops a search not yet sent; "/" focuses it) and one chip per `ListFilter`
  (`{ param, label, values: {value, label, count}[] }`, `ui/list/filters.ts`).
  A chip is a Select drawn as a button (`aria-haspopup="listbox"`,
  `aria-expanded`, the Select's keyboard and search); its options show each
  value's count. A chosen value becomes a chip "Status: Online" with an ×
  ("Remove filter Status: Online"); focus moves to the chip that replaces
  the one used. On the right: **Clear all** (every parameter but `sort` and
  `dir`), **Save view** (only with something set and not already saved; a
  refusal such as "You already have a view with that name" is a
  `role="alert"` tied to the name field) and **Columns**. Saved views are
  chips: a click applies one (its parameters replace today's; only the
  page's filters, `q`, `sort` and `dir` are taken from it); × asks
  "Delete the view “…”?" before deleting (Escape cancels). After a save or
  delete, focus goes to the saved views, or to the search when none is left.
- **Columns** (`ui/list/ColumnsMenu.tsx`): a disclosure button with a
  checkbox per column; the first (Host) is checked and disabled, and all are
  disabled until the person's columns have loaded. Each change is a
  `PUT /api/v1/list-columns/{page}` carrying the full set after every
  toggle so far (`columnSaver` queues them, so quick toggles never undo
  each other); a refusal is a toast, and the queued set stays until the
  queue drains (a toggle made meanwhile builds on it), then the server's
  copy shows again.
- **Saved views** (`ui/list/savedViews.ts`): `useSavedViews(page)` and
  `useHiddenColumns(page)` (undefined until loaded) over `GET /api/v1/saved-views?page=` and
  `GET /api/v1/list-columns/{page}`; `saveView`, `deleteView` and
  `setHiddenColumns`. `importBrowserViews(page, legacyKey, mapQuery)` moves
  a page's old browser-only views to the console, mapping each query and
  storing it normalised (so it shows as active). Names are cut to 60
  characters; a name taken by a different view is retried once as
  "name (imported)". The key is removed only when every view is saved or
  already there (same name, same query); otherwise it stays and the next
  visit tries again.
- **SummaryLine** (`ui/list/SummaryLine.tsx`): `{count, text}` parts joined
  with " · ", zeros left out with `skipZero`; a `role="status"` paragraph
  that is always present, so a change is announced.
- **DetailPage** (`ui/detail/DetailPage.tsx`): optional crumb; header with
  icon, title, status, a facts line (joined with " · ", empty facts left
  out) and actions; an error callout (`role="alert"`); tiles; a narrow left
  and a wide right column (one column fills the width). An empty slot draws
  nothing. `Card` (a card of either column) lives here too; the person,
  group and settings pages use it. **Tile**
  (`ui/detail/Tile.tsx`): a link to the full list, named "Open alarms: 3". **FactTile** (`ui/detail/FactTile.tsx`): the same look for a fact, no link. **HourlyBars** (`ui/charts/HourlyBars.tsx`): 24 bars, a `<title>` each for hover, the SVG hidden from screen readers (`aria-hidden`); a visually hidden table with a caption carries the values. **BulkBar** on a server-paged list: it acts on the ids it is given (this page); the bulk route takes no filter, so `DataTable serverPaged` says "All n on this page are selected." and offers no "select all n matching". A `ListFilter` with `chipOnly` (the Alarms host) is drawn only while chosen.
  Tiles and the settings pages' links use `viewLink` (`app/nav.ts`): a
  plain left click navigates in place, a modified or middle click is left
  to the browser.
- **Demo** (`demo/routes/lists.ts`): the same routes, codes, caps (60
  characters, 1000-character query, 50 views per page, case-blind names, no
  Host column) and messages as `src/lists/saved_views.rs`, kept per person
  in the browser (`openvibes.v2.demo.lists.<user>`) and checked on load.
- **Tests:** `ui/list/FilterBar.test.tsx`, `ui/list/savedViews.test.ts`,
  `ui/detail/DetailPage.test.tsx`, `demo/routes/lists.test.ts`,
  `views/investigate/Hosts.test.tsx`, `demo/versionOrder.test.ts`,
  `app/location.test.ts` (the redirects). Vitest has no DOM: the bar is
  checked as markup and its actions as the helpers it calls; click and key
  flows (the chip menu from the keyboard, focus on the new chip's ×,
  Escape) are in `e2e/demo/hosts.spec.ts`.

## Interfaces

- **Entry:** `web/index.html` → `src/main.tsx` → `shell/App.tsx`.
- **Browser routes:** every view's path, `/login`,
  `/dashboards/{dashboard_id}`, `/settings/roles/{role_id}`,
  `/settings/people/{user_id}` and `/settings/host-groups/{group_id}`, listed in `web/frontend-contract.json` for
  the server's router; `app/frontendContract.test.ts` keeps the two in step
  (a page missing there loads in the app but is a 404 on reload or a link).
- **`app/registry.tsx`:** declares every view (path, icon, group, required
  permissions, shortcut) and object kind (panel). A new module is one entry
  in each.
- **Where code lives** (`web/src`):
  - `views/`: one file per page, in a folder per menu group:
    `investigate/` (Alarms, Compliance, Vulnerabilities, Hosts, Software,
    Ports and Services, Cases), `operate/` (Alarm suppressions, Site rules,
    Coverage), `admin/` (`Audit.tsx`, `settings/`: `Settings.tsx` plus
    one file per tab (`General.tsx`: the General tab), `roles/`: the role page, `people/`: a person's
    page, and `groups/`: a host group's page) and `help/` (About). `views/lists/` holds what the
    lists share: filter catalogues (`filters.ts`), row selection and
    sorting (`rows.ts`) and the test-trigger rules (`testRules.ts`).
  - `panels/`: one folder per subject (`hosts/`, `alarms/`, `findings/`,
    `triage/`, `cases/`, `rules/`, `admin/`), one file per object kind,
    named `<Kind>Panel.tsx`, holding
    that kind's panel and its "new" form (`ServiceAccountPanel.tsx` has
    both).
  - Logic without React sits beside its component in a lowercase `.ts`
    file with a unit test (`ruleAssignment.ts` next to `WhereItRuns.tsx`).
  - `app/`: session, navigation and the registry; `ui/`: shared controls;
    `dashboards/`: the dashboards feature; `demo/`: the in-browser API.
  - An `export` means another file imports it; a helper used by one file
    stays unexported.
  - Every folder has a `README.md`: what the folder is for and one line per
    file. `scripts/check-folder-readmes.sh` (local gate and CI) fails when a
    file is added, renamed or removed without its line.
- **Adding things:**
  - A page: its file in its menu group's folder under `views/`, one entry in `registry.tsx` (with its
    `access`), its path in `frontend-contract.json`.
  - A Settings tab: its file in `views/admin/settings/` and one line in the
    `tabs` list of `Settings.tsx`, with its `access`. The Settings menu
    entry opens to any tab's access by itself. Tabs: People, Roles, Host
    groups, Service accounts, Enrollment, Rule sets, Assistant. Settings has
    no outer filter: each tab has its own search field.
  - A full page under `/settings/…` (roles, people): the `subPage` function in
    `Settings.tsx`; it renders in place of the Settings header and tabs, with
    a "Settings › …" breadcrumb back (approved screens 2 and 5). The rail
    keeps Settings current on these pages (`prefix` in the registry).
  - Permission checks are `can(permission)`; there is no `global` flag. The
    catalogue and the needs closure helpers are in `app/permissions.ts`.
  - A permission: the server side only (`access/permission.rs`
    `Permission`, `access/catalogue.rs`, a migration for the database's
    permission rows, and the route's check). Then regenerate the API client
    (`npm run generate:api`) and `web/src/api/permissions.json`
    (`cargo run -p openvibes-console --bin export_openapi -- --permissions >
    crates/openvibes-console/web/src/api/permissions.json`); tests fail while
    either is stale. Role pickers read the live role list from
    `GET /api/v1/roles` (people: `GET /api/v1/users*`, host groups:
    `GET /api/v1/host-groups`); the demo seeds its roles from
    `templates.json` and `permissions.json` (Administrator).
- **Roles (`views/admin/settings/Roles.tsx`, `views/admin/roles/`):**
  - **Purpose:** Settings › Roles lists the roles (Administrator first,
    "Protected"; templates are not roles) with where each applies, its
    permission count and members. `/settings/roles/new` and
    `/settings/roles/{id}` open the role page: 1 Name and 2 Start from
    (Blank or a template; new roles only), the permission matrix (areas ×
    View / Change / Export / Approve and publish, "All" per row and a toggle
    per column, ⓘ on platform permissions), Hosts (All hosts or host groups)
    and a sticky bar with the summary, Cancel, Delete role, Create or Save.
  - **Interfaces:** `GET/POST /api/v1/roles`, `GET/PATCH/DELETE
    /api/v1/roles/{id}` (PATCH sends the `version` read),
    `GET /api/v1/host-groups`. Templates and the catalogue come from
    `app/permissions.ts`, so `/role-templates` is not fetched. Turning a
    permission on adds what it needs (`turnOn`), turning it off removes
    what depends on it (`turnOff`), and a notice names the others changed:
    the console only ever sends a closed set.
  - **Config:** none. Read-only for Administrator ("cannot be changed") and
    for anyone without `access.roles`.
  - **Failure behaviour:** a refused save or delete (403 with the missing
    permission, 409 name taken or role in use, 422 missing needs or unknown
    group, 400) shows the server's message above the bar and keeps the
    edits. A 409 `stale_role` reloads the role and says "Someone else
    changed this role; your edits were not saved."
  - **How to test:** `roles/RolePage.test.tsx` (reducer, markup and the
    request bodies, no DOM library); the demo e2e `roles.spec.ts` creates
    "Night shift" from the Analyst template on WindowsServers (with axe)
    and hits the case-insensitive name check.
- **People (`views/admin/settings/People.tsx`, `views/admin/people/`):**
  - **Purpose:** Settings › People lists everyone inside the viewer's
    share: Person, Roles as badges "<role> · <where it applies>", Signs in
    with (Password / Single sign-on), Status (Active / Disabled) and Last
    sign-in. "+ New person" (`access.users`) opens a dialog that creates a
    local sign-in and shows its one-time password once. A row opens
    `/settings/people/{id}`, one page with no tabs: the header (initials,
    name, status, "<n> roles · <n> permissions · last signed in <when>",
    Edit details for yourself or with `access.users`, and ⋯ with Reset
    password and Disable/Enable, hidden on your own page); Details and
    Recent activity (with a link to the audit log filtered to the person)
    on the left; Roles (compact cards with Open role and Remove, "+ Add
    role") and Access (grouped under "On all hosts", "Only on <groups>"
    and "Across the platform", each line "<permission> · from <role>") on
    the right.
  - **Interfaces:** `GET/POST /api/v1/users`, `GET/PATCH
    /api/v1/users/{id}` (display name and email), `POST
    …/disable|enable|reset-password`, `PUT|DELETE …/roles/{role_id}`,
    `GET /api/v1/roles`. A change invalidates `/api/v1/users` and
    `/api/v1/roles` (members counts).
  - **Config:** none. Add role and Remove need `access.grant` and are
    hidden on your own page (the server refuses changing your own roles).
    Add role and New person offer only roles inside the viewer's share
    (`fitsShare`/`outsideShare` in `people/people.ts`, the client copy of
    `access/share.rs`, which the demo server uses too); the server decides.
    `fitsShare` skips `assistant.use`, which the session leaves out while
    no assistant is set up.
  - **Failure behaviour:** a refused change shows above the columns; a 409
    `last_administrator` reads "This is the last Administrator. Give
    someone else the Administrator role first." A person outside the
    share is a 404 (`user_not_found`), shown as an error. A refused
    Edit details shows the server's message in the form and keeps the
    edits.
  - **How to test:** `people/PersonPage.test.tsx` and
    `settings/People.test.tsx` (markup, grouping, the PUT with a stubbed
    fetch, the 409 message, no Disable on your own page); the demo e2e
    creates a person with a one-time password (`smoke.spec.ts`), and
    `people.spec.ts` gives and removes a role on one group ("Only on
    WindowsServers", with axe) and checks your own page. The live e2e
    (`e2e/live/teams.spec.ts`, helpers in `e2e/live/helpers.ts`) runs two
    teams against the real server: each sees and changes only its hosts,
    and a team lead gives only roles inside their access (see
    console-rbac.md, Live check). `e2e/live/suppressions.spec.ts` runs
    a suppression through approval by the other team lead (same section).
- **Host groups (`views/admin/settings/HostGroups.tsx`, `views/admin/groups/`):**
  - **Purpose:** Settings › Host groups (approved screen 9) lists the
    groups, automatic first, then rule, then manual: Group (name, kind
    badge, description), Membership (the server's sentence), Hosts ("N
    hosts", "M online"), Open problems and Who reaches it (role badges,
    people). "+ New group" opens `/settings/host-groups/new` (Rule or
    Manual, then the same editor); a row opens `/settings/host-groups/{id}`
    (screens 10, 10b, 10c) in the shared layout: the header (counts, roles,
    people; Edit and ⋯ with Duplicate… and Delete group…), Details, Who
    reaches it (roles linked to their page, permissions, people) and Recent
    changes on the left; the Rule card ("Where"/"and" rows) or Hosts picked
    by hand (chips, "Search hosts to add"), then Hosts in this group on the
    right. Automatic groups show the "Made by OpenVIBES…" callout; groups
    made from tags offer "Turn into a rule". While editing, a debounced
    preview says "If you save: +N (…), −M (…)" and who gains or loses
    access; Delete shows the same preview and the rule-set switches it
    removes.
  - **Interfaces:** `GET /api/v1/host-groups`, `GET|PATCH|DELETE
    /api/v1/host-groups/{id}` (the version read; DELETE `?version=`),
    `GET …/{id}/hosts` (all pages, `after` = last agent id; up to 10000, the
    server's pick limit, for manual groups and Duplicate, else 2000),
    `POST /api/v1/host-groups`, `POST …/preview` and `…/{id}/preview`
    (`{}` previews a delete), `GET /api/v1/agents?state=active` (hosts to
    add, filtered in the browser), and with `access.read` `GET
    /api/v1/users` and `/api/v1/roles` (actor names, people and permission
    counts). A save invalidates `/api/v1/host-groups` and
    `/api/v1/rule-set-assignments`.
  - **Config:** none. Writes need `host_groups.manage` (else hidden) and
    `hosts.read` on every host (else disabled, titled "Changing host groups
    needs access to every host", the server's 403). PATCH sends only what
    changed (`patchBody`), so a rename sends the name alone. Without
    `hosts.read` everywhere, counts read "N hosts you can see" (0: "No hosts
    you can see", without "online") and a manual group's membership drops
    its count. The reason writes are off shows as text under the header.
  - **Failure behaviour:** a refusal shows above the columns (a 422 names
    the field). A 409 `stale_group` reloads the group and says "Someone
    else changed this group. It has been reloaded." while the edit stays
    open: the user's own changes (against what editing started from) move
    onto the reload, and everything else, such as someone else's rename or
    added hosts, comes from it. If fewer picked hosts load than the group
    has, picks cannot be edited (or duplicated) and the page says why.
    Stop editing and Cancel ask before discarding changes. A 409 `group_in_use` on delete reads "Roles still
    use this group: …". A failed preview reads "Preview unavailable".
  - **How to test:** `groups/groupState.test.ts` (reducer, PATCH bodies,
    preview sentences, list wording), `groups/GroupPage.test.tsx` (markup:
    rule, editing, automatic callout, upgraded note, write access, the
    PATCH through a stubbed fetch) and `settings/hostGroups.test.tsx` (the
    list's columns and order).
- **`app/location.ts`:** URL ↔ state (view, panel stack, filters); tested.
- **`api/client.ts`:** `request`, `load` (cached by path), `invalidate(prefix)`
  after mutations, and the `useResource`/`useAllPages` hooks (`useAllPages`
  also follows plain-array pages continued by `after=<field of the last row>`). Live requests
  send the session cookie, plus `x-csrf-token` on mutations.
- **`app/source.ts`:** picks live or demo data. An installed build (`npm run
  build`, embedded in the RPM) is always live, and the demo code is left out
  of its bundle.
- **`demo/server.ts`:** (preview and dev builds only) an in-browser implementation of the endpoints v2 uses,
  over deterministic synthetic data (`demo/data.ts`). `demo/context.ts`
  holds the state every area shares; each area's routes are in
  `demo/routes/` (hosts, findings, alarms, rules, cases, …). It follows the wire
  types and the permission model, with personas viewer, analyst, operator,
  scoped operator, team lead, rule author and admin. Each persona signs in as a seeded
  person (Vic, Sam, Ola, Pia, Lee, Rae, Alex) whose demo roles give its capabilities through
  `resolveCapabilities` in `demo/share.ts` (the port of `access/rbac.rs`);
  roles are Administrator, Viewer, Analyst and Operator on all hosts,
  "Windows lead" (Team lead on WindowsServers, held by Wen), "Pilot lead"
  (Team lead on Pilot hosts, the team lead persona) and "Operator (Prod)"
  (the scoped operator), and "Rule author" on all hosts (the rule author
  persona: hosts but no alarms, vulnerabilities or compliance, so a host's
  page shows none of them). `routes/roles.ts` and
  `routes/access.ts` mirror the roles, people and service-account routes
  with their refusal codes (`stale_role`, `role_name_taken`, `role_in_use`
  with `holders`, `protected_role`, `missing_needs`, `unknown_group`,
  `last_administrator`, `use_change_password`, nobody changing or disabling
  themself) and the share check, so people and accounts outside it are
  404. Host groups and labels (`routes/groups.ts`, labels in
  `routes/hosts.ts`) mirror `hosts/groups.rs` and `hosts/labels.rs`: the
  list, page, hosts, preview, create, edit (an automatic group edited
  becomes a rule group) and delete, with `invalid_group`,
  `invalid_condition`, `unknown_host`, `group_name_taken`, `stale_group`,
  `group_in_use` with `roles`, `group_not_found`, "Changing host groups
  needs access to every host", `invalid_label`, `too_many_labels` and
  `host_not_found`. Membership is `demo/hostGroups.ts`, a port of the SQL
  function `console_host_in_group` (glob with `*` only, case-insensitive;
  CIDR; negate; unknown facts never match; active hosts only, the demo's
  "stale" counting as active), tested against the store's membership
  cases. The demo starts with automatic groups (Linux, Debian 12, Fedora
  44, Ubuntu 24.04), rule groups (WindowsServers, HQ network, Lab) and
  manual ones (Production, upgraded from tags; Pilot hosts). Triage assignees follow the server: holders of the area's
  `*.triage` through a role that reaches some host, or an Administrator;
  bulk program suppressions are skipped without `alarms.suppress` on all
  hosts, close every selected alarm of their rule and program (kept on the
  row as `closed` and replayed on load), and list all of them as requested
  while approval is on; a group's delete writes one audit line per ended
  suppression. Tested. Its compliance findings use only the
  rules OpenVIBES ships (openvibes-rules `baseline/rules.json`: ids,
  severities, messages and expressions as they are), so the public demo and
  the website's screenshots never show a check the product lacks; a test
  holds it to that list.
- **Types:** from the OpenAPI client (`src/api/generated.ts`, generated by
  `npm run generate:api`), via `api/types.ts`.

## Upgrading

- **Roles step 4 (Hosts):** Hosts moved from `/agents` to `/hosts`, and the
  host panel became the host page `/hosts/{id}`. Old links and bookmarks
  redirect (`/agents?…` to the list, `?open=agent:ID` to the page). Views
  saved in the browser are imported to the person's account the first time
  they open Hosts; see [console-hosts.md](console-hosts.md).
- **Roles step 5a (Alarms):** the alarm panel became the alarm's page
  `/alarms/{id}`; old links (`?open=alarm:ID`) redirect to it. Its Last 24
  hours timeline starts filling after the upgrade (ingest records hourly
  starts from then on). Rules without `explain` and `check` text show their
  title and message. The list no longer sorts by message, host or state.
  Alarm views saved in the browser are moved to the person's account the
  first time they open Alarms; see [console-alarms.md](console-alarms.md).

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
- demo persona, the demo's general settings and its alarm suppressions.

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
read-only, the two-team journey (`teams.spec.ts`), the Hosts journey
(`hosts.spec.ts`, see console-hosts.md), and axe in both themes.
The live tests also check the service accounts empty state on a fresh server
and the People and Audit filtered empty states at narrow widths in light and
dark themes. Audit distinguishes an empty date range from filters that hide existing events.

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

## Side panel anatomy

Every side panel is built from the same parts (`ui/panel.tsx`, styles in
`styles/panels.css`), so new panels look like the rest without new CSS:

- `PanelHeader` first: kind, title, badges and actions.
- A padded `<div className="panel-body stack">` for text, key-value lists and
  controls, built from `Section`.
- `Section flush` for full-width tables and lists. It lines up the same
  inside a `panel-body` or beside one (it cancels the body padding), so there
  is no need to place it outside.
- An action that looks like a link is `<button className="link-button">`
  (`object-link` is for `<a>` only). Spacing comes from shared classes such
  as `gap-start`, not inline styles.
