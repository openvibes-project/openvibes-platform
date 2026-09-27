# Console v2: design

Status: experimental, branch `console-v2`, not for merge until the user
has tried it. Written 2026-09-28 by Claude on the user's instruction to
"completely redo the design of the console" without questions.

## What the user asked for

- A complete redesign. Keep only the dark mode, the logo and the favicon.
- Modern, with window-in-window behaviour: opening a finding,
  vulnerability or agent must not leave the page you are on.
- The assistant usable while looking around, not a page of its own.
- Simple to use, still all the information one needs; many small
  usability fixes.
- Hostable from its own branch so the user can look at it (chosen: both
  a local run and a GitHub Pages preview with built-in demo data).
- Prepared for the future.

## Principles (from `decisions.md`, applied)

Interface first: every screen answers a question quickly, no dashboard
for its own sake. Quiet by default. Customisable views. Fast: no new
runtime dependency (React only, as v1).

## Layout

```
┌────┬──────────────────────────────────────────┬──────────────┬─────────┐
│rail│ top bar: title · search/⌘K · assistant · │              │         │
│    ├──────────────────────────────────────────┤  inspector   │assistant│
│    │ view: filter bar + saved views           │  (panel      │ dock    │
│    │       dense table / overview             │   stack)     │ (toggle)│
│    │                                          │              │         │
└────┴──────────────────────────────────────────┴──────────────┴─────────┘
            floating windows (popped-out panels) above everything, dock of
            minimised windows at the bottom
```

- **Rail:** icon navigation, expands to labels on hover or when pinned.
  Groups: Investigate (Overview, Findings, Vulnerabilities, Agents),
  Operate (Enrollment, Rule sets), Administer (Access, Service accounts,
  Audit). Items the session cannot open are hidden.
- **Inspector (window-in-window):** clicking any object opens its panel on
  the right; the list stays usable. Following a link inside a panel
  (finding → agent → advisory) pushes a panel onto a stack with a
  breadcrumb; Esc or Back pops. The stack lives in the URL (`?open=`), so
  back/forward, reload and shared links restore it. The inspector is
  resizable and can be maximised.
- **Floating windows:** any panel can be popped out into a draggable,
  resizable window, to compare two agents or keep an advisory open while
  browsing. Windows can be minimised to a dock and are restored after a
  reload (browser storage, per viewer).
- **Assistant dock:** a toggle (button or Ctrl+J) opens a chat column on
  the far right, available on every view. It knows the object on top of
  the inspector and offers it as context ("Ask about host-00012"); the
  context is sent inside the question, so the API is unchanged. Citations
  in answers open the cited object in the inspector. Hidden when the
  session lacks `assistant.use`.
- **Command palette (Ctrl+K):** jump to any view, open an agent by host
  name, an advisory or CVE, a rule; run actions (new enrollment token,
  toggle theme, open the assistant). Recent objects are listed first.

## Views

- **Overview** answers "what needs me now": a strip of counts (agents
  active/stale/revoked, findings by severity, vulnerabilities by severity,
  exploited, reboot needed) and one **attention list** mixing exploited
  vulnerabilities, critical and high open finding groups and stale agents,
  each opening its panel. Top exposed hosts beside it.
- **Findings:** finding groups (rule × rule set) with severity, endpoints,
  triage counts. The panel lists endpoints with bulk triage.
- **Vulnerabilities:** advisory rows with CVSS, EPSS, KEV/exploited,
  reboot, hosts; quick filters for the server-side filters.
- **Agents:** hosts with status, last contact, version; the agent panel
  shows its findings, vulnerabilities, certificates and tags, with revoke.
- **Enrollment, Rule sets, Access, Service accounts, Audit:** the same
  table + panel pattern; creation happens in a panel, never a new page.

Every table: sortable columns, text filter, keyboard navigation (j/k,
Enter opens, / focuses the filter), sticky header, empty and error states
that say what to do, and **saved views** (filter + sort, stored per
viewer) as the first step of "customisable everything".

## Data

- Types come from the OpenAPI client (`web/src/api/generated.ts`), shared
  with v1.
- Two sources: **live** (the console's own `/api/v1` with the browser
  session and CSRF token) and **demo** (an in-browser implementation of
  every endpoint over deterministic synthetic data, with a persona switch
  for the built-in roles). The Pages preview and `?demo=1` use demo.
- Permissions: the same capability model as v1 (`permission` + global or
  asset-group scope); in demo the persona's role table.

## Prepared for the future

- Views and object kinds are registered in one place
  (`v2/src/app/registry.tsx`): a new module (threat alarms, inventory,
  agent health) is one view entry and one panel entry, and immediately
  gets the inspector, windows, palette search and the assistant context.
- Panels are addressed by `kind:id`, the same identifiers the assistant
  cites, so assistant answers and future notifications can open them.
- Agent health (P12) has a place in the agent panel once the API exposes
  it.

## Hosting

- `npm run dev:v2` in `crates/openvibes-console/web` serves v2 on
  http://127.0.0.1:5174 with demo data (live data when a console is
  proxied, see the component page).
- `.github/workflows/console-v2-pages.yml` builds v2 in demo mode and
  deploys it to GitHub Pages on every push to `console-v2`.

## Out of scope

Server changes, replacing v1 in the RPM, SSO. v1 stays untouched and is
still what `main` ships.
