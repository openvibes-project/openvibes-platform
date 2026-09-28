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
  (marked expired once past).

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
- **Phones:** tiles stack in reading order, and editing is hidden.
- **Menu:**
  - Duplicate, Rename and Delete;
  - Share with role (owner with `dashboards.share`);
  - Set as home.
- **The demo** (preview and dev only) keeps dashboards and home choices in the browser's
  `localStorage` (`openvibes.v2.demo.dashboards`).

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
npm ci
npm run lint && npm run typecheck
npm test                     # location, client, table, source, contract, demo server
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
The live tests also check the service accounts empty state on a fresh server.

The `Console demo preview` workflow (`console-demo-pages.yml`) runs lint,
types, unit tests and the demo end-to-end tests on pull requests; on pushes
to `main` it also builds the demo and publishes it to GitHub Pages
(https://openvibes-project.github.io/openvibes-platform/). A failing check
stops the deploy. The main CI workflow runs the live tests.
