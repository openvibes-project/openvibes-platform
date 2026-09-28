# console-v2 (experimental web console)

A redesign of the console's web interface (approved by the user on
2026-09-28), in `crates/openvibes-console/web/v2` beside v1. It talks to the same
`/api/v1` as v1 and changes nothing on the server. v1
(`crates/openvibes-console/web/src`) is still what the RPM embeds until v2
replaces it there.
Design: [2026-09-28-console-v2-design.md](../superpowers/specs/2026-09-28-console-v2-design.md).

## Purpose

Show everything v1 shows, without page changes for details:

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
- **Parity with v1:**
  - findings with bulk triage and a 14-day trend of reporting hosts;
  - vulnerabilities by advisory, with CVEs, EPSS and KEV;
  - agents, with tags and revocation;
  - enrollment tokens;
  - rule sets, with signed-bundle preview and publish;
  - access: roles, bindings and asset groups;
  - service accounts, with tokens issued once;
  - audit log, with ranges, CSV export and retention.

  Not yet in v2: per-host triage fields for assignee and "accepted until"
  (v1's single-finding form).

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
- **The demo** keeps dashboards and home choices in the browser's
  `localStorage` (`openvibes.v2.demo.dashboards`).

## Interfaces

- **Entry:** `web/v2/index.html` → `v2/src/main.tsx` → `shell/App.tsx`.
- **`app/registry.tsx`:** declares every view (path, icon, group, required
  permissions, shortcut) and object kind (panel). A new module is one entry
  in each.
- **`app/location.ts`:** URL ↔ state (view, panel stack, filters); tested.
- **`api/client.ts`:** `request`, `load` (cached by path), `invalidate(prefix)`
  after mutations, and the `useResource`/`useAllPages` hooks. Live requests
  send the session cookie, plus `x-csrf-token` on mutations.
- **`demo/server.ts`:** an in-browser implementation of the endpoints v2 uses,
  over deterministic synthetic data (`demo/data.ts`). It follows the wire
  types and the permission model, with personas viewer, analyst, operator,
  scoped operator and admin. Tested.
- **Types:** from the shared OpenAPI client (`web/src/api/generated.ts`), via
  `api/types.ts`.

## Configuration

| Setting | Where | Effect |
|---|---|---|
| `VITE_V2_SOURCE` | build env | `demo` or `live`; the default is `demo` in dev and `live` in a build |
| `?demo=1` / `?live=1` | URL | switches the source for this browser session |
| `V2_BASE` | build env | public path (`/openvibes-platform/` on Pages) |
| `V2_LIVE` | dev env | proxy target for `/api` and `/auth` (default: the seeded server) |

Per-viewer conveniences go in browser storage and are never needed for
correctness:
- theme (`openvibes.theme`, shared with v1);
- saved views;
- rail pinned;
- inspector width;
- windows;
- recent objects;
- assistant open state;
- demo persona.

## Failure behaviour

- **401 on the session:** shows the sign-in form. Another failure shows
  "not reachable", with a link to the demo.
- **Failed request:** its view or panel shows the API's problem title, plus
  a hint for 403 and for network errors.
- **Mutation errors:** shown inline or as a toast. A 409 on triage reloads
  the data.
- **Unknown panel kinds and views:** they show an explanation instead of
  failing.

## How to test

```sh
cd crates/openvibes-console/web
npm ci
npx vitest run --config vite.v2.config.ts   # location, client, table, demo server
npx eslint v2 vite.v2.config.ts --max-warnings 0 && npx tsc --noEmit
npm run test:e2e:v2                          # Playwright smoke, dashboards + axe (both themes), Chromium and Firefox
npm run dev:v2                               # http://127.0.0.1:5174 with demo data
V2_LIVE=https://127.0.0.1:8443 npm run dev:v2 -- --open '/?live=1'   # against a running console
```

The `Console v2 preview` workflow runs the same checks and the end-to-end
tests on pull requests; on pushes to `main` it also builds with demo data
and publishes to GitHub Pages (https://openvibes-project.github.io/openvibes-platform/).
A failing check stops the deploy.

Tested against a real console (2026-09-28): a throwaway database from
`scripts/test-db.sh`, `openvibes-admin migrate`, `user create`, and `import`
of generated finding exports, with the console's `public_origin` set to the
dev server. Covered: sign-in, every view, token creation (Idempotency-Key),
bulk triage, the agent panel and the audit log.
