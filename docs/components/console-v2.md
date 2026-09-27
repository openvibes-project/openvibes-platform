# console-v2 (experimental web console)

A redesign of the console's web interface, on the `console-v2` branch for
review. It talks to the same `/api/v1` as v1 and changes nothing on the
server. v1 (`crates/openvibes-console/web/src`) is still what the RPM ships.
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
  and one table component for every list.

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
npm run dev:v2                               # http://127.0.0.1:5174 with demo data
V2_LIVE=https://127.0.0.1:8443 npm run dev:v2 -- --open '/?live=1'   # against a running console
```

The `Console v2 preview` workflow runs the same checks, builds with demo data
and publishes to GitHub Pages on every push to `console-v2`.
