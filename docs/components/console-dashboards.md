# console-dashboards

User dashboards over `/api/v1` (module `crates/openvibes-console/src/dashboards.rs`,
store `platform_store::dashboards`, schema 26). Spec:
[2026-09-28-console-dashboards-design.md](../superpowers/specs/2026-09-28-console-dashboards-design.md).

## Purpose

People build their own views of the fleet: dashboards made of tiles, saved on
the platform, opened on any device, optionally shared with a role. A dashboard
stores the questions, never the answers: a name and a layout of widgets. Every
widget loads its data through the normal read APIs with the viewer's own
permissions and asset-group scope, so a shared dashboard shows each viewer only
what that viewer may see.

## Interfaces

Browser session only; a service-account bearer token gets 403.

| Route | Who | Result |
|---|---|---|
| `GET /api/v1/dashboards` | any signed-in user | own dashboards first, then those shared with a role the user holds, each by name (`DashboardPage`) |
| `POST /api/v1/dashboards` | any signed-in user | `201 DashboardView` + `ETag` |
| `GET /api/v1/dashboards/{id}` | owner or holder of the shared role | `DashboardView` + `ETag` |
| `PUT /api/v1/dashboards/{id}` | owner, `If-Match` required | `DashboardView` + new `ETag` |
| `DELETE /api/v1/dashboards/{id}` | owner | 204 |
| `PUT /api/v1/dashboards/{id}/sharing` | owner with global `dashboards.share` | `{ "role_id": "analyst" \| null }` |
| `GET /api/v1/me/home` | any signed-in user | `{ "dashboard_id": id \| null }` (`null` = built-in Overview) |
| `PUT /api/v1/me/home` | any signed-in user | the dashboard must be visible |

Layout: `{ "schema": 1, "widgets": [{ "id", "type", "x", "y", "w", "h", "config" }] }`.
Limits: at most 64 KiB and 40 widgets; `id` 1–32 of `a-z0-9-`, unique;
`x` 0–11, `w` 1–12, `x + w ≤ 12`, `y` 0–199, `h` 1–12; `type` one of
`number breakdown attention list trend top-hosts note`; `config` at most 16
keys whose values are strings (≤ 256 characters), integers, booleans or
string lists (≤ 16). Names: 1–80 characters, trimmed, no control characters.
At most 100 dashboards per owner. Adding a widget type means adding it to
`WIDGET_TYPES` here and to the UI in the same change.

Audit: `dashboard.create`, `.update`, `.delete`, `.share` (old and new role),
`.home`, in the same transaction as the change; the name is recorded, never
the layout.

## User interface

In the web console (`web/src/dashboards`). The grid rules live in `layout.ts`
and mirror this module's validation. The widgets are in `widgets.tsx`,
`tiles.tsx` and `tiles2.tsx`. The editor store is `editor.ts`, and the page
is `DashboardsView.tsx`. See [console-web.md](console-web.md#dashboards) for
behaviour. The in-browser demo API (`web/src/demo/dashboards.ts`)
applies the same rules and status codes as this API.

## Configuration

None.

## Failure behaviour

| Situation | Result |
|---|---|
| no session | 401 |
| bearer token, sharing without `dashboards.share`, editing someone else's dashboard | 403 |
| unknown, invisible or malformed id | 404 (the same answer, so ids cannot be probed) |
| stale version / missing `If-Match` | 412 / 428 |
| invalid JSON body | 400 |
| invalid name or layout, 100 dashboards already, unknown role | 422 (validation lists `field_errors`, e.g. `layout.widgets[0].type`) |
| database unavailable | 503 |
| home dashboard deleted or no longer visible | `GET /me/home` answers `null` |
| a tile with nothing to show (no findings, no vulnerable host) | the tile says so ("All clear", "No host has an open vulnerability"), never a blank box; a failed read shows its error |
| no vulnerability feed ever imported (vulns not installed, or its first download failed) | no vulnerability tile claims "nothing found": Most exposed hosts and a vulnerabilities breakdown say "Vulnerability scanning is not set up", and vulnerability number tiles show "— Not set up" instead of 0 (summary's `feed_last_imported_at` is null) |

## How to test

With `eval "$(scripts/test-db.sh)"`:

```sh
cargo test -p platform-store --test console_dashboards       # ownership, sharing, versions, limit, home
cargo test -p openvibes-console --lib dashboards              # layout and name validation
cargo test -p openvibes-console --all-features --test dashboards_http   # routes, auth, audit
cd crates/openvibes-console/web
npm test -- src/dashboards src/demo                                      # grid, config, editor, demo API
npm run test:e2e:demo -- dashboards                                     # create, edit, keyboard, share, home, axe
```
