# Console custom dashboards: design

Status: design approved by the user section by section on 2026-09-28;
written spec awaiting review. Builds on console v2 (#52).

## Goal

Users build their own views of the fleet: dashboards made of tiles that
they arrange, save on the platform, reopen on any device, and optionally
share with a role. The built-in Overview becomes the default dashboard.

User decisions (2026-09-28):
- **Storage:** dashboards are saved on the platform, per user; one can be
  shared with a role.
- **Overview:** it becomes the built-in default dashboard. Users duplicate
  it to customise, and they pick which dashboard opens first.

## Principles

- **A dashboard stores the questions, never the answers.** It is a name
  and a layout of widgets with their settings. Every widget loads its data
  through the existing read APIs, with the viewer's own permissions and
  asset-group scope. A shared dashboard therefore shows each viewer only
  what that viewer may see, and sharing cannot leak data.
- **No dashboards for their own sake** (`decisions.md`, principle 1).
  Tiles are working tools: every number, bar and row opens the object in
  the inspector, or a filtered list.
- **Customisable, with sensible defaults** (principle 3): the built-in
  Overview stays good without any setup.

## 1. Data and API

### Storage (migration 0026, schema 26)

```sql
CREATE TABLE console_dashboards (
    dashboard_id uuid PRIMARY KEY,
    owner_user_id uuid NOT NULL REFERENCES console_users ON DELETE CASCADE,
    name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 80),
    layout jsonb NOT NULL CHECK (octet_length(layout::text) <= 65536),
    shared_role_id text NULL REFERENCES console_roles ON DELETE SET NULL,
    version integer NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
);
CREATE INDEX console_dashboards_owner_idx ON console_dashboards (owner_user_id);
CREATE INDEX console_dashboards_shared_idx ON console_dashboards (shared_role_id) WHERE shared_role_id IS NOT NULL;

CREATE TABLE console_user_home (
    user_id uuid PRIMARY KEY REFERENCES console_users ON DELETE CASCADE,
    dashboard_id uuid NOT NULL REFERENCES console_dashboards ON DELETE CASCADE
);
```

- Grants go to `openvibes-console`, like the other console tables.
- The migration also adds the permission `dashboards.share` (scope class
  `global`) and grants it to the built-in `admin` role. The Rust role table
  changes in the same change, and the existing PostgreSQL/Rust parity test
  covers it.
- A missing home row, or one whose dashboard was deleted, means the
  built-in Overview.

### Visibility and ownership

Viewers see:
- their own dashboards;
- dashboards whose `shared_role_id` is a role they hold through any
  binding (a global binding or an asset-group binding).

Only the owner may edit, delete or change sharing. Sharing needs
`dashboards.share` with a global scope, in addition to ownership. A user
with no roles sees only their own dashboards.

### API (`/api/v1`, in the OpenAPI document, browser session only)

Dashboards belong to console users; a service-account bearer token gets
403 on every dashboard route.

| Method and path | Who | Result |
|---|---|---|
| `GET /dashboards` | any signed-in user | `{ items: DashboardSummary[] }`: id, name, owner display name, `mine`, `shared_role_id`, version, updated_at. Own dashboards first, then shared ones, each ordered by name. |
| `POST /dashboards` | any signed-in user | `201 DashboardView` (body `{ name, layout }`) |
| `GET /dashboards/{id}` | owner, or holder of the shared role | `DashboardView` with an `ETag: "<version>"` header |
| `PUT /dashboards/{id}` | owner; `If-Match` required | `DashboardView`; stale version → 412, missing → 428 |
| `DELETE /dashboards/{id}` | owner | 204 |
| `PUT /dashboards/{id}/sharing` | owner with global `dashboards.share` | body `{ role_id: string \| null }`; unknown role → 422 |
| `GET /me/home` | any signed-in user | `{ dashboard_id: uuid \| null }` |
| `PUT /me/home` | any signed-in user | body `{ dashboard_id: uuid \| null }`; the dashboard must be visible to the user (else 404) |

- A dashboard that doesn't exist and one the caller may not see both
  answer 404, so ids can't be probed.
- Editing a visible dashboard the caller doesn't own is 403.
- **Audit events:** `dashboard.create`, `dashboard.update`,
  `dashboard.delete`, `dashboard.share` (with the old and new role),
  `dashboard.home`. The target is the dashboard id. The layout itself is
  not copied into the audit log.
- **Limits:** at most 100 dashboards per owner (422 above that). Names are
  1–80 characters with no control characters.

### Layout (validated by the server)

```json
{
  "schema": 1,
  "widgets": [
    { "id": "w1", "type": "number", "x": 0, "y": 0, "w": 3, "h": 2,
      "config": { "metric": "findings.open.critical" } }
  ]
}
```

- `schema` must be 1. The layout is at most 64 KiB, with at most 40
  widgets.
- `id`: 1–32 characters `[a-z0-9-]`, unique within the layout.
- `x` 0–11, `w` 1–12, `x + w ≤ 12`; `y` 0–199, `h` 1–12.
- `type` is one of the allow-listed widget types (§2). `config` is an
  object of at most 16 keys; values are strings of at most 256 characters,
  integers, booleans, or arrays of at most 16 such strings.
- The server checks `config` only for shape; each widget's meaning is
  validated by the UI. An unknown `type` is refused (422, with
  `field_errors` naming `widgets[i].type`). A new widget type is added to
  the allow-list in the same change as its UI.

### Built-in Overview

It is defined in the console frontend as a constant layout, id
`builtin:overview`. It isn't stored, can't be edited or shared, and
changes with releases. `PUT /me/home` with `dashboard_id: null` selects it.

## 2. User interface

### Navigation

- The rail's first item becomes **Dashboards** (path `/`). It opens the
  home dashboard; `/dashboards/{id}` opens a specific one.
- The header's switcher groups dashboards into **Built-in**, **Mine** and
  **Shared with me**. A star sets the current one as home.
- The Ctrl+K palette lists dashboards under "Dashboards".

### Grid

- 12 columns, with a row height of 56 px. Tiles are placed by `x, y, w, h`.
- Below 720 px wide, tiles stack in one column in reading order (by `y`,
  then `x`).
- Items inside tiles open in the inspector like everywhere else. A
  tile's "Open list" goes to the matching filtered view.

### Editing

- An **Edit** button switches to edit mode; view mode never moves
  anything.
- **In edit mode:**
  - dragging a tile moves it and dragging its corner resizes it, snapping
    to the grid;
  - overlapping tiles push the ones below them down;
  - with a tile focused, arrow keys move it and Shift+arrows resize it.
- **Add widget** opens the widget gallery in the inspector. Choosing a
  type adds a tile and opens its settings in the inspector, and the tile
  shows a live preview.
- **Save** or **Cancel**. A 412 on save keeps the edits and offers
  "Reload theirs" or "Save as a copy".
- **The dashboard menu:** Duplicate, Rename, Delete (with inline
  confirmation), Share with role… (shown only with global
  `dashboards.share`), and Set as home.
- **The built-in and shared dashboards** offer only Duplicate ("Duplicate
  to edit").

### Widgets (allow-list, first version)

| type | Shows | config |
|---|---|---|
| `number` | one count, linked to its filtered list | `metric`: `agents.active`, `agents.stale`, `agents.revoked`, `findings.open.{critical,high,medium,low}`, `vulns.exploited`, `vulns.reboot_hosts`, `vulns.no_fix` |
| `breakdown` | a severity or status bar with a legend | `source`: `findings`, `vulnerabilities`, `agents` |
| `attention` | the "Needs attention" list | `include`: any of `exploited`, `findings`, `stale`; `limit` 1–20 |
| `list` | the first rows of a list view | `view`: `/findings`, `/vulnerabilities`, `/agents`, `/audit`; `query`: the view's URL query (the same format as saved views); `limit` 1–20 |
| `trend` | hosts reporting a finding, per day | `finding`: `rule_set/rule`; `days`: 7, 14 or 30 |
| `top-hosts` | most exposed hosts | `limit` 1–10 |
| `note` | plain text, with line breaks and bare `https://` links | `text` ≤ 256 characters × up to 16 lines (array) |

- A note is rendered as text: never HTML or markdown, and links are
  shown with their full URL.
- Each tile has its own title (`config.title`, optional), loading and
  error states, and a caption saying what it counts ("open findings, your
  scope").
- A tile whose data the viewer may not read says "Not available with
  your role", and the rest of the dashboard renders.

### Built-in Overview

It is rebuilt from these widgets:
- a greeting;
- number tiles for hosts online, stale, open critical and high findings,
  exploited, and reboot needed;
- attention;
- the findings breakdown;
- top hosts.

It looks as it does today.

## 3. Build order, failure behaviour and testing

### Build order

One branch (`console-dashboards`), one PR per layer, each passing the
local gate before the next:
1. **Store and API:**
   - the migration;
   - `platform_store::dashboards`;
   - the routes, with RBAC and audit;
   - the `dashboards.share` permission in Rust and the database;
   - OpenAPI and the regenerated TypeScript client;
   - `docs/components` pages (`console-dashboards.md`; updates to
     `platform-store.md`, `openvibes-console.md` and `console-rbac.md`).
2. **The demo API:** the same endpoints and rules (ownership, sharing by
   role, `If-Match`, limits), so the Pages preview and the tests behave
   like a real console.
3. **UI:**
   - the widget library;
   - the grid and edit mode;
   - the switcher, gallery and settings panels;
   - the built-in Overview as a dashboard;
   - the `console-v2.md` update.

### Failure behaviour

| Situation | Result |
|---|---|
| invalid layout, name or config shape | 422 with `field_errors`; the editor marks the field |
| stale save | 412; edits kept; "Reload theirs" or "Save as a copy" |
| missing `If-Match` | 428 |
| dashboard deleted, unshared, or no longer visible | 404; the UI says so and links home |
| home dashboard deleted or no longer visible | home falls back to the built-in Overview (row removed by cascade, or ignored when not visible) |
| editing a shared or built-in dashboard | 403 from the API; the UI offers only Duplicate |
| sharing without `dashboards.share` | 403 |
| tile data not readable by the viewer | that tile shows "Not available with your role"; the others render |
| database unavailable | 503 problem; the dashboard shows the standard error box |

### Testing

- **Store tests** (test database):
  - create, list, get, update, delete;
  - ownership;
  - visibility through global and asset-group bindings, and after a
    binding is removed;
  - the version conflict;
  - the 100-per-owner limit;
  - cascades (owner deleted, role deleted → unshared, dashboard deleted →
    home removed);
  - home fallback.
- **API tests:**
  - 401 without a session;
  - 403 and 404 rules;
  - 412 and 428;
  - validation limits (size, widget count, positions, unknown type, config
    shape);
  - audit events recorded;
  - the permission parity test including `dashboards.share`.
- **Demo API:** unit tests for the same rules.
- **UI unit tests:**
  - grid placement (snapping, pushing tiles down on overlap, phone
    stacking order);
  - layout validation matching the server's limits;
  - each widget's config parsing.
- **Playwright** (Chromium and Firefox):
  - create a dashboard, add each widget type, arrange, save, reload;
  - set as home;
  - duplicate the built-in;
  - share as admin, then open it as an analyst (read-only, their scope);
  - the conflict flow (two tabs);
  - keyboard move and resize;
  - axe in both themes, in view and edit modes.
- **Live:** the same flows once against a real console (throwaway
  database), as for v2.

## Out of scope

Sharing with individual users, per-dashboard time ranges, dashboard
export or import files, charts beyond the widgets above, server-side
caching of widget data, and widgets fed by data the API does not expose
yet (they arrive with their API, such as agent health).
