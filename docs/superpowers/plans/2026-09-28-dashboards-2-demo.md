# Console Dashboards, part 2 of 3: Demo API Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The in-browser demo API (`web/v2/src/demo`) serves the
dashboard endpoints with the same rules as the real API, so the Pages
preview and the UI tests behave like a live console.

**Architecture:**
- The layout rules become one TypeScript module,
  `v2/src/dashboards/layout.ts`. It mirrors the server's
  `validate_layout` and is used by both the demo server and (in part 3)
  the editor.
- The demo server keeps dashboards and homes in memory, keyed by the
  persona's user id. Visibility comes from the demo access bindings.

**Tech Stack:** TypeScript, Vitest.

**Spec:** `docs/superpowers/specs/2026-09-28-console-dashboards-design.md`.
It depends on part 1's generated types (`DashboardView`, `DashboardPage`,
`SaveDashboardRequest`, `ShareDashboardRequest`, `HomeDashboard` in
`web/src/api/generated.ts`).

## Global Constraints

- The limits are the same numbers as part 1:
  - name 1–80 characters (trimmed, no control characters);
  - layout ≤ 65536 bytes (`JSON.stringify` length in UTF-8), `schema` 1,
    ≤ 40 widgets;
  - id `^[a-z0-9-]{1,32}$` and unique;
  - `x` 0–11, `w` 1–12, `x+w ≤ 12`, `y` 0–199, `h` 1–12;
  - type allow-list `number breakdown attention list trend top-hosts note`;
  - config an object ≤ 16 keys (key ≤ 32 characters), each value a
    string ≤ 256 characters, an integer, a boolean, or an array ≤ 16 of
    strings ≤ 256 characters;
  - ≤ 100 per owner.
- The status codes are the same as part 1, including the precise field
  paths (`layout.widgets[0].type`).
- The demo enforces `If-Match` (428 when missing, 412 when stale), which
  the real API requires.
- **Run from `crates/openvibes-console/web`:**
  - `npx vitest run --config vite.v2.config.ts`;
  - `npx eslint . --max-warnings 0`;
  - `npx tsc --noEmit`.
- **Commits** end with
  `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Review Focus

1. **The demo must accept every layout the real API accepts.** The
   built-in Overview layout (part 3) validates cleanly in
   `validateLayout`. Tested in part 3, Task 1.
2. **Field-path parity with the server:** the same bad layout gives the
   same `field_errors[].field` values as Rust's
   `each_widget_is_checked_with_a_precise_path`. This task copies that
   test's input and expected list.
3. **A persona switch must not leak dashboards:** the viewer persona never
   lists admin's unshared dashboard. Tested below
   (`a_viewer_never_sees_an_unshared_dashboard`).

---

### Task 1: `layout.ts` validation (shared by demo and editor)

**Files:**
- Create: `crates/openvibes-console/web/v2/src/dashboards/layout.ts`
- Test: `crates/openvibes-console/web/v2/src/dashboards/layout.test.ts`

**Interfaces:**
- Produces:
  - `export type WidgetType = "number" | "breakdown" | "attention" | "list" | "trend" | "top-hosts" | "note";`
  - `export const WIDGET_TYPES: readonly WidgetType[]`
  - `export type ConfigValue = string | number | boolean | string[];`
  - `export type Widget = { id: string; type: WidgetType; x: number; y: number; w: number; h: number; config: Record<string, ConfigValue> };`
  - `export type Layout = { schema: 1; widgets: Widget[] };`
  - `export type FieldProblem = { field: string; code: string; message: string };`
  - `export function validateName(raw: string): string | FieldProblem`: the trimmed name, or a problem
  - `export function validateLayout(layout: unknown): FieldProblem[]`: empty when valid; at most 32 problems

- [ ] **Step 1: Write the failing test**

```ts
import { describe, expect, it } from "vitest";

import { validateLayout, validateName } from "./layout";

const widget = (id: string, type: string, x: number, w: number) =>
  ({ id, type, x, y: 0, w, h: 2, config: { metric: "agents.active" } });
const fields = (layout: unknown) => validateLayout(layout).map((p) => p.field);

describe("validateLayout (mirrors the server)", () => {
  it("accepts a small layout and an empty one", () => {
    expect(validateLayout({ schema: 1, widgets: [widget("w1", "number", 0, 3), widget("w2", "note", 3, 9)] })).toEqual([]);
    expect(validateLayout({ schema: 1, widgets: [] })).toEqual([]);
  });

  it("needs an object", () => {
    expect(fields([1, 2])).toEqual(["layout"]);
    expect(fields(7)).toEqual(["layout"]);
  });

  it("bounds schema, widget count and size", () => {
    expect(fields({ schema: 2, widgets: [] })).toEqual(["layout.schema"]);
    expect(fields({ schema: 1, widgets: Array.from({ length: 41 }, (_, i) => widget(`w${i}`, "number", 0, 1)) })).toEqual(["layout.widgets"]);
    const long = "x".repeat(256);
    const heavy = Array.from({ length: 40 }, (_, i) => ({ id: `w${i}`, type: "note", x: 0, y: 0, w: 1, h: 1, config: { text: Array(7).fill(long) } }));
    expect(fields({ schema: 1, widgets: heavy })).toEqual(["layout"]);
  });

  it("gives the server's field paths for each widget problem", () => {
    const layout = { schema: 1, widgets: [
      widget("w1", "pie-chart", 0, 3),
      widget("w1", "number", 10, 3),
      widget("Bad Id", "number", 0, 13),
      { id: "w4", type: "number", x: 0, y: 200, w: 1, h: 13, config: {} },
      { id: "w5", type: "number", x: 0, y: 0, w: 1, h: 1, config: { nested: { a: 1 } } },
    ] };
    expect(fields(layout)).toEqual([
      "layout.widgets[0].type",
      "layout.widgets[1].id", "layout.widgets[1].x",
      "layout.widgets[2].id", "layout.widgets[2].w",
      "layout.widgets[3].y", "layout.widgets[3].h",
      "layout.widgets[4].config.nested",
    ]);
  });
});

describe("validateName", () => {
  it("trims and bounds", () => {
    expect(validateName("  Morning  ")).toBe("Morning");
    expect(validateName("   ")).toMatchObject({ field: "name" });
    expect(validateName("n".repeat(81))).toMatchObject({ field: "name" });
    expect(validateName("tab\there")).toMatchObject({ field: "name" });
    expect(validateName("é".repeat(80))).toBe("é".repeat(80));
  });
});
```

- [ ] **Step 2: Run the test and watch it fail**

Run: `npx vitest run --config vite.v2.config.ts src/dashboards/layout`
Expected: FAIL, "Cannot find module './layout'".

- [ ] **Step 3: Implement**

```ts
// Dashboard layouts: the same rules the server applies (the Rust module
// openvibes-console/src/dashboards.rs), so the editor can show problems
// before saving and the demo API refuses exactly what a console refuses.
export const WIDGET_TYPES = ["number", "breakdown", "attention", "list", "trend", "top-hosts", "note"] as const;
export type WidgetType = (typeof WIDGET_TYPES)[number];
export type ConfigValue = string | number | boolean | string[];
export type Widget = { id: string; type: WidgetType; x: number; y: number; w: number; h: number; config: Record<string, ConfigValue> };
export type Layout = { schema: 1; widgets: Widget[] };
export type FieldProblem = { field: string; code: string; message: string };

const MAX_BYTES = 65_536;
const MAX_WIDGETS = 40;
const problem = (field: string, code: string, message: string): FieldProblem => ({ field, code, message });
const isInt = (value: unknown): value is number => typeof value === "number" && Number.isInteger(value);
const chars = (text: string) => [...text].length;
const bytes = (value: unknown) => new TextEncoder().encode(JSON.stringify(value)).length;

export function validateName(raw: string): string | FieldProblem {
  const name = raw.trim();
  // eslint-disable-next-line no-control-regex
  if (chars(name) === 0 || chars(name) > 80 || /[\u0000-\u001f\u007f-\u009f]/.test(name)) {
    return problem("name", "invalid_name", "Use 1 to 80 characters, without control characters");
  }
  return name;
}

function validConfigValue(value: unknown): boolean {
  if (typeof value === "string") return chars(value) <= 256;
  if (typeof value === "boolean") return true;
  if (typeof value === "number") return Number.isInteger(value);
  return Array.isArray(value) && value.length <= 16 && value.every((item) => typeof item === "string" && chars(item) <= 256);
}

export function validateLayout(layout: unknown): FieldProblem[] {
  if (typeof layout !== "object" || layout === null || Array.isArray(layout)) return [problem("layout", "invalid_layout", "The layout must be an object")];
  if (bytes(layout) > MAX_BYTES) return [problem("layout", "layout_too_large", "The layout exceeds 64 KiB")];
  const object = layout as Record<string, unknown>;
  const problems: FieldProblem[] = [];
  if (object.schema !== 1) problems.push(problem("layout.schema", "unsupported_schema", "Layout schema must be 1"));
  const widgets = object.widgets;
  if (!Array.isArray(widgets)) return [...problems, problem("layout.widgets", "invalid_widgets", "widgets must be an array")];
  if (widgets.length > MAX_WIDGETS) return [...problems, problem("layout.widgets", "too_many_widgets", "A dashboard holds at most 40 widgets")];
  const seen = new Set<string>();
  widgets.forEach((raw, index) => {
    const at = (field: string) => `layout.widgets[${index}].${field}`;
    if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
      problems.push(problem(`layout.widgets[${index}]`, "invalid_widget", "A widget must be an object"));
      return;
    }
    const widget = raw as Record<string, unknown>;
    if (!(WIDGET_TYPES as readonly unknown[]).includes(widget.type)) problems.push(problem(at("type"), "unknown_widget_type", "Unknown widget type"));
    const id = typeof widget.id === "string" ? widget.id : "";
    if (!/^[a-z0-9-]{1,32}$/.test(id) || seen.has(id)) problems.push(problem(at("id"), "invalid_widget_id", "Widget ids are 1-32 of a-z, 0-9 and -, unique"));
    seen.add(id);
    const { x, y, w, h } = widget;
    const wOk = isInt(w) && w >= 1 && w <= 12;
    if (!(isInt(x) && x >= 0 && x <= 11) || (wOk && isInt(x) && x + w > 12)) problems.push(problem(at("x"), "invalid_position", "x must be 0-11 and x + w at most 12"));
    if (!wOk) problems.push(problem(at("w"), "invalid_size", "w must be 1-12"));
    if (!(isInt(y) && y >= 0 && y <= 199)) problems.push(problem(at("y"), "invalid_position", "y must be 0-199"));
    if (!(isInt(h) && h >= 1 && h <= 12)) problems.push(problem(at("h"), "invalid_size", "h must be 1-12"));
    const config = widget.config;
    if (typeof config !== "object" || config === null || Array.isArray(config)) {
      problems.push(problem(at("config"), "invalid_config", "config must be an object"));
    } else if (Object.keys(config).length > 16) {
      problems.push(problem(at("config"), "invalid_config", "config holds at most 16 keys"));
    } else {
      for (const [key, value] of Object.entries(config)) {
        if (key.length > 32 || !validConfigValue(value)) problems.push(problem(at(`config.${key}`), "invalid_config", "Config values are short strings, integers, booleans or string lists"));
      }
    }
  });
  return problems.slice(0, 32);
}
```

(Rust's `serde_json::Map` iterates keys in sorted order; JavaScript keeps
insertion order. Only single-key configs appear in the parity test, so
the paths match.)

- [ ] **Step 4: Run the test and watch it pass**

Run: `npx vitest run --config vite.v2.config.ts src/dashboards/layout`
Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
git add crates/openvibes-console/web/v2/src/dashboards
git commit -m "Console v2: dashboard layout rules shared by editor and demo

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 2: Demo dashboard endpoints

**Files:**
- Modify: `crates/openvibes-console/web/v2/src/demo/server.ts` (routes)
- Create: `crates/openvibes-console/web/v2/src/demo/dashboards.ts` (in-memory store and rules; keeps `server.ts` under 500 lines)
- Modify: `crates/openvibes-console/web/v2/src/demo/data.ts` (two seeded dashboards; admin gets `dashboards.share`)
- Modify: `crates/openvibes-console/web/v2/src/api/types.ts` (aliases)
- Test: `crates/openvibes-console/web/v2/src/demo/server.test.ts`

**Interfaces:**
- Consumes: `validateLayout`, `validateName` (Task 1).
- Produces:
  - in `api/types.ts`: `export type Dashboard = S["DashboardView"]; export type DashboardPage = S["DashboardPage"]; export type HomeDashboard = S["HomeDashboard"];`
  - in `demo/dashboards.ts`: `export function createDashboardStore(seed: DemoDashboard[], roleOf: (userId: string) => string[], nameOf: (userId: string) => string)`, returning `{ list(userId), get(userId, id), create(userId, body), update(userId, id, body, ifMatch), remove(userId, id), share(userId, id, roleId, canShare, roles), home(userId), setHome(userId, id) }`. Each returns `{ status: number; body?: unknown; etag?: string }`.

- [ ] **Step 1: Write the failing tests**

Append to `v2/src/demo/server.test.ts`, inside `describe("demo server", ...)`:

```ts
  const layout = { schema: 1, widgets: [{ id: "w1", type: "number", x: 0, y: 0, w: 3, h: 2, config: { metric: "agents.active" } }] };

  it("runs the dashboard lifecycle with ETags and If-Match like the API", async () => {
    const server = createDemoServer({ persona: "admin" });
    const created = await server.handle("POST", "/api/v1/dashboards", { name: " Morning ", layout });
    expect(created.status).toBe(201);
    expect(created.headers.get("etag")).toBe('"1"');
    const dashboard = await json(created);
    expect(dashboard).toMatchObject({ name: "Morning", mine: true, version: 1 });
    const uri = `/api/v1/dashboards/${String(dashboard.dashboard_id)}`;
    expect((await server.handle("PUT", uri, { name: "x", layout })).status).toBe(428);
    expect((await server.handle("PUT", uri, { name: "x", layout }, { "if-match": '"1"' })).status).toBe(200);
    expect((await server.handle("PUT", uri, { name: "y", layout }, { "if-match": '"1"' })).status).toBe(412);
    expect((await server.handle("DELETE", uri)).status).toBe(204);
    expect((await server.handle("GET", uri)).status).toBe(404);
    expect((await server.handle("GET", "/api/v1/dashboards/not-a-uuid")).status).toBe(404);
  });

  it("refuses invalid layouts with the server's field paths", async () => {
    const server = createDemoServer({ persona: "admin" });
    const bad = await server.handle("POST", "/api/v1/dashboards", { name: "X", layout: { schema: 1, widgets: [{ id: "w1", type: "pie-chart", x: 0, y: 0, w: 3, h: 2, config: {} }] } });
    expect(bad.status).toBe(422);
    expect(((await json(bad)).field_errors as { field: string }[])[0]?.field).toBe("layout.widgets[0].type");
    expect((await server.handle("POST", "/api/v1/dashboards", { name: "", layout })).status).toBe(422);
    expect((await server.handle("POST", "/api/v1/dashboards", { name: "X" })).status).toBe(400);
  });

  it("a viewer never sees an unshared dashboard, and sharing needs the permission", async () => {
    const admin = createDemoServer({ persona: "admin" });
    const viewer = createDemoServer({ persona: "viewer" });
    const own = (await json(await viewer.handle("GET", "/api/v1/dashboards"))).items as { name: string; mine: boolean }[];
    expect(own.some((d) => d.name === "My morning check")).toBe(false);
    const mine = await json(await viewer.handle("POST", "/api/v1/dashboards", { name: "Viewer's", layout }));
    expect((await viewer.handle("PUT", `/api/v1/dashboards/${String(mine.dashboard_id)}/sharing`, { role_id: "viewer" })).status).toBe(403);
    expect((await admin.handle("PUT", "/api/v1/dashboards/d-admin-morning/sharing", { role_id: "no_such" })).status).toBe(422);
  });

  it("shows the seeded team dashboard to analysts read-only and lets them make it home", async () => {
    const analyst = createDemoServer({ persona: "analyst" });
    const items = (await json(await analyst.handle("GET", "/api/v1/dashboards"))).items as { dashboard_id: string; name: string; mine: boolean }[];
    const team = items.find((d) => d.name === "Analyst triage");
    expect(team?.mine).toBe(false);
    expect((await analyst.handle("PUT", `/api/v1/dashboards/${team?.dashboard_id ?? ""}`, { name: "x", layout }, { "if-match": '"1"' })).status).toBe(403);
    expect((await analyst.handle("PUT", "/api/v1/me/home", { dashboard_id: team?.dashboard_id })).status).toBe(200);
    expect((await json(await analyst.handle("GET", "/api/v1/me/home"))).dashboard_id).toBe(team?.dashboard_id);
    expect((await analyst.handle("PUT", "/api/v1/me/home", { dashboard_id: "d-admin-morning" })).status).toBe(404);
  });

  it("limits an owner to 100 dashboards", async () => {
    const server = createDemoServer({ persona: "viewer" });
    for (let index = 0; index < 100; index += 1) await server.handle("POST", "/api/v1/dashboards", { name: `D${index}`, layout });
    expect((await server.handle("POST", "/api/v1/dashboards", { name: "One more", layout })).status).toBe(422);
  });
```

(The seeded ids in Step 3, `d-admin-morning` and `d-sam-triage`, are
fixed strings, so the tests can use them.)

- [ ] **Step 2: Run the tests and watch them fail**

Run: `npx vitest run --config vite.v2.config.ts src/demo`
Expected: the five new tests FAIL with 404 (no such endpoint).

- [ ] **Step 3: Seed data, store module and routes**

In `demo/data.ts`:
- add `"dashboards.share"` to the admin role's `permissions` array;
- add to the returned object:

```ts
    dashboards: [
      { dashboard_id: "d-admin-morning", owner: "u-admin", name: "My morning check", shared_role_id: null as string | null,
        layout: { schema: 1 as const, widgets: [
          { id: "exploited", type: "number" as const, x: 0, y: 0, w: 3, h: 2, config: { metric: "vulns.exploited" } },
          { id: "stale", type: "number" as const, x: 3, y: 0, w: 3, h: 2, config: { metric: "agents.stale" } },
          { id: "attention", type: "attention" as const, x: 0, y: 2, w: 8, h: 6, config: { include: ["exploited", "findings"], limit: 8 } },
          { id: "note", type: "note" as const, x: 8, y: 2, w: 4, h: 3, config: { text: ["Patch window: Thursday 20:00", "https://wiki.example.test/patching"] } },
        ] } },
      { dashboard_id: "d-sam-triage", owner: "u-sam", name: "Analyst triage", shared_role_id: "analyst" as string | null,
        layout: { schema: 1 as const, widgets: [
          { id: "critical", type: "list" as const, x: 0, y: 0, w: 8, h: 6, config: { view: "/findings", query: "severity=critical", limit: 10 } },
          { id: "trend", type: "trend" as const, x: 8, y: 0, w: 4, h: 3, config: { finding: "hardening-ssh/SSH-002", days: 14 } },
        ] } },
    ],
```

`demo/dashboards.ts` implements the store with exactly the Task 1 rules
and part 1's status codes. Its core:

```ts
import { type Layout, validateLayout, validateName } from "../dashboards/layout";

export type DemoDashboard = { dashboard_id: string; owner: string; name: string; shared_role_id: string | null; layout: Layout };
type Stored = DemoDashboard & { version: number; created_at: string; updated_at: string };
type Result = { status: number; body?: unknown; etag?: string };

const problem = (status: number, code: string, title: string, field_errors?: unknown) =>
  ({ status, body: { status, code, title, request_id: "demo", ...(field_errors ? { field_errors } : {}) } });

export function createDashboardStore(seed: DemoDashboard[], rolesOf: (userId: string) => string[], nameOf: (userId: string) => string) {
  const now = () => new Date().toISOString();
  const rows: Stored[] = seed.map((d) => ({ ...d, version: 1, created_at: now(), updated_at: now() }));
  const homes = new Map<string, string>();
  const visible = (userId: string, row: Stored) => row.owner === userId || (row.shared_role_id !== null && rolesOf(userId).includes(row.shared_role_id));
  const view = (userId: string, row: Stored) => ({
    dashboard_id: row.dashboard_id, name: row.name, owner_display_name: nameOf(row.owner), mine: row.owner === userId,
    shared_role_id: row.shared_role_id, version: row.version, layout: row.layout, created_at: row.created_at, updated_at: row.updated_at,
  });
  const ok = (status: number, userId: string, row: Stored): Result => ({ status, body: view(userId, row), etag: `"${row.version}"` });
  const checked = (body: Record<string, unknown>): { name: string; layout: Layout } | Result => {
    if (typeof body.name !== "string" || !("layout" in body)) return problem(400, "invalid_request", "The request body is invalid");
    const name = validateName(body.name);
    const errors = [...(typeof name === "string" ? [] : [name]), ...validateLayout(body.layout)];
    return errors.length > 0 ? problem(422, "invalid_dashboard", "The dashboard is invalid", errors.slice(0, 32)) : { name: name as string, layout: body.layout as Layout };
  };
  const owned = (userId: string, id: string): Stored | Result => {
    const row = rows.find((r) => r.dashboard_id === id);
    if (!row || !visible(userId, row)) return problem(404, "dashboard_not_found", "Dashboard not found");
    if (row.owner !== userId) return problem(403, "not_dashboard_owner", "Only the owner can change this dashboard; duplicate it instead");
    return row;
  };
  const isResult = (value: unknown): value is Result => typeof value === "object" && value !== null && "status" in value;
  return {
    list: (userId: string): Result => ({ status: 200, body: { items: rows.filter((r) => visible(userId, r))
      .sort((a, b) => Number(a.owner !== userId) - Number(b.owner !== userId) || a.name.localeCompare(b.name)).map((r) => view(userId, r)) } }),
    get: (userId: string, id: string): Result => {
      const row = rows.find((r) => r.dashboard_id === id);
      return row && visible(userId, row) ? ok(200, userId, row) : problem(404, "dashboard_not_found", "Dashboard not found");
    },
    create: (userId: string, body: Record<string, unknown>): Result => {
      const input = checked(body);
      if (isResult(input)) return input;
      if (rows.filter((r) => r.owner === userId).length >= 100) return problem(422, "too_many_dashboards", "You already have 100 dashboards");
      const row: Stored = { dashboard_id: crypto.randomUUID(), owner: userId, shared_role_id: null, version: 1, created_at: now(), updated_at: now(), ...input };
      rows.push(row);
      return ok(201, userId, row);
    },
    update: (userId: string, id: string, body: Record<string, unknown>, ifMatch: string | undefined): Result => {
      if (ifMatch === undefined) return problem(428, "precondition_required", "If-Match is required");
      const row = owned(userId, id);
      if (isResult(row)) return row;
      if (ifMatch !== `"${row.version}"`) return problem(412, "stale_dashboard", "The dashboard changed since you loaded it");
      const input = checked(body);
      if (isResult(input)) return input;
      Object.assign(row, input, { version: row.version + 1, updated_at: now() });
      return ok(200, userId, row);
    },
    remove: (userId: string, id: string): Result => {
      const row = owned(userId, id);
      if (isResult(row)) return row;
      rows.splice(rows.indexOf(row), 1);
      for (const [user, home] of homes) if (home === id) homes.delete(user);
      return { status: 204 };
    },
    share: (userId: string, id: string, roleId: unknown, canShare: boolean, roles: string[]): Result => {
      if (!canShare) return problem(403, "permission_denied", "Access is not available");
      const row = owned(userId, id);
      if (isResult(row)) return row;
      if (roleId !== null && (typeof roleId !== "string" || !roles.includes(roleId))) return problem(422, "unknown_role", "No such role");
      Object.assign(row, { shared_role_id: roleId, version: row.version + 1, updated_at: now() });
      return ok(200, userId, row);
    },
    home: (userId: string): Result => {
      const id = homes.get(userId);
      const row = rows.find((r) => r.dashboard_id === id);
      return { status: 200, body: { dashboard_id: row && visible(userId, row) ? row.dashboard_id : null } };
    },
    setHome: (userId: string, id: unknown): Result => {
      if (id === null) { homes.delete(userId); return { status: 200, body: { dashboard_id: null } }; }
      const row = rows.find((r) => r.dashboard_id === id);
      if (!row || !visible(userId, row)) return problem(404, "dashboard_not_found", "Dashboard not found");
      homes.set(userId, row.dashboard_id);
      return { status: 200, body: { dashboard_id: row.dashboard_id } };
    },
  };
}
```

In `demo/server.ts`, inside `createDemoServer`:
- create the store with the persona's roles: the role of each binding in
  `data.access.bindings` whose `user_id` is the persona's user id; for
  `scoped_operator`, use `["operator"]`;
- `nameOf` looks up `data.access.users`;
- add a helper `send(result)` that turns a `Result` into a `Response`,
  setting `etag` and the `application/problem+json` content type for
  status ≥ 400 and an empty body for 204;
- add the routes with `permission: null` (any signed-in persona):

```ts
  const me = `u-${actor}`;
  route("GET", "/api/v1/dashboards", null, () => send(dashboards.list(me)));
  route("POST", "/api/v1/dashboards", null, (_, __, body) => send(dashboards.create(me, body)));
  route("GET", "/api/v1/dashboards/{id}", null, ({ id = "" }) => send(dashboards.get(me, id)));
  route("PUT", "/api/v1/dashboards/{id}", null, ({ id = "" }, _, body, headers) => send(dashboards.update(me, id, body, headers["if-match"])));
  route("DELETE", "/api/v1/dashboards/{id}", null, ({ id = "" }) => send(dashboards.remove(me, id)));
  route("PUT", "/api/v1/dashboards/{id}/sharing", null, ({ id = "" }, _, body) =>
    send(dashboards.share(me, id, body.role_id ?? null, permissions.includes("dashboards.share"), data.access.roles.map((r) => r.role_id))));
  route("GET", "/api/v1/me/home", null, () => send(dashboards.home(me)));
  route("PUT", "/api/v1/me/home", null, (_, __, body) => send(dashboards.setHome(me, body.dashboard_id ?? null)));
```

Register the `{id}/sharing` route before `{id}`: the router's patterns
are anchored, but put the more specific one first anyway.

`permissions.includes("dashboards.share")` compiles only if
`"dashboards.share"` is in the generated `Permission` union, which comes
from part 1.

- [ ] **Step 4: Run the tests and watch them pass**

Run: `npx vitest run --config vite.v2.config.ts`
Expected: all pass (the earlier 28 plus 5 new plus Task 1's 5).

- [ ] **Step 5: Lint, typecheck and commit**

Run: `npx eslint . --max-warnings 0 && npx tsc --noEmit`
Expected: no output.

```bash
git add crates/openvibes-console/web/v2/src
git commit -m "Console v2: demo API serves dashboards with the real rules

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```
