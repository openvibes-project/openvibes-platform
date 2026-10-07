import { type Layout, validateLayout, validateName } from "../dashboards/layout";
import { upgradeLayout } from "../dashboards/legacy";

export type DemoDashboard = { dashboard_id: string; owner: string; name: string; shared_role_id: string | null; layout: Layout };
type Stored = DemoDashboard & { version: number; created_at: string; updated_at: string };
type Result = { status: number; body?: unknown; etag?: string };

const problem = (status: number, code: string, title: string, field_errors?: unknown) =>
  ({ status, body: { status, code, title, request_id: "demo", ...(field_errors ? { field_errors } : {}) } });

/** Where the demo keeps dashboards between page loads (browser storage in the preview). */
export type DashboardPersistence = { load: () => unknown; save: (state: { rows: unknown[]; homes: [string, string][] }) => void };

export function createDashboardStore(seed: DemoDashboard[], rolesOf: (userId: string) => string[], nameOf: (userId: string) => string, persistence?: DashboardPersistence) {
  const now = () => new Date().toISOString();
  const saved = persistence?.load() as { rows?: Stored[]; homes?: [string, string][] } | undefined;
  const rows: Stored[] = Array.isArray(saved?.rows) ? saved.rows.map((row) => ({ ...row, layout: upgradeLayout(row.layout) })) : seed.map((d) => ({ ...d, version: 1, created_at: now(), updated_at: now() }));
  const homes = new Map<string, string>(Array.isArray(saved?.homes) ? saved.homes : []);
  const persist = () => persistence?.save({ rows, homes: [...homes] });
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
      persist();
      return ok(201, userId, row);
    },
    update: (userId: string, id: string, body: Record<string, unknown>, ifMatch: string | undefined): Result => {
      // The server's order: If-Match, the body, then ownership and version.
      if (ifMatch === undefined) return problem(428, "precondition_required", "If-Match is required");
      const input = checked(body);
      if (isResult(input)) return input;
      const row = owned(userId, id);
      if (isResult(row)) return row;
      if (ifMatch !== `"${row.version}"`) return problem(412, "stale_dashboard", "The dashboard changed since you loaded it");
      Object.assign(row, input, { version: row.version + 1, updated_at: now() });
      persist();
      return ok(200, userId, row);
    },
    remove: (userId: string, id: string): Result => {
      const row = owned(userId, id);
      if (isResult(row)) return row;
      rows.splice(rows.indexOf(row), 1);
      for (const [user, home] of homes) if (home === id) homes.delete(user);
      persist();
      return { status: 204 };
    },
    share: (userId: string, id: string, roleId: unknown, canShare: boolean, roles: string[]): Result => {
      if (!canShare) return problem(403, "permission_denied", "Access is not available");
      const row = owned(userId, id);
      if (isResult(row)) return row;
      if (roleId !== null && (typeof roleId !== "string" || !roles.includes(roleId))) return problem(422, "unknown_role", "No such role");
      Object.assign(row, { shared_role_id: roleId, version: row.version + 1, updated_at: now() });
      persist();
      return ok(200, userId, row);
    },
    home: (userId: string): Result => {
      const id = homes.get(userId);
      const row = rows.find((r) => r.dashboard_id === id);
      return { status: 200, body: { dashboard_id: row && visible(userId, row) ? row.dashboard_id : null } };
    },
    setHome: (userId: string, id: unknown): Result => {
      if (id === null) { homes.delete(userId); persist(); return { status: 200, body: { dashboard_id: null } }; }
      const row = rows.find((r) => r.dashboard_id === id);
      if (!row || !visible(userId, row)) return problem(404, "dashboard_not_found", "Dashboard not found");
      homes.set(userId, row.dashboard_id);
      persist();
      return { status: 200, body: { dashboard_id: row.dashboard_id } };
    },
  };
}
