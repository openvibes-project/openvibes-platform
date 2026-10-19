// Roles (access/roles.rs): the permission catalogue, the templates, roles
// and host groups. Every role write fits inside the editor's share, as on
// the server. Returns what the people and service-account routes share.
import type { Role } from "../../api/types";
import catalogue from "../../api/permissions.json";
import templates from "../../api/templates.json";
import type { DemoContext } from "../context";
import { json, problem } from "../http";
import { ADMIN_ROLE, type StoredReach, shareRefusal } from "../share";

type StoredRole = DemoContext["data"]["access"]["roles"][number];
const NEEDS = new Map(catalogue.map((p) => [p.id, p.needs]));

export function registerRoleRoutes(ctx: DemoContext) {
  const { data, me, capabilities, permissions, rolesOf, audit, route } = ctx;
  const groupName = (id: string) => data.access.asset_groups.find((g) => g.asset_group_id === id)?.name ?? id;
  const reachView = (reach: StoredReach): Role["reach"] =>
    reach.kind === "groups" ? { kind: "groups", groups: reach.asset_group_ids.map((id) => ({ asset_group_id: id, name: groupName(id) })) } : { kind: reach.kind };
  // Active bindings, people and service accounts.
  const members = (roleId: string) => data.access.bindings.filter((b) => b.role_id === roleId).length
    + data.serviceAccounts.filter((a) => a.enabled && a.role_ids.includes(roleId)).length;
  const roleView = (role: StoredRole): Role => ({
    role_id: role.role_id, name: role.name, description: role.description, builtin: role.builtin,
    permissions: role.permissions as Role["permissions"], reach: reachView(role.reach), members: members(role.role_id), version: role.version,
  });
  const admin = rolesOf(me).some((r) => r.role_id === ADMIN_ROLE);
  /** The share check (editor.rs `role_fits`): a 403 when the role does not fit, else null. */
  const refuseOutside = (perms: readonly string[], reach: StoredReach) => {
    const title = admin ? null : shareRefusal(capabilities, perms, reachView(reach));
    return title === null ? null : problem(403, "permission_denied", title);
  };
  /** Do all these roles fit (people and accounts are shown only when they do)? */
  const rolesFit = (roles: readonly StoredRole[]) => roles.every((r) => refuseOutside(r.permissions, r.reach) === null);
  const roleById = (id: string) => data.access.roles.find((r) => r.role_id === id);
  const roleNotFound = () => problem(404, "role_not_found", "No such role");

  route("GET", "/api/v1/permissions", null, () => json(catalogue));
  route("GET", "/api/v1/role-templates", null, () => json(templates));
  // access.read lists every role, and so does service_accounts.manage (its
  // role picker); held=true lists the caller's own roles for anyone.
  route("GET", "/api/v1/roles", null, (_, query) => {
    const held = query.get("held") === "true";
    if (!held && !permissions.includes("access.read") && !permissions.includes("service_accounts.manage")) return problem(403, "permission_denied", "Access is not available");
    const mine = new Set(rolesOf(me).map((r) => r.role_id));
    return json([...data.access.roles].filter((r) => !held || mine.has(r.role_id))
      .sort((a, b) => Number(b.builtin) - Number(a.builtin) || a.name.localeCompare(b.name)).map(roleView));
  });
  route("GET", "/api/v1/roles/{id}", "access.read", ({ id = "" }) => {
    const role = roleById(id);
    return role ? json(roleView(role)) : roleNotFound();
  });

  const invalid = (field: string, message: string) =>
    problem(400, "invalid_role", "The role is invalid", { field_errors: [{ field, code: "invalid", message }] });
  /** roles.rs `Checked::new`: the body as the store takes it, or the refusal. */
  const checked = (body: Record<string, unknown>) => {
    const name = typeof body.name === "string" ? body.name.trim() : "";
    // eslint-disable-next-line no-control-regex
    if (name === "" || [...name].length > 64 || /[\u0000-\u001f\u007f-\u009f]/.test(name)) return invalid("name", "Use 1 to 64 characters, without control characters");
    const description = typeof body.description === "string" ? body.description : "";
    if ([...description].length > 500) return invalid("description", "Use at most 500 characters");
    const asked = Array.isArray(body.permissions) ? body.permissions.map(String) : null;
    if (asked === null || asked.some((p) => !NEEDS.has(p))) return invalid("body", "The request body is invalid");
    const set = new Set(asked);
    for (const p of catalogue) {
      const need = set.has(p.id) ? p.needs.find((n) => !set.has(n)) : undefined;
      if (need) return problem(422, "missing_needs", "A permission is missing what it needs", { permission: p.id, needs: need });
    }
    const reachBody = (body.reach ?? {}) as { kind?: string; asset_group_ids?: unknown };
    let reach: StoredReach;
    if (reachBody.kind === "none" || reachBody.kind === "all") reach = { kind: reachBody.kind };
    else if (reachBody.kind === "groups" && Array.isArray(reachBody.asset_group_ids)) {
      const ids = reachBody.asset_group_ids.map((id) => String(id).toLowerCase());
      if (ids.length === 0 || ids.length > 64 || new Set(ids).size !== ids.length) return invalid("reach.asset_group_ids", "Choose 1 to 64 host groups, each once");
      reach = { kind: "groups", asset_group_ids: [...ids].sort() };
    } else return invalid("body", "The request body is invalid");
    return { name, description, permissions: catalogue.filter((p) => set.has(p.id)).map((p) => p.id), reach };
  };
  /** What the store refuses: a name taken whatever its case, a group that does not exist. */
  const storeRefusal = (role: { name: string; reach: StoredReach }, except?: string) => {
    if (data.access.roles.some((r) => r.role_id !== except && r.name.toLowerCase() === role.name.toLowerCase())) return problem(409, "role_name_taken", "Another role has this name");
    if (role.reach.kind === "groups" && role.reach.asset_group_ids.some((id) => !data.access.asset_groups.some((g) => g.asset_group_id === id))) {
      return problem(422, "unknown_group", "A host group does not exist");
    }
    return null;
  };
  const protectedRole = () => problem(403, "protected_role", "Administrator cannot be changed or deleted");

  route("POST", "/api/v1/roles", "access.roles", (_, __, body) => {
    const role = checked(body);
    if (role instanceof Response) return role;
    const refused = refuseOutside(role.permissions, role.reach) ?? storeRefusal(role);
    if (refused) return refused;
    const stored: StoredRole = { role_id: `role-${crypto.randomUUID()}`, builtin: false, version: 1, ...role };
    data.access.roles.push(stored);
    audit("rbac.role.created", stored.name, "role");
    return json(roleView(stored), 201);
  });
  route("PATCH", "/api/v1/roles/{id}", "access.roles", ({ id = "" }, _, body) => {
    if (id === ADMIN_ROLE) return protectedRole();
    if (typeof body.version !== "number") return invalid("version", "Send the version you read");
    const role = checked(body);
    if (role instanceof Response) return role;
    const stored = roleById(id);
    if (!stored) return roleNotFound();
    if (stored.version !== body.version) return problem(409, "stale_role", "The role changed since you read it");
    const refused = refuseOutside(stored.permissions, stored.reach) ?? refuseOutside(role.permissions, role.reach) ?? storeRefusal(role, id);
    if (refused) return refused;
    Object.assign(stored, role, { version: stored.version + 1 });
    audit("rbac.role.updated", stored.name, "role");
    return json(roleView(stored));
  });
  route("DELETE", "/api/v1/roles/{id}", "access.roles", ({ id = "" }) => {
    if (id === ADMIN_ROLE) return protectedRole();
    const stored = roleById(id);
    if (!stored) return roleNotFound();
    const refused = refuseOutside(stored.permissions, stored.reach);
    if (refused) return refused;
    const holders = members(id);
    if (holders > 0) return problem(409, "role_in_use", "Take the role away from everyone who holds it first", { holders });
    data.access.roles = data.access.roles.filter((r) => r.role_id !== id);
    audit("rbac.role.deleted", stored.name, "role");
    return new Response(null, { status: 204 });
  });

  // Host groups: listed for host_groups.manage or access.read.
  route("GET", "/api/v1/host-groups", null, () => {
    if (!permissions.includes("host_groups.manage") && !permissions.includes("access.read")) return problem(403, "permission_denied", "Access is not available");
    const reaching = (id: string) => data.access.roles.filter((r) => r.reach.kind === "groups" && r.reach.asset_group_ids.includes(id)).length;
    return json(data.access.asset_groups.map((g) => ({ ...g, roles: reaching(g.asset_group_id) })));
  });
  const saveGroup = (id: string, body: Record<string, unknown>) => {
    const name = String(body.name ?? "").trim();
    const selectors = ((body.selectors ?? []) as { key: string; value: string }[]).map((sel) => `${sel.key}=${sel.value}`);
    if (name === "" || selectors.length === 0 || selectors.some((sel) => /^=|=$/.test(sel))) return undefined;
    return { asset_group_id: id, name, selectors };
  };
  route("POST", "/api/v1/access-control/asset-groups", "host_groups.manage", (_, __, body) => {
    const group = saveGroup(`grp-${Date.now().toString(36)}`, body);
    if (!group) return problem(422, "invalid_asset_group", "Give the group a name and at least one key=value selector");
    data.access.asset_groups.push(group);
    audit("access.asset_group.create", group.asset_group_id, "asset_group");
    return json(group, 201);
  });
  route("PUT", "/api/v1/access-control/asset-groups/{id}", "host_groups.manage", ({ id = "" }, _, body) => {
    const index = data.access.asset_groups.findIndex((g) => g.asset_group_id === id);
    const group = saveGroup(id, body);
    if (index < 0) return problem(404, "not_found", "Asset group not found");
    if (!group) return problem(422, "invalid_asset_group", "Give the group a name and at least one key=value selector");
    data.access.asset_groups[index] = group;
    audit("access.asset_group.update", id, "asset_group");
    return json(group);
  });

  return { roleView, roleById, refuseOutside, rolesFit, admin };
}

export type RoleHelpers = ReturnType<typeof registerRoleRoutes>;
