// The demo's access rules, as the server has them: roles resolved into
// capabilities (access/rbac.rs) and the share check (access/share.rs, one
// copy shared with the web in views/admin/people/people.ts).
import type { Capability, Permission, Role } from "../api/types";
import { CATALOGUE, labelOf } from "../app/permissions";
import { outsideShare } from "../views/admin/people/people";

export type StoredReach = { kind: "none" } | { kind: "all" } | { kind: "groups"; asset_group_ids: string[] };
export type Grant = { role_id: string; permissions: readonly string[]; reach: StoredReach };

/** The built-in Administrator: every permission on every host, whatever is stored. */
export const ADMIN_ROLE = "admin";

/** Host permissions: those a role's reach limits. */
export const hostScoped = new Set(CATALOGUE.filter((p) => p.scope === "host").map((p) => p.id));

/**
 * A platform permission is global whatever the reach; a host permission
 * applies on the union of its roles' reaches (all dominates, none grants it
 * nowhere). Administrator holds all 48 globally.
 */
export function resolveCapabilities(grants: readonly Grant[]): Capability[] {
  const admin = grants.some((g) => g.role_id === ADMIN_ROLE);
  return CATALOGUE.flatMap((p): Capability[] => {
    let global = admin;
    const groups = new Set<string>();
    for (const grant of grants.filter((g) => g.permissions.includes(p.id))) {
      if (!hostScoped.has(p.id) || grant.reach.kind === "all") global = true;
      else if (grant.reach.kind === "groups") grant.reach.asset_group_ids.forEach((id) => groups.add(id));
    }
    if (global) return [{ permission: p.id as Permission, scope: { kind: "global" } }];
    return groups.size ? [{ permission: p.id as Permission, scope: { kind: "asset_groups", asset_group_ids: [...groups].sort((a, b) => a.localeCompare(b)) } }] : [];
  });
}

/** The server's 403 title when a role does not fit the editor's share, or null when it fits. */
export function shareRefusal(editor: readonly Capability[], permissions: readonly string[], reach: Role["reach"]): string | null {
  const outside = outsideShare(editor, permissions, reach);
  return outside === undefined ? null
    : `You can only give roles that fit inside your own access (${labelOf(outside as Permission)} is outside it)`;
}
