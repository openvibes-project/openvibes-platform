// The permission catalogue and role templates (generated JSON from the
// server) and the "needs" closure the role editor uses.
import type { Permission } from "../api/types";
import catalogue from "../api/permissions.json";
import templates from "../api/templates.json";

export type PermissionId = Permission;
export type PermissionDef = {
  id: PermissionId;
  area: string;
  label: string;
  column: "View" | "Change" | "Export" | "Approve and publish";
  scope: "host" | "platform";
  needs: PermissionId[];
};

export const CATALOGUE = catalogue as readonly PermissionDef[];
export const AREAS: readonly string[] = [...new Set(CATALOGUE.map((p) => p.area))];
export const TEMPLATES = templates as readonly { name: string; description: string; permissions: PermissionId[] }[];

const byId = new Map(CATALOGUE.map((p) => [p.id, p]));

export const labelOf = (p: PermissionId): string => byId.get(p)?.label ?? p;

/** `p` plus everything it needs, transitively. */
export function turnOn(on: ReadonlySet<PermissionId>, p: PermissionId): { next: Set<PermissionId>; added: PermissionId[] } {
  const next = new Set(on);
  const added: PermissionId[] = [];
  const stack = [p];
  for (let id = stack.pop(); id !== undefined; id = stack.pop()) {
    if (next.has(id)) continue;
    next.add(id);
    added.push(id);
    stack.push(...(byId.get(id)?.needs ?? []));
  }
  return { next, added: added.filter((id) => id !== p) };
}

/** `p` plus everything that needs it, transitively. */
export function turnOff(on: ReadonlySet<PermissionId>, p: PermissionId): { next: Set<PermissionId>; removed: PermissionId[] } {
  const next = new Set(on);
  next.delete(p);
  const removed: PermissionId[] = [];
  for (let changed = true; changed;) {
    changed = false;
    for (const id of next) {
      if (byId.get(id)?.needs.some((n) => !next.has(n))) { next.delete(id); removed.push(id); changed = true; }
    }
  }
  return { next, removed };
}
