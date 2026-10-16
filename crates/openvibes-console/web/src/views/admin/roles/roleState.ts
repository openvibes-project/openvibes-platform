// The role editor's state: a pure reducer, so the clicks are testable without a DOM.
import type { Role, SaveRole } from "../../../api/types";
import { CATALOGUE, type PermissionDef, type PermissionId, TEMPLATES, labelOf, turnOff, turnOn } from "../../../app/permissions";

export type GroupRef = { asset_group_id: string; name: string };
export type Reach = { kind: "none" } | { kind: "all" } | { kind: "groups"; groups: GroupRef[] };
export type Column = PermissionDef["column"];
export const COLUMNS: readonly Column[] = ["View", "Change", "Export", "Approve and publish"];
export const BLANK = "Blank";

export type RoleState = {
  name: string;
  /** Blank or a template name; only a new role has it. */
  startFrom: string;
  /** The Start from choice before this one, which the outlines compare with. */
  previous: string;
  on: Set<PermissionId>;
  /** Chips that differ from the previous Start from choice, until the next change. */
  changed: Map<PermissionId, "added" | "removed">;
  /** "Also turned on: …" after a click that changed others too. */
  notice: string;
  reach: Reach;
};

export type Action =
  | { type: "name"; name: string }
  | { type: "template"; name: string }
  | { type: "toggle"; permission: PermissionId }
  | { type: "area"; area: string }
  | { type: "column"; column: Column }
  | { type: "allHosts" }
  | { type: "group"; group: GroupRef };

export const blank = (): RoleState => ({ name: "", startFrom: BLANK, previous: BLANK, on: new Set(), changed: new Map(), notice: "", reach: { kind: "none" } });

export function fromRole(role: Role): RoleState {
  const reach: Reach = role.reach.kind === "groups" ? { kind: "groups", groups: role.reach.groups } : { kind: role.reach.kind };
  return { name: role.name, startFrom: "", previous: "", on: new Set(role.permissions), changed: new Map(), notice: "", reach };
}

const also = (verb: string, ids: PermissionId[]) => (ids.length ? `Also turned ${verb}: ${ids.map(labelOf).join(", ")}.` : "");

/** Turns every one of `ids` on, or off when all are already on; others that change come back in the notice. */
function bulk(state: RoleState, ids: PermissionId[]): RoleState {
  let on: Set<PermissionId> = state.on;
  const extra: PermissionId[] = [];
  const allOn = ids.every((id) => on.has(id));
  for (const id of ids) {
    if (allOn) { const r = turnOff(on, id); on = r.next; extra.push(...r.removed); }
    else if (!on.has(id)) { const r = turnOn(on, id); on = r.next; extra.push(...r.added); }
  }
  return { ...state, on, changed: new Map(), notice: also(allOn ? "off" : "on", [...new Set(extra)].filter((id) => !ids.includes(id))) };
}

export function reduce(state: RoleState, action: Action): RoleState {
  switch (action.type) {
    case "name": return { ...state, name: action.name };
    case "template": {
      const on = new Set(TEMPLATES.find((t) => t.name === action.name)?.permissions ?? []);
      const changed = new Map<PermissionId, "added" | "removed">();
      for (const p of CATALOGUE) if (on.has(p.id) !== state.on.has(p.id)) changed.set(p.id, on.has(p.id) ? "added" : "removed");
      return { ...state, startFrom: action.name, previous: state.startFrom, on, changed, notice: "" };
    }
    case "toggle": {
      if (state.on.has(action.permission)) {
        const { next, removed } = turnOff(state.on, action.permission);
        return { ...state, on: next, changed: new Map(), notice: also("off", removed) };
      }
      const { next, added } = turnOn(state.on, action.permission);
      return { ...state, on: next, changed: new Map(), notice: also("on", added) };
    }
    case "area": return bulk(state, CATALOGUE.filter((p) => p.area === action.area).map((p) => p.id));
    case "column": return bulk(state, CATALOGUE.filter((p) => p.column === action.column).map((p) => p.id));
    case "allHosts": return { ...state, reach: state.reach.kind === "all" ? { kind: "none" } : { kind: "all" } };
    case "group": {
      const id = action.group.asset_group_id;
      const current = state.reach.kind === "groups" ? state.reach.groups : [];
      const groups = current.some((g) => g.asset_group_id === id) ? current.filter((g) => g.asset_group_id !== id) : [...current, action.group];
      return { ...state, reach: groups.length ? { kind: "groups", groups } : { kind: "none" } };
    }
  }
}

export const hostsSummary = (reach: Reach): string =>
  reach.kind === "all" ? "All hosts" : reach.kind === "groups" ? reach.groups.map((g) => g.name).join(", ") : "No hosts";

export const countLabel = (n: number) => `${n} ${n === 1 ? "permission" : "permissions"}`;

/** What Create or Save sends: the permissions in catalogue order (already closed under needs). */
export function saveBody(state: RoleState, role?: Role): SaveRole {
  const reach = state.reach.kind === "groups" ? { kind: "groups" as const, asset_group_ids: state.reach.groups.map((g) => g.asset_group_id) } : { kind: state.reach.kind };
  const description = role ? role.description : state.startFrom !== BLANK ? `From the ${state.startFrom} template` : "";
  return {
    name: state.name.trim(),
    description,
    permissions: CATALOGUE.filter((p) => state.on.has(p.id)).map((p) => p.id),
    reach,
    ...(role ? { version: role.version } : {}),
  };
}
