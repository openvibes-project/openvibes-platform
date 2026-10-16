// What the People list and the person page share, without React: access
// grouped by where it applies, the share check for offered roles, role
// changes and the refusals people see.
import { ApiError, apiMessage, invalidate, request } from "../../../api/client";
import type { Capability, PersonView, Role } from "../../../api/types";
import { CATALOGUE } from "../../../app/permissions";

type AccessLine = PersonView["access"][number];
export type AccessGroup = { key: string; title: string; lines: AccessLine[] };

export const LAST_ADMIN = "This is the last Administrator. Give someone else the Administrator role first.";

/** "Password", or "Single sign-on" for `sso`. */
export const signsIn = (source: string) => (source === "sso" ? "Single sign-on" : "Password");

export const userPath = (id: string) => `/api/v1/users/${encodeURIComponent(id)}`;

/**
 * Access lines under "On all hosts", "Only on <groups>" (one heading per set
 * of groups), then "Across the platform". A permission held on all hosts is
 * not repeated under a group.
 */
export function accessGroups(access: readonly AccessLine[]): AccessGroup[] {
  const everywhere = new Set(access.filter((l) => l.applies === "all").map((l) => l.permission));
  const groups = new Map<string, AccessGroup>();
  for (const line of access) {
    if (line.applies === "groups" && everywhere.has(line.permission)) continue;
    const names = line.groups.map((g) => g.name).sort((a, b) => a.localeCompare(b));
    const [key, title] = line.applies === "all" ? ["all", "On all hosts"]
      : line.applies === "platform" ? ["platform", "Across the platform"]
      : [`groups:${names.join(",")}`, names.length ? `Only on ${names.join(", ")}` : "On no hosts"];
    const group = groups.get(key) ?? { key, title, lines: [] };
    group.lines.push(line);
    groups.set(key, group);
  }
  const rank = (key: string) => (key === "all" ? 0 : key === "platform" ? 2 : 1);
  return [...groups.values()].sort((a, b) => rank(a.key) - rank(b.key) || a.title.localeCompare(b.title));
}

const platform = new Set(CATALOGUE.filter((p) => p.scope === "platform").map((p) => p.id));

/**
 * Whether the viewer may hand out this role: every permission held, and a
 * host permission held everywhere or on every group the role reaches. The
 * server's `fits` (access/share.rs) decides; this only hides what it refuses.
 */
export function fitsShare(capabilities: readonly Capability[], role: Role): boolean {
  return role.permissions.every((p) => {
    const held = capabilities.filter((c) => c.permission === p);
    if (held.length === 0) return false;
    if (platform.has(p) || held.some((c) => c.scope.kind === "global")) return true;
    if (role.reach.kind === "none") return true;
    if (role.reach.kind === "all") return false;
    return role.reach.groups.every((g) => held.some((c) => c.scope.kind === "asset_groups" && c.scope.asset_group_ids.includes(g.asset_group_id)));
  });
}

/** What to say when a change is refused. */
export const refusal = (error: unknown, fallback: string): string =>
  error instanceof ApiError && error.code === "last_administrator" ? LAST_ADMIN : apiMessage(error, fallback);

/** People, their pages and roles' member counts all change together. */
export const refreshPeople = () => { invalidate("/api/v1/users"); invalidate("/api/v1/roles"); };

/** Gives (PUT) or removes (DELETE) a role, then refreshes. */
export async function changeRole(userId: string, roleId: string, give: boolean): Promise<void> {
  await request(give ? "PUT" : "DELETE", `${userPath(userId)}/roles/${encodeURIComponent(roleId)}`);
  refreshPeople();
}

export type PersonAction = { value: "reset" | "disable" | "enable"; label: string };

/** The ⋯ menu: none on your own page (the server refuses both on yourself). */
export function personActions(person: PersonView, self: boolean, manage: boolean): PersonAction[] {
  if (self || !manage) return [];
  return [
    ...(person.auth_source === "sso" ? [] : [{ value: "reset" as const, label: "Reset password…" }]),
    person.enabled ? { value: "disable" as const, label: "Disable user…" } : { value: "enable" as const, label: "Enable user" },
  ];
}

/** "WW" for Wendy Ward. */
export const initials = (name: string) => name.split(/\s+/).filter(Boolean).map((w) => w[0]).join("").slice(0, 2).toUpperCase();
