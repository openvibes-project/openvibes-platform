// Host groups (hosts/groups.rs, group_checks.rs; store host_groups.rs,
// host_group_writes.rs, host_group_preview.rs): the list, a group's page and
// hosts, preview, create, edit and delete, with the server's refusals.
// Reading needs access.read or host_groups.manage and counts hosts inside the
// reader's reach; writes and previews need host_groups.manage and hosts.read
// on every host.
import type { Agent, Capability, GroupHost, HostGroup, HostGroupPreview } from "../../api/types";
import type { DemoContext } from "../context";
import { type Condition, type StoredGroup, distribution, distributionName, hasControl, inGroup, isActive, invalidRule, membershipSentence, ruleHolds } from "../hostGroups";
import { json, problem } from "../http";
import { ADMIN_ROLE, hostScoped, shareRefusal } from "../share";
import type { Suppressions } from "../suppressions";
import type { RoleHelpers } from "./roles";

const ONLINE_MS = 3 * 60_000; // status.rs OFFLINE_AFTER_MINUTES
const PREVIEW_CAP = 50;
const MAX_PICKED = 10_000;

/** The writer check: host_groups.manage, then hosts.read on every host; null when it passes. */
export function writeRefusal(caps: readonly Capability[]) {
  if (!caps.some((c) => c.permission === "host_groups.manage")) return { status: 403, code: "permission_denied", title: "Access is not available" };
  return caps.some((c) => c.permission === "hosts.read" && c.scope.kind === "global") ? null
    : { status: 403, code: "permission_denied", title: "Changing host groups needs access to every host" };
}

const invalid = (field: string, message: string) =>
  problem(400, "invalid_group", "The host group is invalid", { field_errors: [{ field, code: "invalid", message }] });
const badBody = () => invalid("body", "The request body is invalid");
const invalidCondition = (field: string) => problem(422, "invalid_condition", "A condition is invalid", {
  field_errors: [{ field, code: "invalid", message: "Use 1 to 16 conditions on os_family, distribution, hostname or ip, each with 1 to 64 valid values" }],
});
const notFound = () => problem(404, "group_not_found", "No such host group");

type Content = { kind: "rule"; conditions: Condition[] } | { kind: "manual"; picked: string[] };
const isStrings = (v: unknown): v is string[] => Array.isArray(v) && v.every((x) => typeof x === "string");
/** serde with deny_unknown_fields: the body's keys and types, or undefined. */
function shape(body: Record<string, unknown>, keys: Record<string, (v: unknown) => boolean>) {
  return Object.entries(body).every(([k, v]) => keys[k]?.(v)) ? body : undefined;
}
const optional = (test: (v: unknown) => boolean) => (v: unknown) => v === undefined || v === null || test(v);
const conditionsOk = (v: unknown) => Array.isArray(v) && v.every((c) => typeof c === "object" && c !== null
  && shape(c as Record<string, unknown>, { field: (x) => typeof x === "string", negate: optional((x) => typeof x === "boolean"), values: isStrings }) !== undefined
  && typeof (c as Condition).field === "string" && isStrings((c as Condition).values));
const conditionsOf = (v: unknown): Condition[] => (v as Condition[]).map((c) => ({ field: c.field, negate: c.negate ?? false, values: c.values }));

/** Content::checked: 422 for a bad rule, 400 for too many or malformed picks. */
function checked(content: Content): Content | Response {
  if (content.kind === "rule") { const part = invalidRule(content.conditions); return part ? invalidCondition(part) : content; }
  if (content.picked.length > MAX_PICKED) return invalid("agent_ids", "Pick at most 10000 hosts");
  if (content.picked.some((id) => id.length < 1 || id.length > 255)) return invalid("agent_ids", "Host ids are 1–255 characters");
  return content;
}

export function registerGroupRoutes(ctx: DemoContext & { roles: RoleHelpers; overridesOf: (groupId: string) => number; dropGroup: (groupId: string) => void; suppressions: Suppressions }) {
  const { data, capabilities, permissions, me, audit, route, visible, facts, rolesOf, roles: { rolesFit, admin }, overridesOf, dropGroup, suppressions } = ctx;
  const groups = () => data.access.host_groups;
  const byId = (id: string) => groups().find((g) => g.asset_group_id === id);
  const members = (g: StoredGroup) => data.agents.filter((a) => inGroup(facts(a), g));
  const sortHosts = <T extends { hostname?: string | null; agent_id: string }>(hosts: T[]) =>
    hosts.sort((a, b) => (a.hostname ?? "").toLowerCase().localeCompare((b.hostname ?? "").toLowerCase()) || a.agent_id.localeCompare(b.agent_id));
  const reachingRoles = (id: string) => data.access.roles.filter((r) => r.reach.kind === "groups" && r.reach.asset_group_ids.includes(id))
    .sort((a, b) => a.name.localeCompare(b.name) || a.role_id.localeCompare(b.role_id));
  const enabledHolders = (roleIds: readonly string[]) => data.access.users.filter((u) => u.enabled
    && data.access.bindings.some((b) => b.user_id === u.user_id && roleIds.includes(b.role_id)));
  const online = (a: Agent) => !!a.last_seen_at && Date.parse(a.last_seen_at) >= Date.now() - ONLINE_MS;
  const alarms = (id: string) => data.alarms.filter((al) => al.agent_id === id && al.state === "open").length;
  const critical = (id: string) => data.vulnerabilities.filter((v) => v.agent_id === id && v.fixed_at == null && v.severity === "critical").length;

  /** HostGroupView, counted inside the reader's hosts.read reach. */
  const view = (g: StoredGroup): HostGroup => {
    const hosts = members(g).filter((a) => visible(a.id));
    const picked = g.kind === "manual" ? data.agents.filter((a) => g.picked.includes(a.id) && isActive(a) && visible(a.id)).length : 0;
    const roles = reachingRoles(g.asset_group_id);
    return {
      asset_group_id: g.asset_group_id, name: g.name, kind: g.kind, description: g.description, conditions: g.conditions,
      membership: membershipSentence(g.kind, g.conditions, picked), picked, hosts: hosts.length, online: hosts.filter(online).length,
      open_alarms: hosts.reduce((n, a) => n + alarms(a.id), 0), critical: hosts.reduce((n, a) => n + critical(a.id), 0),
      roles: roles.map((r) => ({ role_id: r.role_id, name: r.name })), people: enabledHolders(roles.map((r) => r.role_id)).length,
      upgraded_from_tags: g.upgraded_from_tags, changed_at: g.changed_at, changed_by: g.changed_by, version: g.version,
    };
  };
  const reader = () => (permissions.includes("host_groups.manage") || permissions.includes("access.read") ? null : problem(403, "permission_denied", "Access is not available"));
  const writer = () => { const r = writeRefusal(capabilities); return r && problem(r.status, r.code, r.title); };
  const record = (g: StoredGroup, action: string, detail: Record<string, unknown>) => {
    data.groupChanges.unshift({ group_id: g.asset_group_id, at: new Date().toISOString(), action, actor: me, detail });
    audit(action, g.name, "host_group", g.asset_group_id);
  };

  route("GET", "/api/v1/host-groups", null, () => reader() ?? json([...groups()].sort((a, b) => a.name.toLowerCase().localeCompare(b.name.toLowerCase())).map(view)));
  route("GET", "/api/v1/host-groups/{id}", null, ({ id = "" }) => {
    const g = byId(id);
    const refused = reader() ?? (g ? null : notFound());
    if (refused || !g) return refused ?? notFound();
    const seesAll = capabilities.some((c) => c.permission === "hosts.read" && c.scope.kind === "global");
    // A scoped reader's history never names or counts hosts outside their reach.
    const recent = data.groupChanges.filter((c) => c.group_id === id).slice(0, 10).map(({ action, actor, at, detail }) => {
      const { picked, hosts, ...rest } = detail;
      return { action, actor, at, detail: seesAll ? { ...rest, ...(picked === undefined ? {} : { picked }), ...(hosts === undefined ? {} : { hosts }) } : rest };
    });
    return json({ ...view(g), recent });
  });
  route("GET", "/api/v1/host-groups/{id}/hosts", null, ({ id = "" }, query) => {
    const g = byId(id);
    const refused = reader() ?? (g ? null : notFound());
    if (refused || !g) return refused ?? notFound();
    const rows = sortHosts(members(g).filter((a) => visible(a.id)).map((a): GroupHost => ({
      agent_id: a.id, hostname: a.hostname ?? null, distribution: ((d) => (d ? distributionName(d) : null))(distribution(facts(a))),
      last_address: data.addresses.get(a.id) ?? null, labels: [...(data.labels.get(a.id) ?? [])].sort((x, y) => (x < y ? -1 : x > y ? 1 : 0)),
      last_seen_at: a.last_seen_at ?? null, online: online(a), open_alarms: alarms(a.id), critical: critical(a.id),
      why: g.kind === "manual" ? "Picked by hand" : "Matches the rule",
    })));
    const after = query.get("after");
    // An unknown `after` is an empty page, as the store's row comparison makes it.
    const start = after === null ? 0 : ((i) => (i < 0 ? rows.length : i + 1))(rows.findIndex((h) => h.agent_id === after));
    return json(rows.slice(start, start + Number(query.get("limit") ?? 50)));
  });

  /** host_group_preview.rs: hosts joining and leaving, and who gains or loses them. */
  const preview = (g: StoredGroup | undefined, content: Content | undefined): HostGroupPreview => {
    const cur = new Set(g ? members(g).map((a) => a.id) : []);
    const prop = new Set(data.agents.filter((a) => (content?.kind === "manual" ? isActive(a) && content.picked.includes(a.id)
      : content?.kind === "rule" ? ruleHolds(facts(a), content.conditions) : false)).map((a) => a.id));
    const refs = (ids: string[]) => sortHosts(data.agents.filter((a) => ids.includes(a.id)).map((a) => ({ agent_id: a.id, hostname: a.hostname ?? null })));
    const joins = refs([...prop].filter((id) => !cur.has(id)));
    const leaves = refs([...cur].filter((id) => !prop.has(id)));
    // People reaching the group through a role, unless another of theirs reaches every host.
    const people = g ? enabledHolders(reachingRoles(g.asset_group_id).map((r) => r.role_id))
      .filter((u) => !rolesOf(u.user_id).some((r) => r.reach.kind === "all" || r.role_id === ADMIN_ROLE))
      .sort((a, b) => a.username.localeCompare(b.username)).map((u) => ({ user_id: u.user_id, username: u.username, display_name: u.display_name })) : [];
    // A non-admin sees only people inside their share (themselves, or all of whose roles fit); totals count everyone.
    const shown = people.slice(0, PREVIEW_CAP).filter((p) => admin || p.user_id === me || rolesFit(rolesOf(p.user_id)));
    return {
      joins: joins.slice(0, PREVIEW_CAP), leaves: leaves.slice(0, PREVIEW_CAP), gains: joins.length ? shown : [], loses: leaves.length ? shown : [],
      joins_total: joins.length, leaves_total: leaves.length, people_total: people.length,
      overrides_removed: g && !content ? overridesOf(g.asset_group_id) : 0,
      suppressions_ended: g && !content ? suppressions.onGroup(g.asset_group_id) : 0,
    };
  };
  const previewRoute = (id: string | undefined, body: Record<string, unknown>) => {
    const refused = writer();
    if (refused) return refused;
    if (!shape(body, { conditions: optional(conditionsOk), agent_ids: optional(isStrings) })) return badBody();
    const content: Content | undefined = body.conditions != null && body.agent_ids == null ? { kind: "rule", conditions: conditionsOf(body.conditions) }
      : body.agent_ids != null && body.conditions == null ? { kind: "manual", picked: body.agent_ids as string[] } : undefined;
    if (!content && (id === undefined || body.conditions != null || body.agent_ids != null)) return invalid("body", "Send conditions or agent_ids");
    const ok = content && checked(content);
    if (ok instanceof Response) return ok;
    const g = id === undefined ? undefined : byId(id);
    if (id !== undefined && !g) return notFound();
    return json(preview(g, ok));
  };
  route("POST", "/api/v1/host-groups/preview", null, (_, __, body) => previewRoute(undefined, body));
  route("POST", "/api/v1/host-groups/{id}/preview", null, ({ id = "" }, _, body) => previewRoute(id, body));

  /** host_group_writes.rs `write`: name and description, then version, picked hosts and the name's uniqueness. */
  const write = (existing: StoredGroup | undefined, version: number | undefined, name: string, description: string, content: Content) => {
    if (name.length === 0 || [...name].length > 128 || hasControl(name)) return invalid("name", "Use 1 to 128 characters, without control characters");
    if ([...description].length > 500) return invalid("description", "Use at most 500 characters");
    if (existing && existing.version !== version) return problem(409, "stale_group", "The group changed since you read it");
    const picked = content.kind === "manual" ? [...new Set(content.picked)] : [];
    const unknown = picked.find((id) => !data.agents.some((a) => a.id === id && isActive(a)));
    if (unknown !== undefined) {
      return problem(422, "unknown_host", "A picked host does not exist", { field_errors: [{ field: "agent_ids", code: "unknown_host", message: `No active host ${unknown}` }] });
    }
    if (groups().some((g) => g !== existing && g.name.toLowerCase() === name.toLowerCase())) return problem(409, "group_name_taken", "Another group has this name");
    const fields = { name, description, kind: content.kind, conditions: content.kind === "rule" ? content.conditions : [], picked, changed_at: new Date().toISOString(), changed_by: me };
    const g: StoredGroup = existing
      ? Object.assign(existing, fields, { version: existing.version + 1 })
      : { asset_group_id: `grp-${crypto.randomUUID()}`, upgraded_from_tags: false, version: 1, ...fields };
    if (!existing) groups().push(g);
    record(g, existing ? "host_group.updated" : "host_group.created",
      { name, kind: content.kind, ...(content.kind === "rule" ? { conditions: content.conditions } : { picked }) });
    return json(view(g), existing ? 200 : 201);
  };

  route("POST", "/api/v1/host-groups", null, (_, __, body) => {
    const refused = writer();
    if (refused) return refused;
    const ok = shape(body, { name: (v) => typeof v === "string", description: (v) => typeof v === "string", kind: (v) => v === "rule" || v === "manual",
      conditions: optional(conditionsOk), agent_ids: optional(isStrings) });
    if (!ok || typeof body.name !== "string" || body.kind === undefined) return badBody();
    const content: Content | undefined = body.kind === "rule" && body.agent_ids == null ? { kind: "rule", conditions: body.conditions == null ? [] : conditionsOf(body.conditions) }
      : body.kind === "manual" && body.conditions == null ? { kind: "manual", picked: (body.agent_ids as string[] | null | undefined) ?? [] } : undefined;
    if (!content) return invalid("kind", "A rule group takes conditions, a manual group agent_ids");
    const valid = checked(content);
    if (valid instanceof Response) return valid;
    return write(undefined, undefined, body.name.trim(), (body.description as string | undefined) ?? "", valid);
  });

  route("PATCH", "/api/v1/host-groups/{id}", null, ({ id = "" }, _, body) => {
    const refused = writer();
    if (refused) return refused;
    const ok = shape(body, { name: optional((v) => typeof v === "string"), description: optional((v) => typeof v === "string"),
      conditions: optional(conditionsOk), agent_ids: optional(isStrings), version: Number.isInteger });
    if (!ok || !Number.isInteger(body.version)) return badBody();
    const g = byId(id);
    if (!g) return notFound();
    const changes = body.conditions != null || body.agent_ids != null;
    // A membership change widens every reaching role: each must fit inside the editor's own access on every host.
    if (changes && !admin) {
      for (const role of reachingRoles(id)) {
        const host = role.permissions.filter((p) => (hostScoped as ReadonlySet<string>).has(p));
        const title = shareRefusal(capabilities, host, { kind: "all" });
        if (title) return problem(403, "permission_denied", title);
      }
    }
    if (body.conditions != null && body.agent_ids != null) return invalid("agent_ids", "Send conditions or agent_ids, not both");
    const content: Content = body.conditions != null ? { kind: "rule", conditions: conditionsOf(body.conditions) }
      : body.agent_ids != null ? { kind: "manual", picked: body.agent_ids as string[] }
        : g.kind === "manual" ? { kind: "manual", picked: data.agents.filter((a) => g.picked.includes(a.id) && isActive(a)).map((a) => a.id).sort((x, y) => x.localeCompare(y)) }
          : { kind: "rule", conditions: g.conditions };
    const valid = checked(content);
    if (valid instanceof Response) return valid;
    return write(g, body.version as number, typeof body.name === "string" ? body.name.trim() : g.name,
      typeof body.description === "string" ? body.description : g.description, valid);
  });

  route("DELETE", "/api/v1/host-groups/{id}", null, ({ id = "" }, query) => {
    const refused = writer();
    if (refused) return refused;
    const version = Number(query.get("version") ?? "x");
    if (!/^-?\d+$/.test(query.get("version") ?? "") || !Number.isSafeInteger(version)) return invalid("version", "Send the version you read");
    const g = byId(id);
    if (!g) return notFound();
    if (g.version !== version) return problem(409, "stale_group", "The group changed since you read it");
    const roles = reachingRoles(id);
    if (roles.length) return problem(409, "group_in_use", "Roles still use this group", { roles: roles.map((r) => r.name) });
    const overrides = overridesOf(id);
    data.access.host_groups = groups().filter((x) => x !== g);
    dropGroup(id);
    const ended = suppressions.endGroup(id);
    record(g, "host_group.deleted", { name: g.name, kind: g.kind, overrides_removed: overrides, suppressions_ended: ended });
    return new Response(null, { status: 204 });
  });
}
