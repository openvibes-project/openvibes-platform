// A service's page (GET /api/v1/services/{unit}/summary and /hosts), answered
// as services/page.rs and the store's service_summary.rs answer it: the
// hosts in the hosts.read reach that run it, this week's log, the Related
// card gated by its own permissions and the actions (step 5f rulings 11-15).
import type { ServicePageHosts, ServicePageSummary } from "../../api/types";
import type { DemoContext } from "../context";
import { distribution, distributionName, isActive } from "../hostGroups";
import { json, problem } from "../http";
import { listQueryError } from "../listQuery";
import { groupIdsOf } from "../portData";
import { privileged, serviceChanges, serviceHosts, type ServiceHost } from "../serviceData";
import { serviceInfo } from "../serviceNames";

const WEEK = 7 * 86_400_000;
const byteOrder = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);

export function registerServicePageRoutes(ctx: DemoContext) {
  const { data, route, reaches, permissions } = ctx;
  const unitOf = (raw = ""): string | null => {
    let unit: string;
    try { unit = decodeURIComponent(raw); } catch { return null; }
    return unit.length >= 1 && unit.length <= 200 && ![...unit].some((c) => c < " ") ? unit : null;
  };
  const invalid = () => problem(400, "invalid_unit", "The unit must be 1 to 200 characters without control characters");

  route("GET", "/api/v1/services/{unit}/summary", "hosts.read", ({ unit: raw }) => {
    const unit = unitOf(raw);
    if (!unit) return invalid();
    const hosts = serviceHosts(ctx).get(unit) ?? [];
    const now = Date.parse(ctx.iso());
    const events = serviceChanges(ctx).filter((c) => c.unit === unit && c.at > now - 90 * 86_400_000).sort((a, b) => b.at - a.at);
    if (hosts.length === 0 && events.length === 0) return problem(404, "service_not_found", "No host in reach runs this service");
    const info = serviceInfo(unit);
    const week = events.filter((c) => c.at > now - WEEK);
    const holds = (permission: (typeof permissions)[number]) => permissions.includes(permission);
    const anyHost = (permission: Parameters<typeof reaches>[0]) => hosts.some((h) => reaches(permission, h.id));
    const count = <T,>(items: T[], key: (t: T) => string | null) => {
      const m = new Map<string, number>();
      for (const i of items) { const k = key(i); if (k !== null) m.set(k, (m.get(k) ?? 0) + 1); }
      return m;
    };
    const packages = count(hosts, (h) => h.package?.name ?? null);
    const versions = new Set(hosts.flatMap((h) => (h.package ? [h.package.version] : [])));
    const runAs = count(hosts, (h) => h.runAs);
    const exposed = hosts.filter((h) => h.ports.some((p) => p.exposed)).length;
    const root = hosts.filter((h) => privileged(h.runAs)).length;
    const owned = new Map<string, { protocol: string; port: number; exposed: boolean; hosts: number }>();
    for (const h of hosts) for (const p of h.ports) {
      const seen = owned.get(`${p.protocol}/${p.port}`) ?? { ...p, exposed: false, hosts: 0 };
      seen.exposed ||= p.exposed;
      seen.hosts += 1;
      owned.set(`${p.protocol}/${p.port}`, seen);
    }
    const programs = [...new Set(hosts.flatMap((h) => h.programs))].sort(byteOrder);
    const groups = new Map<string, number>();
    for (const h of hosts) for (const g of groupIdsOf(ctx, h.id, ["automatic", "rule"])) groups.set(g, (groups.get(g) ?? 0) + 1);
    const members = (g: string) => ctx.hosts().filter((a) => groupIdsOf(ctx, a.id, ["automatic", "rule"]).includes(g)).length;
    const firstLogged = events.filter((c) => c.change === "appeared").at(-1);
    const advisories = (info?.packages ?? []).slice(0, 1).filter((p) => packages.has(p));
    const body: ServicePageSummary = {
      header: {
        unit, ...(info ? { name: info.name, usual_use: info.usual_use } : {}), running: hosts.length, of: ctx.hosts().filter((a) => isActive(ctx.facts(a))).length, exposed, root,
        first_seen: { at: new Date(firstLogged?.at ?? now - 200 * 86_400_000).toISOString(), before: !firstLogged },
      },
      tiles: {
        running: hosts.length,
        ...(holds("alarms.read") ? { alarms: 0 } : {}),
        ...(holds("vulnerabilities.read") ? { vulnerabilities: advisories.length * 2 } : {}),
        ...(packages.size > 0 ? { versions: versions.size } : {}),
      },
      details: {
        run_as: [...runAs].map(([user, n]) => ({ user, hosts: n })).sort((a, b) => b.hosts - a.hosts || byteOrder(a.user, b.user)),
        programs, packages: [...packages].map(([name, n]) => ({ name, hosts: n })).sort((a, b) => b.hosts - a.hosts || byteOrder(a.name, b.name)),
        package_hosts: hosts.filter((h) => h.package).length, processes: hosts.reduce((n, h) => n + h.processes, 0),
        week: { added: week.filter((c) => c.change === "appeared").length, removed: week.filter((c) => c.change === "went_away").length },
      },
      ports: [...owned.values()].sort((a, b) => Number(b.exposed) - Number(a.exposed) || a.port - b.port || byteOrder(a.protocol, b.protocol)),
      by_group: [...groups].map(([id, running]) => {
        const g = data.access.host_groups.find((x) => x.asset_group_id === id);
        return { group_id: id, name: g?.name ?? id, kind: (g?.kind ?? "rule") as "automatic" | "rule", running, of: members(id) };
      }).sort((a, b) => b.running - a.running || a.name.localeCompare(b.name)),
      changes: events.slice(0, 20).map((c) => ({ at: new Date(c.at).toISOString(), agent_id: c.agent, ...(ctx.agentById(c.agent)?.hostname ? { hostname: ctx.agentById(c.agent)?.hostname as string } : {}), change: c.change })),
      related: {
        ...(holds("compliance.read") ? { compliance: info?.area
          ? { items: [{ rule_set_id: "baseline", rule_id: "ssh-root-login", title: "Root login over SSH is allowed", severity: "high", hosts: Math.min(hosts.length, 2) }], total: 1, area: info.area }
          : { items: [], total: 0 } } : {}),
        ...(holds("vulnerabilities.read") ? { vulnerabilities: { advisories: advisories.length * 2, hosts: advisories.length ? Math.min(hosts.length, 3) : 0,
          packages: advisories.map((p) => ({ package: p, advisories: 2, hosts: Math.min(hosts.length, 3) })) } } : {}),
        ...(holds("alarms.read") ? { alarms: { programs_not_collected: programs.length === 0, open: 0, hosts: 0 } } : {}),
      },
      can: { export: anyHost("hosts.export"), add_to_case: anyHost("cases.write") && anyHost("cases.read") },
    };
    return json(body);
  });

  route("GET", "/api/v1/services/{unit}/hosts", "hosts.read", ({ unit: raw }, query) => {
    const unit = unitOf(raw);
    if (!unit) return invalid();
    for (const k of query.keys()) if (!["segment", "offset", "limit"].includes(k)) return problem(400, "invalid_query", "Service host query parameters are invalid",
      { field_errors: [{ field: "query", code: "invalid", message: "The query parameter is invalid" }] });
    const bad = listQueryError(query, "Service host query parameters are invalid", [["segment", ["all", "exposed", "root"]]], []);
    if (bad) return bad;
    const offset = Number(query.get("offset") || 0);
    const limit = Number(query.get("limit") || 50);
    const all = (serviceHosts(ctx).get(unit) ?? []).slice().sort((a, b) => (a.hostname ?? "").localeCompare(b.hostname ?? "") || byteOrder(a.id, b.id));
    const segment = query.get("segment") || "all";
    const test = (h: ServiceHost) => segment === "all" || (segment === "exposed" ? h.ports.some((p) => p.exposed) : privileged(h.runAs));
    const chosen = all.filter(test);
    const body: ServicePageHosts = {
      items: chosen.slice(offset, offset + limit).map((h) => {
        const agent = ctx.agentById(h.id);
        const os = agent ? distribution(ctx.facts(agent)) : null;
        const ip = agent ? data.addresses.get(agent.id) : undefined;
        return {
          agent_id: h.id, ...(h.hostname ? { hostname: h.hostname } : {}), ...(os ? { os: distributionName(os) } : {}), ...(ip ? { ip } : {}),
          processes: h.processes, programs: h.programs, ...(h.runAs ? { run_as: h.runAs } : {}), ...(h.package ? { package: h.package } : {}),
          ports: h.ports, owners_partial: h.ownersPartial, problems: ctx.permissions.includes("alarms.read") && ctx.permissions.includes("vulnerabilities.read") ? { alarms: 0, vulnerabilities: h.package ? 1 : 0 } : {},
          reported_at: h.reportedAt,
        };
      }),
      total: chosen.length,
      segments: { all: all.length, exposed: all.filter((h) => h.ports.some((p) => p.exposed)).length, root: all.filter((h) => privileged(h.runAs)).length },
    };
    return json(body);
  });
}
