// A package's page (GET /api/v1/software-pages/{name}/summary and /hosts),
// answered as software_pages/page.rs and the store's software_summary.rs
// answer it: the hosts in the hosts.read reach that have it, the open
// advisories that name it, this week's log and the actions (step 5g
// rulings 11-16).
import type { SoftwarePageHosts, SoftwarePageSummary } from "../../api/types";
import type { DemoContext } from "../context";
import { distribution, distributionName, isActive } from "../hostGroups";
import { json, problem } from "../http";
import { listQueryError } from "../listQuery";
import { groupIdsOf } from "../portData";
import { byVersion, fullVersion, natural, severityRank, softwareAdvisories, softwareChanges, softwareHosts, softwareUnits, type SoftwareHost } from "../softwareData";

const WEEK = 7 * 86_400_000;
const byteOrder = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);

export function registerSoftwarePageRoutes(ctx: DemoContext) {
  const { data, route, reaches } = ctx;
  const nameOf = (raw = ""): string | null => {
    let name: string;
    try { name = decodeURIComponent(raw); } catch { return null; }
    return name.length >= 1 && name.length <= 200 && ![...name].some((c) => c < " ") ? name : null;
  };
  const invalid = () => problem(400, "invalid_package", "The package must be 1 to 200 characters without control characters");
  const reach = () => new Set(ctx.hosts().filter((a) => isActive(ctx.facts(a))).map((a) => a.id));
  /** The version an update brings a host to: the newest fix of its open, fixable advisories. */
  const updateTo = (name: string, agent: string, all: ReturnType<typeof softwareAdvisories>) => {
    const fixes = [...(all.get(name)?.values() ?? [])].filter((a) => a.fixable.has(agent) && a.fixed).map((a) => a.fixed as string);
    return fixes.sort(natural).at(-1) ?? null;
  };

  route("GET", "/api/v1/software-pages/{name}/summary", "hosts.read", ({ name: raw }) => {
    const name = nameOf(raw);
    if (!name) return invalid();
    const hosts: SoftwareHost[] = softwareHosts(ctx).get(name) ?? [];
    const now = Date.parse(ctx.iso());
    const events = softwareChanges(ctx).filter((c) => c.name === name && c.at > now - 90 * 86_400_000 && reach().has(c.agent)).sort((a, b) => b.at - a.at);
    if (hosts.length === 0 && events.length === 0) return problem(404, "package_not_found", "No host in reach has this package");
    const all = softwareAdvisories(ctx, reach());
    const open = [...(all.get(name)?.values() ?? [])];
    const week = events.filter((c) => c.at > now - WEEK);
    const agents = [...new Set(week.map((c) => c.agent))];
    const gone = (a: string) => week.some((c) => c.agent === a && c.change === "went_away");
    const came = (a: string) => week.some((c) => c.agent === a && c.change === "appeared");
    // An upgrade is a went_away and an appeared at the same instant; installed and removed later is neither.
    const upgraded = (a: string) => week.some((c) => c.agent === a && c.change === "appeared" && week.some((g) => g.agent === a && g.change === "went_away" && g.at === c.at));
    const anyHost = (permission: Parameters<typeof reaches>[0]) => hosts.some((h) => reaches(permission, h.id));

    const byVersionKey = new Map<string, { v: SoftwareHost["versions"][number]; hosts: Set<string> }>();
    for (const h of hosts) for (const v of h.versions) {
      const key = `${fullVersion(v)}.${v.arch}`;
      const seen = byVersionKey.get(key) ?? { v, hosts: new Set<string>() };
      seen.hosts.add(h.id);
      byVersionKey.set(key, seen);
    }
    const versions = [...byVersionKey.values()].sort((a, b) => b.hosts.size - a.hosts.size || byVersion(b.v, a.v)).map(({ v, hosts: on }) => {
      const here = open.filter((a) => [...on].some((id) => a.installed.get(id) === fullVersion(v)));
      return { version: fullVersion(v), arch: v.arch, manager: v.manager, hosts: on.size, advisories: here.length, cves: [...new Set(here.flatMap((a) => a.cves))].slice(0, 4) };
    });
    const updateHosts = new Set(open.flatMap((a) => [...a.fixable]));
    const members = (g: string) => ctx.hosts().filter((a) => groupIdsOf(ctx, a.id, ["automatic", "rule"]).includes(g)).length;
    const groups = new Map<string, number>();
    for (const h of hosts) for (const g of groupIdsOf(ctx, h.id, ["automatic", "rule"])) groups.set(g, (groups.get(g) ?? 0) + 1);
    const firstLogged = events.filter((c) => c.change === "appeared").at(-1);
    const body: SoftwarePageSummary = {
      header: {
        name, hosts: hosts.length, of: reach().size, managers: [...new Set(hosts.flatMap((h) => h.versions.map((v) => v.manager)))].sort(byteOrder),
        first_seen: { at: new Date(firstLogged?.at ?? now - 200 * 86_400_000).toISOString(), before: !firstLogged },
      },
      tiles: { hosts: hosts.length, vulnerabilities: open.length, update_hosts: updateHosts.size, versions: versions.length },
      week: { added: agents.filter((a) => came(a) && !gone(a)).length, updated: agents.filter(upgraded).length, removed: agents.filter((a) => gone(a) && !came(a)).length },
      versions,
      advisories: open.sort((a, b) => Number(b.exploited) - Number(a.exploited) || severityRank(a.severity) - severityRank(b.severity) || b.hosts.size - a.hosts.size || byteOrder(a.id, b.id))
        .map((a) => ({ advisory_id: a.id, title: a.title, severity: a.severity, cves: a.cves, ...(a.cvss == null ? {} : { cvss: a.cvss }), ...(a.epss == null ? {} : { epss: a.epss }),
          exploited: a.exploited, ...(a.fixed ? { fixed_in: a.fixed } : {}), hosts: a.hosts.size })),
      no_fix: open.filter((a) => a.fixed == null).length,
      used_by: [...(softwareUnits(ctx).get(name) ?? [])].map(([unit, on]) => ({ unit, hosts: on.size })).sort((a, b) => b.hosts - a.hosts || byteOrder(a.unit, b.unit)),
      by_group: [...groups].map(([id, have]) => {
        const g = data.access.host_groups.find((x) => x.asset_group_id === id);
        return { group_id: id, name: g?.name ?? id, kind: (g?.kind ?? "rule") as "automatic" | "rule", have, of: members(id) };
      }).sort((a, b) => b.have - a.have || a.name.localeCompare(b.name)),
      changes: events.slice(0, 20).map((c) => ({ at: new Date(c.at).toISOString(), agent_id: c.agent, change: c.change, version: c.version,
        ...(ctx.agentById(c.agent)?.hostname ? { hostname: ctx.agentById(c.agent)?.hostname as string } : {}) })),
      can: { export: anyHost("hosts.export"), add_to_case: anyHost("cases.write") && anyHost("cases.read") },
    };
    return json(body);
  });

  route("GET", "/api/v1/software-pages/{name}/hosts", "hosts.read", ({ name: raw }, query) => {
    const name = nameOf(raw);
    if (!name) return invalid();
    for (const k of query.keys()) if (!["segment", "offset", "limit"].includes(k)) return problem(400, "invalid_query", "Software host query parameters are invalid",
      { field_errors: [{ field: "query", code: "invalid", message: "The query parameter is invalid" }] });
    const bad = listQueryError(query, "Software host query parameters are invalid", [["segment", ["all", "update", "current"]]], []);
    if (bad) return bad;
    const offset = Number(query.get("offset") || 0);
    const limit = Number(query.get("limit") || 50);
    const all = softwareAdvisories(ctx, reach());
    const units = softwareUnits(ctx).get(name) ?? new Map<string, Set<string>>();
    const rows = (softwareHosts(ctx).get(name) ?? []).slice().sort((a, b) => (a.hostname ?? "").localeCompare(b.hostname ?? "") || byteOrder(a.id, b.id))
      .map((h) => ({ h, to: updateTo(name, h.id, all) }));
    const segment = query.get("segment") || "all";
    const chosen = rows.filter(({ to }) => segment === "all" || (segment === "update") === (to !== null));
    const body: SoftwarePageHosts = {
      items: chosen.slice(offset, offset + limit).map(({ h, to }) => {
        const agent = ctx.agentById(h.id);
        const os = agent ? distribution(ctx.facts(agent)) : null;
        const ip = agent ? data.addresses.get(agent.id) : undefined;
        return {
          agent_id: h.id, ...(h.hostname ? { hostname: h.hostname } : {}), ...(os ? { os: distributionName(os) } : {}), ...(ip ? { ip } : {}), reported_at: h.reportedAt,
          ...(to ? { update_to: to } : {}), used_by: [...units].filter(([, on]) => on.has(h.id)).map(([unit]) => unit).sort(byteOrder),
          versions: h.versions.map((v) => ({ manager: v.manager, version: fullVersion(v), arch: v.arch })),
        };
      }),
      total: chosen.length,
      segments: { all: rows.length, update: rows.filter(({ to }) => to !== null).length, current: rows.filter(({ to }) => to === null).length },
    };
    return json(body);
  });
}
