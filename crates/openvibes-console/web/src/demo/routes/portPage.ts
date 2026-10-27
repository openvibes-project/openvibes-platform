// A port's page (GET /api/v1/ports/{protocol}/{port}/summary and /hosts),
// answered as ports/page.rs and the store's port_summary.rs answer it: the
// hosts in the hosts.read reach that listen on it, this week's log, the
// Related card gated by its own permissions and the actions (step 5e
// rulings 18 and 20-22). Reads the demo's listeners and change log
// (portData.ts).
import type { PortPageHosts, PortPageSummary } from "../../api/types";
import type { DemoContext } from "../context";
import { distribution, distributionName, isActive } from "../hostGroups";
import { json, problem } from "../http";
import { listQueryError } from "../listQuery";
import { groupIdsOf, portChanges, portHosts } from "../portData";
import { portInfo } from "../portNames";

const WEEK = 7 * 86_400_000;
const byteOrder = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);

export function registerPortPageRoutes(ctx: DemoContext) {
  const { data, route, reaches, permissions } = ctx;
  const invalid = () => problem(400, "invalid_port", "The protocol must be tcp or udp and the port 1 to 65535");
  /** `tcp/22`, or null when the path is not a port's spelling. */
  const keyOf = (protocol = "", port = ""): string | null => {
    const n = Number(port);
    return (protocol === "tcp" || protocol === "udp") && Number.isInteger(n) && n >= 1 && n <= 65535 && String(n) === port ? `${protocol}/${n}` : null;
  };

  route("GET", "/api/v1/ports/{protocol}/{port}/summary", "hosts.read", ({ protocol, port }) => {
    const key = keyOf(protocol, port);
    if (!key) return invalid();
    const hosts = portHosts(ctx).get(key) ?? [];
    const now = Date.parse(ctx.iso());
    // The log is already in reach: a host that stopped listening is no longer in `hosts`.
    const events = portChanges(ctx).filter((c) => c.key === key).filter((c) => c.at > now - 90 * 86_400_000).sort((a, b) => b.at - a.at);
    if (hosts.length === 0 && events.length === 0) return problem(404, "port_not_found", "No host in reach listens on this port");
    const info = portInfo(key);
    const exposed = hosts.filter((h) => h.exposed).length;
    const week = events.filter((c) => c.at > now - WEEK);
    const programs = [...new Set(hosts.flatMap((h) => (h.program ? [h.program] : [])))].sort(byteOrder);
    const groups = new Map<string, number>();
    for (const h of hosts) for (const g of groupIdsOf(ctx, h.id, ["automatic", "rule"])) groups.set(g, (groups.get(g) ?? 0) + 1);
    const members = (g: string) => ctx.hosts().filter((a) => groupIdsOf(ctx, a.id, ["automatic", "rule"]).includes(g)).length;
    const anyHost = (permission: Parameters<typeof reaches>[0]) => hosts.some((h) => reaches(permission, h.id));
    const holds = (permission: (typeof permissions)[number]) => permissions.includes(permission);
    const firstLogged = events.filter((c) => c.change === "appeared").at(-1);
    const body: PortPageSummary = {
      header: {
        protocol: protocol as string, port: Number(port), ...(info ? { name: info.name, usual_use: info.usual_use } : {}),
        listening: hosts.length, of: ctx.hosts().filter((a) => isActive(ctx.facts(a))).length, exposed, services: new Set(hosts.flatMap((h) => (h.service ? [h.service] : []))).size,
        first_seen: { at: new Date(firstLogged?.at ?? now - 200 * 86_400_000).toISOString(), before: !firstLogged },
      },
      tiles: {
        listening: hosts.length, exposed, local: hosts.length - exposed,
        week: { added: week.filter((c) => c.change === "appeared").length, removed: week.filter((c) => c.change === "went_away").length },
      },
      details: { programs, owners: { collected: hosts.filter((h) => h.service !== null || h.program !== null).length, of: hosts.length } },
      by_group: [...groups].map(([id, listening]) => {
        const g = data.access.host_groups.find((x) => x.asset_group_id === id);
        return { group_id: id, name: g?.name ?? id, kind: (g?.kind ?? "rule") as "automatic" | "rule", listening, of: members(id) };
      }).sort((a, b) => b.listening - a.listening || a.name.localeCompare(b.name)),
      changes: events.slice(0, 20).map((c) => ({ at: new Date(c.at).toISOString(), agent_id: c.agent, ...(ctx.agentById(c.agent)?.hostname ? { hostname: ctx.agentById(c.agent)?.hostname as string } : {}), change: c.change })),
      related: {
        ...(holds("compliance.read") ? { compliance: info?.area
          ? { items: [{ rule_set_id: "baseline", rule_id: "ssh-root-login", title: "Root login over SSH is allowed", severity: "high", hosts: Math.min(hosts.length, 2) }], total: 1, area: info.area }
          : { items: [], total: 0 } } : {}),
        ...(holds("vulnerabilities.read") ? { vulnerabilities: (info?.packages ?? []).slice(0, 1).map((p) => ({ package: p, advisories: 2, hosts: Math.min(hosts.length, 3) })) } : {}),
        ...(holds("alarms.read") ? { alarms: { program_not_collected: programs.length === 0, open: 0, hosts: 0 } } : {}),
      },
      can: { export: anyHost("hosts.export"), add_to_case: anyHost("cases.write") && anyHost("cases.read"), ask: anyHost("assistant.use") },
    };
    return json(body);
  });

  route("GET", "/api/v1/ports/{protocol}/{port}/hosts", "hosts.read", ({ protocol, port }, query) => {
    const key = keyOf(protocol, port);
    if (!key) return invalid();
    for (const k of query.keys()) if (!["segment", "offset", "limit"].includes(k)) return problem(400, "invalid_query", "Port host query parameters are invalid",
      { field_errors: [{ field: "query", code: "invalid", message: "The query parameter is invalid" }] });
    const bad = listQueryError(query, "Port host query parameters are invalid", [["segment", ["all", "exposed", "local"]]], []);
    if (bad) return bad;
    const offset = Number(query.get("offset") || 0);
    const limit = Number(query.get("limit") || 50);
    const all = (portHosts(ctx).get(key) ?? []).slice().sort((a, b) => (a.hostname ?? "").localeCompare(b.hostname ?? "") || byteOrder(a.id, b.id));
    const segment = query.get("segment") || "all";
    const chosen = all.filter((h) => segment === "all" || (segment === "exposed") === h.exposed);
    const body: PortPageHosts = {
      items: chosen.slice(offset, offset + limit).map((h) => {
        const agent = ctx.agentById(h.id);
        const os = agent ? distribution(ctx.facts(agent)) : null;
        return { agent_id: h.id, ...(h.hostname ? { hostname: h.hostname } : {}), ...(os ? { os: distributionName(os) } : {}), bound: h.bound, exposed: h.exposed,
          ...(h.service ? { service: h.service } : {}), ...(h.program ? { program: h.program } : {}), owners_partial: true, reported_at: h.reportedAt };
      }),
      total: chosen.length,
      segments: { all: all.length, exposed: all.filter((h) => h.exposed).length, local: all.filter((h) => !h.exposed).length },
    };
    return json(body);
  });
}
