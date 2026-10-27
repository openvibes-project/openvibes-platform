// The Ports list (GET /api/v1/port-list), answered as ports/list_page.rs and
// the store's port_list.rs answer it: one row per port over the hosts in the
// hosts.read reach that listen on it (a host counts once however many
// addresses it binds), single-value filters that AND together, each filter's
// counts with the others applied, the summary and offset paging (step 5e
// rulings 11-17). "This week" reads the demo's change log (portData.ts).
import type { PortList, PortListRow } from "../../api/types";
import type { DemoContext } from "../context";
import { isActive } from "../hostGroups";
import { listQueryError } from "../listQuery";
import { json, problem } from "../http";
import { groupIdsOf, portChanges, portHosts, type PortHost } from "../portData";
import { keysNamed, portInfo } from "../portNames";

const PARAMS = ["q", "exposure", "protocol", "group", "service", "changes", "host", "sort", "dir", "offset", "limit"];
const SORTS = ["port", "hosts", "exposed", "week"];
const WEEK = 7 * 86_400_000;
const NOT_COLLECTED = "~none";
const byteOrder = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);

type Port = {
  key: string; protocol: string; port: number; hosts: PortHost[]; services: string[]; unowned: boolean; added: number; removed: number; look: string[];
  groups: Map<string, number>; all: Map<string, number>;
};
type Facet = "q" | "exposure" | "protocol" | "group" | "service" | "changes" | "host";
const FACETS: Facet[] = ["q", "exposure", "protocol", "group", "service", "changes", "host"];

export function registerPortListRoute(ctx: DemoContext) {
  const { data, route, reaches } = ctx;
  route("GET", "/api/v1/port-list", "hosts.read", (_, query) => {
    for (const key of query.keys()) if (!PARAMS.includes(key)) return problem(400, "invalid_query", "Port query parameters are invalid",
      { field_errors: [{ field: "query", code: "invalid", message: "The query parameter is invalid" }] });
    const get = (k: string) => query.get(k) || null;
    const bad = listQueryError(query, "Port query parameters are invalid", [["exposure", ["exposed", "local"]], ["protocol", ["tcp", "udp"]], ["changes", ["new", "look"]],
      ["sort", SORTS], ["dir", ["asc", "desc"]]], [["q", 200], ["service", 200], ["host", 100]]);
    if (bad) return bad;
    const chosen = { q: (get("q") ?? "").trim().toLowerCase(), exposure: get("exposure"), protocol: get("protocol"), group: get("group"), service: get("service"),
      changes: get("changes"), host: get("host") };
    const offset = Number(get("offset") ?? 0);
    const limit = Number(get("limit") ?? 50);
    const now = Date.parse(ctx.iso());

    // One row per port: the reachable hosts that listen, this week's log and the Needs a look codes.
    const hostsByKey = portHosts(ctx);
    const reachable = new Set(ctx.hosts().filter((a) => isActive(ctx.facts(a))).map((a) => a.id));
    const week = portChanges(ctx).filter((c) => c.at > now - WEEK && reachable.has(c.agent) && (c.change === "appeared" || c.change === "went_away"));
    const ports: Port[] = [];
    for (const [key, hosts] of hostsByKey) {
      const [protocol = "", number = ""] = key.split("/");
      const info = portInfo(key);
      const added = new Set(week.filter((c) => c.key === key && c.change === "appeared").map((c) => c.agent)).size;
      const removed = new Set(week.filter((c) => c.key === key && c.change === "went_away").map((c) => c.agent)).size;
      const exposed = hosts.some((h) => h.exposed);
      const look = [
        ...(info?.class === "database" && exposed ? ["database_exposed"] : []),
        ...(info?.class === "remote_admin" && exposed ? ["remote_admin_exposed"] : []),
        ...(!info && added > 0 ? ["new_unusual"] : []),
      ];
      const groups = new Map<string, number>();
      const all = new Map<string, number>();
      for (const h of hosts) {
        for (const g of groupIdsOf(ctx, h.id, ["automatic", "rule", "manual"])) {
          all.set(g, (all.get(g) ?? 0) + 1);
          if (data.access.host_groups.find((x) => x.asset_group_id === g)?.kind !== "manual") groups.set(g, (groups.get(g) ?? 0) + 1);
        }
      }
      ports.push({ key, protocol, port: Number(number), hosts, services: [...new Set(hosts.flatMap((h) => (h.service ? [h.service] : [])))].sort(byteOrder),
        unowned: hosts.some((h) => h.service === null), added, removed, look, groups, all });
    }

    const named = chosen.q ? keysNamed(chosen.q) : [];
    const holds = (p: Port, facet: Facet): boolean => {
      switch (facet) {
        case "q": return !chosen.q || named.includes(p.key) || p.key.includes(chosen.q) || `${p.port}/${p.protocol}`.includes(chosen.q) || p.services.some((s) => s.toLowerCase().includes(chosen.q));
        case "exposure": return chosen.exposure === null || (chosen.exposure === "exposed") === p.hosts.some((h) => h.exposed);
        case "protocol": return chosen.protocol === null || p.protocol === chosen.protocol;
        case "group": return chosen.group === null || p.all.has(chosen.group);
        case "service": return chosen.service === null || (chosen.service === NOT_COLLECTED ? p.unowned : p.services.includes(chosen.service));
        case "changes": return chosen.changes === null || (chosen.changes === "new" ? p.added > 0 : p.look.length > 0);
        case "host": return chosen.host === null || p.hosts.some((h) => h.id === chosen.host);
      }
    };
    const except = (...skip: Facet[]) => ports.filter((p) => FACETS.every((f) => skip.includes(f) || holds(p, f)));
    const matching = except();
    const dir = get("dir") === "desc" ? -1 : 1;
    const exposedHosts = (p: Port) => p.hosts.filter((h) => h.exposed).length;
    const sorts: Record<string, (p: Port) => number> = { port: (p) => p.port, hosts: (p) => p.hosts.length, exposed: exposedHosts, week: (p) => p.added };
    const sortKey = sorts[get("sort") ?? "port"] as (p: Port) => number;
    matching.sort((a, b) => dir * (sortKey(a) - sortKey(b) || a.port - b.port || byteOrder(a.protocol, b.protocol)));

    const groupOf = new Map(data.access.host_groups.map((g) => [g.asset_group_id, g]));
    const scope = ctx.capabilities.find((c) => c.permission === "hosts.read")?.scope;
    const reachesGroup = (g: string) => scope?.kind === "global" || (scope?.kind === "asset_groups" && scope.asset_group_ids.includes(g));
    const groupRows = except("group");
    const groupCounts = [...groupOf.keys()].map((g) => ({ g, count: groupRows.filter((p) => p.all.has(g)).length })).filter((x) => x.count > 0 || (x.g === chosen.group && reachesGroup(x.g)));
    const serviceRows = except("service");
    const units = new Map<string, number>();
    for (const p of serviceRows) for (const s of p.services) units.set(s, (units.get(s) ?? 0) + 1);
    const count = (rows: Port[], test: (p: Port) => boolean) => rows.filter(test).length;
    const reporting = data.agents.filter((a) => isActive(ctx.facts(a)) && ctx.visible(a.id) && reaches("hosts.read", a.id)).length;

    const row = (p: Port): PortListRow => {
      const groups = [...p.groups].map(([id, hosts]) => ({ id, name: groupOf.get(id)?.name ?? id, kind: (groupOf.get(id)?.kind ?? "rule") as "automatic" | "rule", hosts }))
        .sort((a, b) => b.hosts - a.hosts || a.name.toLowerCase().localeCompare(b.name.toLowerCase()) || byteOrder(a.id, b.id));
      return { protocol: p.protocol, port: p.port, ...(portInfo(p.key) ? { name: portInfo(p.key)?.name as string } : {}), hosts: p.hosts.length, exposed_hosts: exposedHosts(p),
        services: p.services.slice(0, 8), owners_missing: p.unowned, groups: groups.slice(0, 3), groups_total: groups.length, week_added: p.added, week_removed: p.removed, look: p.look };
    };
    const body: PortList = {
      items: matching.slice(offset, offset + limit).map(row),
      total: matching.length,
      counts: {
        exposure: ["exposed", "local"].map((value) => ({ value, count: count(except("exposure"), (p) => (value === "exposed") === p.hosts.some((h) => h.exposed)) })),
        protocol: ["tcp", "udp"].map((value) => ({ value, count: count(except("protocol"), (p) => p.protocol === value) })),
        changes: [{ value: "new", count: count(except("changes"), (p) => p.added > 0) }, { value: "look", count: count(except("changes"), (p) => p.look.length > 0) }],
        group: groupCounts.map(({ g, count: n }) => ({ value: g, name: groupOf.get(g)?.name ?? g, kind: groupOf.get(g)?.kind ?? "manual", count: n }))
          .sort((a, b) => a.name.toLowerCase().localeCompare(b.name.toLowerCase()) || byteOrder(a.value, b.value)),
        service: [...[...units].sort(([a], [b]) => byteOrder(a, b)).map(([value, n]) => ({ value, count: n })), { value: NOT_COLLECTED, count: count(serviceRows, (p) => p.unowned) }],
      },
      summary: { exposed: count(matching, (p) => p.hosts.some((h) => h.exposed)), new_this_week: count(matching, (p) => p.added > 0),
        need_a_look: count(matching, (p) => p.look.length > 0), reporting_hosts: reporting },
      generated_at: ctx.iso(),
    };
    return json(body);
  });
}
