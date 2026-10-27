// The Services list (GET /api/v1/service-list), answered as services/list_page.rs
// and the store's service_list.rs answer it: one row per unit over the hosts
// in the hosts.read reach that run it, single-value filters that AND
// together, each filter's counts with the others applied, the summary and
// offset paging (step 5f rulings 1-10). "This week" reads the demo's change
// log (serviceData.ts).
import type { ServiceList, ServiceListRow } from "../../api/types";
import type { DemoContext } from "../context";
import { isActive } from "../hostGroups";
import { json, problem } from "../http";
import { listQueryError } from "../listQuery";
import { groupIdsOf } from "../portData";
import { privileged, serviceChanges, serviceHosts, type ServiceHost } from "../serviceData";
import { basesNamed, baseOf, serviceInfo } from "../serviceNames";

const PARAMS = ["q", "runs_as", "listens", "packaged", "group", "changes", "host", "sort", "dir", "offset", "limit"];
const SORTS = ["service", "hosts", "week"];
const WEEK = 7 * 86_400_000;
const byteOrder = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);

type Unit = {
  unit: string; hosts: ServiceHost[]; added: number; removed: number; look: string[]; groups: Map<string, number>; all: Map<string, number>;
  root: number; packaged: number; exposed: number; listening: number;
};
type Facet = "q" | "runs_as" | "listens" | "packaged" | "group" | "changes" | "host";
const FACETS: Facet[] = ["q", "runs_as", "listens", "packaged", "group", "changes", "host"];

export function registerServiceListRoute(ctx: DemoContext) {
  const { data, route, reaches } = ctx;
  route("GET", "/api/v1/service-list", "hosts.read", (_, query) => {
    for (const key of query.keys()) if (!PARAMS.includes(key)) return problem(400, "invalid_query", "Service query parameters are invalid",
      { field_errors: [{ field: "query", code: "invalid", message: "The query parameter is invalid" }] });
    const get = (k: string) => query.get(k) || null;
    const bad = listQueryError(query, "Service query parameters are invalid", [["runs_as", ["root", "other"]], ["listens", ["exposed", "local", "none"]], ["packaged", ["yes", "no"]],
      ["changes", ["new", "look"]], ["sort", SORTS], ["dir", ["asc", "desc"]]], [["q", 200], ["host", 100]]);
    if (bad) return bad;
    const chosen = { q: (get("q") ?? "").trim().toLowerCase(), runs_as: get("runs_as"), listens: get("listens"), packaged: get("packaged"), group: get("group"), changes: get("changes"), host: get("host") };
    const offset = Number(get("offset") ?? 0);
    const limit = Number(get("limit") ?? 50);
    const now = Date.parse(ctx.iso());

    const reachable = new Set(ctx.hosts().filter((a) => isActive(ctx.facts(a))).map((a) => a.id));
    const week = serviceChanges(ctx).filter((c) => c.at > now - WEEK && reachable.has(c.agent));
    const units: Unit[] = [];
    for (const [unit, hosts] of serviceHosts(ctx)) {
      const info = serviceInfo(unit);
      const added = new Set(week.filter((c) => c.unit === unit && c.change === "appeared").map((c) => c.agent)).size;
      const removed = new Set(week.filter((c) => c.unit === unit && c.change === "went_away").map((c) => c.agent)).size;
      const exposed = hosts.filter((h) => h.ports.some((p) => p.exposed)).length;
      const root = hosts.filter((h) => privileged(h.runAs)).length;
      const look = [
        ...(hosts.some((h) => privileged(h.runAs) && !h.package) ? ["root_unpackaged"] : []),
        ...(info?.class === "database" && exposed > 0 ? ["database_exposed"] : []),
        ...(info?.class === "remote_admin" && exposed > 0 ? ["remote_admin_exposed"] : []),
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
      units.push({ unit, hosts, added, removed, look, groups, all, root, exposed, packaged: hosts.filter((h) => h.package).length, listening: hosts.filter((h) => h.ports.length > 0).length });
    }

    const named = chosen.q ? basesNamed(chosen.q) : [];
    const holds = (u: Unit, facet: Facet): boolean => {
      switch (facet) {
        case "q": return !chosen.q || u.unit.toLowerCase().includes(chosen.q) || named.includes(baseOf(u.unit)) || u.hosts.some((h) => h.programs.some((p) => p.toLowerCase().includes(chosen.q))
          || h.package?.name.toLowerCase().includes(chosen.q) || h.ports.some((p) => `${p.port}/${p.protocol}`.includes(chosen.q)));
        case "runs_as": return chosen.runs_as === null || (chosen.runs_as === "root") === (u.root > 0);
        case "listens": return chosen.listens === null || (chosen.listens === "exposed" ? u.exposed > 0 : chosen.listens === "local" ? u.listening > 0 && u.exposed === 0 : u.listening === 0);
        case "packaged": return chosen.packaged === null || (chosen.packaged === "yes") === (u.packaged === u.hosts.length);
        case "group": return chosen.group === null || u.all.has(chosen.group);
        case "changes": return chosen.changes === null || (chosen.changes === "new" ? u.added > 0 : u.look.length > 0);
        case "host": return chosen.host === null || u.hosts.some((h) => h.id === chosen.host);
      }
    };
    const except = (...skip: Facet[]) => units.filter((u) => FACETS.every((f) => skip.includes(f) || holds(u, f)));
    const matching = except();
    const dir = get("dir") === "desc" ? -1 : 1;
    const sorts: Record<string, (u: Unit) => number> = { hosts: (u) => u.hosts.length, week: (u) => u.added };
    const by = get("sort") ?? "service";
    matching.sort((a, b) => dir * ((by === "service" ? 0 : (sorts[by] as (u: Unit) => number)(a) - (sorts[by] as (u: Unit) => number)(b)) || byteOrder(a.unit, b.unit)));

    const groupOf = new Map(data.access.host_groups.map((g) => [g.asset_group_id, g]));
    const scope = ctx.capabilities.find((c) => c.permission === "hosts.read")?.scope;
    const reachesGroup = (g: string) => scope?.kind === "global" || (scope?.kind === "asset_groups" && scope.asset_group_ids.includes(g));
    const groupRows = except("group");
    const groupCounts = [...groupOf.keys()].map((g) => ({ g, count: groupRows.filter((u) => u.all.has(g)).length })).filter((x) => x.count > 0 || (x.g === chosen.group && reachesGroup(x.g)));
    const count = (rows: Unit[], test: (u: Unit) => boolean) => rows.filter(test).length;
    const reporting = data.agents.filter((a) => isActive(ctx.facts(a)) && ctx.visible(a.id) && reaches("hosts.read", a.id)).length;

    const row = (u: Unit): ServiceListRow => {
      const info = serviceInfo(u.unit);
      const groups = [...u.groups].map(([id, hosts]) => ({ id, name: groupOf.get(id)?.name ?? id, kind: (groupOf.get(id)?.kind ?? "rule") as "automatic" | "rule", hosts }))
        .sort((a, b) => b.hosts - a.hosts || a.name.toLowerCase().localeCompare(b.name.toLowerCase()) || byteOrder(a.id, b.id));
      const ports = new Map<string, { protocol: string; port: number; exposed: boolean; hosts: number }>();
      for (const h of u.hosts) for (const p of h.ports) {
        const seen = ports.get(`${p.protocol}/${p.port}`) ?? { ...p, exposed: false, hosts: 0 };
        seen.exposed ||= p.exposed;
        seen.hosts += 1;
        ports.set(`${p.protocol}/${p.port}`, seen);
      }
      const owned = [...ports.values()].sort((a, b) => Number(b.exposed) - Number(a.exposed) || a.port - b.port || byteOrder(a.protocol, b.protocol));
      const packages = [...new Set(u.hosts.flatMap((h) => (h.package ? [h.package.name] : [])))].sort(byteOrder);
      return {
        unit: u.unit, ...(info ? { name: info.name, usual_use: info.usual_use } : {}), hosts: u.hosts.length, root_hosts: u.root, package_hosts: u.packaged, exposed_hosts: u.exposed,
        listening_hosts: u.listening, run_as: [...new Set(u.hosts.flatMap((h) => (h.runAs ? [h.runAs] : [])))].sort(byteOrder).slice(0, 4),
        programs: [...new Set(u.hosts.flatMap((h) => h.programs))].sort(byteOrder).slice(0, 4), ...(packages[0] ? { package: packages[0] } : {}),
        groups: groups.slice(0, 3), groups_total: groups.length, ports: owned.slice(0, 4), ports_total: owned.length, week_added: u.added, week_removed: u.removed, look: u.look,
      };
    };
    const body: ServiceList = {
      items: matching.slice(offset, offset + limit).map(row),
      total: matching.length,
      counts: {
        runs_as: ["root", "other"].map((value) => ({ value, count: count(except("runs_as"), (u) => (value === "root") === (u.root > 0)) })),
        listens: [["exposed", (u: Unit) => u.exposed > 0], ["local", (u: Unit) => u.listening > 0 && u.exposed === 0], ["none", (u: Unit) => u.listening === 0]]
          .map(([value, test]) => ({ value: value as string, count: count(except("listens"), test as (u: Unit) => boolean) })),
        packaged: ["yes", "no"].map((value) => ({ value, count: count(except("packaged"), (u) => (value === "yes") === (u.packaged === u.hosts.length)) })),
        changes: [{ value: "new", count: count(except("changes"), (u) => u.added > 0) }, { value: "look", count: count(except("changes"), (u) => u.look.length > 0) }],
        group: groupCounts.map(({ g, count: n }) => ({ value: g, name: groupOf.get(g)?.name ?? g, kind: groupOf.get(g)?.kind ?? "manual", count: n }))
          .sort((a, b) => a.name.toLowerCase().localeCompare(b.name.toLowerCase()) || byteOrder(a.value, b.value)),
      },
      summary: { root: count(matching, (u) => u.root > 0), exposed: count(matching, (u) => u.exposed > 0), not_packaged: count(matching, (u) => u.packaged < u.hosts.length),
        new_this_week: count(matching, (u) => u.added > 0), need_a_look: count(matching, (u) => u.look.length > 0), reporting_hosts: reporting },
      generated_at: ctx.iso(),
    };
    return json(body);
  });
}
