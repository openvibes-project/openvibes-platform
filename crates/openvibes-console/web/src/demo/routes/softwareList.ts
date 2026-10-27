// The Software list (GET /api/v1/software-list), answered as
// software_pages/list_page.rs and the store's software_list.rs answer it:
// one row per package name over the hosts in the hosts.read reach that have
// it, single-value filters that AND together, each filter's counts with the
// others applied, the summary and offset paging (step 5g rulings 1-10).
// "This week" reads the demo's change log (softwareData.ts).
import type { SoftwareList, SoftwareListRow } from "../../api/types";
import type { DemoContext } from "../context";
import { isActive } from "../hostGroups";
import { json, problem } from "../http";
import { listQueryError } from "../listQuery";
import { groupIdsOf } from "../portData";
import { byVersion, fullVersion, severityRank, softwareAdvisories, softwareChanges, softwareHosts, softwareUnits } from "../softwareData";

const PARAMS = ["q", "vulns", "fix", "versions", "type", "group", "changes", "host", "sort", "dir", "offset", "limit"];
const SORTS = ["package", "hosts", "vulnerabilities", "versions", "week"];
const WEEK = 7 * 86_400_000;
const byteOrder = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);

type Pkg = {
  name: string; hosts: Set<string>; versions: number; rpm: boolean; dpkg: boolean; oldest: string; newest: string;
  adv: number; noFix: number; sev: number | null; exploited: boolean; update: number; added: number; updated: number; removed: number;
  units: [string, number][]; groups: Set<string>;
};
type Facet = "q" | "vulns" | "fix" | "versions" | "type" | "group" | "changes" | "host";
const FACETS: Facet[] = ["q", "vulns", "fix", "versions", "type", "group", "changes", "host"];

export function registerSoftwareListRoute(ctx: DemoContext) {
  const { data, route, reaches } = ctx;
  route("GET", "/api/v1/software-list", "hosts.read", (_, query) => {
    for (const key of query.keys()) if (!PARAMS.includes(key)) return problem(400, "invalid_query", "Software query parameters are invalid",
      { field_errors: [{ field: "query", code: "invalid", message: "The query parameter is invalid" }] });
    const get = (k: string) => query.get(k) || null;
    const bad = listQueryError(query, "Software query parameters are invalid", [["vulns", ["exploited", "critical_high", "any", "none"]], ["fix", ["available", "none"]],
      ["versions", ["one", "several"]], ["type", ["dpkg", "rpm"]], ["changes", ["new", "updated", "removed"]], ["sort", SORTS], ["dir", ["asc", "desc"]]], [["q", 200], ["host", 100]]);
    if (bad) return bad;
    const chosen = { q: (get("q") ?? "").trim().toLowerCase(), vulns: get("vulns"), fix: get("fix"), versions: get("versions"), type: get("type"), group: get("group"),
      changes: get("changes"), host: get("host") };
    const offset = Number(get("offset") ?? 0);
    const limit = Number(get("limit") ?? 50);
    const now = Date.parse(ctx.iso());

    const reach = new Set(ctx.hosts().filter((a) => isActive(ctx.facts(a))).map((a) => a.id));
    const advisories = softwareAdvisories(ctx, reach);
    const unitsOf = softwareUnits(ctx);
    const week = softwareChanges(ctx).filter((c) => c.at > now - WEEK && reach.has(c.agent));
    const pkgs: Pkg[] = [];
    for (const [name, hosts] of softwareHosts(ctx)) {
      const versions = hosts.flatMap((h) => h.versions);
      const distinct = [...new Map(versions.map((v) => [fullVersion(v), v])).values()].sort(byVersion);
      const open = [...(advisories.get(name)?.values() ?? [])];
      const mine = week.filter((c) => c.name === name);
      const agents = [...new Set(mine.map((c) => c.agent))];
      const gone = (a: string) => mine.some((c) => c.agent === a && c.change === "went_away");
      const came = (a: string) => mine.some((c) => c.agent === a && c.change === "appeared");
      const groups = new Set(hosts.flatMap((h) => groupIdsOf(ctx, h.id, ["automatic", "rule", "manual"])));
      pkgs.push({
        name, hosts: new Set(hosts.map((h) => h.id)), versions: distinct.length, rpm: distinct.some((v) => v.manager === "rpm"), dpkg: distinct.some((v) => v.manager === "dpkg"),
        oldest: fullVersion(distinct[0] as never), newest: fullVersion(distinct[distinct.length - 1] as never),
        adv: open.length, noFix: open.filter((a) => a.fixed == null).length, sev: open.length ? Math.min(...open.map((a) => severityRank(a.severity))) : null,
        exploited: open.some((a) => a.exploited), update: new Set(open.flatMap((a) => [...a.fixable])).size,
        added: agents.filter((a) => came(a) && !gone(a)).length, updated: agents.filter((a) => came(a) && gone(a)).length, removed: agents.filter((a) => gone(a) && !came(a)).length,
        units: [...(unitsOf.get(name) ?? [])].map(([unit, h]) => [unit, h.size] as [string, number]).sort((a, b) => b[1] - a[1] || byteOrder(a[0], b[0])), groups,
      });
    }

    const holds = (p: Pkg, facet: Facet): boolean => {
      switch (facet) {
        case "q": return !chosen.q || p.name.toLowerCase().includes(chosen.q) || p.units.some(([u]) => u.toLowerCase().includes(chosen.q));
        case "vulns": return chosen.vulns === null || (chosen.vulns === "exploited" ? p.exploited : chosen.vulns === "critical_high" ? p.sev !== null && p.sev <= 1 : chosen.vulns === "any" ? p.adv > 0 : p.adv === 0);
        case "fix": return chosen.fix === null || (chosen.fix === "available" ? p.update > 0 : p.noFix > 0);
        case "versions": return chosen.versions === null || (chosen.versions === "one") === (p.versions === 1);
        case "type": return chosen.type === null || (chosen.type === "dpkg" ? p.dpkg : p.rpm);
        case "group": return chosen.group === null || p.groups.has(chosen.group);
        case "changes": return chosen.changes === null || (chosen.changes === "new" ? p.added > 0 : chosen.changes === "updated" ? p.updated > 0 : p.removed > 0);
        case "host": return chosen.host === null || p.hosts.has(chosen.host);
      }
    };
    const except = (...skip: Facet[]) => pkgs.filter((p) => FACETS.every((f) => skip.includes(f) || holds(p, f)));
    const matching = except();
    const dir = get("dir") === "desc" ? -1 : 1;
    const by = get("sort") ?? "package";
    const key = (p: Pkg): number[] => by === "hosts" ? [p.hosts.size] : by === "versions" ? [p.versions]
      : by === "week" ? [p.added + p.updated + p.removed] : by === "vulnerabilities" ? [Number(p.exploited), 6 - (p.sev ?? 6), p.adv] : [];
    matching.sort((a, b) => {
      const [x, y] = [key(a), key(b)];
      for (let i = 0; i < x.length; i += 1) if (x[i] !== y[i]) return dir * ((x[i] as number) - (y[i] as number));
      return dir * byteOrder(a.name, b.name);
    });

    const groupOf = new Map(data.access.host_groups.map((g) => [g.asset_group_id, g]));
    const scope = ctx.capabilities.find((c) => c.permission === "hosts.read")?.scope;
    const reachesGroup = (g: string) => scope?.kind === "global" || (scope?.kind === "asset_groups" && scope.asset_group_ids.includes(g));
    const members = (g: string) => [...reach].filter((id) => groupIdsOf(ctx, id, ["automatic", "rule", "manual"]).includes(g)).length;
    const groupCounts = [...groupOf.keys()].map((g) => ({ g, count: members(g) })).filter((x) => x.count > 0 || (x.g === chosen.group && reachesGroup(x.g)));
    const count = (rows: Pkg[], test: (p: Pkg) => boolean) => rows.filter(test).length;
    const reporting = data.agents.filter((a) => isActive(ctx.facts(a)) && ctx.visible(a.id) && reaches("hosts.read", a.id)).length;

    const row = (p: Pkg): SoftwareListRow => ({
      name: p.name, hosts: p.hosts.size, versions: p.versions, rpm: p.rpm, dpkg: p.dpkg, oldest: p.oldest, newest: p.newest, advisories: p.adv, no_fix: p.noFix,
      ...(p.sev === null ? {} : { worst_severity: ["critical", "important", "moderate", "low", "unrated"][p.sev] as string }), exploited: p.exploited, update_hosts: p.update,
      used_by: p.units.slice(0, 3).map(([unit, hosts]) => ({ unit, hosts })), used_by_total: p.units.length, week_added: p.added, week_updated: p.updated, week_removed: p.removed,
    });
    const body: SoftwareList = {
      items: matching.slice(offset, offset + limit).map(row),
      total: matching.length,
      counts: {
        vulns: [["exploited", (p: Pkg) => p.exploited], ["critical_high", (p: Pkg) => p.sev !== null && p.sev <= 1], ["any", (p: Pkg) => p.adv > 0], ["none", (p: Pkg) => p.adv === 0]]
          .map(([value, test]) => ({ value: value as string, count: count(except("vulns"), test as (p: Pkg) => boolean) })),
        fix: [["available", (p: Pkg) => p.update > 0], ["none", (p: Pkg) => p.noFix > 0]].map(([value, test]) => ({ value: value as string, count: count(except("fix"), test as (p: Pkg) => boolean) })),
        versions: [["one", (p: Pkg) => p.versions === 1], ["several", (p: Pkg) => p.versions > 1]].map(([value, test]) => ({ value: value as string, count: count(except("versions"), test as (p: Pkg) => boolean) })),
        type: [["dpkg", (p: Pkg) => p.dpkg], ["rpm", (p: Pkg) => p.rpm]].map(([value, test]) => ({ value: value as string, count: count(except("type"), test as (p: Pkg) => boolean) })),
        changes: [["new", (p: Pkg) => p.added > 0], ["updated", (p: Pkg) => p.updated > 0], ["removed", (p: Pkg) => p.removed > 0]]
          .map(([value, test]) => ({ value: value as string, count: count(except("changes"), test as (p: Pkg) => boolean) })),
        group: groupCounts.map(({ g, count: n }) => ({ value: g, name: groupOf.get(g)?.name ?? g, kind: groupOf.get(g)?.kind ?? "manual", count: n }))
          .sort((a, b) => a.name.toLowerCase().localeCompare(b.name.toLowerCase()) || byteOrder(a.value, b.value)),
      },
      summary: { exploited: count(matching, (p) => p.exploited), fixable: count(matching, (p) => p.update > 0), several_versions: count(matching, (p) => p.versions > 1),
        new_this_week: count(matching, (p) => p.added > 0), reporting_hosts: reporting },
      generated_at: ctx.iso(),
    };
    return json(body);
  });
}
