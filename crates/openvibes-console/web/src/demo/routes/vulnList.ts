// The Vulnerabilities list (GET /api/v1/vulnerability-list), answered as
// vulnerabilities/list_page.rs and the store's vuln_list.rs answer it: one row
// per CVE (an advisory without CVEs is its own row) over the host and
// advisory pairs in the vulnerabilities.read reach, single-value filters that
// AND together, each filter's counts with the others applied, the summary of
// rows with an open pair under every filter but state, offset paging (plan
// rulings 2-6).
import type { Vulnerability, VulnList, VulnListRow } from "../../api/types";
import type { DemoContext } from "../context";
import { hasControl, inGroup, isActive } from "../hostGroups";
import { json, problem, severityRank } from "../http";

type Pair = Vulnerability & { state: string; groups: string[] };
type Row = { row: VulnListRow; pairs: Pair[] };

const STATES = ["open", "mitigated", "accepted_risk", "false_positive", "resolved", "all"];
const SEVERITIES = ["critical", "important", "moderate", "low", "unrated"];
const SIGNALS = ["exploited", "due30", "nofix", "reboot", "lowconf"];
const SORTS = ["priority", "severity", "cvss", "epss", "open", "due"];
const byteOrder = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);
const invalid = (field: string) => problem(400, "invalid_query", "Vulnerability query parameters are invalid",
  { field_errors: [{ field, code: "invalid", message: `The ${field} parameter is invalid` }] });
const unique = (values: string[]) => [...new Set(values)].sort(byteOrder);

export function registerVulnListRoute(ctx: DemoContext) {
  const { data, route, me, facts } = ctx;
  route("GET", "/api/v1/vulnerability-list", "vulnerabilities.read", (_, query) => {
    const get = (k: string) => query.get(k) || null;
    const closed: [string, string | null, string[]][] = [["state", get("state"), STATES], ["severity", get("severity"), SEVERITIES],
      ["signal", get("signal"), SIGNALS], ["sort", get("sort"), SORTS], ["dir", get("dir"), ["asc", "desc"]]];
    for (const [field, value, allowed] of closed) if (value !== null && !allowed.includes(value)) return invalid(field);
    for (const [field, max] of [["q", 200], ["package", 200], ["host", 100], ["advisory", 200]] as const) {
      const v = get(field);
      if (v !== null && ([...v].length > max || hasControl(v))) return invalid(field);
    }
    // Ids have the demo's shapes (grp-…, u-…), standing in for the server's UUID check.
    const group = get("group");
    if (group !== null && !/^grp-[a-z0-9-]{1,64}$/.test(group)) return invalid("group");
    const assignee = get("assignee");
    if (assignee !== null && assignee !== "me" && assignee !== "unassigned" && !/^u-[a-z0-9-]{1,32}$/.test(assignee)) return invalid("assignee");
    const offset = Number(get("offset") ?? 0);
    const limit = Number(get("limit") ?? 50);
    if (!Number.isInteger(offset) || offset < 0 || offset > 100_000) return invalid("offset");
    if (!Number.isInteger(limit) || limit < 1 || limit > 100) return invalid("limit");

    const chosen = { state: get("state") ?? "open", severity: get("severity"), signal: get("signal"), package: get("package"),
      advisory: get("advisory"), q: (get("q") ?? "").trim().toLowerCase() };
    const host = get("host");
    const users = new Map(data.access.users.map((u) => [u.user_id, u]));
    const username = assignee === "me" ? users.get(me)?.username : assignee === null || assignee === "unassigned" ? undefined : users.get(assignee)?.username;
    const nameOf = (u: string | null | undefined) => data.access.users.find((x) => x.username === u);
    const today = Date.parse(ctx.iso().slice(0, 10));

    const pairs: Pair[] = data.vulnerabilities.filter((v) => ctx.reaches("vulnerabilities.read", v.agent_id)).map((v) => {
      const agent = data.agents.find((a) => a.id === v.agent_id);
      const f = agent ? facts(agent) : undefined;
      return { ...v, state: v.fixed_at != null ? "resolved" : v.triage_state,
        groups: f && isActive(f) ? data.access.host_groups.filter((g) => inGroup(f, g)).map((g) => g.asset_group_id) : [] };
    });
    const cvesOf = new Map<string, string[]>();
    for (const p of pairs) cvesOf.set(p.advisory_id, p.cves);

    /** The rows over the pairs of hosts passing `hostOk` (the Host chip and, per count, a group). */
    const rowsOf = (hostOk: (p: Pair) => boolean): Row[] => {
      const byKey = new Map<string, Pair[]>();
      for (const p of pairs.filter(hostOk)) for (const key of p.cves.length ? p.cves : [p.advisory_id]) byKey.set(key, [...(byKey.get(key) ?? []), p]);
      return [...byKey].map(([key, ps]) => ({ row: buildRow(key, ps), pairs: ps }));
    };
    const buildRow = (key: string, ps: Pair[]): VulnListRow => {
      const open = ps.filter((p) => p.state === "open");
      const advisories = unique(ps.map((p) => p.advisory_id));
      const perAdvisory = advisories.map((id) => ({ id, n: ps.filter((p) => p.advisory_id === id).length, p: ps.find((p) => p.advisory_id === id) as Pair }));
      const lead = [...perAdvisory].sort((a, b) => b.n - a.n || byteOrder(a.id, b.id))[0]?.p as Pair;
      const fixed = unique(ps.flatMap((p) => (Array.isArray(p.packages) ? (p.packages as { fixed?: string | null }[]).flatMap((k) => (k.fixed ? [k.fixed] : [])) : [])));
      const people = unique(open.flatMap((p) => (p.assigned_to ? [p.assigned_to] : [])));
      const one = nameOf(people[0]);
      const dues = ps.flatMap((p) => (p.kev_due ? [p.kev_due.slice(0, 10)] : [])).sort(byteOrder);
      return {
        key, title: lead.title,
        severity: ps.map((p) => p.severity).sort((a, b) => (severityRank[a] ?? 9) - (severityRank[b] ?? 9))[0] ?? "unrated",
        exploited: ps.some((p) => p.exploited), due: dues[0] ?? null,
        cvss: lead.cvss ?? null, epss: lead.epss ?? null, epss_percentile: lead.epss_percentile ?? null,
        packages: unique(ps.flatMap((p) => (Array.isArray(p.packages) ? (p.packages as { name: string }[]).map((k) => k.name) : []))),
        fixed: fixed.length === 0 ? { kind: "none" } : fixed.length === 1 ? { kind: "one", version: fixed[0] ?? "" } : { kind: "several", count: fixed.length },
        open: open.length, total: ps.length, reboot: ps.some((p) => p.reboot_needed), low_confidence: false,
        advisories, also_covers: unique(advisories.flatMap((id) => cvesOf.get(id) ?? []).filter((c) => c !== key)).slice(0, 10),
        assignee: people.length === 0 ? { kind: "none" } : people.length === 1 && one ? { kind: "one", id: one.user_id, name: one.display_name } : { kind: "several", count: people.length },
      };
    };

    type Facet = "state" | "severity" | "signal" | "package" | "assignee" | "advisory" | "q";
    const holds = ({ row, pairs: ps }: Row, facet: Facet): boolean => {
      switch (facet) {
        case "state": return chosen.state === "all" || ps.some((p) => p.state === chosen.state);
        case "severity": return chosen.severity === null || row.severity === chosen.severity;
        case "signal": switch (chosen.signal) {
          case null: return true;
          case "exploited": return row.exploited;
          case "due30": return row.due != null && Date.parse(row.due) <= today + 30 * 86_400_000;
          case "nofix": return row.fixed.kind === "none";
          case "reboot": return row.reboot;
          default: return row.low_confidence;
        }
        case "package": return chosen.package === null || row.packages.includes(chosen.package);
        case "advisory": return chosen.advisory === null || row.advisories.includes(chosen.advisory) || (cvesOf.get(chosen.advisory) ?? []).includes(row.key);
        case "q": return !chosen.q || [row.key, row.title, ...row.advisories, ...row.packages].some((h) => h.toLowerCase().includes(chosen.q));
        case "assignee": {
          const open = ps.filter((p) => p.state === "open");
          return assignee === null || (assignee === "unassigned" ? open.some((p) => !p.assigned_to) : open.some((p) => p.assigned_to === username));
        }
      }
    };
    const FACETS: Facet[] = ["state", "severity", "signal", "package", "assignee", "advisory", "q"];
    const hostOnly = (p: Pair) => host === null || p.agent_id === host;
    const base = rowsOf((p) => hostOnly(p) && (group === null || p.groups.includes(group)));
    const except = (...skip: Facet[]) => base.filter((r) => FACETS.every((f) => skip.includes(f) || holds(r, f)));
    const tally = (rows: Row[], keys: (r: Row) => string[]) => {
      const n = new Map<string, number>();
      for (const r of rows) for (const k of unique(keys(r))) n.set(k, (n.get(k) ?? 0) + 1);
      return n;
    };
    // A state count over rows whose own pair has that state, the other filters applied.
    const stateRows = except("state");
    const byState = (s: string) => (s === "all" ? stateRows.length : stateRows.filter((r) => r.pairs.some((p) => p.state === s)).length);
    const bySeverity = tally(except("severity"), (r) => [r.row.severity]);
    const bySignal = except("signal");
    const signalCount = (s: string) => bySignal.filter((r) => { const prev = chosen.signal; chosen.signal = s; const ok = holds(r, "signal"); chosen.signal = prev; return ok; }).length;
    const packageRows = tally(except("package"), (r) => r.row.packages);
    const topPackages = [...packageRows].sort((a, b) => b[1] - a[1] || byteOrder(a[0], b[0])).slice(0, 50).map(([value, count]) => ({ value, count }));
    if (chosen.package !== null && !topPackages.some((t) => t.value === chosen.package)) topPackages.push({ value: chosen.package, count: packageRows.get(chosen.package) ?? 0 });
    const groupOf = new Map(data.access.host_groups.map((g) => [g.asset_group_id, g]));
    const groupsInReach = unique(pairs.flatMap((p) => p.groups));
    const byGroup = groupsInReach.map((g) => ({ g, count: rowsOf((p) => hostOnly(p) && p.groups.includes(g)).filter((r) => FACETS.every((f) => holds(r, f))).length }));
    const assigneeRows = except("assignee");
    const people = new Map<string, number>();
    for (const r of assigneeRows) for (const u of new Set(r.pairs.filter((p) => p.state === "open" && p.assigned_to).map((p) => p.assigned_to as string))) people.set(u, (people.get(u) ?? 0) + 1);
    const unassigned = assigneeRows.filter((r) => r.pairs.some((p) => p.state === "open" && !p.assigned_to)).length;
    const meName = users.get(me)?.username ?? "";

    const matching = except();
    const dir = get("dir") === "asc" ? 1 : -1;
    const sev = (r: Row) => SEVERITIES.length - (SEVERITIES.indexOf(r.row.severity));
    const num = (a: number | null | undefined, b: number | null | undefined) => (a ?? -1) - (b ?? -1);
    const order: Record<string, (a: Row, b: Row) => number> = {
      priority: (a, b) => Number(a.row.exploited) - Number(b.row.exploited) || num(a.row.epss_percentile, b.row.epss_percentile) || sev(a) - sev(b) || num(a.row.cvss, b.row.cvss),
      severity: (a, b) => sev(a) - sev(b), cvss: (a, b) => num(a.row.cvss, b.row.cvss), epss: (a, b) => num(a.row.epss, b.row.epss),
      open: (a, b) => a.row.open - b.row.open, due: (a, b) => byteOrder(a.row.due ?? "", b.row.due ?? ""),
    };
    const cmp = order[get("sort") ?? "priority"] ?? (order.priority as (a: Row, b: Row) => number);
    matching.sort((a, b) => dir * (cmp(a, b) || byteOrder(a.row.key, b.row.key)));

    const summarised = except("state").filter((r) => r.row.open > 0);
    const body: VulnList = {
      items: matching.slice(offset, offset + limit).map((r) => r.row),
      total: matching.length,
      counts: {
        state: STATES.map((value) => ({ value, count: byState(value) })),
        severity: SEVERITIES.map((value) => ({ value, count: bySeverity.get(value) ?? 0 })),
        signal: SIGNALS.map((value) => ({ value, count: signalCount(value) })),
        package: topPackages,
        group: byGroup.filter((x) => x.count > 0 || x.g === group).map(({ g, count }) => ({ value: g, name: groupOf.get(g)?.name ?? g, kind: groupOf.get(g)?.kind ?? "manual", count }))
          .sort((a, b) => a.name.toLowerCase().localeCompare(b.name.toLowerCase()) || byteOrder(a.value, b.value)),
        assignee: {
          me: people.get(meName) ?? 0, unassigned,
          people: [...people].flatMap(([u, count]) => { const x = nameOf(u); return x ? [{ value: x.user_id, name: x.display_name, count }] : []; })
            .sort((a, b) => a.name.toLowerCase().localeCompare(b.name.toLowerCase()) || byteOrder(a.value, b.value)),
        },
      },
      summary: {
        open_rows: summarised.length,
        hosts: new Set(summarised.flatMap((r) => r.pairs.filter((p) => p.state === "open").map((p) => p.agent_id))).size,
        exploited: summarised.filter((r) => r.row.exploited).length, with_due: summarised.filter((r) => r.row.due != null).length,
        no_fix: summarised.filter((r) => r.row.fixed.kind === "none").length, unassigned: summarised.filter((r) => r.row.assignee.kind === "none").length,
      },
      generated_at: ctx.iso(),
    };
    return json(body);
  });
}
