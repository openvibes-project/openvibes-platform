// The Cases list (GET /api/v1/case-list), answered as cases/list_page.rs and
// the store's case_list.rs answer it (step 5d rulings 2, 4, 6-10): one row
// per case the viewer sees, single-value filters that AND together, each
// filter's counts with the others applied (host and search narrow every
// count), the summary of cases that are not closed under every filter but
// status, offset paging. Items, hosts and counts are only those the viewer
// sees; "ready to close" is close's own rule, hidden items included.
import { EXCLUSIVE_KINDS } from "../../panels/cases/cases";
import type { CaseStore, ListedCase } from "../cases";
import type { DemoContext } from "../context";
import { inGroup } from "../hostGroups";
import { json, problem } from "../http";
import { listQueryError } from "../listQuery";

const STATUSES = ["active", "open", "investigating", "closed", "all"];
const SEVERITIES = ["critical", "high", "medium", "low"];
const CONTAINS = ["alarms", "vulnerabilities", "findings"];
const UPDATED = ["today", "week", "quiet"];
const SORTS = ["updated", "severity", "number", "opened"];
const PARAMS = ["q", "status", "severity", "assignee", "contains", "host", "group", "updated", "sort", "dir", "offset", "limit"];
const KIND: Record<string, string> = { alarms: "alarm", vulnerabilities: "vulnerability", findings: "compliance_finding" };
const WEEK = 7 * 86_400_000;
const byteOrder = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);
const byName = (a: { name: string; value: string }, b: { name: string; value: string }) =>
  byteOrder(a.name.toLowerCase(), b.name.toLowerCase()) || byteOrder(a.value, b.value);
/** The case number a search names: `C-12`, `c12` or `12` (console_cases case_number). */
const caseNumber = (q: string) => {
  const digits = q.replace(/^[Cc]-?/, "");
  return /^\+?\d+$/.test(digits) && Number(digits) > 0 ? Number(digits) : null;
};

type Facet = "status" | "severity" | "assignee" | "contains" | "updated" | "group";
type Row = ListedCase & { kinds: Record<string, number>; groups: Set<string>; hosts: string[] };

export function registerCaseListRoute(ctx: DemoContext & { cases: CaseStore }) {
  const { data, route, me, facts, visible, capabilities, cases } = ctx;
  route("GET", "/api/v1/case-list", "cases.read", (_, query) => {
    for (const key of query.keys()) if (!PARAMS.includes(key)) {
      return problem(400, "invalid_query", "Case query parameters are invalid", { field_errors: [{ field: "query", code: "invalid", message: "The query parameter is invalid" }] });
    }
    const bad = listQueryError(query, "Case query parameters are invalid",
      [["status", STATUSES], ["severity", SEVERITIES], ["contains", CONTAINS], ["updated", UPDATED], ["sort", SORTS], ["dir", ["asc", "desc"]]],
      [["q", 200], ["host", 100]]);
    if (bad) return bad;
    const get = (k: string) => query.get(k) || null;
    const chosen = {
      status: get("status") ?? "active", severity: get("severity"), assignee: get("assignee"), contains: get("contains"),
      host: get("host"), group: get("group"), updated: get("updated"), q: (get("q") ?? "").trim().toLowerCase(),
    };
    const offset = Number(get("offset") ?? 0);
    const limit = Number(get("limit") ?? 50);
    const now = Date.now();
    const midnight = new Date(now).setUTCHours(0, 0, 0, 0);

    const groupsOfHost = new Map<string, string[]>();
    const groupsOf = (agentId: string) => {
      const known = groupsOfHost.get(agentId);
      if (known) return known;
      const agent = data.agents.find((a) => a.id === agentId);
      const ids = agent ? data.access.host_groups.filter((g) => inGroup(facts(agent), g)).map((g) => g.asset_group_id) : [];
      groupsOfHost.set(agentId, ids);
      return ids;
    };
    const hostname = (id: string) => data.agents.find((a) => a.id === id)?.hostname ?? null;
    const rows: Row[] = cases.listed().map((l) => {
      const kinds: Record<string, number> = { alarm: 0, compliance_finding: 0, vulnerability: 0, host: 0, software: 0 };
      for (const i of l.visible) kinds[i.kind] = (kinds[i.kind] ?? 0) + 1;
      const hosts = [...new Set(l.visible.flatMap((i) => (i.agent_id === null ? [] : [i.agent_id])))];
      // By name, nameless last, then by id (the store's ORDER BY hostname, agent_id).
      hosts.sort((a, b) => { const [x, y] = [hostname(a), hostname(b)]; return x === y ? byteOrder(a, b) : x === null ? 1 : y === null ? -1 : byteOrder(x, y); });
      return { ...l, kinds, hosts, groups: new Set(hosts.flatMap(groupsOf)) };
    });

    const updatedOk = (r: Row, v: string) => {
      const at = Date.parse(r.c.updated_at);
      return v === "today" ? at >= midnight : v === "week" ? at >= now - WEEK : at < now - WEEK;
    };
    const holds = (r: Row, facet: Facet): boolean => {
      switch (facet) {
        case "status": return chosen.status === "all" || (chosen.status === "active" ? r.c.status !== "closed" : r.c.status === chosen.status);
        case "severity": return chosen.severity === null || r.c.severity === chosen.severity;
        case "assignee": return chosen.assignee === null
          || (chosen.assignee === "unassigned" ? r.c.assignee_user_id === null : r.c.assignee_user_id === (chosen.assignee === "me" ? me : chosen.assignee));
        case "contains": return chosen.contains === null || (r.kinds[KIND[chosen.contains] ?? ""] ?? 0) > 0;
        case "updated": return chosen.updated === null || updatedOk(r, chosen.updated);
        case "group": return chosen.group === null || r.groups.has(chosen.group);
      }
    };
    const number = caseNumber(chosen.q);
    const always = (r: Row) => (chosen.host === null || r.visible.some((i) => i.agent_id === chosen.host))
      && (chosen.q === "" || r.c.number === number || [r.c.title, r.opener.display_name, r.opener.username].some((t) => t.toLowerCase().includes(chosen.q)));
    const FACETS: Facet[] = ["status", "severity", "assignee", "contains", "updated", "group"];
    const except = (...skip: Facet[]) => rows.filter((r) => always(r) && FACETS.every((f) => skip.includes(f) || holds(r, f)));

    const statusRows = except("status");
    const severityRows = except("severity");
    const containsRows = except("contains");
    const updatedRows = except("updated");
    const assigneeRows = except("assignee");
    const groupRows = except("group");
    const people = new Map<string, number>();
    for (const r of rows) if (r.c.assignee_user_id !== null) people.set(r.c.assignee_user_id, 0);
    for (const r of assigneeRows) if (r.c.assignee_user_id !== null) people.set(r.c.assignee_user_id, (people.get(r.c.assignee_user_id) ?? 0) + 1);
    const scope = capabilities.find((c) => c.permission === "hosts.read")?.scope;
    const reaches = (g: string) => scope?.kind === "global" || (scope?.kind === "asset_groups" && scope.asset_group_ids.includes(g));
    const seenGroups = new Set(data.agents.filter((a) => visible(a.id)).flatMap((a) => groupsOf(a.id)));

    const matching = except();
    const dir = get("dir") === "asc" ? 1 : -1;
    const key: Record<string, (r: Row) => number> = {
      updated: (r) => Date.parse(r.c.updated_at), severity: (r) => [...SEVERITIES].reverse().indexOf(r.c.severity),
      number: (r) => r.c.number, opened: (r) => Date.parse(r.c.created_at),
    };
    const sortKey = key[get("sort") ?? "updated"] as (r: Row) => number;
    matching.sort((a, b) => dir * (sortKey(a) - sortKey(b) || byteOrder(a.c.case_id, b.c.case_id)));
    const summarised = statusRows.filter((r) => r.c.status !== "closed");
    const userView = (u: { user_id: string; username: string; display_name: string }) => ({ user_id: u.user_id, username: u.username, display_name: u.display_name });
    const nameOf = (id: string) => data.access.users.find((u) => u.user_id === id)?.display_name ?? id;

    return json({
      items: matching.slice(offset, offset + limit).map((r) => ({
        case_id: r.c.case_id, number: r.c.number, title: r.c.title, status: r.c.status, severity: r.c.severity,
        opened_by: userView(r.opener), assignee: r.assignee && userView(r.assignee), latest_note: r.note,
        hosts: r.hosts.slice(0, 5).map((agent_id) => ({ agent_id, hostname: hostname(agent_id) })), host_count: r.hosts.length,
        kinds: { alarms: r.kinds.alarm, findings: r.kinds.compliance_finding, vulnerabilities: r.kinds.vulnerability, hosts: r.kinds.host, software: r.kinds.software },
        takes_outcome: r.visible.filter((i) => EXCLUSIVE_KINDS.has(i.kind)).length,
        with_outcome: r.visible.filter((i) => EXCLUSIVE_KINDS.has(i.kind) && i.outcome !== null).length,
        updated_at: r.c.updated_at,
      })),
      total: matching.length,
      counts: {
        status: STATUSES.map((value) => ({ value, count: value === "all" ? statusRows.length
          : statusRows.filter((r) => (value === "active" ? r.c.status !== "closed" : r.c.status === value)).length })),
        severity: SEVERITIES.map((value) => ({ value, count: severityRows.filter((r) => r.c.severity === value).length })),
        contains: CONTAINS.map((value) => ({ value, count: containsRows.filter((r) => (r.kinds[KIND[value] ?? ""] ?? 0) > 0).length })),
        updated: UPDATED.map((value) => ({ value, count: updatedRows.filter((r) => updatedOk(r, value)).length })),
        group: data.access.host_groups.filter((g) => seenGroups.has(g.asset_group_id) || (g.asset_group_id === chosen.group && reaches(g.asset_group_id)))
          .map((g) => ({ value: g.asset_group_id, name: g.name, kind: g.kind, count: groupRows.filter((r) => r.groups.has(g.asset_group_id)).length }))
          .sort(byName),
        assignee: {
          me: people.get(me) ?? 0,
          unassigned: assigneeRows.filter((r) => r.c.assignee_user_id === null).length,
          people: [...people].map(([value, count]) => ({ value, name: nameOf(value), count })).sort(byName),
        },
      },
      summary: {
        open: summarised.filter((r) => r.c.status === "open").length,
        investigating: summarised.filter((r) => r.c.status === "investigating").length,
        unassigned: summarised.filter((r) => r.c.assignee_user_id === null).length,
        ready_to_close: summarised.filter((r) => r.ready).length,
      },
      generated_at: new Date(now).toISOString(),
    });
  });
}
