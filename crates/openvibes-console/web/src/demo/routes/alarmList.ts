// The Alarms list (GET /api/v1/alarm-list), answered as alarms/list.rs and
// the store's alarm_list.rs answer it: single-value filters that AND
// together, each filter's counts with the others applied, the summary of
// open alarms under every filter but state, offset paging, rows inside the
// alarms.read reach (plan rulings 1–5).
import type { AlarmList, AlarmListRow } from "../../api/types";
import { demoMappings } from "../attack";
import type { createCaseStore } from "../cases";
import type { DemoContext } from "../context";
import { distribution, distributionName, hasControl, inGroup, isActive, osFamily } from "../hostGroups";
import { json, problem } from "../http";

type Facet = "state" | "severity" | "suppressed" | "group" | "technique" | "case" | "assignee";
export type Row = { row: AlarmListRow; groups: string[]; severe: boolean; alarmsOff: boolean };

const STATES = ["open", "mitigated", "accepted_risk", "false_positive"];
const SEVERITIES = ["critical", "high", "medium", "low", "info"];
const SORTS = ["last_seen", "first_seen", "count", "severity"];
const byteOrder = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);
const invalid = (field: string) => problem(400, "invalid_query", "Alarm query parameters are invalid",
  { field_errors: [{ field, code: "invalid", message: `The ${field} parameter is invalid` }] });

export function registerAlarmListRoute(ctx: DemoContext & { cases: ReturnType<typeof createCaseStore> }) {
  const { data, route, me } = ctx;
  route("GET", "/api/v1/alarm-list", "alarms.read", (_, query) => {
    const get = (k: string) => query.get(k) || null;
    const closed: [string, string | null, string[]][] = [["state", get("state"), [...STATES, "all"]], ["severity", get("severity"), SEVERITIES],
      ["suppressed", get("suppressed"), ["hidden", "shown"]], ["case", get("case"), ["yes", "no"]], ["sort", get("sort"), SORTS], ["dir", get("dir"), ["asc", "desc"]]];
    for (const [field, value, allowed] of closed) if (value !== null && !allowed.includes(value)) return invalid(field);
    for (const [field, max] of [["q", 200], ["host", 100], ["technique", 16]] as const) {
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

    const state = get("state") ?? "open";
    const chosen = { state: state === "all" ? null : state, severity: get("severity"), suppressed: get("suppressed") === "shown", group,
      technique: get("technique"), case: get("case"), assignee: assignee === "me" ? me : assignee };
    const host = get("host");
    const q = (get("q") ?? "").trim().toLowerCase();
    const people = new Map(data.access.users.map((u) => [u.user_id, u]));
    const base = alarmRows(ctx).filter(({ row: r }) =>
      !q || [r.message, r.rule_id, r.host.name ?? "", r.program, r.parent_program ?? ""].some((h) => h.toLowerCase().includes(q)));
    const groupOf = new Map(data.access.host_groups.map((g) => [g.asset_group_id, g]));

    const holds = ({ row, groups }: Row, facet: Facet): boolean => {
      switch (facet) {
        case "state": return chosen.state === null || row.state === chosen.state;
        case "severity": return chosen.severity === null || row.severity === chosen.severity;
        case "suppressed": return chosen.suppressed || !row.suppressed;
        case "group": return chosen.group === null || groups.includes(chosen.group);
        case "technique": return chosen.technique === null || row.techniques.includes(chosen.technique);
        case "case": return chosen.case === null || (chosen.case === "yes") === (row.case !== null);
        case "assignee": return chosen.assignee === null ? true : chosen.assignee === "unassigned" ? row.assignee === null : row.assignee?.id === chosen.assignee;
      }
    };
    const hostOk = (r: Row) => host === null || r.row.host.id === host;
    const FACETS: Facet[] = ["state", "severity", "suppressed", "group", "technique", "case", "assignee"];
    /** The alarms every filter but `skip` lets through. */
    const except = (...skip: Facet[]) => base.filter((r) => hostOk(r) && FACETS.every((f) => skip.includes(f) || holds(r, f)));
    const tally = (rows: Row[], keys: (r: Row) => string[]) => {
      const n = new Map<string, number>();
      for (const r of rows) for (const k of keys(r)) n.set(k, (n.get(k) ?? 0) + 1);
      return n;
    };

    const byState = tally(except("state"), (r) => [r.row.state]);
    const bySeverity = tally(except("severity"), (r) => [r.row.severity]);
    const bySuppressed = except("suppressed");
    const byCase = tally(except("case"), (r) => [r.row.case ? "yes" : "no"]);
    const byTechnique = tally(except("technique"), (r) => r.row.techniques);
    // Groups, techniques and people come from alarms in reach, so none is named from a host out of reach.
    const byGroup = tally(base.filter((r) => hostOk(r) && FACETS.every((f) => f === "group" || holds(r, f))), (r) => r.groups);
    const byPerson = tally(except("assignee"), (r) => (r.row.assignee ? [r.row.assignee.id] : []));
    const unassigned = except("assignee").filter((r) => r.row.assignee === null).length;
    const scope = ctx.capabilities.find((c) => c.permission === "alarms.read")?.scope;
    const reachable = (g: string) => base.some((r) => r.groups.includes(g)) || scope?.kind === "global"
      || (scope?.kind === "asset_groups" && scope.asset_group_ids.includes(g));
    const groupIds = [...byGroup.keys(), ...(group && groupOf.has(group) && !byGroup.has(group) && reachable(group) ? [group] : [])];
    const byName = (a: string, b: string) => (groupOf.get(a)?.name ?? "").toLowerCase().localeCompare((groupOf.get(b)?.name ?? "").toLowerCase()) || a.localeCompare(b);

    const matching = except();
    const dir = get("dir") === "asc" ? 1 : -1;
    const severityRank = (r: Row) => SEVERITIES.length - SEVERITIES.indexOf(r.row.severity);
    const key: Record<string, (a: Row, b: Row) => number> = {
      last_seen: (a, b) => byteOrder(a.row.last_seen, b.row.last_seen), first_seen: (a, b) => byteOrder(a.row.first_seen, b.row.first_seen),
      count: (a, b) => a.row.count - b.row.count, severity: (a, b) => severityRank(a) - severityRank(b),
    };
    const order = key[get("sort") ?? "last_seen"] ?? key.last_seen;
    matching.sort((a, b) => dir * (order?.(a, b) || a.row.id - b.row.id));

    const summarised = except("state").filter((r) => r.row.state === "open");
    const hostsRead = ctx.permissions.includes("hosts.read");
    const body: AlarmList = {
      items: matching.slice(offset, offset + limit).map((r) => r.row),
      total: matching.length,
      counts: {
        state: STATES.map((value) => ({ value, count: byState.get(value) ?? 0 })),
        severity: SEVERITIES.map((value) => ({ value, count: bySeverity.get(value) ?? 0 })),
        suppressed: [{ value: "hidden", count: bySuppressed.filter((r) => !r.row.suppressed).length }, { value: "shown", count: bySuppressed.length }],
        case: ["yes", "no"].map((value) => ({ value, count: byCase.get(value) ?? 0 })),
        group: groupIds.sort(byName).map((value) => ({ value, name: groupOf.get(value)?.name ?? value, kind: groupOf.get(value)?.kind ?? "manual", count: byGroup.get(value) ?? 0 })),
        technique: [...byTechnique].sort((a, b) => byteOrder(a[0], b[0])).map(([value, count]) => ({ value, count })),
        assignee: {
          me: byPerson.get(me) ?? 0, unassigned,
          people: [...byPerson].map(([value, count]) => ({ value, name: people.get(value)?.display_name ?? value, count }))
            .sort((a, b) => a.name.toLowerCase().localeCompare(b.name.toLowerCase()) || byteOrder(a.value, b.value)),
        },
      },
      summary: {
        open: summarised.length, critical_or_high: summarised.filter((r) => r.severe).length,
        // Hosts inside the hosts.read reach too (alarm_list.rs).
        on_alarms_off_hosts: hostsRead ? summarised.filter((r) => r.alarmsOff && ctx.reaches("hosts.read", r.row.host.id)).length : null,
      },
      generated_at: ctx.iso(),
    };
    return json(body);
  });
}

/** Every alarm in reach as a list row, with what the filters need. */
export function alarmRows(ctx: DemoContext & { cases: ReturnType<typeof createCaseStore> }): Row[] {
  const { data, alarmList, facts, cases } = ctx;
  const userOf = (name: string | null) => data.access.users.find((u) => u.username === name);
  const inCase = new Map(((cases.activeItems(new URLSearchParams({ kind: "alarm" })).body as { items: { ref: string }[] }).items)
    .map(({ ref }) => {
      const found = (cases.forItem(new URLSearchParams({ kind: "alarm", ref })).body as { items: { case: { case_id: string; number: number } }[] }).items[0];
      return [ref, found ? { id: found.case.case_id, number: found.case.number } : null] as const;
    }));
  return alarmList().map((a) => {
    const agent = data.agents.find((x) => x.id === a.agent_id);
    const f = agent ? facts(agent) : undefined;
    const dist = f && distribution(f);
    const user = userOf(a.triage.assigned_to);
    const found = inCase.get(a.id) ?? null;
    const techniques = [...new Set((demoMappings[a.rule_id] ?? []).flatMap((p) => (p.technique ? [p.technique] : [])))].sort(byteOrder);
    return {
      // Members are active hosts only (console_host_in_group).
      groups: f && isActive(f) ? data.access.host_groups.filter((g) => inGroup(f, g)).map((g) => g.asset_group_id) : [],
      severe: a.severity === "critical" || a.severity === "high",
      alarmsOff: agent?.status === "active" && agent.alarms?.state === "off" && agent.alarms.fault === true,
      row: {
        id: Number(a.id), host: { id: a.agent_id, name: a.hostname, os_family: f ? osFamily(f) : null, distribution: dist ? distributionName(dist) : null },
        rule_set_id: a.rule_set_id, rule_id: a.rule_id, severity: a.severity, message: a.message, program: a.exe, parent_program: a.parent_exe,
        techniques, count: a.count, first_seen: a.first_seen, last_seen: a.last_seen, state: a.state,
        assignee: user ? { id: user.user_id, name: user.display_name } : null,
        case: found ? { id: found.id, number: found.number } : null, suppressed: a.suppressed_by !== null,
      },
    };
  });
}
