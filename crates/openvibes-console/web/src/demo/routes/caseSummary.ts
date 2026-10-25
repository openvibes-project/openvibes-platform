// A case's page summary (GET /api/v1/cases/{id}/summary), answered as
// cases/page.rs and the store's case_summary.rs answer it (step 5d rulings
// 12-14): 404 case_not_found when the viewer does not see the case; tiles
// over visible items, "ready" by close's own rule over every item; each
// visible host with its problems where that kind's read reaches it; who can
// see it (names with access.read, at most 20); the can flags.
import { EXCLUSIVE_KINDS } from "../../panels/cases/cases";
import type { CaseStore } from "../cases";
import type { DemoContext } from "../context";
import { distribution, distributionName, inGroup, isActive, osFamily } from "../hostGroups";
import { json, problem } from "../http";
import { resolveCapabilities } from "../share";
import { complianceStale, openFailing } from "./checkList";
import { listedCritical } from "./hostList";

const byteOrder = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);
const MAX_PEOPLE = 20;

export function registerCaseSummaryRoute(ctx: DemoContext & { cases: CaseStore }) {
  const { data, route, me, permissions, reaches, rolesOf, facts, cases } = ctx;
  route("GET", "/api/v1/cases/{id}/summary", "cases.read", ({ id = "" }) => {
    const l = cases.listed().find((x) => x.c.case_id === id);
    if (!l) return problem(404, "case_not_found", "Case not found");
    const { c } = l;
    const now = Date.parse(ctx.iso());
    const agents = [...new Set(l.visible.flatMap((i) => (i.agent_id === null ? [] : [i.agent_id])))]
      .flatMap((agentId) => data.agents.filter((a) => a.id === agentId))
      // By name, nameless last, then by id (ORDER BY hostname, agent_id).
      .sort((a, b) => (a.hostname === b.hostname ? byteOrder(a.id, b.id) : a.hostname == null ? 1 : b.hostname == null ? -1 : byteOrder(a.hostname, b.hostname)));
    const stale = (a: (typeof agents)[number]) => reaches("compliance.read", a.id) && complianceStale(a.last_seen_at, now);
    const hosts = agents.map((a) => {
      const dist = distribution(facts(a));
      return {
        agent_id: a.id, hostname: a.hostname ?? null,
        os: { id: a.os_id ?? null, version: a.os_version ?? null, distribution: dist && distributionName(dist), family: osFamily(facts(a)) },
        problems: {
          // Agent alarms only (al.source = 'agent'); the demo's alarms carry no source and are all the agent's.
          alarms: reaches("alarms.read", a.id) ? data.alarms.filter((x) => x.agent_id === a.id && x.state === "open"
            && (!("source" in x) || x.source === "agent")).length : null,
          critical_vulns: reaches("vulnerabilities.read", a.id) ? listedCritical(data, a.id) : null,
          // No report in the last day: unknown, not 0 (the Hosts list's rule).
          failing_checks: reaches("compliance.read", a.id) && !stale(a) ? data.findings.filter((f) => f.agent_id === a.id && openFailing(ctx, f, now)).length : null,
          compliance_stale: stale(a),
        },
      };
    });
    // Who can see it (ruling 13): enabled people whose cases.read reaches every
    // host or a group holding a visible item's host (members are active hosts
    // only), or, for the opener and the assignee, anywhere.
    const groups = data.access.host_groups.filter((g) => agents.some((a) => isActive(facts(a)) && inGroup(facts(a), g))).map((g) => g.asset_group_id);
    const people = data.access.users.filter((u) => u.enabled && resolveCapabilities(rolesOf(u.user_id)).some((cap) => cap.permission === "cases.read"
      && (u.user_id === c.opened_by_user_id || u.user_id === c.assignee_user_id
        || cap.scope.kind === "global" || cap.scope.asset_group_ids.some((g) => groups.includes(g)))))
      .sort((a, b) => byteOrder(a.display_name.toLowerCase(), b.display_name.toLowerCase()) || byteOrder(a.username, b.username));
    const user = (u: { user_id: string; username: string; display_name: string }) => ({ user_id: u.user_id, username: u.username, display_name: u.display_name });
    // Changes stay inside what the viewer reads: cases.write and cases.read both reach the case.
    // Visible items suffice: the shared reach is inside the cases.read one.
    const hostBound = l.visible.filter((i) => i.agent_id !== null);
    const global = (p: "cases.read" | "cases.write") => ctx.capabilities.some((cap) => cap.permission === p && cap.scope.kind === "global");
    const write = permissions.includes("cases.write") && (c.opened_by_user_id === me || c.assignee_user_id === me
      || hostBound.some((i) => reaches("cases.read", i.agent_id ?? "") && reaches("cases.write", i.agent_id ?? ""))
      || (hostBound.length === 0 && global("cases.read") && global("cases.write")));
    const closed = c.status === "closed";
    return json({
      header: {
        case_id: c.case_id, number: c.number, title: c.title, status: c.status, severity: c.severity,
        opened_by: user(l.opener), created_at: c.created_at, assignee: l.assignee && user(l.assignee), version: c.version,
      },
      tiles: {
        items: l.visible.length,
        need_outcome: l.visible.filter((i) => EXCLUSIVE_KINDS.has(i.kind) && i.outcome === null).length,
        hosts: hosts.length,
        open_for_seconds: Math.max(0, Math.floor(((c.closed_at ? Date.parse(c.closed_at) : now) - Date.parse(c.created_at)) / 1000)),
        ready: l.ready,
      },
      details: {
        title: c.title, severity: c.severity, status: c.status, opened_by: user(l.opener), created_at: c.created_at, updated_at: c.updated_at,
        closed_at: c.closed_at, resolution: c.resolution, resolution_note: c.resolution_note,
      },
      hosts,
      people: {
        names: permissions.includes("access.read") ? people.slice(0, MAX_PEOPLE).map(user) : null, total: people.length,
        // Everyone only when the viewer reads cases on every host; never from this case's hidden items.
        complete: global("cases.read"),
      },
      can: {
        edit: write, assign: write && permissions.includes("cases.assign"), close: write && !closed, reopen: write && closed,
        note: write, outcome: write && !closed,
        // The assistant takes no case reference (assistant/ cites agents, findings and advisories only).
        ask: false, export: true,
      },
    });
  });
}
