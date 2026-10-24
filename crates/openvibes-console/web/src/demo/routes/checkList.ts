// The Compliance list (GET /api/v1/compliance-list), answered as
// compliance/list_page.rs and the store's check_list.rs answer it: one row per
// check (a rule of a rule set) over the hosts in the compliance.read reach that
// fail it (a current finding, not ended, seen within 24 hours) or pass it
// (inferred from the rule sets the host runs), single-value filters that AND
// together, each filter's counts with the others applied, the summary of rows
// with an open failing host under every filter but state, offset paging
// (plan rulings 2-7).
// ponytail: a host passes a check when it is active, runs the check's rule set
// (its report lists it with a version and not `not_assigned`) and has no failing
// finding for it; failing, too, only counts on an active host. The server also asks
// that the collectors the rule reads ran ok and that the running version
// indexes the rule; the demo has neither.
import type { CheckList, CheckListRow } from "../../api/types";
import { type CheckMeta, EXTRA_META } from "../checkSeed";
import type { DemoContext } from "../context";
import { hasControl, inGroup, isActive } from "../hostGroups";
import { json, problem } from "../http";

type Pair = { agent: string; groups: string[]; state: string; assignee: string | null; first: number };
type Fnd = { agent: string; severity: string; seen: number; failing: boolean };
type Row = { row: CheckListRow; pairs: Pair[] };

const STATES = ["open", "mitigated", "accepted_risk", "false_positive", "passing", "all"];
const SEVERITIES = ["critical", "high", "medium", "low", "info"];
const SORTS = ["severity", "failing", "since", "title"];
const PARAMS = ["q", "state", "severity", "rule_set", "area", "group", "host", "assignee", "sort", "dir", "offset", "limit"];
const DAY = 86_400_000;
const byteOrder = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);
const byName = (a: { name: string; value: string }, b: { name: string; value: string }) =>
  a.name.toLowerCase().localeCompare(b.name.toLowerCase()) || byteOrder(a.value, b.value);
const invalid = (field: string) => problem(400, "invalid_query", "Compliance query parameters are invalid",
  { field_errors: [{ field, code: "invalid", message: `The ${field} parameter is invalid` }] });

/** The area of a rule ID (ruling 3; platform-store check_area.rs), the first prefix that matches. */
const AREAS: [string, string][] = [["port.", "Network exposure"], ["package.", "Packages"], ["harden.ssh.", "SSH"], ["harden.net.", "Network"],
  ["harden.kernel.", "Kernel"], ["harden.modules.", "Kernel"], ["harden.files.", "Files"], ["harden.fs.", "Files"], ["harden.accounts.", "Accounts"],
  ["harden.login.", "Accounts"], ["harden.lsm.", "Security modules"], ["harden.services.", "Services"], ["test.", "Tests"]];
export const checkArea = (ruleId: string) => AREAS.find(([prefix]) => ruleId.startsWith(prefix))?.[1] ?? "Other";

export function registerCheckListRoute(ctx: DemoContext) {
  const { data, route, me, facts, capabilities } = ctx;
  route("GET", "/api/v1/compliance-list", "compliance.read", (_, query) => {
    for (const key of query.keys()) if (!PARAMS.includes(key)) return invalid("query");
    const get = (k: string) => query.get(k) || null;
    const closed: [string, string | null, string[]][] = [["state", get("state"), STATES], ["severity", get("severity"), SEVERITIES],
      ["sort", get("sort"), SORTS], ["dir", get("dir"), ["asc", "desc"]]];
    for (const [field, value, allowed] of closed) if (value !== null && !allowed.includes(value)) return invalid(field);
    for (const [field, max] of [["q", 200], ["rule_set", 200], ["area", 100], ["host", 100]] as const) {
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

    const chosen = { state: get("state") ?? "open", severity: get("severity"), ruleSet: get("rule_set"), area: get("area"),
      q: (get("q") ?? "").trim().toLowerCase() };
    const host = get("host");
    const now = Date.parse(ctx.iso());
    const users = new Map(data.access.users.map((u) => [u.user_id, u]));
    const username = assignee === "me" ? users.get(me)?.username : assignee === null || assignee === "unassigned" ? undefined : users.get(assignee)?.username;
    const nameOf = (u: string | null | undefined) => data.access.users.find((x) => x.username === u);

    // The checks the server indexes (the newest version of every set) and every current finding in reach.
    const metas = new Map<string, CheckMeta>();
    const title = (message: string) => (message.split(/[;.]\s/)[0] ?? message).replace(/\.$/, "");
    for (const r of data.rules) metas.set(`${r.ruleSetId}/${r.ruleId}`, { ruleSetId: r.ruleSetId, ruleId: r.ruleId, title: title(r.message), severity: r.severity });
    for (const m of EXTRA_META) metas.set(`${m.ruleSetId}/${m.ruleId}`, m);
    const failingFrom = now - DAY;
    const finds = new Map<string, Fnd[]>();
    const firsts = new Map<string, number>();
    const triageOf = new Map<string, { state: string; assignee: string | null }>();
    const active = new Set(data.agents.filter((a) => a.status === "active").map((a) => a.id));
    for (const f of data.findings) {
      if (!ctx.reaches("compliance.read", f.agent_id)) continue;
      const key = `${f.rule_set_id}/${f.rule_id}`;
      const seen = Date.parse(f.last_observed_at);
      finds.set(key, [...(finds.get(key) ?? []), { agent: f.agent_id, severity: f.severity, seen, failing: f.ended_at == null && seen >= failingFrom && active.has(f.agent_id) }]);
      const t = data.triage.get(ctx.triageKey(f.agent_id, f.rule_set_id, f.rule_id));
      const expired = t?.state === "accepted_risk" && t.accepted_until != null && Date.parse(t.accepted_until) <= now;
      triageOf.set(`${key}|${f.agent_id}`, { state: t === undefined || expired ? "open" : t.state, assignee: t?.assigned_to ?? null });
      firsts.set(`${key}|${f.agent_id}`, Date.parse(f.first_observed_at));
    }
    const groupsOf = new Map<string, string[]>();
    const groupsFor = (id: string) => {
      const known = groupsOf.get(id);
      if (known) return known;
      const agent = data.agents.find((a) => a.id === id);
      const f = agent ? facts(agent) : undefined;
      const ids = f && isActive(f) ? data.access.host_groups.filter((g) => inGroup(f, g)).map((g) => g.asset_group_id) : [];
      groupsOf.set(id, ids);
      return ids;
    };
    const runs = (agent: (typeof data.agents)[number], set: string) =>
      agent.rule_sets.some((s) => s.id === set && s.version != null && s.state !== "not_assigned" && !s.refused);

    /** The rows over the pairs of hosts passing `hostOk` (the Host chip and, per count, a group). */
    const rowsOf = (hostOk: (agent: string) => boolean): Row[] => {
      const keys = new Set([...metas.keys(), ...finds.keys()]);
      const rows: Row[] = [];
      for (const key of [...keys].sort(byteOrder)) {
        const [set = "", id = ""] = [key.slice(0, key.indexOf("/")), key.slice(key.indexOf("/") + 1)];
        const fs = (finds.get(key) ?? []).filter((f) => hostOk(f.agent));
        const meta = metas.get(key);
        const pairs: Pair[] = fs.filter((f) => f.failing).map((f) => {
          const t = triageOf.get(`${key}|${f.agent}`);
          return { agent: f.agent, groups: groupsFor(f.agent), state: t?.state ?? "open", assignee: t?.assignee ?? null, first: firsts.get(`${key}|${f.agent}`) ?? 0 };
        });
        const failingAgents = new Set(pairs.map((p) => p.agent));
        for (const a of data.agents) {
          if (a.status === "active" && hostOk(a.id) && !failingAgents.has(a.id) && ctx.reaches("compliance.read", a.id) && runs(a, set)) {
            pairs.push({ agent: a.id, groups: groupsFor(a.id), state: "passing", assignee: null, first: 0 });
          }
        }
        if (pairs.length === 0) continue;
        const failing = pairs.filter((p) => p.state !== "passing");
        const count = (s: string) => pairs.filter((p) => p.state === s).length;
        // The newest finding's severity, failing ones first, else the indexed one.
        const newest = [...fs].sort((a, b) => Number(b.failing) - Number(a.failing) || b.seen - a.seen || SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity))[0];
        const people = [...new Set(pairs.filter((p) => p.state === "open" && p.assignee).map((p) => p.assignee as string))].filter((u) => nameOf(u));
        const one = nameOf(people[0]);
        const first = failing.length ? Math.min(...failing.map((p) => p.first)) : null;
        const row: CheckListRow = {
          rule_set_id: set, rule_id: id, title: meta?.title ?? id, ...((newest?.severity ?? meta?.severity) ? { severity: (newest?.severity ?? meta?.severity) as string } : {}),
          area: checkArea(id), failing: failing.length, passing: count("passing"), open: count("open"), mitigated: count("mitigated"),
          accepted_risk: count("accepted_risk"), false_positive: count("false_positive"), since: first === null ? null : new Date(first).toISOString(),
          assignee: people.length === 0 ? { kind: "none" } : people.length === 1 && one ? { kind: "one", id: one.user_id, name: one.display_name } : { kind: "several", count: people.length },
        };
        rows.push({ row, pairs });
      }
      return rows;
    };

    // A pair holds the state and assignee filters together (m_sa); each alone for the counts that skip the other.
    const stateOk = (p: Pair) => chosen.state === "all" || p.state === chosen.state;
    const assigneeOk = (p: Pair) => assignee === null || (p.state !== "passing" && (assignee === "unassigned" ? p.assignee === null : p.assignee !== null && p.assignee === username));
    type Facet = "state" | "assignee" | "severity" | "rule_set" | "area" | "q";
    const holds = ({ row }: Row, facet: Exclude<Facet, "state" | "assignee">): boolean => {
      switch (facet) {
        case "severity": return chosen.severity === null || row.severity === chosen.severity;
        case "rule_set": return chosen.ruleSet === null || row.rule_set_id === chosen.ruleSet;
        case "area": return chosen.area === null || row.area === chosen.area;
        case "q": return !chosen.q || [row.title, row.rule_id, row.rule_set_id].some((h) => h.toLowerCase().includes(chosen.q));
      }
    };
    /** Rows passing every filter but `skip`; the pair filters together unless one is skipped. */
    const except = (rows: Row[], ...skip: Facet[]) => rows.filter((r) =>
      r.pairs.some((p) => (skip.includes("state") || stateOk(p)) && (skip.includes("assignee") || assigneeOk(p)))
      && (["severity", "rule_set", "area", "q"] as const).every((f) => skip.includes(f) || holds(r, f)));

    const hostOnly = (a: string) => host === null || a === host;
    const base = rowsOf((a) => hostOnly(a) && (group === null || groupsFor(a).includes(group)));
    const all = rowsOf(hostOnly);
    const tally = (rows: Row[], key: (r: Row) => string) => { const n = new Map<string, number>(); for (const r of rows) n.set(key(r), (n.get(key(r)) ?? 0) + 1); return n; };
    const stateRows = except(base, "state");
    const countState = (s: string) => (s === "all" ? stateRows.length : stateRows.filter((r) => r.pairs.some((p) => p.state === s && assigneeOk(p))).length);
    const bySeverity = tally(except(base, "severity").filter((r) => r.row.severity), (r) => r.row.severity as string);
    const ruleSets = tally(except(base, "rule_set"), (r) => r.row.rule_set_id);
    const areas = tally(except(base, "area"), (r) => r.row.area);
    const everyKey = (rows: Row[], key: (r: Row) => string) => [...new Set(rows.map(key))].sort(byteOrder);
    const groupRows = except(all, "state", "assignee");
    const groupOf = new Map(data.access.host_groups.map((g) => [g.asset_group_id, g]));
    const scope = capabilities.find((c) => c.permission === "compliance.read")?.scope;
    const reaches = (g: string) => scope?.kind === "global" || (scope?.kind === "asset_groups" && scope.asset_group_ids.includes(g));
    const inMatching = (r: Row, g: string) => r.pairs.some((p) => stateOk(p) && assigneeOk(p) && p.groups.includes(g));
    const byGroup = [...groupOf.keys()].map((g) => ({ g, count: groupRows.filter((r) => inMatching(r, g)).length }))
      .filter((x) => x.count > 0 || (x.g === group && reaches(x.g)));
    const assigneeRows = except(base, "assignee");
    const people = new Map<string, number>();
    for (const r of assigneeRows) for (const u of new Set(r.pairs.filter((p) => p.state !== "passing" && p.assignee && stateOk(p)).map((p) => p.assignee as string))) people.set(u, (people.get(u) ?? 0) + 1);
    const unassigned = assigneeRows.filter((r) => r.pairs.some((p) => p.state !== "passing" && p.assignee === null && stateOk(p))).length;
    const meName = users.get(me)?.username ?? "";

    const matching = except(base);
    const dir = get("dir") === "asc" ? 1 : -1;
    const sev = (r: Row) => (r.row.severity ? 6 - (SEVERITIES.indexOf(r.row.severity) + 1) : null);
    const keysOf: Record<string, (r: Row) => (number | string | null)[]> = {
      severity: (r) => [sev(r), r.row.failing], failing: (r) => [r.row.failing],
      since: (r) => [r.row.since ? Date.parse(r.row.since) : null], title: (r) => [r.row.title.toLowerCase()],
    };
    const keys = keysOf[get("sort") ?? "severity"] as (r: Row) => (number | string | null)[];
    matching.sort((a, b) => {
      const [x, y] = [keys(a), keys(b)];
      for (let i = 0; i < x.length; i += 1) {
        const [p, q] = [x[i] ?? null, y[i] ?? null];
        if (p === q) continue;
        if (p === null) return 1;
        if (q === null) return -1;
        return dir * (typeof p === "string" ? byteOrder(p, q as string) : p - (q as number));
      }
      return dir * (byteOrder(a.row.rule_set_id, b.row.rule_set_id) || byteOrder(a.row.rule_id, b.row.rule_id));
    });

    const summarised = except(base, "state").filter((r) => r.pairs.some((p) => p.state === "open" && assigneeOk(p)));
    const body: CheckList = {
      items: matching.slice(offset, offset + limit).map((r) => r.row),
      total: matching.length,
      counts: {
        state: STATES.map((value) => ({ value, count: countState(value) })),
        severity: SEVERITIES.map((value) => ({ value, count: bySeverity.get(value) ?? 0 })),
        rule_set: everyKey(base, (r) => r.row.rule_set_id).map((value) => ({ value, count: ruleSets.get(value) ?? 0 })),
        area: everyKey(base, (r) => r.row.area).map((value) => ({ value, count: areas.get(value) ?? 0 })),
        group: byGroup.map(({ g, count }) => ({ value: g, name: groupOf.get(g)?.name ?? g, kind: groupOf.get(g)?.kind ?? "manual", count }))
          .sort((a, b) => byName(a, b)),
        assignee: {
          me: people.get(meName) ?? 0, unassigned,
          people: [...people].flatMap(([u, count]) => { const x = nameOf(u); return x ? [{ value: x.user_id, name: x.display_name, count }] : []; })
            .sort((a, b) => byName(a, b)),
        },
      },
      summary: {
        failing_checks: summarised.length,
        hosts: new Set(summarised.flatMap((r) => r.pairs.filter((p) => p.state === "open" && assigneeOk(p)).map((p) => p.agent))).size,
        critical: summarised.filter((r) => r.row.severity === "critical").length,
        unassigned: summarised.filter((r) => r.row.assignee.kind === "none").length,
        rule_sets: everyKey(summarised, (r) => r.row.rule_set_id).map((value) => ({ value, count: summarised.filter((r) => r.row.rule_set_id === value).length })),
      },
      generated_at: ctx.iso(),
    };
    return json(body);
  });
}
