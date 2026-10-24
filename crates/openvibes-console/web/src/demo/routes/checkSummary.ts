// A check's page (GET /api/v1/compliance/checks/{rule_set_id}/{rule_id}/summary
// and /hosts), answered as compliance/page.rs and the store's check_summary.rs
// answer them: one rule of a rule set over its failing and passing hosts in the
// compliance.read reach, under the Compliance list's rules (checkList.ts), or
// 404 check_not_found; each action when its permission reaches a host with a
// pair (plan rulings 8, 11-17).
// ponytail: the demo keeps no triage history and no listener or service
// tables, so History has episodes and rule-set publishes only, and Related
// counts a port or unit on the hosts failing the check.
import type { CheckHostsPage, CheckSummaryPage } from "../../api/types";
import { EXTRA_META } from "../checkSeed";
import type { DemoContext } from "../context";
import { distribution, distributionName, hasControl } from "../hostGroups";
import { json, problem, severityRank } from "../http";
import { checkArea } from "./checkList";

const DAY = 86_400_000;
const SEVERITIES = ["critical", "high", "medium", "low", "info"];
const byteOrder = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);
const invalid = (field: string) => problem(400, "invalid_query", "Compliance query parameters are invalid",
  { field_errors: [{ field, code: "invalid", message: `The ${field} parameter is invalid` }] });
const notFound = () => problem(404, "check_not_found", "Compliance check not found");
/** The literal an expression tests for in `fact` (check_related.rs `member_of`). */
const memberOf = (expression: string, fact: string) => {
  const end = expression.indexOf(`' in facts['${fact}']`);
  const start = end < 0 ? -1 : expression.lastIndexOf("'", end - 1) + 1;
  return start > 0 && end > start ? expression.slice(start, end) : null;
};
const appliesTo = (set: string) => (set.startsWith("hardening-linux-") ? "Linux hosts" : set === "baseline" ? "All hosts" : "Hosts with this rule set");

export function registerCheckSummaryRoutes(ctx: DemoContext) {
  const { data, route, reaches, facts } = ctx;
  const title = (message: string) => (message.split(/[;.]\s/)[0] ?? message).replace(/\.$/, "");

  /** The check's pairs in reach, as the list counts them, or null when the list has no row for it. */
  const pairsOf = (set: string, rule: string) => {
    if (!set || !rule || [...set].length > 256 || [...rule].length > 256 || hasControl(set) || hasControl(rule)) return null;
    const shipped = data.rules.find((r) => r.ruleSetId === set && r.ruleId === rule);
    const extra = EXTRA_META.find((m) => m.ruleSetId === set && m.ruleId === rule);
    const now = Date.parse(ctx.iso());
    const active = new Set(data.agents.filter((a) => a.status === "active").map((a) => a.id));
    const found = data.findings.filter((f) => f.rule_set_id === set && f.rule_id === rule && reaches("compliance.read", f.agent_id));
    if (!shipped && !extra && found.length === 0) return null;
    const failingOf = (f: (typeof found)[number]) => f.ended_at == null && Date.parse(f.last_observed_at) >= now - DAY && active.has(f.agent_id);
    const failing = found.filter(failingOf).map((f) => {
      const t = data.triage.get(ctx.triageKey(f.agent_id, set, rule));
      const expired = t?.state === "accepted_risk" && t.accepted_until != null && Date.parse(t.accepted_until) <= now;
      return { f, state: t === undefined || expired ? "open" : t.state, assignee: t?.assigned_to ?? null, version: t?.version ?? 0 };
    });
    const failingAgents = new Set(failing.map((p) => p.f.agent_id));
    const passing = data.agents.filter((a) => a.status === "active" && !failingAgents.has(a.id) && reaches("compliance.read", a.id)
      && a.rule_sets.some((s) => s.id === set && s.version != null && s.state !== "not_assigned" && !s.refused));
    if (failing.length + passing.length === 0) return null;
    return { now, shipped, extra, found, failing, passing, failingOf };
  };

  route("GET", "/api/v1/compliance/checks/{set}/{rule}/summary", "compliance.read", ({ set = "", rule = "" }) => {
    const p = pairsOf(set, rule);
    if (!p) return notFound();
    const { now, shipped, extra, found, failing, passing } = p;
    const newest = [...found].sort((a, b) => Number(p.failingOf(b)) - Number(p.failingOf(a))
      || Date.parse(b.last_observed_at) - Date.parse(a.last_observed_at) || (severityRank[a.severity] ?? 9) - (severityRank[b.severity] ?? 9))[0];
    const severity = newest?.severity ?? shipped?.severity ?? extra?.severity ?? null;
    const people = [...new Set(failing.filter((x) => x.state === "open" && x.assignee).map((x) => x.assignee as string))];
    const one = data.access.users.find((u) => u.username === people[0]);
    const first = [...failing].sort((a, b) => a.f.first_observed_at.localeCompare(b.f.first_observed_at) || byteOrder(a.f.agent_id, b.f.agent_id))[0];
    const today = Math.floor(now / DAY) * DAY;
    const days = Array.from({ length: 14 }, (_, i) => {
      const start = today - (13 - i) * DAY;
      return found.filter((f) => Date.parse(f.first_observed_at) < start + DAY
        && (f.ended_at != null ? Date.parse(f.ended_at) : p.failingOf(f) ? Infinity : Date.parse(f.last_observed_at)) >= start).length;
    });
    const set0 = data.ruleSets.find((s) => s.rule_set_id === set);
    const events = [
      ...found.map((f) => ({ at: f.first_observed_at, kind: "failing", agent_id: f.agent_id, hostname: f.hostname ?? null })),
      ...found.flatMap((f) => (f.ended_at ? [{ at: f.ended_at, kind: "passes_again", agent_id: f.agent_id, hostname: f.hostname ?? null }] : [])),
      ...(data.bundles.get(set) ?? []).map((b) => ({ at: b.published_at, kind: "published", actor: b.published_by, version: b.version })),
    ].sort((a, b) => b.at.localeCompare(a.at)).slice(0, 50);
    const area = checkArea(rule);
    const others = new Map<string, string>();
    for (const f of data.findings) {
      if ((f.rule_set_id === set && f.rule_id === rule) || checkArea(f.rule_id) !== area || !reaches("compliance.read", f.agent_id)) continue;
      if (f.ended_at != null || Date.parse(f.last_observed_at) < now - DAY) continue;
      const key = `${f.rule_set_id}/${f.rule_id}`;
      const was = others.get(key);
      if (was === undefined || SEVERITIES.indexOf(f.severity) < SEVERITIES.indexOf(was)) others.set(key, f.severity);
    }
    const worst = [...others.values()].sort((a, b) => SEVERITIES.indexOf(a) - SEVERITIES.indexOf(b))[0] ?? null;
    const expression = shipped?.expression ?? "";
    const tcp = rule.startsWith("port.") ? memberOf(expression, "port.tcp.exposed") : null;
    const udp = rule.startsWith("port.") ? memberOf(expression, "port.udp.exposed") : null;
    const unit = rule.startsWith("harden.services.") ? memberOf(expression, "service.enabled") : null;
    const agents = [...failing.map((x) => x.f.agent_id), ...passing.map((a) => a.id)];
    const anyHost = (permission: Parameters<typeof reaches>[0]) => agents.some((a) => reaches(permission, a));
    const triage = anyHost("compliance.triage");
    const body: CheckSummaryPage = {
      header: {
        title: extra?.title ?? (shipped ? title(shipped.message) : rule), severity, rule_set_id: set,
        rule_set_version: shipped || extra ? (set0?.current_version ?? null) : null, rule_id: rule,
        rule_version: newest?.rule_version ?? (shipped || extra ? 1 : null), area,
        failing: failing.length, checked: failing.length + passing.length,
        assignee: people.length === 0 ? { kind: "none" } : people.length === 1 && one ? { kind: "one", id: one.user_id, name: one.display_name } : { kind: "several", count: people.length },
      },
      tiles: {
        failing: failing.length, passing: passing.length, days,
        first_seen: first ? { at: first.f.first_observed_at, hostname: first.f.hostname ?? null } : null,
      },
      text: { explain: null, check: null, message: shipped?.message ?? newest?.message ?? extra?.title ?? "" },
      details: { applies_to: appliesTo(set), techniques: [] },
      history: events.map((e) => ({ actor: null, agent_id: null, hostname: null, from_state: null, to_state: null, note: null, version: null, ...e })),
      related: {
        port: tcp || udp ? { protocol: tcp ? "tcp" : "udp", port: Number(tcp ?? udp), hosts: failing.length } : null,
        service: unit ? { unit, hosts: failing.length } : null,
        same_area: { checks: others.size, worst },
      },
      can: {
        triage, assign: triage, add_to_case: anyHost("cases.write") && anyHost("cases.read"),
        ask: anyHost("assistant.use"), export: anyHost("compliance.export"),
      },
    };
    return json(body);
  });

  route("GET", "/api/v1/compliance/checks/{set}/{rule}/hosts", "compliance.read", ({ set = "", rule = "" }, query) => {
    for (const k of query.keys()) if (!["segment", "offset", "limit"].includes(k)) return invalid("query");
    const segment = query.get("segment") || "all";
    if (!["all", "failing", "passing"].includes(segment)) return invalid("segment");
    const offset = Number(query.get("offset") || 0);
    const limit = Number(query.get("limit") || 50);
    if (!Number.isInteger(offset) || offset < 0 || offset > 100_000) return invalid("offset");
    if (!Number.isInteger(limit) || limit < 1 || limit > 100) return invalid("limit");
    const p = pairsOf(set, rule);
    if (!p) return notFound();
    const agentOf = new Map(data.agents.map((a) => [a.id, a]));
    const host = (id: string) => {
      const a = agentOf.get(id);
      const d = a && distribution(facts(a));
      return { agent_id: id, hostname: a?.hostname ?? null, os: (d && distributionName(d)) ?? null, address: data.addresses.get(id) ?? null };
    };
    const person = (u: string | null) => { const x = data.access.users.find((v) => v.username === u); return x ? { id: x.user_id, name: x.display_name } : null; };
    const rows = [
      ...p.failing.map((x) => ({
        ...host(x.f.agent_id), state: x.state, assignee: person(x.assignee), checked_at: x.f.last_observed_at, triage_version: x.version,
        evidence: (x.f.detection?.inputs ?? []).map((i) => (i.status === "complete" || i.status == null
          ? { fact: i.key, value: String(i.value) } : { fact: i.key, status: i.status })),
      })),
      ...p.passing.map((a) => ({ ...host(a.id), state: "passing", assignee: null, checked_at: a.last_seen_at ?? null, triage_version: null, evidence: [] })),
    ].sort((a, b) => (a.hostname === null ? 1 : b.hostname === null ? -1 : byteOrder(a.hostname, b.hostname)) || byteOrder(a.agent_id, b.agent_id));
    const segments = { all: rows.length, failing: p.failing.length, passing: p.passing.length };
    const chosen = rows.filter((r) => segment === "all" || (segment === "passing") === (r.state === "passing"));
    const body: CheckHostsPage = { rows: chosen.slice(offset, offset + limit), total: chosen.length, segments };
    return json(body);
  });
}
