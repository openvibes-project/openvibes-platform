// An in-browser implementation of the console's /api/v1 over synthetic data,
// for the GitHub Pages preview, `?demo=1` and tests. It follows the wire
// contracts (types from the OpenAPI client) and the permission model, and
// keeps mutations in memory for the life of the page.
import type {
  Agent, AssistantSegment, AuditEvent, Capability, FindingGroup, GroupEndpoint, Permission,
  Severity, TriageCounts, Vulnerability,
} from "../api/types";
import { createCaseStore, seedCases } from "./cases";
import { createDashboardStore } from "./dashboards";
import { buildDemoData } from "./data";

import type { Persona } from "./personas";
import { splitRef } from "../panels/cases";
import { allowedStates, noteRequired } from "../panels/triage";

export { personas, type Persona } from "./personas";

type Params = Record<string, string>;
type Handler = (params: Params, query: URLSearchParams, body: Record<string, unknown>, headers: Record<string, string>) => Response | Promise<Response>;
type Route = { method: string; pattern: RegExp; keys: string[]; permission: Permission | null; handler: Handler };

const json = (value: unknown, status = 200) =>
  new Response(JSON.stringify(value), { status, headers: { "content-type": "application/json" } });
const problem = (status: number, code: string, title: string) =>
  new Response(JSON.stringify({ status, code, title, request_id: `demo-${Date.now().toString(36)}` }), {
    status, headers: { "content-type": "application/problem+json" },
  });

function page<T>(items: readonly T[], query: URLSearchParams, fallback = 50) {
  const limit = Number(query.get("limit") ?? fallback) || fallback;
  const offset = Number(atob(query.get("cursor") ?? "") || 0) || 0;
  const slice = items.slice(offset, offset + limit);
  const next = offset + limit < items.length ? btoa(String(offset + limit)) : null;
  return { items: slice, next_cursor: next };
}

/** The real API's `MAX_PAGE_SIZE` (crates/openvibes-console/src/api.rs). */
export const MAX_PAGE = 100;

const severityRank: Record<string, number> = { critical: 0, important: 1, high: 1, moderate: 2, medium: 2, low: 3, unrated: 4 };

/** Browser storage for demo state, when there is a browser; never required. */
function browserPersistence(key: string) {
  if (typeof localStorage === "undefined") return undefined;
  return {
    load: () => { try { return JSON.parse(localStorage.getItem(key) ?? "null") as unknown; } catch { return undefined; } },
    save: (state: unknown) => { try { localStorage.setItem(key, JSON.stringify(state)); } catch { /* the demo still works without storage */ } },
  };
}

export function createDemoServer({ persona = "admin" as Persona, now = Date.now() } = {}) {
  const data = buildDemoData(now);
  const iso = (ms = Date.now()) => new Date(ms).toISOString();
  const role = persona === "scoped_operator" ? "operator" : persona;
  const permissions = (data.access.roles.find((r) => r.role_id === role)?.permissions ?? []) as Permission[];
  const scoped = persona === "scoped_operator";
  const capabilities: Capability[] = permissions.map((permission) => ({
    permission,
    scope: scoped && !["tokens.read", "tokens.create", "tokens.revoke", "rules.upload"].includes(permission)
      ? { kind: "asset_groups", asset_group_ids: ["grp-prod"] }
      : { kind: "global" },
  }));
  const actor = { admin: "admin", analyst: "sam", operator: "ola", scoped_operator: "ola", viewer: "vic" }[persona];

  const visible = (agentId: string) =>
    !scoped || (data.tags.get(agentId) ?? []).some((tag) => tag.key === "env" && tag.value === "prod");
  const agentById = (id: string) => data.agents.find((agent) => agent.id === id && visible(id));
  const audit = (action: string, target: string, targetKind: string) => {
    const event: AuditEvent = {
      id: String(Number(data.audit[0]?.id ?? 0) + 1), action, actor, actor_id: `u-${actor}`, actor_kind: "user",
      at: iso(), authentication_method: "local_password", result: "success", reason_code: null,
      request_id: `demo-${Date.now().toString(36)}`, target, target_id: target, target_kind: targetKind,
    };
    data.audit.unshift(event);
  };
  const triageKey = (agentId: string, ruleSetId: string, ruleId: string) => `${agentId}|${ruleSetId}|${ruleId}`;
  const findings = () => data.findings.filter((finding) => visible(finding.agent_id));
  const vulnerabilities = () => data.vulnerabilities.filter((item) => visible(item.agent_id) && item.fixed_at == null);

  const groups = (): FindingGroup[] => {
    const byRule = new Map<string, FindingGroup>();
    for (const finding of findings()) {
      const key = `${finding.rule_set_id}/${finding.rule_id}`;
      const counts: TriageCounts = byRule.get(key)?.triage_counts ?? { open: 0, investigating: 0, mitigated: 0, accepted_risk: 0, false_positive: 0 };
      const state = data.triage.get(triageKey(finding.agent_id, finding.rule_set_id, finding.rule_id))?.state ?? "open";
      counts[state as keyof TriageCounts] += 1;
      const existing = byRule.get(key);
      byRule.set(key, {
        rule_set_id: finding.rule_set_id, rule_id: finding.rule_id, severity: finding.severity,
        latest_message: finding.message, rule_versions: [finding.rule_version], older_endpoint_count: 0,
        endpoint_count: (existing?.endpoint_count ?? 0) + 1, triage_counts: counts,
        first_observed_at: existing && existing.first_observed_at < finding.first_observed_at ? existing.first_observed_at : finding.first_observed_at,
        last_observed_at: existing && existing.last_observed_at > finding.last_observed_at ? existing.last_observed_at : finding.last_observed_at,
      });
    }
    return [...byRule.values()].sort((a, b) =>
      (severityRank[a.severity] ?? 9) - (severityRank[b.severity] ?? 9) || b.triage_counts.open - a.triage_counts.open);
  };

  const endpoints = (ruleSetId: string, ruleId: string): GroupEndpoint[] => findings()
    .filter((finding) => finding.rule_set_id === ruleSetId && finding.rule_id === ruleId)
    .map((finding) => {
      const triage = data.triage.get(triageKey(finding.agent_id, ruleSetId, ruleId));
      return {
        agent_id: finding.agent_id, hostname: finding.hostname ?? null, authenticated: finding.authenticated,
        origin: finding.origin, first_observed_at: finding.first_observed_at, last_observed_at: finding.last_observed_at,
        outside_window: false, rule_version: finding.rule_version,
        triage_state: triage?.state ?? "open", triage_version: triage?.version ?? 0,
        assigned_to: triage?.assigned_to ?? null, accepted_until: triage?.accepted_until ?? null,
        // Demo: a mitigated host's agent later reported the match ended (P13).
        ended_at: triage?.state === "mitigated" ? finding.last_observed_at : null, end_approximate: false,
      };
    });

  const setTriage = (agentId: string, ruleSetId: string, ruleId: string, body: Record<string, unknown>) => {
    const key = triageKey(agentId, ruleSetId, ruleId);
    const current = data.triage.get(key);
    const next = {
      state: String(body.state ?? "open"), version: (current?.version ?? 0) + 1, rule_version: 3,
      note: (body.note as string | null | undefined) ?? null, assigned_to: (body.assigned_to as string | null | undefined) ?? null,
      accepted_until: (body.accepted_until as string | null | undefined) ?? null,
    };
    data.triage.set(key, next);
    return next;
  };

  // The server's rules: an expiry in the future exactly when the risk is
  // accepted, and an assignee who is an analyst or admin.
  const triageProblem = (body: Record<string, unknown>) => {
    const until = typeof body.accepted_until === "string" ? Date.parse(body.accepted_until) : null;
    if ((body.state === "accepted_risk") !== (until !== null) || (until !== null && !(until > Date.now()))) {
      return problem(400, "invalid_triage", "Triage state, note, expiry, or selection is invalid");
    }
    if (typeof body.assigned_to === "string" && !data.access.bindings.some((b) => b.username === body.assigned_to && ["analyst", "admin"].includes(b.role_id))) {
      return problem(400, "invalid_assignee", "Assignee must be an enabled analyst or admin");
    }
    return null;
  };

  const assistant = (question: string): AssistantSegment[] => {
    const q = question.toLowerCase();
    const text = (value: string): AssistantSegment => ({ kind: "text", text: value });
    const cite = (target_kind: string, id: string): AssistantSegment => ({ kind: "citation", target_kind, id, path: "" });
    if (q.includes("stale") || q.includes("offline") || q.includes("contact")) {
      const stale = data.agents.filter((agent) => agent.status === "stale" && visible(agent.id)).slice(0, 4);
      return [text(`${stale.length} of the hosts I looked at have not checked in for over a day. The longest silent ones are `),
        ...stale.flatMap((agent, index) => [cite("agent", agent.id), text(index === stale.length - 1 ? ". Check that the agent service runs and that the host can reach the platform on port 443." : ", ")])];
    }
    if (q.includes("exploit") || q.includes("kev") || q.includes("vulnerab") || q.includes("patch")) {
      const hot = [...new Map(vulnerabilities().filter((v) => v.exploited).map((v) => [v.advisory_id, v])).values()].slice(0, 3);
      return [text("These advisories fix vulnerabilities known to be exploited, so patch them first: "),
        ...hot.flatMap((item, index) => [cite("advisory", item.advisory_id), text(index === hot.length - 1 ? `. Together they affect ${vulnerabilities().filter((v) => v.exploited).length} host findings.` : ", ")])];
    }
    const context = /agent-\d{5}/.exec(question)?.[0];
    if (context !== undefined) {
      const agent = agentById(context);
      const open = findings().filter((finding) => finding.agent_id === context).sort((a, b) => (severityRank[a.severity] ?? 9) - (severityRank[b.severity] ?? 9));
      const vulns = vulnerabilities().filter((item) => item.agent_id === context);
      return [text("For "), cite("agent", context), text(` (${agent?.status ?? "unknown"}): ${open.length} findings and ${vulns.length} open vulnerabilities. `),
        ...(open[0] ? [text("The most serious finding is "), cite("finding", `${open[0].rule_set_id}/${open[0].rule_id}`), text(` — ${open[0].message.toLowerCase()}.`)] : [text("No findings right now.")])];
    }
    const top = groups()[0];
    return [text("Start with the most severe open finding: "), ...(top ? [cite("finding", `${top.rule_set_id}/${top.rule_id}`), text(` (${top.latest_message.toLowerCase()}, ${top.triage_counts.open} hosts open).`)] : []),
      text(" This is the demo assistant; it answers from synthetic data only.")];
  };

  const routes: Route[] = [];
  const route = (method: string, path: string, permission: Permission | null, handler: Handler) => {
    const keys: string[] = [];
    const pattern = new RegExp(`^${path.replace(/\{(\w+)\}/g, (_, key: string) => { keys.push(key); return "([^/]+)"; })}$`);
    routes.push({ method, pattern, keys, permission, handler });
  };

  route("GET", "/api/v1/session", null, () => json({
    principal: { id: `u-${actor}`, display_name: data.access.users.find((u) => u.username === actor)?.display_name ?? actor, username: actor },
    capabilities, csrf_token: "demo-csrf", authentication_level: "single_factor", authentication_method: "local_password",
    idle_expires_at: iso(Date.now() + 30 * 60_000), absolute_expires_at: iso(Date.now() + 12 * 3_600_000),
    password_must_change: false,
  }));
  // The demo has no real passwords: any change of at least 15 new characters succeeds.
  route("POST", "/api/v1/session/password", null, (_, __, body) => {
    const next = String(body.new_password ?? "");
    if (next.length < 15) return problem(400, "weak_password", "Use at least 15 characters for the new password");
    if (next === String(body.current_password ?? "")) return problem(400, "password_unchanged", "Choose a password different from the current one");
    audit("auth.password.changed", `u-${actor}`, "user");
    return new Response(null, { status: 204 });
  });
  route("GET", "/api/v1/agents", "agents.read", (_, query) => {
    const state = query.get("state");
    const items = data.agents.filter((agent) => visible(agent.id) && (state === null || agent.status === state));
    return json({ ...page(items, query), generated_at: iso() });
  });
  route("GET", "/api/v1/agents/summary", "agents.read", () => {
    const items = data.agents.filter((agent) => visible(agent.id));
    const count = (status: Agent["status"]) => items.filter((agent) => agent.status === status).length;
    // The demo fleet's newest agents run the demo platform's version.
    return json({ total: items.length, active: count("active"), stale: count("stale"), revoked: count("revoked"), imported: count("imported"), platform_version: "0.4.2" });
  });
  route("GET", "/api/v1/agents/{id}", "agents.read", ({ id = "" }) => {
    const agent = agentById(id);
    return agent ? json({ ...agent, certificates: data.certificates.get(id) ?? [] }) : problem(404, "not_found", "Agent not found");
  });
  route("GET", "/api/v1/agents/{id}/certificates", "agents.read", ({ id = "" }, query) =>
    json({ ...page(data.certificates.get(id) ?? [], query), generated_at: iso() }));
  route("POST", "/api/v1/agents/{id}/revoke", "agents.revoke", ({ id = "" }, _, body) => {
    const agent = agentById(id);
    if (!agent) return problem(404, "not_found", "Agent not found");
    if (String(body.reason ?? "").trim() === "") return problem(422, "invalid_reason", "A reason is required");
    agent.status = "revoked";
    agent.revoked_at = iso();
    audit("agent.revoke", id, "agent");
    return json(agent);
  });
  route("POST", "/api/v1/agents/{id}/tags/preview", "asset_groups.manage", ({ id = "" }, _, body) => json({
    current: data.tags.get(id) ?? [], proposed: body.tags ?? [], preview_token: `preview-${id}`,
    gained_groups: [], lost_groups: [], gained_bindings: [], lost_bindings: [],
  }));
  route("PUT", "/api/v1/agents/{id}/tags", "asset_groups.manage", ({ id = "" }, _, body) => {
    data.tags.set(id, (body.tags ?? []) as { key: string; value: string }[]);
    audit("agent.tags.update", id, "agent");
    return json({ tags: data.tags.get(id) });
  });

  route("GET", "/api/v1/findings/summary", "findings.read", () => {
    const open = findings().filter((f) => (data.triage.get(triageKey(f.agent_id, f.rule_set_id, f.rule_id))?.state ?? "open") === "open");
    const count = (severity: Severity) => open.filter((f) => f.severity === severity).length;
    return json({ total: open.length, impacted_agents: new Set(open.map((f) => f.agent_id)).size, critical: count("critical"), high: count("high"), medium: count("medium"), low: count("low") });
  });
  route("GET", "/api/v1/findings/groups", "findings.read", (_, query) =>
    json({ ...page(groups(), query), generated_at: iso(), since: iso(Date.now() - 30 * 86_400_000) }));
  route("GET", "/api/v1/findings/groups/{set}/{rule}/endpoints", "findings.read", ({ set = "", rule = "" }, query) =>
    json({ ...page(endpoints(set, rule), query), generated_at: iso(), since: iso(Date.now() - 30 * 86_400_000) }));
  route("POST", "/api/v1/findings/groups/{set}/{rule}/triage", "findings.triage", ({ set = "", rule = "" }, _, body) => {
    const changes = (body.changes ?? []) as { agent_id: string; version: number }[];
    // The server's order: fields, then versions, then the workflow.
    const invalid = triageProblem(body) ?? (noteRequired.has(String(body.state)) && typeof body.note !== "string"
      ? problem(400, "invalid_triage", "Triage state, note, expiry, or selection is invalid") : null);
    if (invalid) return invalid;
    for (const change of changes) {
      const current = data.triage.get(triageKey(change.agent_id, set, rule))?.version ?? 0;
      if (current !== change.version) return problem(412, "stale_triage", "One or more selected endpoints changed; reload before saving");
    }
    const from = changes.map((change) => data.triage.get(triageKey(change.agent_id, set, rule))?.state ?? "open");
    if (!allowedStates(from).includes(String(body.state))) return problem(409, "invalid_transition", "Requested triage transition is not allowed");
    const updated = changes.map((change) => [change.agent_id, setTriage(change.agent_id, set, rule, body)]);
    audit("finding.triage", `${set}/${rule}`, "finding");
    return json({ updated });
  });
  route("GET", "/api/v1/findings/history", "findings.read", (_, query) => {
    const since = Date.parse(query.get("since") ?? "");
    if (Number.isNaN(since)) return problem(400, "invalid_query", "since is required");
    const day = 86_400_000;
    const items = findings().filter((f) => (query.get("agent_id") === null || f.agent_id === query.get("agent_id")) &&
      (query.get("rule_set_id") === null || f.rule_set_id === query.get("rule_set_id")) && (query.get("rule_id") === null || f.rule_id === query.get("rule_id")))
      .flatMap((f) => {
        // A mitigated finding stopped being observed a few days ago; the rest are still seen daily.
        const state = data.triage.get(triageKey(f.agent_id, f.rule_set_id, f.rule_id))?.state;
        const last = state === "mitigated" ? Date.parse(f.last_observed_at) - 3 * day : Date.parse(f.last_observed_at);
        const out = [];
        for (let at = last; at >= Math.max(since, Date.parse(f.first_observed_at)); at -= day) {
          out.push({ ...f, id: `${f.id}-${Math.floor(at / day)}`, observed_at: iso(at), observed_day: iso(at).slice(0, 10) });
        }
        return out;
      }).sort((a, b) => b.observed_at.localeCompare(a.observed_at));
    return json({ ...page(items, query), generated_at: iso() });
  });
  route("GET", "/api/v1/findings/latest", "findings.read", (_, query) => {
    const severity = query.get("severity");
    const agent = query.get("agent_id");
    const items = findings().filter((f) => (severity === null || f.severity === severity) && (agent === null || f.agent_id === agent));
    return json({ ...page(items, query), generated_at: iso() });
  });
  route("GET", "/api/v1/findings/latest/{agent}/{set}/{rule}/triage", "findings.read", ({ agent = "", set = "", rule = "" }) =>
    json(data.triage.get(triageKey(agent, set, rule)) ?? { state: "open", version: 0, rule_version: 3, note: null, assigned_to: null, accepted_until: null }));
  route("PUT", "/api/v1/findings/latest/{agent}/{set}/{rule}/triage", "findings.triage", ({ agent = "", set = "", rule = "" }, _, body) => {
    const invalid = triageProblem(body);
    if (invalid) return invalid;
    audit("finding.triage", `${set}/${rule}`, "finding");
    return json(setTriage(agent, set, rule, body));
  });

  // Threat alarms (P14), with the server's rules: scoped like findings,
  // the findings workflow for triage, program/command suppressions only
  // for a global caller, applied to new alarms only.
  const alarmList = () => data.alarms.filter((alarm) => visible(alarm.agent_id));
  const summary = (alarm: (typeof data.alarms)[number]) => ({
    id: alarm.id, agent_id: alarm.agent_id, hostname: alarm.hostname, rule_set_id: alarm.rule_set_id, rule_id: alarm.rule_id,
    severity: alarm.severity, message: alarm.message, exe: alarm.exe, parent_exe: alarm.parent_exe, count: alarm.count,
    first_seen: alarm.first_seen, last_seen: alarm.last_seen, state: alarm.state, suppressed_by: alarm.suppressed_by,
  });
  route("GET", "/api/v1/alarms", "alarms.read", (_, query) => {
    const suppressed = query.get("suppressed") === "true";
    const state = query.get("state");
    const severity = query.get("severity");
    const items = alarmList().filter((alarm) => (suppressed || !alarm.suppressed_by)
        && (!state || alarm.state === state || (state === "active" && ["open", "investigating"].includes(alarm.state)))
        && (!severity || alarm.severity === severity))
      .sort((a, b) => b.last_seen.localeCompare(a.last_seen)).map(summary);
    return json(page(items, query));
  });
  route("GET", "/api/v1/alarms/{id}", "alarms.read", ({ id = "" }) => {
    const alarm = alarmList().find((candidate) => candidate.id === id);
    return alarm ? json(alarm) : problem(404, "alarm_not_found", "Alarm not found");
  });
  route("PUT", "/api/v1/alarms/{id}/triage", "alarms.triage", ({ id = "" }, _, body, headers) => {
    const alarm = alarmList().find((candidate) => candidate.id === id);
    if (!alarm) return problem(404, "alarm_not_found", "Alarm not found");
    if (headers["if-match"] !== `"${alarm.triage.version}"`) return problem(412, "stale_triage", "Triage changed; reload before saving");
    const state = String(body.state ?? "");
    if (!allowedStates([alarm.state]).includes(state)) return problem(409, "invalid_transition", "Requested triage transition is not allowed");
    const note = typeof body.note === "string" && body.note.trim() ? body.note.trim() : null;
    if (noteRequired.has(state) && !note) return problem(400, "invalid_triage", "Triage state, note, or expiry is invalid");
    alarm.state = state;
    alarm.triage = { state, assigned_to: typeof body.assigned_to === "string" ? body.assigned_to : null, note,
      accepted_until: typeof body.accepted_until === "string" ? body.accepted_until : null,
      version: alarm.triage.version + 1, updated_at: iso(), updated_by: actor };
    audit("alarm.triage.changed", id, "alarm");
    return json(alarm.triage);
  });
  const globalSuppress = capabilities.some((c) => c.permission === "alarms.suppress" && c.scope.kind === "global");
  const suppressionVisible = (s: (typeof data.alarmSuppressions)[number]) => globalSuppress || (s.scope === "host" && !!s.agent_id && visible(s.agent_id));
  route("GET", "/api/v1/alarm-suppressions", "alarms.read", () => json({ items: data.alarmSuppressions.filter(suppressionVisible) }));
  route("POST", "/api/v1/alarm-suppressions", "alarms.suppress", (_, __, body) => {
    const scope = String(body.scope ?? "");
    const note = typeof body.note === "string" ? body.note.trim() : "";
    if (!["host", "program", "command"].includes(scope) || !note) return problem(400, "invalid_suppression", "Scope must be host, program or command, with a note");
    if (scope !== "host" && !globalSuppress) return problem(403, "global_scope_required", "Only a user with access to every host may suppress on every host");
    const alarm = alarmList().find((candidate) => candidate.id === String(body.alarm_id ?? ""));
    if (!alarm) return problem(404, "alarm_not_found", "Alarm or suppression not found");
    const created = {
      id: String(data.alarmSuppressions.length + 1), rule_set_id: alarm.rule_set_id, rule_id: alarm.rule_id, scope,
      agent_id: scope === "host" ? alarm.agent_id : null, exe: scope === "host" ? null : alarm.exe,
      args_sha256: scope === "command" ? "demo" : null, note, created_by: actor, created_at: iso(),
    };
    data.alarmSuppressions.unshift(created);
    audit("alarm.suppression.created", created.id, "alarm_suppression");
    return json(created, 201);
  });
  route("DELETE", "/api/v1/alarm-suppressions/{id}", "alarms.suppress", ({ id = "" }) => {
    const index = data.alarmSuppressions.findIndex((s) => s.id === id && suppressionVisible(s));
    const [removed] = index < 0 ? [] : data.alarmSuppressions.splice(index, 1);
    if (!removed) return problem(404, "alarm_not_found", "Alarm or suppression not found");
    audit("alarm.suppression.removed", id, "alarm_suppression");
    return json(removed);
  });

  // Assets v1: each host's packages. A base set every host has, a few by
  // role (from the host name), plus the packages its open vulnerabilities
  // name at their installed versions (fixable when the advisory has a fix).
  const BASE: [string, string][] = [["bash", "5.2.37-1"], ["coreutils", "9.5-11"], ["glibc", "2.40-25"], ["openssl", "3.2.4-3"], ["openssh-server", "9.8p1-3"], ["systemd", "256.17-1"], ["curl", "8.9.1-5"], ["sudo", "1.9.15-6"]];
  const BY_ROLE: Record<string, [string, string][]> = {
    web: [["nginx", "1.26.3-1"]], proxy: [["nginx", "1.26.3-1"], ["haproxy", "3.0.5-1"]], api: [["nodejs", "20.18.1-1"]],
    db: [["postgresql-server", "16.6-1"]], cache: [["redis", "7.2.7-1"]], mail: [["postfix", "3.9.1-2"]], build: [["git-core", "2.47.1-1"], ["gcc", "14.2.1-3"]],
  };
  type DemoPackage = { manager: string; name: string; epoch: number; version: string; release: string; arch: string; fixable_vulnerable: boolean };
  const hostPackages = (agentId: string): DemoPackage[] => {
    const agent = data.agents.find((a) => a.id === agentId);
    const role = (agent?.hostname ?? "").split("-")[0] ?? "";
    const split = (full: string) => { const [version = full, release = ""] = full.split(/-(?=[^-]*$)/); return { version, release }; };
    const byName = new Map<string, DemoPackage>();
    for (const [name, full] of [...BASE, ...(BY_ROLE[role] ?? [])]) {
      byName.set(name, { manager: "rpm", name, epoch: 0, ...split(full), arch: "x86_64", fixable_vulnerable: false });
    }
    for (const v of data.vulnerabilities.filter((item) => item.agent_id === agentId && item.fixed_at == null)) {
      for (const pkg of v.packages as { name: string; installed: string; fixed?: string | null }[]) {
        const fixable = pkg.fixed != null || byName.get(pkg.name)?.fixable_vulnerable === true;
        byName.set(pkg.name, { manager: "rpm", name: pkg.name, epoch: 0, ...split(pkg.installed), arch: "x86_64", fixable_vulnerable: fixable });
      }
    }
    return [...byName.values()].sort((a, b) => a.name.localeCompare(b.name));
  };
  const hosts = () => data.agents.filter((agent) => visible(agent.id) && agent.status !== "revoked");
  route("GET", "/api/v1/agents/{id}/packages", "agents.read", ({ id = "" }, query) => {
    if (!agentById(id)) return problem(404, "not_found", "Agent not found");
    const q = (query.get("q") ?? "").toLowerCase();
    const fixable = query.get("fixable") === "true";
    return json(page(hostPackages(id).filter((p) => p.name.toLowerCase().includes(q) && (!fixable || p.fixable_vulnerable)), query));
  });
  const fleet = () => {
    const rows = new Map<string, { manager: string; name: string; hosts: Set<string>; versions: Set<string>; fixable: Set<string> }>();
    for (const agent of hosts()) {
      for (const p of hostPackages(agent.id)) {
        const key = `${p.manager}/${p.name}`;
        const row = rows.get(key) ?? { manager: p.manager, name: p.name, hosts: new Set(), versions: new Set(), fixable: new Set() };
        row.hosts.add(agent.id);
        row.versions.add(`${p.version}-${p.release}`);
        if (p.fixable_vulnerable) row.fixable.add(agent.id);
        rows.set(key, row);
      }
    }
    return [...rows.values()].sort((a, b) => a.name.localeCompare(b.name));
  };
  // Assets v2: open ports and running services, from the host's role.
  const PORTS: Record<string, [number, string, string][]> = {
    web: [[443, "nginx.service", "nginx"], [80, "nginx.service", "nginx"]], proxy: [[443, "haproxy.service", "haproxy"]], api: [[8080, "api.service", "node"]],
    db: [[5432, "postgresql.service", "postgres"]], cache: [[6379, "redis.service", "redis-server"]], mail: [[25, "postfix.service", "master"]],
  };
  const hostServices = (agentId: string) => {
    const role = (data.agents.find((a) => a.id === agentId)?.hostname ?? "").split("-")[0] ?? "";
    const own = PORTS[role] ?? [];
    const listeners = [
      ...own.map(([port, service, program]) => ({ protocol: "tcp", address: "0.0.0.0", port, exposed: true, service, program })),
      { protocol: "tcp", address: "0.0.0.0", port: 22, exposed: true, service: "sshd.service", program: "sshd" },
      { protocol: "udp", address: "127.0.0.53", port: 53, exposed: false, service: "systemd-resolved.service", program: "systemd-resolve" },
    ].sort((a, b) => Number(b.exposed) - Number(a.exposed) || a.port - b.port);
    const units = new Map(listeners.map((l) => [l.service, l.program]));
    units.set("chronyd.service", "chronyd");
    const services = [...units].map(([unit, program]) => ({ unit, programs: [program], processes: unit === "nginx.service" ? 3 : 1, run_as: "root" })).sort((a, b) => a.unit.localeCompare(b.unit));
    // The mail hosts' last report was refused (over 512 KiB): the tab says so.
    const refused = role === "mail" ? { refused: "too_large", refused_at: new Date(Date.now() - 5 * 60_000).toISOString() } : { refused: null, refused_at: null };
    // The build hosts run more than a report carries: their lists were cut.
    return { reported_at: new Date(Date.now() - 20 * 60_000).toISOString(), owners: "partial", truncated: role === "build", ...refused, listeners, services };
  };
  route("GET", "/api/v1/agents/{id}/services", "agents.read", ({ id = "" }) => {
    if (!agentById(id)) return problem(404, "agent_not_found", "Agent not found");
    return json(hostServices(id));
  });
  route("GET", "/api/v1/ports", "agents.read", (_, query) => {
    const rows = new Map<string, { protocol: string; port: number; hosts: number; exposed_hosts: number; services: Set<string> }>();
    for (const agent of hosts()) {
      for (const l of hostServices(agent.id).listeners) {
        const row = rows.get(`${l.protocol}/${l.port}`) ?? { protocol: l.protocol, port: l.port, hosts: 0, exposed_hosts: 0, services: new Set() };
        row.hosts += 1;
        if (l.exposed) row.exposed_hosts += 1;
        row.services.add(l.service);
        rows.set(`${l.protocol}/${l.port}`, row);
      }
    }
    const exposed = query.get("exposed") === "true";
    return json([...rows.values()].filter((r) => !exposed || r.exposed_hosts > 0).sort((a, b) => a.port - b.port || a.protocol.localeCompare(b.protocol)).map((r) => ({ ...r, services: [...r.services].sort((a, b) => a.localeCompare(b)).slice(0, 8) })));
  });
  route("GET", "/api/v1/services", "agents.read", () => {
    const counts = new Map<string, number>();
    for (const agent of hosts()) for (const s of hostServices(agent.id).services) counts.set(s.unit, (counts.get(s.unit) ?? 0) + 1);
    return json([...counts].sort(([a], [b]) => a.localeCompare(b)).map(([unit, hosts]) => ({ unit, hosts })));
  });
  route("GET", "/api/v1/ports/{protocol}/{port}", "agents.read", ({ protocol = "", port = "" }, query) => {
    const found = hosts().flatMap((agent) => hostServices(agent.id).listeners
      .filter((l) => l.protocol === protocol && String(l.port) === port)
      .map((l) => ({ agent_id: agent.id, hostname: agent.hostname ?? null, address: l.address, exposed: l.exposed, service: l.service, program: l.program, last_seen_at: agent.last_seen_at ?? null })));
    if (found.length === 0) return problem(404, "port_not_found", "No host listens on this port");
    const { items, next_cursor } = page(found.sort((a, b) => (a.hostname ?? "").localeCompare(b.hostname ?? "")), query);
    return json({ protocol, port: Number(port), hosts: items, next_cursor });
  });
  route("GET", "/api/v1/services/{unit}", "agents.read", ({ unit = "" }, query) => {
    const name = decodeURIComponent(unit);
    const found = hosts().flatMap((agent) => hostServices(agent.id).services
      .filter((s) => s.unit === name)
      .map((s) => ({ agent_id: agent.id, hostname: agent.hostname ?? null, programs: s.programs, processes: s.processes, run_as: s.run_as, last_seen_at: agent.last_seen_at ?? null })));
    if (found.length === 0) return problem(404, "service_not_found", "No host runs this service");
    const { items, next_cursor } = page(found.sort((a, b) => (a.hostname ?? "").localeCompare(b.hostname ?? "")), query);
    return json({ unit: name, hosts: items, next_cursor });
  });
  route("GET", "/api/v1/software", "agents.read", (_, query) => {
    const q = (query.get("q") ?? "").toLowerCase();
    const fixable = query.get("fixable") === "true";
    const items = fleet().filter((row) => row.name.toLowerCase().includes(q) && (!fixable || row.fixable.size > 0))
      .map((row) => ({ manager: row.manager, name: row.name, hosts: row.hosts.size, versions: row.versions.size, fixable_vulnerable_hosts: row.fixable.size }));
    return json(page(items, query));
  });
  route("GET", "/api/v1/software/{manager}/{name}", "agents.read", ({ manager = "", name = "" }, query) => {
    const found = hosts().flatMap((agent) => hostPackages(agent.id).filter((p) => p.manager === manager && p.name === decodeURIComponent(name)).map((p) => ({ agent, p })));
    if (found.length === 0) return problem(404, "not_found", "No visible host has it");
    const versions = new Map<string, { epoch: number; version: string; release: string; arch: string; hosts: number; fixable_vulnerable_hosts: number }>();
    for (const { p } of found) {
      const key = `${p.version}-${p.release}.${p.arch}`;
      const v = versions.get(key) ?? { epoch: p.epoch, version: p.version, release: p.release, arch: p.arch, hosts: 0, fixable_vulnerable_hosts: 0 };
      v.hosts += 1;
      if (p.fixable_vulnerable) v.fixable_vulnerable_hosts += 1;
      versions.set(key, v);
    }
    const { items, next_cursor } = page(found.map(({ agent, p }) => ({ agent_id: agent.id, hostname: agent.hostname ?? null, version: `${p.version}-${p.release}`, arch: p.arch, last_seen_at: agent.last_seen_at ?? null, fixable_vulnerable: p.fixable_vulnerable })), query);
    return json({ manager, name: decodeURIComponent(name), versions: [...versions.values()], hosts: items, next_cursor });
  });

  route("GET", "/api/v1/vulnerabilities", "vulnerabilities.read", (_, query) => {
    const flag = (name: string) => query.get(name) === "true";
    const items = vulnerabilities().filter((item: Vulnerability) =>
      (query.get("host") === null || item.agent_id === query.get("host")) &&
      (query.get("advisory") === null || item.advisory_id === query.get("advisory")) &&
      (query.get("severity") === null || item.severity === query.get("severity")) &&
      (query.get("cve") === null || item.cves.includes(query.get("cve") ?? "")) &&
      (!flag("exploited") || item.exploited) && (!flag("reboot_needed") || item.reboot_needed))
      .sort((a, b) => Number(b.exploited) - Number(a.exploited) || (severityRank[a.severity] ?? 9) - (severityRank[b.severity] ?? 9) || (b.epss ?? 0) - (a.epss ?? 0));
    return json({ items: items.slice(0, 1000), more_available: items.length > 1000, generated_at: iso() });
  });
  route("GET", "/api/v1/vulnerabilities/summary", "vulnerabilities.read", () => {
    const items = vulnerabilities();
    const hosts = new Map<string, { agent_id: string; hostname: string | null; open: number; serious: number }>();
    for (const item of items) {
      const host = hosts.get(item.agent_id) ?? { agent_id: item.agent_id, hostname: item.hostname ?? null, open: 0, serious: 0 };
      host.open += 1;
      if (item.severity === "critical" || item.severity === "important") host.serious += 1;
      hosts.set(item.agent_id, host);
    }
    return json({
      by_severity: (["critical", "important", "moderate", "low", "unrated"] as const).map((severity) => ({ severity, count: items.filter((i) => i.severity === severity).length })),
      exploited: items.filter((i) => i.exploited).length, hosts: hosts.size,
      no_fix: items.filter((i) => Array.isArray(i.packages) && (i.packages as { fixed: unknown }[]).every((p) => p.fixed == null)).length,
      reboot_hosts: new Set(items.filter((i) => i.reboot_needed).map((i) => i.agent_id)).size,
      top_hosts: [...hosts.values()].sort((a, b) => b.serious - a.serious || b.open - a.open).slice(0, 8),
      feed_last_imported_at: iso(Date.now() - 6 * 3600_000),
    });
  });
  route("GET", "/api/v1/vulnerabilities/advisories/{id}", "vulnerabilities.read", ({ id = "" }) => {
    const advisory = data.advisories.find((item) => item.id === decodeURIComponent(id));
    if (!advisory) return problem(404, "not_found", "Advisory not found");
    const items = vulnerabilities().filter((item) => item.advisory_id === advisory.id);
    return json({ cves: advisory.cves, hosts: { items, more_available: false, generated_at: iso() } });
  });

  route("GET", "/api/v1/audit-events", "audit.read", (_, query) => {
    const since = Date.parse(query.get("since") ?? "");
    if (Number.isNaN(since) || since > Date.now()) return problem(400, "invalid_query", "Audit event query parameters are invalid");
    return json(page(data.audit.filter((event) => Date.parse(event.at) >= since), query));
  });
  route("GET", "/api/v1/audit-retention", "audit.read", () => json(data.retention));
  route("PUT", "/api/v1/audit-retention", "audit.retention.manage", (_, __, body, headers) => {
    const match = headers["if-match"];
    if (match === undefined) return problem(428, "precondition_required", "If-Match is required");
    if (match !== `"${data.retention.version}"`) return problem(412, "stale_policy", "The retention policy changed; reload and try again");
    const days = Number(body.retention_days);
    if (!Number.isInteger(days) || days < 1 || days > 36_500) return problem(422, "invalid_retention", "Retention must be between 1 and 36,500 days");
    data.retention = { ...data.retention, retention_days: days, version: data.retention.version + 1, updated_at: iso(), updated_by: actor };
    audit("audit.retention.update", "audit", "retention");
    return json(data.retention);
  });
  route("GET", "/api/v1/access-control", "rbac.read", () => json(data.access));
  route("POST", "/api/v1/access-control/users", "rbac.manage", (_, __, body) => {
    const username = String(body.username ?? "").toLowerCase();
    const displayName = String(body.display_name ?? "").trim();
    if (!/^[a-z0-9._@+-]{1,64}$/.test(username) || displayName === "") return problem(400, "invalid_user", "Use 1 to 64 letters, digits or ._@+- for the username, and a name");
    if (data.access.users.some((u) => u.username === username)) return problem(409, "user_conflict", "A user with this username already exists");
    const user = { user_id: `u-${Date.now().toString(36)}`, username, display_name: displayName };
    data.access.users.push(user);
    data.access.bindings.push({ binding_id: `b-${Date.now().toString(36)}`, user_id: user.user_id, username, display_name: displayName, role_id: String(body.role_id ?? "viewer"), asset_group_id: null, asset_group_name: null, created_at: iso(), created_by: actor });
    audit("user.created", user.user_id, "user");
    return json({ ...user, role_id: String(body.role_id ?? "viewer"), one_time_password: "demo1-pass2-word3-onlyx" }, 201);
  });
  route("POST", "/api/v1/access-control/bindings", "rbac.manage", (_, __, body) => {
    const user = data.access.users.find((u) => u.user_id === body.user_id);
    if (!user) return problem(422, "invalid_user", "Choose a user");
    const group = data.access.asset_groups.find((g) => g.asset_group_id === body.asset_group_id);
    const binding = { binding_id: `b-${Date.now().toString(36)}`, user_id: user.user_id, username: user.username, display_name: user.display_name, role_id: String(body.role_id), asset_group_id: group?.asset_group_id ?? null, asset_group_name: group?.name ?? null, created_at: iso(), created_by: actor };
    data.access.bindings.push(binding);
    audit("access.binding.create", binding.binding_id, "binding");
    return json(binding, 201);
  });
  const saveGroup = (id: string, body: Record<string, unknown>) => {
    const name = String(body.name ?? "").trim();
    const selectors = ((body.selectors ?? []) as { key: string; value: string }[]).map((sel) => `${sel.key}=${sel.value}`);
    if (name === "" || selectors.length === 0 || selectors.some((sel) => /^=|=$/.test(sel))) return undefined;
    return { asset_group_id: id, name, selectors };
  };
  route("POST", "/api/v1/access-control/asset-groups", "asset_groups.manage", (_, __, body) => {
    const group = saveGroup(`grp-${Date.now().toString(36)}`, body);
    if (!group) return problem(422, "invalid_asset_group", "Give the group a name and at least one key=value selector");
    data.access.asset_groups.push(group);
    audit("access.asset_group.create", group.asset_group_id, "asset_group");
    return json(group, 201);
  });
  route("PUT", "/api/v1/access-control/asset-groups/{id}", "asset_groups.manage", ({ id = "" }, _, body) => {
    const index = data.access.asset_groups.findIndex((g) => g.asset_group_id === id);
    const group = saveGroup(id, body);
    if (index < 0) return problem(404, "not_found", "Asset group not found");
    if (!group) return problem(422, "invalid_asset_group", "Give the group a name and at least one key=value selector");
    data.access.asset_groups[index] = group;
    audit("access.asset_group.update", id, "asset_group");
    return json(group);
  });
  route("DELETE", "/api/v1/access-control/bindings/{id}", "rbac.manage", ({ id = "" }) => {
    data.access.bindings = data.access.bindings.filter((b) => b.binding_id !== id);
    audit("access.binding.delete", id, "binding");
    return new Response(null, { status: 204 });
  });

  route("GET", "/api/v1/enrollment-tokens", "tokens.read", () => json({ items: data.enrollmentTokens }));
  const idempotent = new Map<string, { token_id: string; expires_at: string }>();
  route("POST", "/api/v1/enrollment-tokens", "tokens.create", (_, __, body, headers) => {
    const key = headers["idempotency-key"] ?? "";
    if (!/^[\x21-\x7e]{16,128}$/.test(key)) return problem(400, "invalid_idempotency_key", "Provide an Idempotency-Key header between 16 and 128 visible ASCII characters");
    const previous = idempotent.get(key);
    if (previous) return json({ ...previous, secret_available: false, replayed: true });
    const token_id = `tok-${Date.now().toString(16).slice(-4)}${idempotent.size}`;
    const expires = iso(Date.now() + Number(body.expires_in_hours ?? 24) * 3_600_000);
    idempotent.set(key, { token_id, expires_at: expires });
    data.enrollmentTokens.unshift({ token_id, label: (body.label as string | null) ?? null, created_at: iso(), expires_at: expires, max_uses: Number(body.max_uses ?? 1), uses: 0, revoked: false });
    audit("enrollment_token.create", token_id, "enrollment_token");
    return json({ token_id, token: `ovet_demo_${crypto.randomUUID().replaceAll("-", "")}`, expires_at: expires, secret_available: true, replayed: false }, 201);
  });
  route("POST", "/api/v1/enrollment-tokens/{id}/revoke", "tokens.revoke", ({ id = "" }) => {
    const token = data.enrollmentTokens.find((t) => t.token_id === id);
    if (!token) return problem(404, "not_found", "Token not found");
    token.revoked = true;
    audit("enrollment_token.revoke", id, "enrollment_token");
    return json(token);
  });
  route("GET", "/api/v1/rule-sets", "rules.read", () => json({ items: data.ruleSets }));
  route("GET", "/api/v1/rule-sets/{id}/bundles", "rules.read", ({ id = "" }) => json({ items: data.bundles.get(id) ?? [] }));
  const previews = new Map<string, string>();
  const envelopeOf = (body: Record<string, unknown>) => ({
    set: String(body.rule_set_id ?? ""), version: Number(body.rule_set_version), key: String(body.issuer_key_id ?? ""), expires: Number(body.expires_at_unix_ms),
  });
  route("POST", "/api/v1/rule-bundles/preview", "rules.upload", (_, __, body) => {
    const e = envelopeOf(body);
    const set = data.ruleSets.find((candidate) => candidate.rule_set_id === e.set);
    if (!set || !Number.isInteger(e.version) || e.key === "") return problem(422, "invalid_envelope", "The envelope failed signature or trust validation");
    if (set.current_version != null && e.version <= set.current_version) return problem(409, "version_not_newer", `Version ${e.version} is not newer than ${set.current_version}`);
    const preview_token = `preview-${crypto.randomUUID()}`;
    previews.set(preview_token, JSON.stringify(e));
    return json({ rule_set_id: e.set, version: e.version, current_version: set.current_version ?? null, issuer_key_id: e.key, envelope_sha256: "demo".padEnd(64, "0"), expires_at_ms: e.expires, preview_token });
  });
  route("POST", "/api/v1/rule-bundles/publish", "rules.upload", (_, __, body, headers) => {
    const token = headers["x-rule-preview-token"];
    if (token === undefined) return problem(428, "preview_required", "Preview the bundle first");
    const e = envelopeOf(body);
    if (previews.get(token) !== JSON.stringify(e)) return problem(409, "preview_mismatch", "The envelope changed since its preview; preview it again");
    previews.delete(token);
    const set = data.ruleSets.find((candidate) => candidate.rule_set_id === e.set);
    if (!set) return problem(404, "not_found", "Rule set not found");
    set.current_version = e.version;
    set.current_issuer_key_id = e.key;
    set.current_expires_at_ms = e.expires;
    data.bundles.set(e.set, [{ version: e.version, bytes: JSON.stringify(body).length, created_at_ms: Date.now(), published_at: iso(), published_by: actor, envelope_sha256: "demo".padEnd(64, "0"), expires_at_ms: e.expires, issuer_key_id: e.key }, ...(data.bundles.get(e.set) ?? [])]);
    audit("rule_bundle.publish", e.set, "rule_set");
    return new Response(null, { status: 201 });
  });
  route("GET", "/api/v1/service-accounts", "service_accounts.read", () => json({ items: data.serviceAccounts }));
  route("GET", "/api/v1/service-accounts/{id}/tokens", "service_accounts.read", ({ id = "" }) => json({ items: data.serviceTokens.get(id) ?? [] }));
  route("POST", "/api/v1/service-accounts", "service_accounts.manage", (_, __, body) => {
    const name = String(body.name ?? "").trim();
    if (name === "" || name.length > 128) return problem(422, "invalid_name", "Give the account a name");
    const account = { service_account_id: `sa-${Date.now().toString(36)}`, name, role_ids: [String(body.role_id ?? "viewer")], enabled: true, active_tokens: 0, created_at: iso() };
    data.serviceAccounts.push(account);
    audit("service_account.create", account.service_account_id, "service_account");
    return json(account, 201);
  });
  const issued = new Map<string, { token_id: string; expires_at: string }>();
  route("POST", "/api/v1/service-accounts/{id}/tokens", "service_accounts.manage", ({ id = "" }, _, body, headers) => {
    const key = headers["idempotency-key"] ?? "";
    if (!/^[\x21-\x7e]{16,128}$/.test(key)) return problem(400, "invalid_idempotency_key", "Provide an Idempotency-Key header between 16 and 128 visible ASCII characters");
    const account = data.serviceAccounts.find((a) => a.service_account_id === id);
    if (!account) return problem(404, "not_found", "Service account not found");
    const previous = issued.get(key);
    if (previous) return json({ ...previous, secret_available: false, replayed: true });
    const token = { token_id: `st-${Date.now().toString(36)}${issued.size}`, label: String(body.label ?? ""), created_at: iso(), expires_at: iso(Date.now() + Number(body.expires_in_hours ?? 24) * 3_600_000), revoked: false };
    issued.set(key, { token_id: token.token_id, expires_at: token.expires_at });
    data.serviceTokens.set(id, [token, ...(data.serviceTokens.get(id) ?? [])]);
    account.active_tokens += 1;
    audit("service_token.create", id, "service_account");
    return json({ token_id: token.token_id, token: `ovst_demo_${crypto.randomUUID().replaceAll("-", "")}`, expires_at: token.expires_at, secret_available: true, replayed: false }, 201);
  });
  route("POST", "/api/v1/service-accounts/{id}/tokens/{token}/revoke", "service_accounts.manage", ({ id = "", token = "" }) => {
    const found = data.serviceTokens.get(id)?.find((t) => t.token_id === token);
    const account = data.serviceAccounts.find((a) => a.service_account_id === id);
    if (!found || !account) return problem(404, "not_found", "Token not found");
    if (!found.revoked) account.active_tokens = Math.max(0, account.active_tokens - 1);
    found.revoked = true;
    audit("service_token.revoke", id, "service_account");
    return json(found);
  });
  route("POST", "/api/v1/service-accounts/{id}/disable", "service_accounts.manage", ({ id = "" }) => {
    const account = data.serviceAccounts.find((a) => a.service_account_id === id);
    if (!account) return problem(404, "not_found", "Service account not found");
    account.enabled = false;
    audit("service_account.disable", id, "service_account");
    return json(account);
  });

  route("GET", "/api/v1/assistant/status", "assistant.use", () => json({ available: true, model: "demo (synthetic answers)", location: "in your browser" }));
  route("POST", "/api/v1/assistant/messages", "assistant.use", (_, __, body) =>
    json({ segments: assistant(String(body.question ?? "")), lookups: [{ name: "fleet", objects: data.agents.length, error: null }] }));

  const dashboards = createDashboardStore(
    data.dashboards,
    (userId) => (scoped && userId === `u-${actor}` ? ["operator"] : data.access.bindings.filter((b) => b.user_id === userId).map((b) => b.role_id)),
    (userId) => data.access.users.find((u) => u.user_id === userId)?.display_name ?? userId,
    browserPersistence("openvibes.v2.demo.dashboards"),
  );
  const send = (result: { status: number; body?: unknown; etag?: string }) => {
    if (result.status === 204) return new Response(null, { status: 204 });
    const headers: Record<string, string> = { "content-type": result.status >= 400 ? "application/problem+json" : "application/json" };
    if (result.etag) headers.etag = result.etag;
    return new Response(JSON.stringify(result.body), { status: result.status, headers });
  };
  const me = `u-${actor}`;
  route("GET", "/api/v1/dashboards", null, () => send(dashboards.list(me)));
  route("POST", "/api/v1/dashboards", null, (_, __, body) => send(dashboards.create(me, body)));
  route("GET", "/api/v1/dashboards/{id}", null, ({ id = "" }) => send(dashboards.get(me, id)));
  route("PUT", "/api/v1/dashboards/{id}", null, ({ id = "" }, _, body, headers) => send(dashboards.update(me, id, body, headers["if-match"])));
  route("DELETE", "/api/v1/dashboards/{id}", null, ({ id = "" }) => send(dashboards.remove(me, id)));
  route("PUT", "/api/v1/dashboards/{id}/sharing", null, ({ id = "" }, _, body) =>
    send(dashboards.share(me, id, body.role_id ?? null, permissions.includes("dashboards.share"), data.access.roles.map((r) => r.role_id))));
  route("GET", "/api/v1/me/home", null, () => send(dashboards.home(me)));
  route("PUT", "/api/v1/me/home", null, (_, __, body) => send(dashboards.setHome(me, body.dashboard_id ?? null)));

  // Cases: what an item is comes from the objects above, so triaging an
  // alarm or finding here changes what a case may record for it.
  const mitigated = (state: string | undefined) => state === "mitigated";
  const cases = createCaseStore({
    me: { user_id: me, username: actor, display_name: data.access.users.find((u) => u.user_id === me)?.display_name ?? actor },
    people: data.access.users,
    assignable: data.access.bindings.filter((b) => ["analyst", "admin"].includes(b.role_id)).map((b) => b.user_id),
    canSee: visible,
    hostname: (agentId) => data.agents.find((a) => a.id === agentId)?.hostname ?? null,
    facts: (kind, ref) => {
      const [first, rest] = splitRef(ref);
      if (kind === "alarm") {
        const alarm = alarmList().find((a) => a.id === ref);
        return alarm && { agent_id: alarm.agent_id, title: alarm.message, severity: alarm.severity, gone: mitigated(alarm.state) };
      }
      if (kind === "finding") {
        const [set, rule] = splitRef(rest);
        const finding = findings().find((f) => f.agent_id === first && f.rule_set_id === set && f.rule_id === rule);
        return finding && { agent_id: first, title: finding.message, severity: finding.severity, gone: mitigated(data.triage.get(triageKey(first, set, rule))?.state) };
      }
      if (kind === "vulnerability") {
        const row = data.vulnerabilities.find((v) => v.agent_id === first && v.advisory_id === rest && visible(v.agent_id));
        return row && { agent_id: first, title: row.title, severity: row.severity, gone: row.fixed_at != null };
      }
      if (kind === "host") {
        const agent = agentById(ref);
        return agent && { agent_id: agent.id, title: agent.hostname ?? agent.id, severity: null, gone: false };
      }
      const present = hosts().some((agent) => hostPackages(agent.id).some((p) => `${p.manager}/${p.name}` === ref));
      return present ? { agent_id: null, title: rest, severity: null, gone: false } : undefined;
    },
    audit: (action, target) => audit(action, target, "case"),
  }, () => seedCases(data), browserPersistence("openvibes.v2.demo.cases"));
  const listed = (query: URLSearchParams) => {
    const result = cases.list(query);
    return result.status === 200 ? json(page(result.body as unknown[], query)) : send(result);
  };
  route("GET", "/api/v1/cases", "cases.read", (_, query) => listed(query));
  route("POST", "/api/v1/cases", "cases.manage", (_, __, body) => send(cases.create(body)));
  route("GET", "/api/v1/cases/for-item", "cases.read", (_, query) => send(cases.forItem(query)));
  route("GET", "/api/v1/cases/assignees", "cases.manage", () => send(cases.assignees()));
  route("GET", "/api/v1/cases/{id}", "cases.read", ({ id = "" }) => send(cases.get(id)));
  route("PUT", "/api/v1/cases/{id}", "cases.manage", ({ id = "" }, _, body, headers) => send(cases.update(id, body, headers["if-match"])));
  route("POST", "/api/v1/cases/{id}/notes", "cases.manage", ({ id = "" }, _, body) => send(cases.addNote(id, body)));
  route("POST", "/api/v1/cases/{id}/items", "cases.manage", ({ id = "" }, _, body) => send(cases.addItem(id, body)));
  route("DELETE", "/api/v1/cases/{id}/items/{item}", "cases.manage", ({ id = "", item = "" }) => send(cases.removeItem(id, item)));
  route("PUT", "/api/v1/cases/{id}/items/{item}/outcome", "cases.manage", ({ id = "", item = "" }, _, body) => send(cases.setOutcome(id, item, body)));

  return {
    persona,
    async handle(method: string, url: string, body?: unknown, headers: Record<string, string> = {}): Promise<Response> {
      const parsed = new URL(url, "http://demo");
      const limit = parsed.searchParams.get("limit");
      if (limit !== null && !(Number.isInteger(Number(limit)) && Number(limit) >= 1 && Number(limit) <= MAX_PAGE)) {
        return problem(400, "invalid_pagination", "limit must be between 1 and 100");
      }
      for (const candidate of routes) {
        if (candidate.method !== method) continue;
        const match = candidate.pattern.exec(parsed.pathname);
        if (!match) continue;
        if (candidate.permission !== null && !permissions.includes(candidate.permission)) {
          return problem(403, "forbidden", "Your role does not allow this");
        }
        const params = Object.fromEntries(candidate.keys.map((key, index) => [key, decodeURIComponent(match[index + 1] ?? "")]));
        const lower = Object.fromEntries(Object.entries(headers).map(([key, value]) => [key.toLowerCase(), value]));
        return candidate.handler(params, parsed.searchParams, (body ?? {}) as Record<string, unknown>, lower);
      }
      return problem(404, "not_found", "No such endpoint");
    },
  };
}
