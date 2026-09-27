// An in-browser implementation of the console's /api/v1 over synthetic data,
// for the GitHub Pages preview, `?demo=1` and tests. It follows the wire
// contracts (types from the OpenAPI client) and the permission model, and
// keeps mutations in memory for the life of the page.
import type {
  Agent, AssistantSegment, AuditEvent, Capability, FindingGroup, GroupEndpoint, Permission,
  Severity, TriageCounts, Vulnerability,
} from "../api/types";
import { buildDemoData } from "./data";

export const personas = ["viewer", "analyst", "operator", "scoped_operator", "admin"] as const;
export type Persona = (typeof personas)[number];

type Params = Record<string, string>;
type Handler = (params: Params, query: URLSearchParams, body: Record<string, unknown>) => Response | Promise<Response>;
type Route = { method: string; pattern: RegExp; keys: string[]; permission: Permission | null; handler: Handler };

const json = (value: unknown, status = 200) =>
  new Response(JSON.stringify(value), { status, headers: { "content-type": "application/json" } });
const problem = (status: number, code: string, title: string) =>
  new Response(JSON.stringify({ status, code, title, request_id: `demo-${Date.now().toString(36)}` }), {
    status, headers: { "content-type": "application/problem+json" },
  });

function page<T>(items: readonly T[], query: URLSearchParams, fallback = 50) {
  const limit = Math.min(500, Math.max(1, Number(query.get("limit") ?? fallback) || fallback));
  const offset = Number(atob(query.get("cursor") ?? "") || 0) || 0;
  const slice = items.slice(offset, offset + limit);
  const next = offset + limit < items.length ? btoa(String(offset + limit)) : null;
  return { items: slice, next_cursor: next };
}

const severityRank: Record<string, number> = { critical: 0, important: 1, high: 1, moderate: 2, medium: 2, low: 3, unrated: 4 };

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
      const open = findings().filter((finding) => finding.agent_id === context);
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
  }));
  route("GET", "/api/v1/agents", "agents.read", (_, query) => {
    const state = query.get("state");
    const items = data.agents.filter((agent) => visible(agent.id) && (state === null || agent.status === state));
    return json({ ...page(items, query), generated_at: iso() });
  });
  route("GET", "/api/v1/agents/summary", "agents.read", () => {
    const items = data.agents.filter((agent) => visible(agent.id));
    const count = (status: Agent["status"]) => items.filter((agent) => agent.status === status).length;
    return json({ total: items.length, active: count("active"), stale: count("stale"), revoked: count("revoked"), imported: count("imported") });
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
    for (const change of changes) {
      const current = data.triage.get(triageKey(change.agent_id, set, rule))?.version ?? 0;
      if (current !== change.version) return problem(409, "triage_conflict", "Someone changed this triage; reload and try again");
    }
    const updated = changes.map((change) => [change.agent_id, setTriage(change.agent_id, set, rule, body)]);
    audit("finding.triage", `${set}/${rule}`, "finding");
    return json({ updated });
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
    audit("finding.triage", `${set}/${rule}`, "finding");
    return json(setTriage(agent, set, rule, body));
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
    });
  });
  route("GET", "/api/v1/vulnerabilities/advisories/{id}", "vulnerabilities.read", ({ id = "" }) => {
    const advisory = data.advisories.find((item) => item.id === decodeURIComponent(id));
    if (!advisory) return problem(404, "not_found", "Advisory not found");
    const items = vulnerabilities().filter((item) => item.advisory_id === advisory.id);
    return json({ cves: advisory.cves, hosts: { items, more_available: false, generated_at: iso() } });
  });

  route("GET", "/api/v1/audit-events", "audit.read", (_, query) => json(page(data.audit, query)));
  route("GET", "/api/v1/audit-retention", "audit.read", () => json(data.retention));
  route("PUT", "/api/v1/audit-retention", "audit.retention.manage", (_, __, body) => {
    data.retention = { ...data.retention, retention_days: Number(body.retention_days), version: data.retention.version + 1, updated_at: iso(), updated_by: actor };
    audit("audit.retention.update", "audit", "retention");
    return json(data.retention);
  });
  route("GET", "/api/v1/access-control", "rbac.read", () => json(data.access));
  route("POST", "/api/v1/access-control/bindings", "rbac.manage", (_, __, body) => {
    const user = data.access.users.find((u) => u.user_id === body.user_id);
    if (!user) return problem(422, "invalid_user", "Choose a user");
    const group = data.access.asset_groups.find((g) => g.asset_group_id === body.asset_group_id);
    const binding = { binding_id: `b-${Date.now().toString(36)}`, user_id: user.user_id, username: user.username, display_name: user.display_name, role_id: String(body.role_id), asset_group_id: group?.asset_group_id ?? null, asset_group_name: group?.name ?? null, created_at: iso(), created_by: actor };
    data.access.bindings.push(binding);
    audit("access.binding.create", binding.binding_id, "binding");
    return json(binding, 201);
  });
  route("DELETE", "/api/v1/access-control/bindings/{id}", "rbac.manage", ({ id = "" }) => {
    data.access.bindings = data.access.bindings.filter((b) => b.binding_id !== id);
    audit("access.binding.delete", id, "binding");
    return new Response(null, { status: 204 });
  });

  route("GET", "/api/v1/enrollment-tokens", "tokens.read", () => json({ items: data.enrollmentTokens }));
  route("POST", "/api/v1/enrollment-tokens", "tokens.create", (_, __, body) => {
    const token_id = `tok-${Date.now().toString(16).slice(-4)}`;
    const expires = iso(Date.now() + Number(body.expires_in_hours ?? 24) * 3_600_000);
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
  route("GET", "/api/v1/service-accounts", "service_accounts.read", () => json({ items: data.serviceAccounts }));
  route("GET", "/api/v1/service-accounts/{id}/tokens", "service_accounts.read", ({ id = "" }) => json({ items: data.serviceTokens.get(id) ?? [] }));
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

  return {
    persona,
    async handle(method: string, url: string, body?: unknown): Promise<Response> {
      const parsed = new URL(url, "http://demo");
      for (const candidate of routes) {
        if (candidate.method !== method) continue;
        const match = candidate.pattern.exec(parsed.pathname);
        if (!match) continue;
        if (candidate.permission !== null && !permissions.includes(candidate.permission)) {
          return problem(403, "forbidden", "Your role does not allow this");
        }
        const params = Object.fromEntries(candidate.keys.map((key, index) => [key, decodeURIComponent(match[index + 1] ?? "")]));
        return candidate.handler(params, parsed.searchParams, (body ?? {}) as Record<string, unknown>);
      }
      return problem(404, "not_found", "No such endpoint");
    },
  };
}
