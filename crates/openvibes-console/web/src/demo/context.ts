// The demo server's shared context: the persona's data, permissions and
// visibility, the helpers more than one area uses, and the route registrar.
import { RULE_READERS } from "../panels/ruleAssignment";
import type { AuditEvent, Capability, FindingGroup, Permission, TriageCounts } from "../api/types";
import { buildDemoData } from "./data";
import { problem, severityRank } from "./http";
import type { Persona } from "./personas";

type Params = Record<string, string>;
type Handler = (params: Params, query: URLSearchParams, body: Record<string, unknown>, headers: Record<string, string>) => Response | Promise<Response>;
type Route = { method: string; pattern: RegExp; keys: string[]; permission: Permission | null; handler: Handler };

export type DemoContext = ReturnType<typeof createDemoContext>;

export function createDemoContext({ persona, now }: { persona: Persona; now: number }) {
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
  // Rule sets, their switches, history and coverage: rules.read or rules.upload, globally (the real API's rule).
  const readsRules = () => RULE_READERS.some((r) => capabilities.some((c) => c.permission === r.permission && (!r.global || c.scope.kind === "global")));
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
      const counts: TriageCounts = byRule.get(key)?.triage_counts ?? { open: 0, mitigated: 0, accepted_risk: 0, false_positive: 0 };
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
    if ((body.state === "accepted_risk") !== (until !== null) || (until !== null && !(until > Date.now() && until <= Date.now() + 366 * 86_400_000))) {
      return problem(400, "invalid_triage", "Triage state, note, expiry, or selection is invalid");
    }
    if (typeof body.assigned_to === "string" && !data.access.bindings.some((b) => b.username === body.assigned_to && ["analyst", "admin"].includes(b.role_id))) {
      return problem(400, "invalid_assignee", "Assignee must be an enabled analyst or admin");
    }
    return null;
  };

  const alarmList = () => data.alarms.filter((alarm) => visible(alarm.agent_id));
  const addSuppression = (alarm: ReturnType<typeof alarmList>[number], scope: string, note: string) => {
    const created = {
      id: String(data.alarmSuppressions.length + 1), rule_set_id: alarm.rule_set_id, rule_id: alarm.rule_id, scope,
      agent_id: scope === "host" ? alarm.agent_id : null, exe: scope === "host" ? null : alarm.exe,
      args_sha256: scope === "command" ? "demo" : null, note, created_by: actor, created_at: iso(),
    };
    data.alarmSuppressions.unshift(created);
    audit("alarm.suppression.created", created.id, "alarm_suppression");
    return created;
  };

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

  const routes: Route[] = [];
  const route = (method: string, path: string, permission: Permission | null, handler: Handler) => {
    const keys: string[] = [];
    const pattern = new RegExp(`^${path.replace(/\{(\w+)\}/g, (_, key: string) => { keys.push(key); return "([^/]+)"; })}$`);
    routes.push({ method, pattern, keys, permission, handler });
  };
  const send = (result: { status: number; body?: unknown; etag?: string }) => {
    if (result.status === 204) return new Response(null, { status: 204 });
    const headers: Record<string, string> = { "content-type": result.status >= 400 ? "application/problem+json" : "application/json" };
    if (result.etag) headers.etag = result.etag;
    return new Response(JSON.stringify(result.body), { status: result.status, headers });
  };
  const me = `u-${actor}`;

  return {
    now, data, iso, permissions, scoped, capabilities, readsRules, actor, me, visible, agentById, audit, triageKey,
    findings, vulnerabilities, groups, setTriage, triageProblem, alarmList, addSuppression, hostPackages, hosts, routes, route, send,
  };
}
