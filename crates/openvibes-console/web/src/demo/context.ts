// The demo server's shared context: the persona's data, permissions and
// visibility, the helpers more than one area uses, and the route registrar.
import type { Agent, AuditEvent, FindingGroup, Permission, TriageCounts } from "../api/types";
import { buildDemoData } from "./data";
import { type HostFacts, inGroup } from "./hostGroups";
import { problem, severityRank } from "./http";
import type { Persona } from "./personas";
import { ADMIN_ROLE, resolveCapabilities } from "./share";

type Params = Record<string, string>;
type Handler = (params: Params, query: URLSearchParams, body: Record<string, unknown>, headers: Record<string, string>) => Response | Promise<Response>;
type Route = { method: string; pattern: RegExp; keys: string[]; permission: Permission | null; handler: Handler };

export type DemoContext = ReturnType<typeof createDemoContext>;

// Who each persona signs in as; what they may do comes from that person's roles.
const PERSON: Record<Persona, string> = { admin: "u-admin", analyst: "u-sam", operator: "u-ola", scoped_operator: "u-pia", viewer: "u-vic" };

export function createDemoContext({ persona, now }: { persona: Persona; now: number }) {
  const data = buildDemoData(now);
  const iso = (ms = Date.now()) => new Date(ms).toISOString();
  /** The roles a person holds. */
  const rolesOf = (userId: string) => data.access.bindings.filter((b) => b.user_id === userId)
    .flatMap((b) => data.access.roles.filter((r) => r.role_id === b.role_id));
  const me = PERSON[persona];
  const actor = data.access.users.find((u) => u.user_id === me)?.username ?? persona;
  const capabilities = resolveCapabilities(rolesOf(me));
  const permissions = capabilities.map((c) => c.permission);
  // Rule sets and history (rules.read), their switches (rules.assignment.read) and coverage (rules.coverage.read), globally (the real API's rule).
  const readsRules = (permission: Permission = "rules.read") => capabilities.some((c) => c.permission === permission && c.scope.kind === "global");

  /** What group membership reads of a host. */
  const facts = (agent: Agent): HostFacts => ({ ...agent, last_address: data.addresses.get(agent.id) ?? null });
  /** Whether a host is in one of these groups (console_host_in_group). */
  const inAnyGroup = (agentId: string, groupIds: readonly string[]) => {
    const agent = data.agents.find((a) => a.id === agentId);
    return !!agent && data.access.host_groups.some((g) => groupIds.includes(g.asset_group_id) && inGroup(facts(agent), g));
  };
  /** Whether the persona holds `permission` on this host (agent_visibility: scoped readers never see imported hosts). */
  const reaches = (permission: Permission, agentId: string) => {
    const scope = capabilities.find((c) => c.permission === permission)?.scope;
    return scope?.kind === "global" || (scope?.kind === "asset_groups" && inAnyGroup(agentId, scope.asset_group_ids));
  };
  // ponytail: one host scope for everything (that of hosts.read), where the
  // server scopes each permission; per-permission scopes if a persona needs them.
  const hostScope = capabilities.find((c) => c.permission === "hosts.read")?.scope;
  const scoped = hostScope?.kind !== "global";
  const visible = (agentId: string) => reaches("hosts.read", agentId);
  const agentById = (id: string) => data.agents.find((agent) => agent.id === id && visible(id));
  const audit = (action: string, target: string, targetKind: string, targetId = target) => {
    const event: AuditEvent = {
      id: String(Number(data.audit[0]?.id ?? 0) + 1), action, actor, actor_id: me, actor_kind: "user",
      at: iso(), authentication_method: "local_password", result: "success", reason_code: null,
      request_id: `demo-${Date.now().toString(36)}`, target, target_id: targetId, target_kind: targetKind,
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

  /**
   * The server's triage assignee (console_roles::assignee): an enabled person
   * holding the area's *.triage through a role that reaches some host, or an
   * Administrator.
   */
  const triageAssignable = (username: string, triage: Permission) => {
    const user = data.access.users.find((u) => u.username === username && u.enabled);
    return !!user && rolesOf(user.user_id).some((r) => r.role_id === ADMIN_ROLE || (r.permissions.includes(triage) && r.reach.kind !== "none"));
  };
  // The server's rules: an expiry in the future exactly when the risk is
  // accepted, and an assignee who may triage the area (`triage`).
  const triageProblem = (body: Record<string, unknown>, triage: Permission) => {
    const until = typeof body.accepted_until === "string" ? Date.parse(body.accepted_until) : null;
    if ((body.state === "accepted_risk") !== (until !== null) || (until !== null && !(until > Date.now() && until <= Date.now() + 366 * 86_400_000))) {
      return problem(400, "invalid_triage", "Triage state, note, expiry, or selection is invalid");
    }
    if (typeof body.assigned_to === "string" && !triageAssignable(body.assigned_to, triage)) {
      return problem(400, "invalid_assignee", "Assignee must be an enabled person who may triage this on some host, or an Administrator");
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

  return {
    now, data, iso, rolesOf, permissions, scoped, capabilities, readsRules, actor, me, visible, reaches, facts, agentById, audit, triageKey,
    findings, vulnerabilities, groups, setTriage, triageProblem, alarmList, addSuppression, hostPackages, hosts, routes, route, send,
  };
}
