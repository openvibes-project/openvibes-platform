import type { Agent, Permission } from "../../api/types";
import type { DemoContext } from "../context";
import { demoHistory } from "../history";
import { json, problem } from "../http";

export function registerMetricRoutes(ctx: DemoContext) {
  const { data, now, capabilities, visible, alarmList, vulnerabilities, findings, triageKey, route } = ctx;
  // History of the real catalogue's metrics, ending on the demo's own live counts.
  const vulnSeverity = { critical: "critical", high: "important", medium: "moderate", low: "low" } as const;
  const liveValue = (metric: string): number | undefined => {
    const [kind = "", mid = "", level = ""] = metric.split(".");
    const alarmsOpen = alarmList().filter((a) => !a.suppressed_by && a.state === "open");
    const vulns = vulnerabilities();
    const openFindings = findings().filter((f) => (data.triage.get(triageKey(f.agent_id, f.rule_set_id, f.rule_id))?.state ?? "open") === "open");
    const alarmsAt = (v: string) => alarmsOpen.filter((a) => a.severity === v).length;
    const vulnsAt = (v: keyof typeof vulnSeverity) => vulns.filter((i) => i.severity === vulnSeverity[v]).length;
    const findingsAt = (v: string) => openFindings.filter((f) => f.severity === v).length;
    const agentsAt = (v: Agent["status"]) => data.agents.filter((a) => visible(a.id) && a.status === v).length;
    if (kind === "all" && (level === "critical" || level === "high")) return alarmsAt(level) + vulnsAt(level) + findingsAt(level);
    if (metric === "alarms.active") return alarmsOpen.length;
    if (kind === "alarms") return alarmsAt(level);
    if (metric === "vulns.exploited") return vulns.filter((i) => i.exploited).length;
    if (metric === "vulns.no_fix") return vulns.filter((i) => Array.isArray(i.packages) && (i.packages as { fixed: unknown }[]).every((p) => p.fixed == null)).length;
    if (metric === "vulns.reboot_hosts") return new Set(vulns.filter((i) => i.reboot_needed).map((i) => i.agent_id)).size;
    if (kind === "vulns" && mid === "open" && level in vulnSeverity) return vulnsAt(level as keyof typeof vulnSeverity);
    if (kind === "compliance" && mid === "open") return findingsAt(level);
    if (kind === "agents" && (mid === "active" || mid === "stale" || mid === "revoked")) return agentsAt(mid);
    return undefined;
  };
  const metricPermissions = (metric: string): Permission[] =>
    metric.startsWith("all.") ? ["alarms.read", "vulnerabilities.read", "compliance.read"] : [metric.startsWith("vulns.") ? "vulnerabilities.read" : metric.startsWith("alarms.") ? "alarms.read" : metric.startsWith("compliance.") ? "compliance.read" : "agents.read"];
  const invalidQuery = (field: string, code: string, message: string) => new Response(JSON.stringify({
    status: 422, code: "invalid_metric_query", title: "The metric query is invalid", request_id: `demo-${Date.now().toString(36)}`,
    field_errors: [{ field, code, message }],
  }), { status: 422, headers: { "content-type": "application/problem+json" } });
  route("GET", "/api/v1/metrics/history", null, (_, query) => {
    const metric = query.get("metric") ?? "";
    const current = liveValue(metric);
    if (current === undefined) return invalidQuery("metric", "unknown_metric", "Unknown metric");
    const days = { "7": 7, "30": 30, "90": 90, "365": 365 }[query.get("days") ?? "30"];
    if (days === undefined) return invalidQuery("days", "invalid_days", "days must be 7, 30, 90 or 365");
    if (metricPermissions(metric).some((p) => !capabilities.some((c) => c.permission === p))) return problem(403, "permission_denied", "You do not have access to that");
    return json({ metric, points: demoHistory(metric, days, current, now) });
  });
  // Hosts ranked by critical + high of all three kinds, then by all open problems.
  route("GET", "/api/v1/metrics/top-hosts", null, (_, query) => {
    const limit = Number(query.get("limit") ?? "6");
    if (!Number.isInteger(limit) || limit < 1 || limit > 10) return invalidQuery("limit", "invalid_limit", "limit must be 1 to 10");
    if (metricPermissions("all.open.critical").some((p) => !capabilities.some((c) => c.permission === p))) return problem(403, "permission_denied", "You do not have access to that");
    const hosts = new Map<string, { agent_id: string; hostname: string | null; serious: number; open: number }>();
    const add = (agent_id: string, severity: string) => {
      if (!["critical", "high", "important", "medium", "moderate", "low"].includes(severity)) return;
      const host = hosts.get(agent_id) ?? { agent_id, hostname: data.agents.find((a) => a.id === agent_id)?.hostname ?? null, serious: 0, open: 0 };
      host.open += 1;
      if (severity === "critical" || severity === "high" || severity === "important") host.serious += 1;
      hosts.set(agent_id, host);
    };
    for (const a of alarmList()) if (!a.suppressed_by && a.state === "open") add(a.agent_id, a.severity);
    for (const v of vulnerabilities()) add(v.agent_id, v.severity);
    for (const f of findings()) if ((data.triage.get(triageKey(f.agent_id, f.rule_set_id, f.rule_id))?.state ?? "open") === "open") add(f.agent_id, f.severity);
    const items = [...hosts.values()].filter((h) => visible(h.agent_id)).sort((a, b) => b.serious - a.serious || b.open - a.open || a.agent_id.localeCompare(b.agent_id));
    return json({ items: items.slice(0, limit) });
  });
}
