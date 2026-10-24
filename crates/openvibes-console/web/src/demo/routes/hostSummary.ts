// A host's page summary (GET /api/v1/hosts/{id}/summary), answered as
// hosts/summary.rs and the store's host_summary.rs answer it: the host in
// the hosts.read scope or 404, and each tile, top three and action only
// where its own permission reaches the host (plan ruling 10).
import type { Agent, HostSummary } from "../../api/types";
import type { DemoContext } from "../context";
import { distribution, distributionName, inGroup, isActive, osFamily } from "../hostGroups";
import { json, problem, severityRank } from "../http";
import { older } from "../versionOrder";
import { hostServices } from "./assets";
import { LATEST_AGENT_VERSION } from "./session";

const TOP = 3;
/** The Vulnerabilities list's default confidence floor (views/lists/rows.ts). */
const LIST_MIN_CONFIDENCE = 80;
const statusOf = (a: Agent) => (a.status === "active" ? "online" : a.status === "stale" ? "offline" : a.status);
const rank = (severity: string) => severityRank[severity] ?? 9;
const byteOrder = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);
const top = <T,>(items: T[]) => ({ items: items.slice(0, TOP), total: items.length });

/** What the Vulnerabilities list shows by default with this host as its filter
 * (confidence at least 80, triage open), in its order, one row per advisory:
 * the first three and the total. */
export function topVulnerabilities({ vulnerabilities }: DemoContext, id: string) {
  const seen = new Set<string>();
  return top(vulnerabilities().filter((v) => v.agent_id === id && v.confidence >= LIST_MIN_CONFIDENCE && v.triage_state === "open")
    .sort((a, b) => Number(b.exploited) - Number(a.exploited) || rank(a.severity) - rank(b.severity) || (b.epss ?? 0) - (a.epss ?? 0))
    .filter((v) => !seen.has(v.advisory_id) && seen.add(v.advisory_id))
    .map((v) => ({ advisory: v.advisory_id, severity: v.severity, kev: v.kev, exploited: v.exploited, title: v.title })));
}

export function registerHostSummaryRoute(ctx: DemoContext) {
  const { data, route, agentById, reaches, facts, hostPackages, triageKey } = ctx;
  const findingOpen = (x: { agent_id: string; rule_set_id: string; rule_id: string; ended_at?: string | null }) =>
    x.ended_at == null && (data.triage.get(triageKey(x.agent_id, x.rule_set_id, x.rule_id))?.state ?? "open") === "open";
  route("GET", "/api/v1/hosts/{id}/summary", "hosts.read", ({ id = "" }) => {
    const agent = agentById(id);
    if (!agent) return problem(404, "host_not_found", "No such host");
    const here = (p: Parameters<typeof reaches>[0]) => reaches(p, id);
    const f = facts(agent);
    const dist = distribution(f);

    const alarms = here("alarms.read") ? top(data.alarms.filter((a) => a.agent_id === id && a.state === "open")
      .sort((a, b) => rank(a.severity) - rank(b.severity) || b.last_seen.localeCompare(a.last_seen) || Number(b.id) - Number(a.id))
      .map((a) => ({ id: Number(a.id), rule_id: a.rule_id, message: a.message, severity: a.severity, last_seen: a.last_seen }))) : null;
    const vulns = here("vulnerabilities.read") ? topVulnerabilities(ctx, id) : null;
    // Failing and not triaged away, as the Compliance list counts open hosts.
    const failing = here("compliance.read") ? top(data.findings.filter((x) => x.agent_id === id && findingOpen(x))
      .sort((a, b) => rank(a.severity) - rank(b.severity) || b.last_observed_at.localeCompare(a.last_observed_at))
      .map((x) => ({ rule_set_id: x.rule_set_id, rule_id: x.rule_id, severity: x.severity, message: x.message }))) : null;

    const packages = hostPackages(id).length;
    const report = hostServices(data, id);
    const ports = (only: boolean) => new Set(report.listeners.filter((l) => !only || l.exposed).map((l) => `${l.protocol}/${l.port}`)).size;
    const certificates = data.certificates.get(id) ?? [];
    const status = statusOf(agent);
    const changeable = status === "online" || status === "offline";
    const body: HostSummary = {
      host: {
        id, hostname: agent.hostname ?? null, status, address: data.addresses.get(id) ?? null,
        os: { id: agent.os_id ?? null, version: agent.os_version ?? null, distribution: dist && distributionName(dist), family: osFamily(f) },
        running_kernel: agent.running_kernel ?? null, scanner_version: agent.scanner_version ?? null,
        agent_older: agent.scanner_version ? older(agent.scanner_version, LATEST_AGENT_VERSION) : null,
        enrolled_at: agent.enrolled_at, revoked_at: agent.revoked_at ?? null, last_seen_at: agent.last_seen_at ?? null,
        inventory_at: agent.inventory_at ?? null, capabilities: agent.capabilities,
      },
      tiles: { open_alarms: alarms?.total ?? null, compliance_failing: failing?.total ?? null, vulnerabilities: vulns?.total ?? null, software: packages },
      protection: {
        threat_alarms: agent.alarms ?? null,
        // As GET /api/v1/agents/{id} answers it in the demo.
        last_test: { alarm_at: id.endsWith("1") ? new Date(Date.now() - 120_000).toISOString() : null, finding_at: null },
      },
      // Members are active hosts only (console_host_in_group), by name.
      groups: isActive(f) ? data.access.host_groups.filter((g) => inGroup(f, g))
        .sort((a, b) => a.name.toLowerCase().localeCompare(b.name.toLowerCase()))
        .map((g) => ({ id: g.asset_group_id, name: g.name, kind: g.kind })) : [],
      labels: [...(data.labels.get(id) ?? [])].sort(byteOrder),
      certificates: certificates.slice(0, 5), certificate_count: certificates.length,
      top_alarms: alarms, top_vulnerabilities: vulns, top_failing: failing,
      inventory: { packages, listening_ports: ports(false), exposed_ports: ports(true), services: report.services.length },
      can: {
        label: changeable && here("hosts.label"), revoke: changeable && here("hosts.revoke"), export: here("hosts.export"),
        add_to_case: here("cases.write"), ask: here("assistant.use"),
      },
    };
    return json(body);
  });
}
