// What each list view shows for a query, in one place: the views and the
// dashboard List tile both use it, so a tile always matches its view.
import { useMemo } from "react";

import { type ApiError, useAllPages, useResource } from "../api/client";
import type { Agent, AuditEvent, FindingGroup, Vulnerability, VulnerabilityPage } from "../api/types";
import type { PanelRef } from "../app/location";
import { auditSince, capitalise, severityOrder } from "../ui/format";
import { matches } from "../ui/table";

export const LIST_VIEWS = ["/compliance", "/vulnerabilities", "/agents", "/audit"] as const;
export type ListView = (typeof LIST_VIEWS)[number];
export type ListRow = { key: string; open: PanelRef; title: string; meta: string; badge: { label: string; tone: string } };

export type AdvisoryRow = {
  id: string; title: string; severity: string; cves: string[]; cvss: number | null; epss: number | null;
  exploited: boolean; kev: boolean; ransomware: boolean; hosts: number; reboot: number; noFix: boolean;
  /** The weakest mapping among the hosts, 0 to 100. */
  confidence: number;
};

/** Mappings below this (NVD CPE ranges, at most 75) are hidden unless "Lower confidence" is switched on. */
export const MIN_CONFIDENCE = 80;

export function groupByAdvisory(items: readonly Vulnerability[]): AdvisoryRow[] {
  const rows = new Map<string, AdvisoryRow>();
  for (const item of items) {
    const row = rows.get(item.advisory_id) ?? {
      id: item.advisory_id, title: item.title, severity: item.severity, cves: item.cves, cvss: item.cvss ?? null, epss: item.epss ?? null,
      exploited: item.exploited, kev: item.kev, ransomware: item.ransomware, hosts: 0, reboot: 0, confidence: item.confidence,
      noFix: Array.isArray(item.packages) && (item.packages as { fixed?: unknown }[]).every((p) => p?.fixed == null),
    };
    row.hosts += 1;
    row.confidence = Math.min(row.confidence, item.confidence);
    if (item.reboot_needed) row.reboot += 1;
    rows.set(item.advisory_id, row);
  }
  return [...rows.values()];
}

/** Hosts where the finding still needs work: the open ones. Mitigated,
 * accepted risk and false positive count as resolved (#83). */
export function activeCount(group: Pick<FindingGroup, "triage_counts">): number {
  return group.triage_counts.open;
}

export function selectFindings(all: readonly FindingGroup[], params: URLSearchParams): FindingGroup[] {
  const severity = params.get("severity");
  const onlyOpen = params.get("state") !== "all";
  const ruleSet = params.get("set");
  const q = params.get("q") ?? "";
  return all.filter((g) => (!severity || g.severity === severity) && (!onlyOpen || activeCount(g) > 0)
    && (!ruleSet || g.rule_set_id === ruleSet) && matches([g.latest_message, g.rule_id, g.rule_set_id], q));
}

/** Newest first: by number ("0.10.0" before "0.9.0"), a release before
 * its pre-release ("0.10.0" before "0.10.0-rc.1"), build metadata ignored. */
function versionOrder(a: string, b: string): number {
  const [aCore, aPre] = versionParts(a);
  const [bCore, bPre] = versionParts(b);
  return bCore.localeCompare(aCore, "en", { numeric: true })
    || (aPre === "" ? -1 : 0) - (bPre === "" ? -1 : 0)
    || bPre.localeCompare(aPre, "en", { numeric: true });
}

/** "1.2.3-rc.1+build" → ["1.2.3", "rc.1"]. */
function versionParts(version: string): [string, string] {
  const plus = version.indexOf("+");
  const plain = plus < 0 ? version : version.slice(0, plus);
  const dash = plain.indexOf("-");
  return dash < 0 ? [plain, ""] : [plain.slice(0, dash), plain.slice(dash + 1)];
}

/** Whether an agent's `version` is older than this platform's (board #54):
 * one agent claiming a far newer version flags nothing. */
export function olderThan(version: string, platform: string): boolean {
  return versionOrder(version, platform) > 0;
}

/** The Hosts list badges an online host whose threat alarms are off by a
 * fault; off by choice (process events not enabled) stays quiet. */
export function alarmsOff(agent: { status: string; alarms?: { state: string; fault: boolean } | null }): boolean {
  return agent.status === "active" && agent.alarms?.state === "off" && agent.alarms.fault;
}

export function selectAgents(all: readonly Agent[], params: URLSearchParams): Agent[] {
  const status = params.get("status");
  const q = params.get("q") ?? "";
  return all.filter((a) => (!status || a.status === status) && matches([a.hostname, a.id, a.scanner_version], q));
}

export function vulnerabilityQuery(params: URLSearchParams): string {
  const query = new URLSearchParams();
  if (params.get("exploited") === "true") query.set("exploited", "true");
  if (params.get("reboot") === "true") query.set("reboot_needed", "true");
  const severity = params.get("severity");
  if (severity) query.set("severity", severity);
  if (params.get("lowconf") !== "true") query.set("min_confidence", String(MIN_CONFIDENCE));
  return `/api/v1/vulnerabilities${query.size ? `?${query}` : ""}`;
}

export function selectAdvisories(all: readonly AdvisoryRow[], params: URLSearchParams): AdvisoryRow[] {
  const q = params.get("q") ?? "";
  return all.filter((row) => (params.get("nofix") !== "true" || row.noFix) && matches([row.title, row.id, ...row.cves], q));
}

export function selectAudit(all: readonly AuditEvent[], params: URLSearchParams): AuditEvent[] {
  const failed = params.get("result") === "failure";
  return all.filter((e) => (!failed || e.result !== "success") && matches([e.action, e.actor, e.target], params.get("q") ?? ""));
}

export const severityBadge = (s: string) => ({ label: capitalise(s), tone: s });
const sev = (s: string) => severityOrder[s] ?? 9;

/** The first rows of a list view for a query, ready for a compact list. */
export function useListRows(view: ListView | null, params: URLSearchParams): { rows: ListRow[]; total: number; loading: boolean; error: ApiError | undefined } {
  const groups = useAllPages<FindingGroup>(view === "/compliance" ? "/api/v1/compliance/groups" : null);
  const agents = useAllPages<Agent>(view === "/agents" ? "/api/v1/agents" : null);
  const vulns = useResource<VulnerabilityPage>(view === "/vulnerabilities" ? vulnerabilityQuery(params) : null);
  const audit = useAllPages<AuditEvent>(view === "/audit" ? `/api/v1/audit-events?since=${encodeURIComponent(auditSince(params))}` : null, 1000);
  return useMemo(() => {
    const status = view === "/compliance" ? groups : view === "/agents" ? agents : view === "/audit" ? audit : vulns;
    let rows: ListRow[];
    if (view === "/compliance") {
      rows = selectFindings(groups.data ?? [], params).sort((a, b) => sev(a.severity) - sev(b.severity) || activeCount(b) - activeCount(a))
        .map((g) => ({ key: `${g.rule_set_id}/${g.rule_id}`, open: { kind: "finding", id: `${g.rule_set_id}/${g.rule_id}` }, title: g.latest_message,
          meta: `${g.rule_id} · ${activeCount(g)} active`, badge: severityBadge(g.severity) }));
    } else if (view === "/agents") {
      rows = selectAgents(agents.data ?? [], params).map((a) => ({ key: a.id, open: { kind: "agent", id: a.id }, title: a.hostname ?? a.id,
        meta: a.id, badge: { label: a.status, tone: a.status === "active" ? "ok" : a.status === "stale" ? "warn" : a.status === "revoked" ? "bad" : "info" } }));
    } else if (view === "/audit") {
      rows = selectAudit(audit.data ?? [], params).sort((a, b) => b.at.localeCompare(a.at)).map((e) => ({ key: e.id, open: { kind: "audit-event", id: e.id },
        title: e.action, meta: `${e.actor} · ${e.target ?? ""}`, badge: { label: e.result, tone: e.result === "success" ? "ok" : "bad" } }));
    } else {
      rows = selectAdvisories(groupByAdvisory(vulns.data?.items ?? []), params)
        .sort((a, b) => Number(b.exploited) - Number(a.exploited) || sev(a.severity) - sev(b.severity) || (b.epss ?? 0) - (a.epss ?? 0))
        .map((r) => ({ key: r.id, open: { kind: "advisory", id: r.id }, title: r.title, meta: `${r.hosts} hosts${r.exploited ? " · exploited" : ""}`,
          badge: severityBadge(r.severity) }));
    }
    const data = "data" in status ? status.data : undefined;
    return { rows, total: rows.length, loading: status.loading && data === undefined, error: status.error };
  }, [view, params, groups, agents, vulns, audit]);
}
