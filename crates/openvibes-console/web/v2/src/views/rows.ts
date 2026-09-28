// What each list view shows for a query, in one place: the views and the
// dashboard List tile both use it, so a tile always matches its view.
import { useMemo } from "react";

import { type ApiError, useAllPages, useResource } from "../api/client";
import type { Agent, AuditEvent, FindingGroup, Vulnerability, VulnerabilityPage } from "../api/types";
import type { PanelRef } from "../app/location";
import { auditSince, severityOrder } from "../ui/format";
import { matches } from "../ui/table";

export const LIST_VIEWS = ["/findings", "/vulnerabilities", "/agents", "/audit"] as const;
export type ListView = (typeof LIST_VIEWS)[number];
export type ListRow = { key: string; open: PanelRef; title: string; meta: string; badge: { label: string; tone: string } };

export type AdvisoryRow = {
  id: string; title: string; severity: string; cves: string[]; cvss: number | null; epss: number | null;
  exploited: boolean; kev: boolean; ransomware: boolean; hosts: number; reboot: number; noFix: boolean;
};

export function groupByAdvisory(items: readonly Vulnerability[]): AdvisoryRow[] {
  const rows = new Map<string, AdvisoryRow>();
  for (const item of items) {
    const row = rows.get(item.advisory_id) ?? {
      id: item.advisory_id, title: item.title, severity: item.severity, cves: item.cves, cvss: item.cvss ?? null, epss: item.epss ?? null,
      exploited: item.exploited, kev: item.kev, ransomware: item.ransomware, hosts: 0, reboot: 0,
      noFix: Array.isArray(item.packages) && (item.packages as { fixed?: unknown }[]).every((p) => p?.fixed == null),
    };
    row.hosts += 1;
    if (item.reboot_needed) row.reboot += 1;
    rows.set(item.advisory_id, row);
  }
  return [...rows.values()];
}

export function selectFindings(all: readonly FindingGroup[], params: URLSearchParams): FindingGroup[] {
  const severity = params.get("severity");
  const onlyOpen = params.get("state") !== "all";
  const ruleSet = params.get("set");
  const q = params.get("q") ?? "";
  return all.filter((g) => (!severity || g.severity === severity) && (!onlyOpen || g.triage_counts.open > 0)
    && (!ruleSet || g.rule_set_id === ruleSet) && matches([g.latest_message, g.rule_id, g.rule_set_id], q));
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

const sev = (s: string) => severityOrder[s] ?? 9;

/** The first rows of a list view for a query, ready for a compact list. */
export function useListRows(view: ListView | null, params: URLSearchParams): { rows: ListRow[]; total: number; loading: boolean; error: ApiError | undefined } {
  const groups = useAllPages<FindingGroup>(view === "/findings" ? "/api/v1/findings/groups" : null);
  const agents = useAllPages<Agent>(view === "/agents" ? "/api/v1/agents" : null);
  const vulns = useResource<VulnerabilityPage>(view === "/vulnerabilities" ? vulnerabilityQuery(params) : null);
  const audit = useAllPages<AuditEvent>(view === "/audit" ? `/api/v1/audit-events?since=${encodeURIComponent(auditSince(params))}` : null, 1000);
  return useMemo(() => {
    const status = view === "/findings" ? groups : view === "/agents" ? agents : view === "/audit" ? audit : vulns;
    let rows: ListRow[];
    if (view === "/findings") {
      rows = selectFindings(groups.data ?? [], params).sort((a, b) => sev(a.severity) - sev(b.severity) || b.triage_counts.open - a.triage_counts.open)
        .map((g) => ({ key: `${g.rule_set_id}/${g.rule_id}`, open: { kind: "finding", id: `${g.rule_set_id}/${g.rule_id}` }, title: g.latest_message,
          meta: `${g.rule_id} · ${g.triage_counts.open} open`, badge: { label: g.severity, tone: g.severity } }));
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
          badge: { label: r.severity, tone: r.severity } }));
    }
    const data = "data" in status ? status.data : undefined;
    return { rows, total: rows.length, loading: status.loading && data === undefined, error: status.error };
  }, [view, params, groups, agents, vulns, audit]);
}
