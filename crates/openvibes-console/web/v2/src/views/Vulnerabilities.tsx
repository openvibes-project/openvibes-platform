// Vulnerabilities by advisory (one row per fix, not per host), because a
// fix is what someone acts on; the panel lists the hosts.
import { useMemo } from "react";

import { useResource } from "../api/client";
import type { Vulnerability, VulnerabilityPage } from "../api/types";
import { nav, useLocation } from "../app/nav";
import { Empty, ErrorBox, Loading, SeverityBadge } from "../ui/bits";
import { DataTable } from "../ui/DataTable";
import { pct, severityOrder } from "../ui/format";
import { Icon } from "../ui/Icon";
import { matches } from "../ui/table";
import { ViewHeader } from "../ui/ViewHeader";

type Row = {
  id: string; title: string; severity: string; cves: string[]; cvss: number | null; epss: number | null;
  exploited: boolean; kev: boolean; ransomware: boolean; hosts: number; reboot: number; noFix: boolean;
};

export function groupByAdvisory(items: readonly Vulnerability[]): Row[] {
  const rows = new Map<string, Row>();
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

export function Vulnerabilities() {
  const { params, panels } = useLocation();
  const query = new URLSearchParams();
  if (params.get("exploited") === "true") query.set("exploited", "true");
  if (params.get("reboot") === "true") query.set("reboot_needed", "true");
  if (params.get("severity")) query.set("severity", params.get("severity") ?? "");
  const list = useResource<VulnerabilityPage>(`/api/v1/vulnerabilities${query.size ? `?${query}` : ""}`);
  const q = params.get("q") ?? "";
  const all = useMemo(() => groupByAdvisory(list.data?.items ?? []), [list.data]);
  const rows = useMemo(() => all.filter((row) => (params.get("nofix") !== "true" || row.noFix) && matches([row.title, row.id, ...row.cves], q)), [all, q, params]);
  const top = panels[panels.length - 1];

  return (
    <div className="view">
      <ViewHeader title="Vulnerabilities" count={rows.length} refresh="/api/v1/vulnerabilities" placeholder="Filter by package, advisory or CVE…"
        chips={[
          { label: "Known exploited", param: "exploited", value: "true" },
          { label: "Reboot needed", param: "reboot", value: "true" },
          { label: "No fix yet", param: "nofix", value: "true" },
          ...(["critical", "important", "moderate", "low"] as const).map((s) => ({ label: s[0]?.toUpperCase() + s.slice(1), param: "severity", value: s })),
        ]} />
      {list.data?.more_available && <p className="view-note"><Icon name="alert" size={14} /> Showing the first results only; narrow the filters to see the rest.</p>}
      {list.error ? <div className="view-pad"><ErrorBox error={list.error} /></div> : list.loading && !list.data ? <Loading /> : rows.length === 0 ? (
        <Empty icon="vulnerabilities" title={all.length === 0 ? "No open vulnerabilities" : "Nothing matches these filters"}>
          {all.length === 0 ? "Every package in your scope is up to date against the advisories the platform knows." : "Clear a filter to see more."}
        </Empty>
      ) : (
        <DataTable label="Vulnerabilities" rows={rows} rowKey={(row) => row.id}
          onOpen={(row) => nav.open({ kind: "advisory", id: row.id }, true)}
          isOpen={(row) => top?.kind === "advisory" && top.id === row.id}
          defaultSort={{ key: "priority", direction: "asc" }}
          columns={[
            { key: "priority", header: "Severity", width: "120px", sort: (r) => (r.exploited ? 0 : 10) + (severityOrder[r.severity] ?? 9) - (r.epss ?? 0), render: (r) => <SeverityBadge severity={r.severity} /> },
            { key: "title", header: "Advisory", sort: (r) => r.title, render: (r) => (
              <div className="cell-two">
                <span className="row"><span className="truncate">{r.title}</span>
                  {r.exploited && <span className="badge badge--critical badge--plain" title="Known to be exploited"><Icon name="flame" size={12} /> Exploited</span>}
                  {r.noFix && <span className="badge badge--plain">No fix yet</span>}
                </span>
                <span className="mono subtle truncate">{r.id} · {r.cves.slice(0, 2).join(", ")}{r.cves.length > 2 ? ` +${r.cves.length - 2}` : ""}</span>
              </div>
            ) },
            { key: "cvss", header: "CVSS", numeric: true, width: "70px", hideBelow: 700, sort: (r) => r.cvss, render: (r) => <span className="num">{r.cvss?.toFixed(1) ?? "—"}</span> },
            { key: "epss", header: "EPSS", numeric: true, width: "80px", hideBelow: 800, sort: (r) => r.epss, render: (r) => <span className="num subtle">{pct(r.epss)}</span> },
            { key: "hosts", header: "Hosts", numeric: true, width: "70px", sort: (r) => r.hosts, render: (r) => <strong className="num">{r.hosts}</strong> },
            { key: "reboot", header: "Reboot", numeric: true, width: "80px", hideBelow: 950, sort: (r) => r.reboot, render: (r) => r.reboot > 0 ? <span className="num">{r.reboot}</span> : <span className="subtle">—</span> },
          ]} />
      )}
    </div>
  );
}
