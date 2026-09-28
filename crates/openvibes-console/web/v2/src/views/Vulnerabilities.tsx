// Vulnerabilities by advisory (one row per fix, not per host), because a
// fix is what someone acts on; the panel lists the hosts.
import { useMemo } from "react";

import { useResource } from "../api/client";
import type { VulnerabilityPage } from "../api/types";
import { nav, useLocation } from "../app/nav";
import { Empty, ErrorBox, Loading, SeverityBadge } from "../ui/bits";
import { DataTable } from "../ui/DataTable";
import { pct, severityOrder } from "../ui/format";
import { Icon } from "../ui/Icon";
import { ViewHeader } from "../ui/ViewHeader";
import { groupByAdvisory, selectAdvisories, vulnerabilityQuery } from "./rows";

export function Vulnerabilities() {
  const { params, panels } = useLocation();
  const list = useResource<VulnerabilityPage>(vulnerabilityQuery(params));
  const all = useMemo(() => groupByAdvisory(list.data?.items ?? []), [list.data]);
  const rows = useMemo(() => selectAdvisories(all, params), [all, params]);
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
