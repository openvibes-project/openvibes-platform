// Cases (rough draft): one place to investigate and close what the Alarms,
// Findings and Vulnerabilities views report. A case groups items, has one
// owner and one status, and is closed with a resolution.
//
// DRAFT: the cases below are placeholder data in this file. Next steps are
// to move them into src/demo (so the page loads them with `useResource`, as
// Alarms does), add a `case` panel to app/registry.tsx instead of the
// inline detail below, and wire the real API once the backend exists.
import { useMemo, useState } from "react";

import { Ago, Empty, SeverityBadge } from "../ui/bits";
import { DataTable } from "../ui/DataTable";
import { Icon } from "../ui/Icon";
import { severityOrder } from "../ui/format";
import { matches } from "../ui/table";
import { ViewHeader } from "../ui/ViewHeader";
import { useLocation } from "../app/nav";

type CaseStatus = "open" | "investigating" | "resolved" | "closed";
type ItemKind = "alarm" | "finding" | "vulnerability";

type CaseItem = { kind: ItemKind; title: string; host: string };

type CaseRow = {
  id: string;
  title: string;
  status: CaseStatus;
  severity: string;
  assignee: string | null;
  updated_at: number;
  items: CaseItem[];
  resolution?: string;
};

const statusLabel: Record<CaseStatus, string> = {
  open: "Open", investigating: "Investigating", resolved: "Resolved", closed: "Closed",
};
const statusTone: Record<CaseStatus, string> = { open: "bad", investigating: "warn", resolved: "ok", closed: "plain" };

const HOUR = 3_600_000;
const now = Date.now();

// Placeholder cases until the demo server provides them.
const sample: CaseRow[] = [
  { id: "C-104", title: "Suspicious shell spawned by nginx on web-02", status: "investigating", severity: "critical", assignee: "sam", updated_at: now - 0.5 * HOUR,
    items: [
      { kind: "alarm", title: "nginx → sh", host: "web-02" },
      { kind: "alarm", title: "nginx → curl", host: "web-02" },
      { kind: "vulnerability", title: "CVE-2025-1234 in nginx", host: "web-02" },
    ] },
  { id: "C-103", title: "SSH root login allowed across production", status: "open", severity: "high", assignee: null, updated_at: now - 5 * HOUR,
    items: [
      { kind: "finding", title: "ssh.root_login", host: "lab-1" },
      { kind: "finding", title: "ssh.root_login", host: "lab-2" },
    ] },
  { id: "C-102", title: "Kernel update pending on db hosts", status: "resolved", severity: "medium", assignee: "ola", updated_at: now - 30 * HOUR,
    items: [{ kind: "vulnerability", title: "CVE-2025-9876 in kernel", host: "db-01" }], resolution: "Patched and rebooted." },
  { id: "C-101", title: "Time sync not configured", status: "closed", severity: "low", assignee: "sam", updated_at: now - 96 * HOUR,
    items: [{ kind: "finding", title: "time.unsynced", host: "lab-3" }], resolution: "Accepted: lab hosts only." },
];

function StatusBadge({ status }: { status: CaseStatus }) {
  return <span className={`badge badge--${statusTone[status]}`}>{statusLabel[status]}</span>;
}

const kindIcon = { alarm: "alarm", finding: "findings", vulnerability: "vulnerabilities" } as const;

/** The loaded cases that match the URL's filters (`status`, `severity`, `q`). */
export function selectCases(all: readonly CaseRow[], params: URLSearchParams): CaseRow[] {
  const status = params.get("status");
  const severity = params.get("severity");
  const q = params.get("q") ?? "";
  return all.filter((c) =>
    (status === null ? c.status === "open" || c.status === "investigating" : status === "all" || c.status === status)
    && (severity === null || c.severity === severity)
    && matches([c.id, c.title, c.assignee ?? "unassigned", ...c.items.map((i) => i.host)], q));
}

export function Cases() {
  const { params } = useLocation();
  const [selected, setSelected] = useState<string | null>(null);
  const rows = useMemo(() => selectCases(sample, params), [params]);
  const detail = sample.find((c) => c.id === selected);

  return (
    <div className="view">
      <ViewHeader title="Cases" count={rows.length} total={sample.length} placeholder="Filter by id, title, assignee or host…"
        chips={[
          { label: "Include resolved and closed", param: "status", value: "all" },
          ...(["critical", "high", "medium", "low"] as const).map((s) => ({ label: s[0]?.toUpperCase() + s.slice(1), param: "severity", value: s })),
        ]} />
      {rows.length === 0 ? (
        <Empty icon="cases" title="No cases">
          Nothing matches these filters. Open cases appear here when an analyst groups alarms, findings or vulnerabilities into one.
        </Empty>
      ) : (
        <DataTable label="Cases" rows={rows} rowKey={(c) => c.id}
          onOpen={(c) => setSelected(c.id)}
          isOpen={(c) => c.id === selected}
          defaultSort={{ key: "updated", direction: "desc" }}
          columns={[
            { key: "severity", header: "Severity", width: "110px", sort: (c) => severityOrder[c.severity] ?? 9, render: (c) => <SeverityBadge severity={c.severity} /> },
            { key: "case", header: "Case", sort: (c) => c.title, render: (c) => <div className="cell-two"><span className="truncate">{c.title}</span><span className="mono subtle">{c.id}</span></div> },
            { key: "items", header: "Items", numeric: true, width: "80px", hideBelow: 560, sort: (c) => c.items.length, render: (c) => <span className="num">{c.items.length}</span> },
            { key: "status", header: "Status", width: "140px", hideBelow: 760, sort: (c) => c.status, render: (c) => <StatusBadge status={c.status} /> },
            { key: "assignee", header: "Assignee", width: "130px", hideBelow: 760, sort: (c) => c.assignee ?? "", render: (c) => <span className={c.assignee ? "" : "subtle"}>{c.assignee ?? "Unassigned"}</span> },
            { key: "updated", header: "Updated", width: "120px", hideBelow: 900, sort: (c) => c.updated_at, render: (c) => <span className="subtle"><Ago value={c.updated_at} /></span> },
          ]} />
      )}
      {detail && (
        <section className="view-pad stack" aria-label={`Case ${detail.id}`}>
          <h2>{detail.id}: {detail.title}</h2>
          <div className="row"><StatusBadge status={detail.status} /> <SeverityBadge severity={detail.severity} /> <span className="subtle">{detail.assignee ?? "Unassigned"}</span></div>
          {detail.resolution && <p>Resolution: {detail.resolution}</p>}
          <ul className="stack">
            {detail.items.map((item) => (
              <li key={`${item.kind}-${item.title}-${item.host}`} className="row">
                <Icon name={kindIcon[item.kind]} size={15} /> {item.title} <span className="subtle">on {item.host}</span>
              </li>
            ))}
          </ul>
          <div className="row">
            <button type="button" className="button" disabled>Assign</button>
            <button type="button" className="button button--primary" disabled>Close case</button>
            <button type="button" className="button button--ghost" onClick={() => setSelected(null)}>Hide</button>
          </div>
        </section>
      )}
    </div>
  );
}