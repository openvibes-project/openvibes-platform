// Cases: where one investigation happens. The list shows open and
// investigating cases by default; a row opens the case in the inspector.
import { useMemo } from "react";

import { useAllPages } from "../api/client";
import type { CaseSummary } from "../api/types";
import { nav, useLocation } from "../app/nav";
import { useSession } from "../app/session";
import { caseNumber, caseQuery, selectCases, severities, statusBadge } from "../panels/cases";
import { Ago, Empty, ErrorBox, Loading, SeverityBadge } from "../ui/bits";
import { DataTable } from "../ui/DataTable";
import { severityOrder } from "../ui/format";
import { Icon } from "../ui/Icon";
import { ViewHeader } from "../ui/ViewHeader";

export function CaseStatusBadge({ status, resolution }: { status: string; resolution?: string | null | undefined }) {
  const badge = statusBadge(status, resolution);
  return <span className={`badge badge--${badge.tone}`}>{badge.label}</span>;
}

const filterParams = ["status", "severity", "assignee", "q"];

export function Cases() {
  const { params, panels } = useLocation();
  const { can } = useSession();
  const list = useAllPages<CaseSummary>(caseQuery(params));
  const loaded = useMemo(() => list.data ?? [], [list.data]);
  const rows = useMemo(() => selectCases(loaded, params), [loaded, params]);
  const top = panels[panels.length - 1];
  const filtered = filterParams.some((name) => params.get(name));

  return (
    <div className="view">
      <ViewHeader title="Cases" count={rows.length} total={loaded.length} refresh="/api/v1/case" placeholder="Filter by title, C-104 or assignee…"
        actions={can("cases.manage") && (
          <button type="button" className="button button--primary" onClick={() => nav.open({ kind: "case", id: "new" }, true)}>
            <Icon name="plus" size={15} /> New case
          </button>
        )}
        chips={[
          { label: "Open", param: "status", value: "open" },
          { label: "Investigating", param: "status", value: "investigating" },
          { label: "Closed", param: "status", value: "closed" },
          { label: "Include closed", param: "status", value: "all" },
          ...severities.map((s) => ({ label: s[0]?.toUpperCase() + s.slice(1), param: "severity", value: s })),
          { label: "Assigned to me", param: "assignee", value: "me" },
          { label: "Unassigned", param: "assignee", value: "none" },
        ]} />
      {list.error ? <div className="view-pad"><ErrorBox error={list.error} /></div> : list.loading && !list.data ? <Loading /> : rows.length === 0 ? (
        <Empty icon="cases" title={filtered ? "Nothing matches these filters" : "No open cases"}>
          {filtered
            ? "Closed cases are hidden unless Include closed is on; clear a filter to see more."
            : `A case gathers what belongs to one investigation: hosts, alarms, findings and vulnerabilities, with notes and a timeline.${can("cases.manage") ? " Start one with New case, or use Add to case on an alarm, finding or host." : ""}`}
        </Empty>
      ) : (
        <DataTable label="Cases" rows={rows} rowKey={(c) => c.case_id}
          onOpen={(c) => nav.open({ kind: "case", id: c.case_id }, true)}
          isOpen={(c) => top?.kind === "case" && top.id === c.case_id}
          defaultSort={{ key: "updated", direction: "desc" }}
          columns={[
            { key: "number", header: "Case", width: "90px", sort: (c) => c.number, render: (c) => <span className="mono nowrap">{caseNumber(c.number)}</span> },
            { key: "title", header: "Title", sort: (c) => c.title, render: (c) => <div className="cell-two"><span className="truncate">{c.title}</span><span className="subtle">Opened by {c.opened_by.display_name}</span></div> },
            { key: "severity", header: "Severity", width: "110px", sort: (c) => severityOrder[c.severity] ?? 9, render: (c) => <SeverityBadge severity={c.severity} /> },
            { key: "status", header: "Status", width: "190px", hideBelow: 700, sort: (c) => c.status, render: (c) => <CaseStatusBadge status={c.status} resolution={c.resolution} /> },
            { key: "assignee", header: "Assignee", width: "130px", hideBelow: 820, sort: (c) => c.assignee?.username ?? "", render: (c) => <span className={c.assignee ? "truncate" : "subtle"}>{c.assignee?.display_name ?? "Unassigned"}</span> },
            { key: "items", header: "Items", width: "170px", hideBelow: 560, sort: (c) => c.item_count, render: (c) => (
              <span className="row">
                <span className="num">{c.item_count}</span>
                {c.pending_item_count > 0 && c.status !== "closed" && <span className="badge badge--warn badge--plain" title="Alarms, findings and vulnerabilities without an outcome">{c.pending_item_count} unresolved</span>}
              </span>
            ) },
            { key: "updated", header: "Updated", width: "120px", hideBelow: 940, sort: (c) => c.updated_at, render: (c) => <span className="subtle"><Ago value={c.updated_at} /></span> },
          ]} />
      )}
    </div>
  );
}
