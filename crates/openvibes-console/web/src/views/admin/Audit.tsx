// The audit log: who did what, kept for the retention period.
import { isDemo, useAllPages, useResource } from "../../api/client";
import type { AuditEvent, AuditRetention } from "../../api/types";
import { nav, useLocation, useTopPanel } from "../../app/nav";
import { useSession } from "../../app/session";
import { DataTable } from "../../ui/DataTable";
import { Icon } from "../../ui/Icon";
import { ViewHeader } from "../../ui/ViewHeader";
import { Ago, Empty, ErrorBox, Loading } from "../../ui/bits";
import { auditSince } from "../../ui/format";
import { filterChips } from "../lists/filters";
import { selectAudit } from "../lists/rows";

/** The demo has no server to export from: build the same columns in the browser. */
function downloadCsv(events: readonly AuditEvent[]) {
  const cell = (value: string | null | undefined) => `"${String(value ?? "").replaceAll('"', '""')}"`;
  const lines = [["at", "action", "actor", "target", "result"].join(","), ...events.map((e) => [e.at, e.action, e.actor, e.target, e.result].map(cell).join(","))];
  const url = URL.createObjectURL(new Blob([`${lines.join("\n")}\n`], { type: "text/csv" }));
  const link = Object.assign(document.createElement("a"), { href: url, download: "openvibes-audit-demo.csv" });
  link.click();
  URL.revokeObjectURL(url);
}

export function Audit() {
  const { can } = useSession();
  const { params } = useLocation();
  const since = auditSince(params);
  const page = useAllPages<AuditEvent>(`/api/v1/audit-events?since=${encodeURIComponent(since)}`, 1000);
  const retention = useResource<AuditRetention>("/api/v1/audit-retention");
  const top = useTopPanel();
  const rows = selectAudit(page.data ?? [], params);
  return (
    <div className="view">
      <ViewHeader title="Audit log" count={rows.length} refresh="/api/v1/audit" placeholder="Filter by action, person or target…"
        chips={[
          ...filterChips("/audit"),
        ]}
        actions={<>
          {retention.data && <button type="button" className="button button--ghost" onClick={() => nav.open({ kind: "audit-retention", id: "policy" }, true)} title="Retention policy"><Icon name="clock" size={15} /> Kept {retention.data.retention_days} days</button>}
          {can("audit.export", true) && (isDemo()
            ? <button type="button" className="button" onClick={() => downloadCsv(rows)}><Icon name="download" size={15} /> Export CSV</button>
            : <a className="button" href={`/api/v1/audit-export.csv?since=${encodeURIComponent(since)}`} download><Icon name="download" size={15} /> Export CSV</a>)}
        </>} />
      {page.error ? <div className="view-pad"><ErrorBox error={page.error} /></div> : !page.data ? <Loading /> : rows.length === 0 ? (
        <Empty icon="audit" title={page.data.length === 0 ? "No audit events in this range" : "Nothing matches these filters"}>
          {page.data.length === 0 ? "Actions recorded by the platform appear here." : "Clear a filter to see more."}
        </Empty>
      ) : (
        <DataTable label="Audit events" compact rows={rows} rowKey={(e) => e.id}
          onOpen={(e) => nav.open({ kind: "audit-event", id: e.id }, true)}
          isOpen={(e) => top?.kind === "audit-event" && top.id === e.id}
          defaultSort={{ key: "at", direction: "desc" }}
          columns={[
            { key: "at", header: "When", width: "130px", sort: (e) => e.at, render: (e) => <span className="subtle"><Ago value={e.at} /></span> },
            { key: "action", header: "Action", sort: (e) => e.action, render: (e) => <span className="mono">{e.action}</span> },
            { key: "actor", header: "Who", width: "140px", sort: (e) => e.actor, render: (e) => e.actor },
            { key: "target", header: "Target", hideBelow: 800, sort: (e) => e.target, render: (e) => <span className="mono subtle truncate">{e.target ?? "—"}</span> },
            { key: "result", header: "Result", width: "100px", sort: (e) => e.result, render: (e) => <span className={`badge badge--${e.result === "success" ? "ok" : "bad"}`}>{e.result}</span> },
          ]} />
      )}
    </div>
  );
}
