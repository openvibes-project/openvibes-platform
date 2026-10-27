// Ports and Services (Assets v2): open ports and running services across
// the caller's hosts. The lists are small (distinct ports and units), so
// they load whole and filter in the browser.
import { useMemo } from "react";

import { useResource } from "../../api/client";
import type { PortRow } from "../../api/types";
import { nav, useLocation } from "../../app/nav";
import { Empty, ErrorBox, Loading } from "../../ui/bits";
import { DataTable } from "../../ui/DataTable";
import { ViewHeader } from "../../ui/ViewHeader";

const NOT_YET = "Agents report open ports and running services about an hour after they start.";

export function Ports() {
  const { params } = useLocation();
  const exposed = params.get("exposed") === "true";
  const q = (params.get("q") ?? "").toLowerCase();
  const url = `/api/v1/ports${exposed ? "?exposed=true" : ""}`;
  const ports = useResource<PortRow[]>(url);
  const rows = useMemo(() => (ports.data ?? []).filter((r) => !q || String(r.port).includes(q) || r.services.some((s) => s.toLowerCase().includes(q))), [ports.data, q]);
  return (
    <div className="view">
      <ViewHeader title="Ports" count={rows.length} total={ports.data?.length ?? 0} refresh={url} placeholder="Filter by port or service…"
        chips={[{ label: "Exposed", param: "exposed", value: "true" }]} />
      {ports.error ? <div className="view-pad"><ErrorBox error={ports.error} /></div> : ports.loading && !ports.data ? <Loading /> : rows.length === 0 ? (
        <Empty icon="activity" title={q || exposed ? "Nothing matches these filters" : "No ports reported yet"}>{q || exposed ? "Clear a filter to see more." : NOT_YET}</Empty>
      ) : (
        <DataTable label="Ports" rows={rows} onOpen={(r) => nav.open({ kind: "port", id: `${r.protocol}/${r.port}` }, true)} rowKey={(r) => `${r.protocol}/${r.port}`} defaultSort={{ key: "port", direction: "asc" }}
          columns={[
            { key: "port", header: "Port", sort: (r) => r.port, render: (r) => <span className="mono">{r.port}/{r.protocol}</span> },
            { key: "hosts", header: "Hosts", numeric: true, width: "90px", sort: (r) => r.hosts, render: (r) => <strong className="num">{r.hosts}</strong> },
            { key: "exposed", header: "Exposed on", numeric: true, width: "120px", sort: (r) => r.exposed_hosts,
              render: (r) => r.exposed_hosts > 0 ? <span className="badge badge--warn badge--plain">{r.exposed_hosts} hosts</span> : <span className="subtle">local only</span> },
            { key: "services", header: "Services", hideBelow: 560, sort: (r) => r.services.join(","), render: (r) => <span className="mono truncate">{r.services.join(", ") || "—"}</span> },
          ]} />
      )}
    </div>
  );
}
