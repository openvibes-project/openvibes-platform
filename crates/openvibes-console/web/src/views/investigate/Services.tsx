// Services (Assets v2): running services across the caller's hosts. The list
// is small (distinct units), so it loads whole and filters in the browser.
import { useMemo } from "react";

import { useResource } from "../../api/client";
import type { UnitRow } from "../../api/types";
import { nav, useLocation } from "../../app/nav";
import { Empty, ErrorBox, Loading } from "../../ui/bits";
import { DataTable } from "../../ui/DataTable";
import { ViewHeader } from "../../ui/ViewHeader";

const NOT_YET = "Agents report open ports and running services about an hour after they start.";

export function Services() {
  const { params } = useLocation();
  const q = (params.get("q") ?? "").toLowerCase();
  const units = useResource<UnitRow[]>("/api/v1/services");
  const rows = useMemo(() => (units.data ?? []).filter((r) => !q || r.unit.toLowerCase().includes(q)), [units.data, q]);
  return (
    <div className="view">
      <ViewHeader title="Services" count={rows.length} total={units.data?.length ?? 0} refresh="/api/v1/services" placeholder="Filter by service…" />
      {units.error ? <div className="view-pad"><ErrorBox error={units.error} /></div> : units.loading && !units.data ? <Loading /> : rows.length === 0 ? (
        <Empty icon="layers" title={q ? "Nothing matches this filter" : "No services reported yet"}>{q ? "Clear the filter to see more." : NOT_YET}</Empty>
      ) : (
        <DataTable label="Services" rows={rows} onOpen={(r) => nav.open({ kind: "unit", id: r.unit }, true)} rowKey={(r) => r.unit} defaultSort={{ key: "unit", direction: "asc" }}
          columns={[
            { key: "unit", header: "Service", sort: (r) => r.unit, render: (r) => <span className="mono truncate">{r.unit}</span> },
            { key: "hosts", header: "Hosts", numeric: true, width: "90px", sort: (r) => r.hosts, render: (r) => <strong className="num">{r.hosts}</strong> },
          ]} />
      )}
    </div>
  );
}
