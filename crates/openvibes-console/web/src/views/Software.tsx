// Software (Assets v1): every package across the caller's hosts, how many
// hosts have it and which versions are in use. A row opens the package.
import { useMemo, useState } from "react";

import { useAllPages } from "../api/client";
import type { Software as SoftwareRow } from "../api/types";
import { nav, useLocation } from "../app/nav";
import { Empty, ErrorBox, Loading } from "../ui/bits";
import { DataTable } from "../ui/DataTable";
import { ViewHeader } from "../ui/ViewHeader";

/** Rows fetched per "Load more" (the API's page size). */
const PAGE = 100;

/** The package panel's id: manager and name, which may contain "/". */
export function packageId(row: { manager: string; name: string }): string {
  return `${row.manager}/${row.name}`;
}

export function Software() {
  const { params, panels } = useLocation();
  const [max, setMax] = useState(PAGE);
  // The name filter and "fix available" are applied by the API, so paging
  // stays exact on large fleets.
  const query = new URLSearchParams();
  const q = params.get("q");
  if (q) query.set("q", q);
  if (params.get("fixable") === "true") query.set("fixable", "true");
  const software = useAllPages<SoftwareRow>(`/api/v1/software?${query.toString()}`, max);
  const rows = useMemo(() => software.data ?? [], [software.data]);
  const top = panels[panels.length - 1];
  return (
    <div className="view">
      <ViewHeader title="Software" count={rows.length} total={rows.length} refresh="/api/v1/software" placeholder="Filter by package name…"
        chips={[{ label: "Fix available", param: "fixable", value: "true" }]} />
      {software.error ? <div className="view-pad"><ErrorBox error={software.error} /></div> : software.loading && !software.data ? <Loading /> : rows.length === 0 ? (
        <Empty icon="package" title={q || params.get("fixable") ? "Nothing matches these filters" : "No software reported yet"}>
          {q || params.get("fixable") ? "Clear a filter to see more." : "Agents report their installed packages shortly after they enroll."}
        </Empty>
      ) : (
        <DataTable label="Software" rows={rows} rowKey={packageId}
          onOpen={(row) => nav.open({ kind: "package", id: packageId(row) }, true)}
          isOpen={(row) => top?.kind === "package" && top.id === packageId(row)}
          defaultSort={{ key: "name", direction: "asc" }}
          columns={[
            { key: "name", header: "Package", sort: (row) => row.name, render: (row) => <div className="cell-two"><span className="mono truncate">{row.name}</span><span className="subtle">{row.manager}</span></div> },
            { key: "hosts", header: "Hosts", numeric: true, width: "90px", sort: (row) => row.hosts, render: (row) => <strong className="num">{row.hosts}</strong> },
            { key: "versions", header: "Versions", numeric: true, width: "100px", hideBelow: 560, sort: (row) => row.versions, render: (row) => <span className="num">{row.versions}</span> },
            { key: "fixable", header: "Fix available", numeric: true, width: "130px", hideBelow: 760, sort: (row) => row.fixable_vulnerable_hosts,
              render: (row) => row.fixable_vulnerable_hosts > 0 ? <span className="badge badge--warn badge--plain">{row.fixable_vulnerable_hosts} hosts</span> : <span className="subtle">—</span> },
          ]} />
      )}
      {rows.length >= max && (
        <div className="view-pad"><button type="button" className="button" onClick={() => setMax((m) => m + PAGE)}>Load {PAGE} more</button></div>
      )}
    </div>
  );
}
