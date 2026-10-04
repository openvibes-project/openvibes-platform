import { useMemo } from "react";

import { useAllPages, useResource } from "../api/client";
import type { Agent, AgentSummary } from "../api/types";
import { nav, useLocation } from "../app/nav";
import { Ago, Empty, ErrorBox, Loading, SAVED_HEARTBEAT_HINT, StatusBadge } from "../ui/bits";
import { DataTable } from "../ui/DataTable";
import { date } from "../ui/format";
import { olderThan, selectAgents } from "./rows";
import { ViewHeader } from "../ui/ViewHeader";

export function Agents() {
  const { params, panels } = useLocation();
  const agents = useAllPages<Agent>("/api/v1/agents");
  const summary = useResource<AgentSummary>("/api/v1/agents/summary");
  const all = useMemo(() => agents.data ?? [], [agents.data]);
  const rows = useMemo(() => selectAgents(all, params), [all, params]);
  const top = panels[panels.length - 1];
  // Judged against this platform, not the fleet's highest claim (board #54).
  const platform = summary.data?.platform_version;

  return (
    <div className="view">
      <ViewHeader title="Hosts" count={rows.length} total={all.length} refresh="/api/v1/agents" placeholder="Filter by host name, ID or version…"
        chips={[
          { label: "Online", param: "status", value: "active", count: summary.data?.active },
          { label: "Stale", param: "status", value: "stale", count: summary.data?.stale },
          { label: "Imported", param: "status", value: "imported", count: summary.data?.imported },
          { label: "Revoked", param: "status", value: "revoked", count: summary.data?.revoked },
        ]} />
      {agents.error ? <div className="view-pad"><ErrorBox error={agents.error} /></div> : agents.loading && !agents.data ? <Loading /> : rows.length === 0 ? (
        <Empty icon="agents" title={all.length === 0 ? "No hosts yet" : "Nothing matches these filters"}>
          {all.length === 0 ? "Create an enrollment token under Enrollment, then install the agent on a host." : "Clear a filter to see more."}
        </Empty>
      ) : (
        <DataTable label="Hosts" rows={rows} rowKey={(a) => a.id}
          onOpen={(a) => nav.open({ kind: "agent", id: a.id }, true)}
          isOpen={(a) => top?.kind === "agent" && top.id === a.id}
          defaultSort={{ key: "host", direction: "asc" }}
          columns={[
            { key: "host", header: "Host", sort: (a) => a.hostname ?? a.id, render: (a) => <div className="cell-two"><span className="truncate">{a.hostname ?? "—"}</span><span className="mono subtle">{a.id}</span></div> },
            { key: "status", header: "Status", width: "110px", sort: (a) => a.status, render: (a) => <StatusBadge status={a.status} /> },
            { key: "seen", header: "Last saved heartbeat", width: "175px", hideBelow: 480, sort: (a) => a.last_seen_at, render: (a) => <span className={a.status === "stale" ? "warn-text" : "subtle"}><Ago value={a.last_seen_at} hint={SAVED_HEARTBEAT_HINT} /></span> },
            { key: "version", header: "Agent", width: "110px", hideBelow: 700, sort: (a) => a.scanner_version, render: (a) => a.scanner_version
              ? platform && olderThan(a.scanner_version, platform)
                ? <span className="mono warn-text" title={`Older than this platform (${platform})`}>{a.scanner_version}</span>
                : <span className="mono" title={platform ? `Not older than this platform (${platform})` : undefined}>{a.scanner_version}</span>
              : <span className="subtle">—</span> },
            { key: "enrolled", header: "Enrolled", width: "130px", hideBelow: 900, sort: (a) => a.enrolled_at, render: (a) => <span className="subtle">{date(a.enrolled_at)}</span> },
          ]} />
      )}
    </div>
  );
}
