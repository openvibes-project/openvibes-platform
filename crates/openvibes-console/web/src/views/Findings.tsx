import { useMemo } from "react";

import { useAllPages } from "../api/client";
import type { FindingGroup } from "../api/types";
import { nav, useLocation } from "../app/nav";
import { TriageBar } from "../panels/FindingPanel";
import { Ago, Empty, ErrorBox, Loading, SeverityBadge } from "../ui/bits";
import { BulkBar } from "../panels/BulkBar";
import { CaseBadge, useCaseBadges } from "../panels/CaseBadge";
import { highest } from "../panels/bulk";
import { DataTable } from "../ui/DataTable";
import { filterKey, useSelection } from "../ui/selection";
import { severityOrder } from "../ui/format";
import { activeCount, selectFindings } from "./rows";
import { ViewHeader } from "../ui/ViewHeader";
import { filterChips } from "./filters";
import { isTest } from "./tests";

export function Findings() {
  const { params, panels } = useLocation();
  const groups = useAllPages<FindingGroup>("/api/v1/compliance/groups");
  const onlyOpen = params.get("state") !== "all";
  const all = useMemo(() => groups.data ?? [], [groups.data]);
  const rows = useMemo(() => selectFindings(all, params), [all, params]);
  const [selected, setSelected] = useSelection(filterKey(params));
  const chosen = () => rows.filter((g) => selected.has(`${g.rule_set_id}/${g.rule_id}`));
  const cases = useCaseBadges("compliance_finding");
  const top = panels[panels.length - 1];
  const sets = [...new Set(all.map((group) => group.rule_set_id))].sort((a, b) => a.localeCompare(b));
  const bySeverity = (s: string) => all.filter((g) => g.severity === s && (!onlyOpen || activeCount(g) > 0)).length;
  // Findings resolved on every host: hidden by default, counted on the chip
  // so the default filter is never invisible (#83).
  const resolved = all.filter((g) => activeCount(g) === 0).length;

  return (
    <div className="view">
      <ViewHeader title="Compliance" count={rows.length} total={all.length} refresh="/api/v1/compliance" placeholder="Filter by message, rule or rule set…"
        chips={[
          ...filterChips("/compliance").map((c) => ({ ...c, count: c.param === "state" ? resolved : bySeverity(c.value) })),
          ...sets.map((set) => ({ label: set, param: "set", value: set })),
        ]} />
      {groups.error ? <div className="view-pad"><ErrorBox error={groups.error} /></div> : groups.loading && !groups.data ? <Loading /> : rows.length === 0 ? (
        <Empty icon="findings" title={all.length === 0 ? "No compliance findings" : "Nothing matches these filters"}>
          {all.length === 0 ? "No host matches any rule. New matches appear here within a minute of the next scan."
            : onlyOpen && resolved > 0 ? <>{resolved.toLocaleString()} resolved {resolved === 1 ? "compliance finding is" : "compliance findings are"} hidden. <button type="button" className="link-button" onClick={() => nav.setParams({ state: "all" })}>Include resolved</button></>
            : "Clear a filter to see more."}
        </Empty>
      ) : (
        <DataTable label="Compliance" rows={rows} rowKey={(g) => `${g.rule_set_id}/${g.rule_id}`} selection={{ selected, onChange: setSelected }}
          onOpen={(g) => nav.open({ kind: "finding", id: `${g.rule_set_id}/${g.rule_id}` }, true)}
          isOpen={(g) => top?.kind === "finding" && top.id === `${g.rule_set_id}/${g.rule_id}`}
          defaultSort={{ key: "severity", direction: "asc" }}
          columns={[
            { key: "severity", header: "Severity", width: "110px", sort: (g) => (severityOrder[g.severity] ?? 9) * 100000 - activeCount(g), render: (g) => <SeverityBadge severity={g.severity} /> },
            { key: "finding", header: "Compliance finding", sort: (g) => g.latest_message, render: (g) => <div className="cell-two"><span className="truncate">{isTest(g.rule_set_id, g.rule_id) && <span className="badge badge--plain">Test</span>} {g.latest_message} <CaseBadge numbers={cases.get(`${g.rule_set_id}/${g.rule_id}`)} /></span><span className="mono subtle">{g.rule_id} · {g.rule_set_id}</span></div> },
            { key: "active", header: "Active", numeric: true, width: "80px", sort: (g) => activeCount(g), render: (g) => <strong className="num" title={`${g.triage_counts.open} open`}>{activeCount(g)}</strong> },
            { key: "hosts", header: "Hosts", numeric: true, width: "80px", hideBelow: 560, sort: (g) => g.endpoint_count, render: (g) => <span className="num">{g.endpoint_count}</span> },
            { key: "triage", header: "Triage", width: "140px", hideBelow: 760, render: (g) => <TriageBar counts={g.triage_counts} /> },
            { key: "last", header: "Last seen", width: "120px", hideBelow: 900, sort: (g) => g.last_observed_at, render: (g) => <span className="subtle"><Ago value={g.last_observed_at} /></span> },
          ]} />
      )}
      {/* A selected finding acts on every host in scope where it is current. */}
      <BulkBar kind="compliance" noun={selected.size === 1 ? "finding (all its hosts)" : "findings (all their hosts)"} count={selected.size}
        onClear={() => setSelected(new Set())}
        items={() => chosen().map((g) => ({ rule_set_id: g.rule_set_id, rule_id: g.rule_id }))}
        newCase={() => { const c = chosen(); return { title: `${c.length} findings: ${c[0]?.latest_message ?? ""}`, severity: highest(c.map((g) => g.severity)) }; }} />
    </div>
  );
}
