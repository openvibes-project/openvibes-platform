import { useMemo } from "react";

import { useAllPages } from "../../api/client";
import type { Finding, FindingGroup } from "../../api/types";
import { nav, useLocation } from "../../app/nav";
import { TriageBar } from "../../panels/findings/FindingPanel";
import { Ago, Empty, ErrorBox, Loading, SeverityBadge } from "../../ui/bits";
import { BulkBar } from "../../panels/triage/BulkBar";
import { CaseBadge, useCaseBadges } from "../../panels/cases/CaseBadge";
import { highest } from "../../panels/triage/bulk";
import { DataTable } from "../../ui/DataTable";
import { filterKey, useSelection } from "../../ui/selection";
import { severityOrder } from "../../ui/format";
import { activeCount, hostFindingRows, selectFindings } from "../lists/rows";
import { ViewHeader } from "../../ui/ViewHeader";
import { filterChips } from "../lists/filters";
import { HostChip } from "../lists/HostChip";
import { isTest } from "../lists/testRules";

export function Findings() {
  const { params, panels } = useLocation();
  // Filtered to one host (plan ruling 9): that host's current findings, one row per rule.
  const host = params.get("host");
  const fleet = useAllPages<FindingGroup>(host ? null : "/api/v1/compliance/groups");
  const one = useAllPages<Finding>(host ? `/api/v1/compliance/latest?agent_id=${encodeURIComponent(host)}` : null);
  const groups = host ? one : fleet;
  const onlyOpen = params.get("state") !== "all";
  const all = useMemo(() => (host ? hostFindingRows(one.data ?? []) : fleet.data ?? []), [host, one.data, fleet.data]);
  // Filtered to one host, an action touches that host only.
  const on = host ? { agent_id: host } : {};
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
        filters={<HostChip id={host} />}
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
      {/* A selected finding acts on its hosts in scope; a close leaves the
          ones already closed alone. */}
      <BulkBar kind="compliance" noun={selected.size === 1 ? "finding" : "findings"} count={selected.size}
        onClear={() => setSelected(new Set())}
        items={() => chosen().map((g) => ({ rule_set_id: g.rule_set_id, rule_id: g.rule_id, ...on }))}
        closed={chosen().filter((g) => g.endpoint_count > g.triage_counts.open).length}
        reopenItems={() => chosen().filter((g) => g.endpoint_count > g.triage_counts.open).map((g) => ({ rule_set_id: g.rule_set_id, rule_id: g.rule_id, ...on }))}
        newCase={() => { const c = chosen(); return { title: `${c.length} findings: ${c[0]?.latest_message ?? ""}`, severity: highest(c.map((g) => g.severity)) }; }} />
    </div>
  );
}
