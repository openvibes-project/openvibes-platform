import { useMemo } from "react";

import { useAllPages } from "../api/client";
import type { FindingGroup } from "../api/types";
import { nav, useLocation } from "../app/nav";
import { TriageBar } from "../panels/FindingPanel";
import { Ago, Empty, ErrorBox, Loading, SeverityBadge } from "../ui/bits";
import { DataTable } from "../ui/DataTable";
import { severityOrder } from "../ui/format";
import { matches } from "../ui/table";
import { ViewHeader } from "../ui/ViewHeader";

export function Findings() {
  const { params, panels } = useLocation();
  const groups = useAllPages<FindingGroup>("/api/v1/findings/groups");
  const severity = params.get("severity");
  const onlyOpen = params.get("state") !== "all";
  const ruleSet = params.get("set");
  const q = params.get("q") ?? "";
  const all = useMemo(() => groups.data ?? [], [groups.data]);
  const rows = useMemo(() => all.filter((group) =>
    (!severity || group.severity === severity) && (!onlyOpen || group.triage_counts.open > 0) && (!ruleSet || group.rule_set_id === ruleSet) &&
    matches([group.latest_message, group.rule_id, group.rule_set_id], q)), [all, severity, onlyOpen, ruleSet, q]);
  const top = panels[panels.length - 1];
  const sets = [...new Set(all.map((group) => group.rule_set_id))].sort();
  const bySeverity = (s: string) => all.filter((g) => g.severity === s && (!onlyOpen || g.triage_counts.open > 0)).length;

  return (
    <div className="view">
      <ViewHeader title="Findings" count={rows.length} total={all.length} refresh="/api/v1/findings" placeholder="Filter by message, rule or rule set…"
        chips={[
          { label: "Include resolved", param: "state", value: "all" },
          ...(["critical", "high", "medium", "low"] as const).map((s) => ({ label: s[0]?.toUpperCase() + s.slice(1), param: "severity", value: s, count: bySeverity(s) })),
          ...sets.map((set) => ({ label: set, param: "set", value: set })),
        ]} />
      {groups.error ? <div className="view-pad"><ErrorBox error={groups.error} /></div> : groups.loading && !groups.data ? <Loading /> : rows.length === 0 ? (
        <Empty icon="findings" title={all.length === 0 ? "No findings" : "Nothing matches these filters"}>
          {all.length === 0 ? "No host matches any rule. New matches appear here within a minute of the next scan." : "Clear a filter to see more."}
        </Empty>
      ) : (
        <DataTable label="Findings" rows={rows} rowKey={(g) => `${g.rule_set_id}/${g.rule_id}`}
          onOpen={(g) => nav.open({ kind: "finding", id: `${g.rule_set_id}/${g.rule_id}` }, true)}
          isOpen={(g) => top?.kind === "finding" && top.id === `${g.rule_set_id}/${g.rule_id}`}
          defaultSort={{ key: "severity", direction: "asc" }}
          columns={[
            { key: "severity", header: "Severity", width: "110px", sort: (g) => (severityOrder[g.severity] ?? 9) * 100000 - g.triage_counts.open, render: (g) => <SeverityBadge severity={g.severity} /> },
            { key: "finding", header: "Finding", sort: (g) => g.latest_message, render: (g) => <div className="cell-two"><span className="truncate">{g.latest_message}</span><span className="mono subtle">{g.rule_id} · {g.rule_set_id}</span></div> },
            { key: "open", header: "Open", numeric: true, width: "80px", sort: (g) => g.triage_counts.open, render: (g) => <strong className="num">{g.triage_counts.open}</strong> },
            { key: "hosts", header: "Hosts", numeric: true, width: "80px", hideBelow: 560, sort: (g) => g.endpoint_count, render: (g) => <span className="num">{g.endpoint_count}</span> },
            { key: "triage", header: "Triage", width: "140px", hideBelow: 760, render: (g) => <TriageBar counts={g.triage_counts} /> },
            { key: "last", header: "Last seen", width: "120px", hideBelow: 900, sort: (g) => g.last_observed_at, render: (g) => <span className="subtle"><Ago value={g.last_observed_at} /></span> },
          ]} />
      )}
    </div>
  );
}
