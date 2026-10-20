// Threat alarms (P14): process starts that matched a rule, newest first.
import { useMemo, useState } from "react";

import { useAllPages, useResource } from "../../api/client";
import type { AlarmPage, AlarmSummary, AlarmSuppression } from "../../api/types";
import { nav, useLocation } from "../../app/nav";
import { useSession } from "../../app/session";
import { SuppressButton } from "../../panels/alarms/SuppressForm";
import { BulkBar } from "../../panels/triage/BulkBar";
import { CaseBadge, useCaseBadges } from "../../panels/cases/CaseBadge";
import { highest } from "../../panels/triage/bulk";
import { DataTable } from "../../ui/DataTable";
import { ViewHeader } from "../../ui/ViewHeader";
import { Ago, Empty, ErrorBox, Loading, SeverityBadge, TriageBadge } from "../../ui/bits";
import { severityOrder } from "../../ui/format";
import { filterKey, useSelection } from "../../ui/selection";
import { matches } from "../../ui/table";
import { isTest } from "../lists/testRules";

/** Alarms fetched per "Load more" (the API's page size). */
const PAGE = 100;

/** `parent → program`, by base name, the way an analyst reads it. */
export function lineage(alarm: Pick<AlarmSummary, "exe" | "parent_exe">): string {
  const base = (path: string) => path.split("/").pop() || path;
  return alarm.parent_exe ? `${base(alarm.parent_exe)} → ${base(alarm.exe)}` : base(alarm.exe);
}

/** The API query for the list's filters; the text filter stays local. */
function alarmQuery(params: URLSearchParams): string {
  const query = new URLSearchParams();
  if (params.get("state") !== "all") query.set("state", "active");
  const severity = params.get("severity");
  if (severity) query.set("severity", severity);
  if (params.get("suppressed") === "true") query.set("suppressed", "true");
  return `/api/v1/alarms?${query.toString()}`;
}

/** The loaded alarms that match the text filter. */
function selectAlarms(loaded: readonly AlarmSummary[], params: URLSearchParams): AlarmSummary[] {
  const q = params.get("q") ?? "";
  return loaded.filter((a) => matches([a.message, a.rule_id, a.hostname ?? a.agent_id, a.exe, a.parent_exe ?? ""], q));
}

export function Alarms() {
  const { params, panels } = useLocation();
  // Alarms are per occurrence and can run to thousands: the newest pages
  // only, filtered on the server, more on request.
  // ponytail: Load more refetches from the first page (useAllPages); keep
  // the cursor and append if people page deep.
  const [max, setMax] = useState(PAGE);
  const path = alarmQuery(params);
  const alarms = useAllPages<AlarmSummary>(path, max);
  const loaded = useMemo(() => alarms.data ?? [], [alarms.data]);
  const rows = useMemo(() => selectAlarms(loaded, params), [loaded, params]);
  const [selected, setSelected] = useSelection(filterKey(params));
  const chosen = () => rows.filter((a) => selected.has(a.id));
  const cases = useCaseBadges("alarm");
  // Alarms with my own waiting request show it, not a second Suppress….
  const { can } = useSession();
  const waiting = useResource<{ items: AlarmSuppression[] }>(can("alarms.suppressions.read") && can("alarms.suppress") ? "/api/v1/alarm-suppressions?state=waiting" : null);
  const requested = useMemo(() => new Set((waiting.data?.items ?? []).filter((s) => s.can_withdraw && s.alarm_id).map((s) => s.alarm_id)), [waiting.data]);
  const top = panels[panels.length - 1];
  // An empty filtered page: does any alarm exist at all? If not, the
  // empty state explains how to turn alarms on, not the chips.
  const any = useResource<AlarmPage>(alarms.data && loaded.length === 0 ? "/api/v1/alarms?suppressed=true&limit=1" : null);
  const none = loaded.length === 0 && any.data?.items.length === 0;

  return (
    <div className="view">
      <ViewHeader title="Alarms" count={rows.length} total={loaded.length} refresh="/api/v1/alarms" placeholder="Filter by message, rule, host or program…"
        chips={[
          { label: "Include resolved", param: "state", value: "all" },
          { label: "Include suppressed", param: "suppressed", value: "true" },
          ...(["critical", "high", "medium", "low"] as const).map((s) => ({ label: s[0]?.toUpperCase() + s.slice(1), param: "severity", value: s })),
        ]} />
      {alarms.error ? <div className="view-pad"><ErrorBox error={alarms.error} /></div> : alarms.loading && !alarms.data ? <Loading /> : rows.length === 0 ? (
        <Empty icon="alarm" title={none ? "No alarms" : "Nothing matches these filters"}>
          {none
            ? "Alarms appear here within seconds of a matching program start. Agents report process starts by themselves; each host's page says whether its alarms are on."
            : "Resolved and suppressed alarms are hidden unless their chips are on; clear a filter to see more."}
        </Empty>
      ) : (
        <DataTable label="Alarms" rows={rows} rowKey={(a) => a.id} selection={{ selected, onChange: setSelected }}
          onOpen={(a) => nav.open({ kind: "alarm", id: a.id }, true)}
          isOpen={(a) => top?.kind === "alarm" && top.id === a.id}
          defaultSort={{ key: "last", direction: "desc" }}
          columns={[
            { key: "severity", header: "Severity", width: "110px", sort: (a) => severityOrder[a.severity] ?? 9, render: (a) => <SeverityBadge severity={a.severity} /> },
            { key: "alarm", header: "Alarm", sort: (a) => a.message, render: (a) => <div className="cell-two"><span className="truncate">{isTest(a.rule_set_id, a.rule_id) && <span className="badge badge--plain">Test</span>} {a.message} <CaseBadge numbers={cases.get(a.id)} /></span><span className="mono subtle">{lineage(a)}</span></div> },
            { key: "host", header: "Host", width: "160px", hideBelow: 560, sort: (a) => a.hostname ?? a.agent_id, render: (a) => <span className="truncate">{a.hostname ?? a.agent_id}</span> },
            { key: "count", header: "Count", numeric: true, width: "80px", sort: (a) => a.count, render: (a) => <span className="num">{a.count}</span> },
            { key: "state", header: "Triage", width: "130px", hideBelow: 760, sort: (a) => a.state, render: (a) => <TriageBadge state={a.state} /> },
            { key: "last", header: "Last seen", width: "120px", hideBelow: 900, sort: (a) => a.last_seen, render: (a) => <span className="subtle"><Ago value={a.last_seen} /></span> },
            { key: "suppress", header: "Suppress", width: "120px", hideBelow: 900, render: (a) => requested.has(a.id)
              ? <span className="badge badge--plain" title="Your suppression request waits for approval">Requested</span>
              : <SuppressButton alarm={a} label={`Suppress… ${a.message} on ${a.hostname ?? a.agent_id}`} /> },
          ]} />
      )}
      <BulkBar kind="alarms" noun={selected.size === 1 ? "alarm" : "alarms"} count={selected.size} onClear={() => setSelected(new Set())}
        items={() => chosen().map((a) => ({ id: a.id }))}
        closed={chosen().filter((a) => a.state !== "open").length}
        reopenItems={() => chosen().filter((a) => a.state !== "open").map((a) => ({ id: a.id }))}
        newCase={() => { const c = chosen(); return { title: `${c.length} alarms: ${c[0]?.message ?? ""}`, severity: highest(c.map((a) => a.severity)) }; }} />
      {loaded.length >= max && (
        <div className="view-pad"><button type="button" className="button" onClick={() => setMax((m) => m + PAGE)}>Load {PAGE} more</button></div>
      )}
    </div>
  );
}
