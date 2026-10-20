// The Alarms list (approved screen 29; roles spec §10.3, plan rulings 1–5):
// search and filter chips whose values and counts come from the server,
// saved views, the person's columns, a summary line, paging by offset (all
// in the URL) and the bulk bar (Set state, Assign, Add to case, Suppress…).
// A row opens the alarm's page at /alarms/{id}.
import { useEffect, useState } from "react";

import { invalidate, useResource } from "../../api/client";
import type { AlarmList, AlarmListRow } from "../../api/types";
import { nav, useLocation, viewLink } from "../../app/nav";
import { AlarmPanel } from "../../panels/alarms/AlarmPanel";
import { caseNumber } from "../../panels/cases/cases";
import { highest } from "../../panels/triage/bulk";
import { BulkBar } from "../../panels/triage/BulkBar";
import { Ago, Empty, ErrorBox, Loading, SeverityBadge, TriageBadge } from "../../ui/bits";
import { type Column, DataTable } from "../../ui/DataTable";
import { triageLabel } from "../../ui/format";
import { Icon } from "../../ui/Icon";
import { FilterBar } from "../../ui/list/FilterBar";
import { type ListFilter, PAGE, hasFilters } from "../../ui/list/filters";
import { importBrowserViews, useHiddenColumns } from "../../ui/list/savedViews";
import { SummaryLine } from "../../ui/list/SummaryLine";
import { useSelection } from "../../ui/selection";
import { useHostName } from "../lists/HostChip";
import { isTest } from "../lists/testRules";
import { Pager } from "./Hosts";

const PAGE_SIZE = 50;
/** The list's columns (keys as the console keeps hidden ones), Severity first: it is never hidden. */
const COLUMNS = [
  { key: "severity", label: "Severity" }, { key: "alarm", label: "Alarm" }, { key: "host", label: "Host" }, { key: "count", label: "Count" },
  { key: "seen", label: "Last and first seen" }, { key: "state", label: "State" }, { key: "assignee", label: "Assignee" }, { key: "case", label: "Case" },
] as const;
const header = (key: (typeof COLUMNS)[number]["key"]) => COLUMNS.find((c) => c.key === key)?.label ?? key;

/** The URL's sort (a column key) in the API's spelling. */
const API_SORT: Record<string, string> = { seen: "last_seen", first: "first_seen", count: "count", severity: "severity" };
/** The old list's sorts (views saved in the browser) as today's; the others are gone. */
const OLD_SORT: Record<string, string> = { last: "seen", count: "count", severity: "severity" };
const API_PARAMS = ["q", "state", "severity", "suppressed", "host", "group", "technique", "case", "assignee", "dir", PAGE];

/** The API query for the list's URL: only what the API reads (it refuses anything else). */
export function apiQuery(params: URLSearchParams): string {
  const query = new URLSearchParams();
  for (const key of API_PARAMS) {
    const value = params.get(key);
    // Old links said "include suppressed" as suppressed=true.
    if (value) query.set(key, key === "suppressed" && value === "true" ? "shown" : value);
  }
  const sort = API_SORT[params.get("sort") ?? ""];
  if (sort) query.set("sort", sort);
  query.set("limit", String(PAGE_SIZE));
  return query.toString();
}

/** A view saved in the browser by the old list, in today's parameters. */
export function alarmViewQuery(query: string): string {
  const params = new URLSearchParams(query);
  if (params.get("suppressed") === "true") params.set("suppressed", "shown");
  const sort = params.get("sort");
  if (sort !== null) {
    const next = OLD_SORT[sort];
    if (next) params.set("sort", next);
    else { params.delete("sort"); params.delete("dir"); }
  }
  return params.toString();
}

/** What a selection belongs to: this exact page in this order (a re-sort or another page empties it). */
export const selectionKey = (params: URLSearchParams) => apiQuery(params);

/** The selected ids among the rows on screen: what the bulk bar counts and sends. */
export function onPage(selected: ReadonlySet<string>, rows: readonly AlarmListRow[]): Set<string> {
  return new Set(rows.map((a) => String(a.id)).filter((id) => selected.has(id)));
}

/** `parent → program`, by base name, the way an analyst reads it. */
export function lineage(alarm: Pick<AlarmListRow, "program" | "parent_program">): string {
  const base = (path: string) => path.split("/").pop() || path;
  return alarm.parent_program ? `${base(alarm.parent_program)} → ${base(alarm.program)}` : base(alarm.program);
}

const SEVERITY: Record<string, string> = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info" };
const SUPPRESSED: Record<string, string> = { hidden: "Hidden", shown: "Shown" };
const CASE: Record<string, string> = { yes: "In a case", no: "Not in a case" };
const OS: Record<string, string> = { linux: "Linux", windows: "Windows" };
const named = (labels: Record<string, string>) => (c: { value: string; count: number }) => ({ value: c.value, label: labels[c.value] ?? c.value, count: c.count });

/** The filter chips, their values and counts from the list (none until it loads); Host only while set. */
export function alarmFilters(list: AlarmList | undefined, host: string | null, hostName: string | undefined): ListFilter[] {
  const c = list?.counts;
  const states = c?.state ?? [];
  return [
    { param: "severity", label: "Severity", values: (c?.severity ?? []).map(named(SEVERITY)) },
    { param: "state", label: "State", values: c ? [...states.map(named(triageLabel)), { value: "all", label: "All states", count: states.reduce((n, s) => n + s.count, 0) }] : [] },
    { param: "suppressed", label: "Suppressed", values: (c?.suppressed ?? []).map(named(SUPPRESSED)) },
    { param: "host", label: "Host", chipOnly: true, values: host ? [{ value: host, label: hostName ?? host, count: list?.total ?? 0 }] : [] },
    { param: "group", label: "Group", values: (c?.group ?? []).map((g) => ({ value: g.value, label: g.name, count: g.count })) },
    { param: "technique", label: "Technique", values: (c?.technique ?? []).map(named({})) },
    { param: "case", label: "Case", values: (c?.case ?? []).map(named(CASE)) },
    { param: "assignee", label: "Assignee", values: c ? [{ value: "me", label: "Me", count: c.assignee.me }, { value: "unassigned", label: "Unassigned", count: c.assignee.unassigned },
      ...c.assignee.people.map((p) => ({ value: p.value, label: p.name, count: p.count }))] : [] },
  ];
}

const alarmPath = (id: number | string) => `/alarms/${encodeURIComponent(String(id))}`;
const none = (text: string) => <span className="subtle" title={text}><span aria-hidden="true">—</span><span className="sr-only">{text}</span></span>;

const columns: Column<AlarmListRow>[] = [
  { key: "severity", header: header("severity"), width: "100px", sort: (a) => a.severity, render: (a) => <SeverityBadge severity={a.severity} /> },
  { key: "alarm", header: header("alarm"), render: (a) => (
    <div className="cell-two">
      <span className="truncate">{isTest(a.rule_set_id, a.rule_id) && <span className="badge badge--plain">Test</span>} <a {...viewLink(alarmPath(a.id))}>{a.message}</a></span>
      <span className="mono subtle truncate">{lineage(a)}{a.techniques.length > 0 && ` · ${a.techniques.join(", ")}`}</span>
    </div>
  ) },
  { key: "host", header: header("host"), width: "170px", hideBelow: 560, render: (a) => (
    <div className="cell-two"><span className="truncate">{a.host.name ?? a.host.id}</span>
      <span className="subtle">{a.host.distribution ?? OS[a.host.os_family ?? ""] ?? a.host.os_family ?? ""}</span></div>
  ) },
  { key: "count", header: header("count"), numeric: true, width: "80px", sort: (a) => a.count, render: (a) => <span className="num">{a.count.toLocaleString()}</span> },
  { key: "seen", header: "Last seen", width: "110px", hideBelow: 900, sort: (a) => a.last_seen, render: (a) => <Ago value={a.last_seen} /> },
  // Shown and hidden with Last seen: one column to the person (src/lists/mod.rs keeps "seen").
  { key: "first", header: "First seen", width: "110px", hideBelow: 1000, sort: (a) => a.first_seen, render: (a) => <span className="subtle"><Ago value={a.first_seen} /></span> },
  { key: "state", header: header("state"), width: "130px", hideBelow: 760, render: (a) => <TriageBadge state={a.state} /> },
  { key: "assignee", header: header("assignee"), width: "130px", hideBelow: 1000, render: (a) => a.assignee ? <span className="truncate">{a.assignee.name}</span> : none("Unassigned") },
  { key: "case", header: header("case"), width: "90px", hideBelow: 1100, render: (a) => a.case
    ? <span className="badge badge--info badge--plain" title={`In open case ${caseNumber(a.case.number)}`}>{caseNumber(a.case.number)}</span> : none("In no case") },
];

/** The summary line, the table and the pager for one loaded page. */
export function AlarmListBody({ list, hidden, offset = 0, selected, onSelect }: {
  list: AlarmList; hidden: readonly string[]; offset?: number; selected: ReadonlySet<string>; onSelect: (next: Set<string>) => void;
}) {
  const parts = [
    { count: list.summary.open, text: "open" },
    { count: list.summary.critical_or_high, text: "critical or high" },
    // Only for people who read hosts (plan ruling 5).
    ...(list.summary.on_alarms_off_hosts == null ? [] : [{ count: list.summary.on_alarms_off_hosts, text: "on hosts with alarms off" }]),
  ];
  return (
    <>
      <div className="view-pad host-summary"><SummaryLine parts={parts} /></div>
      <DataTable label="Alarms" rows={list.items} rowKey={(a) => String(a.id)} serverSort serverPaged defaultSort={{ key: "seen", direction: "desc" }}
        selection={{ selected, onChange: onSelect }} onOpen={(a) => nav.view(alarmPath(a.id))}
        columns={columns.filter((c) => c.key === "severity" || !hidden.includes(c.key === "first" ? "seen" : c.key))} />
      <Pager offset={offset} shown={list.items.length} total={list.total} />
    </>
  );
}

function AlarmListView() {
  const { params } = useLocation();
  const list = useResource<AlarmList>(`/api/v1/alarm-list?${apiQuery(params)}`);
  const hidden = useHiddenColumns("alarms");
  const host = params.get("host");
  const hostName = useHostName(host);
  // The last page stays on screen (and its counts in the chips) while the next loads.
  const [kept, setKept] = useState<AlarmList>();
  if (list.data && list.data !== kept) setKept(list.data);
  const data = list.data ?? kept;
  // A selection is of this page in this order, and only of the rows on it
  // (a refresh may drop some): the bar counts exactly what it sends.
  const [picked, setSelected] = useSelection(selectionKey(params));
  const selected = onPage(picked, data?.items ?? []);
  const chosen = () => (data?.items ?? []).filter((a) => selected.has(String(a.id)));
  // Nothing open and no filter: is there any alarm at all? If not, say how alarms start.
  const any = useResource<AlarmList>(data?.total === 0 && !hasFilters(params) ? "/api/v1/alarm-list?state=all&suppressed=shown&limit=1" : null);
  const noAlarms = any.data?.total === 0;
  // Old links said "include suppressed" as suppressed=true: today's spelling, in place.
  const oldSuppressed = params.get("suppressed") === "true";
  useEffect(() => { if (oldSuppressed) nav.setParams({ suppressed: "shown" }); }, [oldSuppressed]);
  // Views saved in this browser before saved views lived on the console.
  useEffect(() => { void importBrowserViews("alarms", "openvibes.v2.views./alarms", alarmViewQuery); }, []);

  return (
    <div className="view">
      <header className="view-header">
        <div className="view-header__top">
          <div className="view-header__title">
            <h1>Alarms</h1>
            {data && <span className="view-header__count num">{data.total.toLocaleString()}</span>}
          </div>
          <button type="button" className="icon-button" title="Refresh" aria-label="Refresh" onClick={() => invalidate("/api/v1/alarm-list")}>
            <Icon name="refresh" size={16} />
          </button>
        </div>
        <FilterBar page="alarms" label="Search alarms" placeholder="Search by message, rule, host or program…" filters={alarmFilters(data, host, hostName)} columns={COLUMNS} />
      </header>
      {list.error ? <div className="view-pad"><ErrorBox error={list.error} /></div> : !data ? <Loading /> : data.total === 0 ? (
        <Empty icon="alarm" title={noAlarms ? "No alarms" : "Nothing matches these filters"}>
          {noAlarms
            ? "Alarms appear here within seconds of a matching program start. Agents report process starts by themselves; each host's page says whether its alarms are on."
            : "Closed and suppressed alarms are hidden unless State or Suppressed says otherwise; clear a filter to see more."}
        </Empty>
      ) : (
        <AlarmListBody list={data} hidden={hidden ?? []} offset={Math.max(0, Number(params.get(PAGE)) || 0)} selected={selected} onSelect={setSelected} />
      )}
      <BulkBar kind="alarms" noun={selected.size === 1 ? "alarm" : "alarms"} count={selected.size} onClear={() => setSelected(new Set())}
        items={() => chosen().map((a) => ({ id: String(a.id) }))}
        closed={chosen().filter((a) => a.state !== "open").length}
        reopenItems={() => chosen().filter((a) => a.state !== "open").map((a) => ({ id: String(a.id) }))}
        newCase={() => { const c = chosen(); return { title: `${c.length} alarms: ${c[0]?.message ?? ""}`, severity: highest(c.map((a) => a.severity)) }; }} />
    </div>
  );
}

/** The alarm id in a /alarms/{id} path; null when the path is not one (bad escapes, a sub-path). */
export function alarmIdOf(view: string): string | null {
  const raw = view.slice("/alarms/".length);
  if (!raw || raw.includes("/")) return null;
  try {
    return decodeURIComponent(raw);
  } catch {
    return null;
  }
}

/** Until the alarm's page (screen 30) lands: the alarm's panel, full width, so a row never dead-ends. */
function AlarmPageStopgap({ id }: { id: string }) {
  return (
    <div className="view">
      <h1 className="sr-only">Alarm {id}</h1>
      <div className="view-pad"><a {...viewLink("/alarms")}>← Alarms</a></div>
      <div className="view-pad"><AlarmPanel id={id} /></div>
    </div>
  );
}

export function Alarms() {
  const { view } = useLocation();
  if (!view.startsWith("/alarms/")) return <AlarmListView />;
  const id = alarmIdOf(view);
  return id === null ? <Empty icon="alarm" title="No such alarm">Check the link, or find the alarm in the list.</Empty> : <AlarmPageStopgap key={id} id={id} />;
}
