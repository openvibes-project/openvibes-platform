// The Cases list (approved screen 31; roles spec §10.3, step 5d rulings
// 6-10): one row per case, search and filter chips whose values and counts
// come from the server, saved views, the person's columns, a summary line
// and paging by offset (all in the URL). A row opens the case's page at
// /cases/{id} (screen 32, views/investigate/case/); New case is /cases/new.
import { useEffect, useState } from "react";

import { invalidate, useResource } from "../../api/client";
import type { CaseList, CaseListRow } from "../../api/types";
import { casePath, casesQuery, hostPath } from "../../app/location";
import { nav, useLocation, viewLink } from "../../app/nav";
import { useSession } from "../../app/session";
import { CaseStatusBadge } from "../../panels/cases/CaseBadge";
import { caseNumber } from "../../panels/cases/cases";
import { Ago, Empty, ErrorBox, Loading, SeverityBadge } from "../../ui/bits";
import { type Column, DataTable } from "../../ui/DataTable";
import { Icon, type IconName } from "../../ui/Icon";
import { FilterBar } from "../../ui/list/FilterBar";
import { type ListFilter, PAGE, hasFilters } from "../../ui/list/filters";
import { importBrowserViews, useHiddenColumns } from "../../ui/list/savedViews";
import { SummaryLine } from "../../ui/list/SummaryLine";
import { useHostName } from "../lists/HostChip";
import { CasePage, NoSuchCase } from "./case/CasePage";
import { NewCasePage } from "./case/NewCasePage";
import { Pager } from "./Hosts";

const PAGE_SIZE = 50;
/** The list's columns (keys as the console keeps hidden ones, page "cases"); Case and Title are never hidden. */
const COLUMNS = [
  { key: "case", label: "Case", fixed: true }, { key: "title", label: "Title", fixed: true }, { key: "severity", label: "Severity" },
  { key: "status", label: "Status" }, { key: "assignee", label: "Assignee" }, { key: "hosts", label: "Hosts" },
  { key: "items", label: "Items" }, { key: "updated", label: "Updated" },
] as const;
const header = (key: (typeof COLUMNS)[number]["key"]) => COLUMNS.find((c) => c.key === key)?.label ?? key;

/** The URL's sort (a column key) in the API's spelling; none is the API's (updated, newest first). */
const API_SORT: Record<string, string> = { case: "number", severity: "severity", updated: "updated" };
const API_PARAMS = ["q", "status", "severity", "assignee", "contains", "host", "group", "updated", "dir", PAGE];

/** The API query for the list's URL: only what the API reads (it refuses anything else). */
export function apiQuery(params: URLSearchParams): string {
  const query = new URLSearchParams();
  for (const key of API_PARAMS) {
    const value = params.get(key);
    if (value) query.set(key, value);
  }
  const sort = API_SORT[params.get("sort") ?? ""];
  if (sort) query.set("sort", sort);
  query.set("limit", String(PAGE_SIZE));
  return query.toString();
}

const STATUS: Record<string, string> = { open: "Open", investigating: "Investigating", closed: "Closed", all: "All statuses" };
const SEVERITY: Record<string, string> = { critical: "Critical", high: "High", medium: "Medium", low: "Low" };
const CONTAINS: Record<string, string> = { alarms: "Alarms", vulnerabilities: "Vulnerabilities", findings: "Compliance findings" };
const UPDATED: Record<string, string> = { today: "Today", week: "This week", quiet: "Quiet for 7 days or more" };
const named = (labels: Record<string, string>) => (c: { value: string; count: number }) => ({ value: c.value, label: labels[c.value] ?? c.value, count: c.count });

/** The filter chips, their values and counts from the list (none until it loads); Host only while set.
 * Status leaves out `active`: it is what no choice means. */
export function caseFilters(list: CaseList | undefined, set: { host: string | null; hostName: string | undefined }): ListFilter[] {
  const c = list?.counts;
  return [
    { param: "status", label: "Status", values: (c?.status ?? []).filter((s) => s.value !== "active").map(named(STATUS)) },
    { param: "severity", label: "Severity", values: (c?.severity ?? []).map(named(SEVERITY)) },
    { param: "assignee", label: "Assignee", values: c ? [{ value: "me", label: "Me", count: c.assignee.me }, { value: "unassigned", label: "Unassigned", count: c.assignee.unassigned },
      ...c.assignee.people.map((p) => ({ value: p.value, label: p.name, count: p.count }))] : [] },
    { param: "contains", label: "Contains", values: (c?.contains ?? []).map(named(CONTAINS)) },
    { param: "host", label: "Host", chipOnly: true, values: set.host ? [{ value: set.host, label: set.hostName ?? set.host, count: list?.total ?? 0 }] : [] },
    { param: "group", label: "Group", values: (c?.group ?? []).map((g) => ({ value: g.value, label: g.name, count: g.count })) },
    { param: "updated", label: "Updated", values: (c?.updated ?? []).map(named(UPDATED)) },
  ];
}

/** The item kinds a row counts: its key, icon and the word for one and for several. */
const KINDS: readonly [keyof CaseListRow["kinds"], IconName, string, string][] = [
  ["alarms", "alarm", "alarm", "alarms"], ["vulnerabilities", "vulnerabilities", "vulnerability", "vulnerabilities"],
  ["findings", "findings", "compliance finding", "compliance findings"], ["hosts", "agents", "host", "hosts"], ["software", "package", "software item", "software items"],
];

function Items({ row }: { row: CaseListRow }) {
  const kinds = KINDS.filter(([key]) => row.kinds[key] > 0);
  const [done, total] = [row.with_outcome, row.takes_outcome];
  const text = `${done} of ${total} with an outcome`;
  return (
    <div className="stack hosts-cell">
      <span className="row">
        {kinds.length === 0 ? <span className="subtle">No items</span> : kinds.map(([key, icon, one, many]) => {
          const n = row.kinds[key];
          return <span key={key} className="row nowrap" style={{ gap: 3 }} title={`${n} ${n === 1 ? one : many}`}><Icon name={icon} size={14} /><span className="num">{n}</span><span className="sr-only"> {n === 1 ? one : many}</span></span>;
        })}
      </span>
      {total > 0 && (
        <span className="row">
          <span className="meter meter--ok" role="progressbar" aria-label={text} aria-valuetext={text} aria-valuemin={0} aria-valuemax={total} aria-valuenow={done}>
            <span style={{ width: `${(100 * done) / total}%` }} />
          </span>
          <span className="subtle hosts-cell__words nowrap">{done}/{total} with an outcome</span>
        </span>
      )}
      {row.ready && <span><span className="badge badge--ok">Ready to close</span></span>}
    </div>
  );
}

function Hosts({ row }: { row: CaseListRow }) {
  if (row.host_count === 0) return <span className="subtle">None</span>;
  const more = row.host_count - row.hosts.length;
  return (
    <span className="row" style={{ flexWrap: "wrap", gap: 6 }}>
      {row.hosts.map((h) => <a key={h.agent_id} className="mono" {...viewLink(hostPath(h.agent_id))}>{h.hostname ?? h.agent_id}</a>)}
      {more > 0 && <span className="subtle">+{more}<span className="sr-only"> more hosts</span></span>}
    </span>
  );
}

const columns: Column<CaseListRow>[] = [
  { key: "case", header: header("case"), width: "80px", sort: (r) => r.number, render: (r) => <span className="mono nowrap">{caseNumber(r.number)}</span> },
  { key: "title", header: header("title"), render: (r) => (
    <div className="cell-two">
      <a className="truncate" {...viewLink(casePath(r.case_id))}><span className="sr-only">{caseNumber(r.number)} </span>{r.title}</a>
      <span className="subtle truncate">Opened by {r.opened_by.display_name}{r.latest_note && (
        <> · <span className="sr-only">Latest note, </span><Ago value={r.latest_note.at} />: <i>“{r.latest_note.text}”</i></>
      )}</span>
    </div>
  ) },
  { key: "severity", header: header("severity"), width: "100px", sort: (r) => r.severity, render: (r) => <SeverityBadge severity={r.severity} /> },
  { key: "status", header: header("status"), width: "125px", hideBelow: 700, render: (r) => <CaseStatusBadge status={r.status} resolution={r.resolution} /> },
  { key: "assignee", header: header("assignee"), width: "130px", hideBelow: 820, render: (r) => <span className={r.assignee ? "truncate" : "subtle"}>{r.assignee?.display_name ?? "Unassigned"}</span> },
  { key: "hosts", header: header("hosts"), width: "200px", hideBelow: 1000, render: (r) => <Hosts row={r} /> },
  { key: "items", header: header("items"), width: "200px", hideBelow: 560, render: (r) => <Items row={r} /> },
  { key: "updated", header: header("updated"), width: "110px", hideBelow: 940, sort: (r) => r.updated_at, render: (r) => <span className="subtle"><Ago value={r.updated_at} /></span> },
];

/** The summary line, the table and the pager for one loaded page. `status` is the URL's (none: not closed). */
export function CaseListBody({ list, hidden, offset = 0, status }: { list: CaseList; hidden: readonly string[]; offset?: number; status: string | null }) {
  const s = list.summary;
  const parts = [{ count: s.open, text: "open" }, { count: s.investigating, text: "investigating" }, { count: s.unassigned, text: "unassigned" }, { count: s.ready_to_close, text: "ready to close" }];
  return (
    <>
      <div className="view-pad host-summary"><SummaryLine parts={parts} {...(!status || status === "active" ? { tail: "closed cases hidden" } : {})} /></div>
      <DataTable label="Cases" rows={list.items} rowKey={(r) => r.case_id} serverSort serverPaged defaultSort={{ key: "updated", direction: "desc" }}
        onOpen={(r) => nav.view(casePath(r.case_id))}
        columns={columns.filter((c) => c.key === "case" || c.key === "title" || !hidden.includes(c.key))} />
      <Pager offset={offset} shown={list.items.length} total={list.total} />
    </>
  );
}

function CaseListView() {
  const { params } = useLocation();
  const { can } = useSession();
  const list = useResource<CaseList>(`/api/v1/case-list?${apiQuery(params)}`);
  const hidden = useHiddenColumns("cases");
  const host = params.get("host");
  const hostName = useHostName(host);
  // The last page stays on screen (and its counts in the chips) while the next loads.
  const [kept, setKept] = useState<CaseList>();
  if (list.data && list.data !== kept) setKept(list.data);
  const data = list.data ?? kept;
  // Views saved in this browser before saved views lived on the console.
  useEffect(() => { void importBrowserViews("cases", "openvibes.v2.views./cases", casesQuery); }, []);

  return (
    <div className="view">
      <header className="view-header">
        <div className="view-header__top">
          <div className="view-header__title">
            <h1>Cases</h1>
            {data && <span className="view-header__count num">{data.total.toLocaleString()}</span>}
          </div>
          <div className="row">
            {can("cases.write") && <a className="button button--primary" {...viewLink("/cases/new")}><Icon name="plus" size={15} /> New case</a>}
            <button type="button" className="icon-button" title="Refresh" aria-label="Refresh" onClick={() => invalidate("/api/v1/case")}>
              <Icon name="refresh" size={16} />
            </button>
          </div>
        </div>
        <FilterBar page="cases" label="Search cases" placeholder="Search case, title or who opened it…"
          filters={caseFilters(data, { host, hostName })} columns={COLUMNS} />
      </header>
      {list.error ? <div className="view-pad"><ErrorBox error={list.error} /></div> : !data ? <Loading /> : data.total === 0 ? (
        hasFilters(params)
          ? <Empty icon="cases" title="No case matches these filters.">Closed cases are hidden unless Status says otherwise; clear a filter to see more.</Empty>
          : <Empty icon="cases" title="No open cases">
            A case gathers what belongs to one investigation: hosts, alarms, vulnerabilities and compliance findings, with notes and a timeline.
            {can("cases.write") ? " Start one with New case, or use Add to case on an alarm, compliance finding or host." : ""}
          </Empty>
      ) : (
        <CaseListBody list={data} hidden={hidden ?? []} offset={Math.max(0, Number(params.get(PAGE)) || 0)} status={params.get("status")} />
      )}
    </div>
  );
}

/** The case id in a /cases/{id} path; null when the path is not one (bad escapes, other depths). */
export function caseIdOf(view: string): string | null {
  const rest = view.slice("/cases/".length);
  if (!rest || rest.includes("/")) return null;
  try {
    return decodeURIComponent(rest);
  } catch {
    return null;
  }
}

/** The list, a case's page (/cases/{id}, screen 32) or the new-case form (/cases/new). */
export function Cases() {
  const { view } = useLocation();
  if (!view.startsWith("/cases/")) return <CaseListView />;
  const id = caseIdOf(view);
  return id === "new" ? <NewCasePage /> : id ? <CasePage key={id} id={id} /> : <NoSuchCase />;
}
