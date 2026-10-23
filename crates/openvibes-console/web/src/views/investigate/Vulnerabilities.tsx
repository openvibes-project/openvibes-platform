// The Vulnerabilities list (approved screen 25; roles spec §10.3, step 5b
// rulings 2–8): one row per CVE (an advisory without CVEs under its own id),
// search and filter chips whose values and counts come from the server,
// saved views, the person's columns, a summary line, paging by offset (all
// in the URL) and the bulk bar (Set state, Assign, Add to case; no Reopen).
// A row opens the CVE's page at /vulnerabilities/{key} (vulnerability/VulnPage.tsx).
import { useEffect, useState } from "react";

import { invalidate, useResource } from "../../api/client";
import type { VulnList, VulnListRow } from "../../api/types";
import { vulnPath, vulnerabilitiesQuery } from "../../app/location";
import { nav, useLocation, viewLink } from "../../app/nav";
import { highest } from "../../panels/triage/bulk";
import { BulkBar } from "../../panels/triage/BulkBar";
import { Empty, ErrorBox, Loading, SeverityBadge } from "../../ui/bits";
import { type Column, DataTable } from "../../ui/DataTable";
import { date, pct, plural, triageLabel } from "../../ui/format";
import { Icon } from "../../ui/Icon";
import { FilterBar } from "../../ui/list/FilterBar";
import { type ListFilter, PAGE, hasFilters } from "../../ui/list/filters";
import { importBrowserViews, useHiddenColumns } from "../../ui/list/savedViews";
import { SummaryLine } from "../../ui/list/SummaryLine";
import { useSelection } from "../../ui/selection";
import { useHostName } from "../lists/HostChip";
import { Pager } from "./Hosts";
import { Reach } from "./vulnerability/Reach";
import { NoSuchVuln, VulnPage } from "./vulnerability/VulnPage";

const PAGE_SIZE = 50;
/** The list's columns (keys as the console keeps hidden ones); Severity and Advisory are never hidden. */
const COLUMNS = [
  { key: "severity", label: "Severity" }, { key: "advisory", label: "Advisory", fixed: true }, { key: "package", label: "Package" },
  { key: "cvss", label: "CVSS" }, { key: "epss", label: "EPSS" }, { key: "hosts", label: "Hosts" }, { key: "due", label: "Due" },
  { key: "assignee", label: "Assignee" },
] as const;
const header = (key: (typeof COLUMNS)[number]["key"]) => COLUMNS.find((c) => c.key === key)?.label ?? key;

/** The URL's sort (a column key) in the API's spelling; none is the API's priority order. */
const API_SORT: Record<string, string> = { severity: "severity", cvss: "cvss", epss: "epss", hosts: "open", due: "due" };
const API_PARAMS = ["q", "state", "severity", "signal", "package", "group", "host", "advisory", "assignee", "dir", PAGE];

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

const SEVERITY: Record<string, string> = { critical: "Critical", important: "Important", moderate: "Moderate", low: "Low", unrated: "Unrated" };
const STATE: Record<string, string> = { ...triageLabel, resolved: "Resolved", all: "All states" };
const SIGNAL: Record<string, string> = {
  exploited: "Known exploited", due30: "Due within 30 days", nofix: "No fix yet", reboot: "Reboot needed", lowconf: "Lower confidence",
};
const named = (labels: Record<string, string>) => (c: { value: string; count: number }) => ({ value: c.value, label: labels[c.value] ?? c.value, count: c.count });

/** The filter chips, their values and counts from the list (none until it loads); Host and Advisory only while set. */
export function vulnFilters(list: VulnList | undefined, set: { host: string | null; hostName: string | undefined; advisory: string | null }): ListFilter[] {
  const c = list?.counts;
  const chip = (value: string | null, label?: string) => (value ? [{ value, label: label ?? value, count: list?.total ?? 0 }] : []);
  return [
    { param: "severity", label: "Severity", values: (c?.severity ?? []).map(named(SEVERITY)) },
    { param: "state", label: "State", values: (c?.state ?? []).map(named(STATE)) },
    { param: "signal", label: "Signals", values: (c?.signal ?? []).map(named(SIGNAL)) },
    { param: "package", label: "Package", values: (c?.package ?? []).map(named({})) },
    { param: "group", label: "Group", values: (c?.group ?? []).map((g) => ({ value: g.value, label: g.name, count: g.count })) },
    { param: "assignee", label: "Assignee", values: c ? [{ value: "me", label: "Me", count: c.assignee.me }, { value: "unassigned", label: "Unassigned", count: c.assignee.unassigned },
      ...c.assignee.people.map((p) => ({ value: p.value, label: p.name, count: p.count }))] : [] },
    { param: "host", label: "Host", chipOnly: true, values: chip(set.host, set.hostName) },
    { param: "advisory", label: "Advisory", chipOnly: true, values: chip(set.advisory) },
  ];
}

/** What a bulk action sends for these rows (ruling 8): each covering advisory, on the Host chip's host when set,
 * open pairs only (`open_only`, so naming the host does not reach its closed pairs). */
export function bulkItems(rows: readonly VulnListRow[], host: string | null) {
  const on = host ? { agent_id: host } : {};
  return [...new Set(rows.flatMap((r) => r.advisories))].map((advisory_id) => ({ advisory_id, ...on, open_only: true }));
}

const none = (text: string) => <span className="subtle" title={text}><span aria-hidden="true">—</span><span className="sr-only">{text}</span></span>;

/** "late" when the KEV due date has passed, "soon" within 30 days. */
function dueTone(due: string, now = Date.now()): "late" | "soon" | null {
  const today = new Date(now).toISOString().slice(0, 10);
  if (due < today) return "late";
  return due <= new Date(now + 30 * 86_400_000).toISOString().slice(0, 10) ? "soon" : null;
}

function Due({ due }: { due: string | null | undefined }) {
  if (!due) return none("No due date");
  const tone = dueTone(due);
  return <span className={tone ? `due due--${tone}` : "due"} title="CISA's due date">{date(`${due}T00:00:00Z`)}{tone && <span className="sr-only">{tone === "late" ? " (overdue)" : " (due within 30 days)"}</span>}</span>;
}

function Fixed({ fixed }: { fixed: VulnListRow["fixed"] }) {
  if (fixed.kind === "one") return <span className="subtle">fixed in {fixed.version}</span>;
  if (fixed.kind === "several") return <span className="subtle">fixed in {fixed.count} versions</span>;
  return <span className="text-warn">no fix yet</span>;
}

const columns: Column<VulnListRow>[] = [
  { key: "severity", header: header("severity"), width: "110px", sort: (r) => r.severity, render: (r) => <SeverityBadge severity={r.severity} /> },
  { key: "advisory", header: header("advisory"), render: (r) => (
    <div className="cell-two">
      <span className="row"><a className="truncate" {...viewLink(vulnPath(r.key))}>{r.title}<span className="sr-only"> ({r.key})</span></a>
        {r.exploited && <span className="badge badge--critical badge--plain" title="Known to be exploited"><Icon name="flame" size={12} /> Exploited</span>}
        {r.low_confidence && <span className="badge badge--plain" title="Matched from upstream version ranges, not a distribution advisory">Lower confidence</span>}
      </span>
      <span className="mono subtle truncate">{r.key}</span>
    </div>
  ) },
  { key: "package", header: header("package"), width: "170px", hideBelow: 640, render: (r) => (
    <div className="cell-two"><span className="mono truncate">{r.packages[0] ?? "—"}{r.packages.length > 1 ? ` +${r.packages.length - 1}` : ""}</span><Fixed fixed={r.fixed} /></div>
  ) },
  { key: "cvss", header: header("cvss"), numeric: true, width: "70px", hideBelow: 760, sort: (r) => r.cvss, render: (r) => <span className="num">{r.cvss?.toFixed(1) ?? "—"}</span> },
  { key: "epss", header: header("epss"), numeric: true, width: "80px", hideBelow: 860, sort: (r) => r.epss, render: (r) => <span className="num subtle">{pct(r.epss)}</span> },
  { key: "hosts", header: header("hosts"), width: "140px", sort: (r) => r.open, render: (r) => (
    <div className="stack hosts-cell">
      <span className="num"><b>{r.open.toLocaleString()}</b> <span className="subtle">open of {r.total.toLocaleString()}</span></span>
      <span className="meter meter--ok" role="progressbar" aria-label={`${r.open} open of ${r.total} hosts`} aria-valuetext={`${r.open} open of ${r.total} hosts`}
        aria-valuemin={0} aria-valuemax={r.total} aria-valuenow={r.total - r.open}>
        <span style={{ width: `${r.total ? Math.round((100 * (r.total - r.open)) / r.total) : 0}%` }} />
      </span>
    </div>
  ) },
  { key: "due", header: header("due"), width: "110px", hideBelow: 960, sort: (r) => r.due ?? null, render: (r) => <Due due={r.due} /> },
  { key: "assignee", header: header("assignee"), width: "130px", hideBelow: 1000, render: (r) => r.assignee.kind === "one"
    ? <span className="truncate">{r.assignee.name}</span> : r.assignee.kind === "several" ? <span>{r.assignee.count} people</span> : none("Unassigned") },
];

/** The summary line, the table and the pager for one loaded page. */
export function VulnListBody({ list, hidden, offset = 0, selected, onSelect }: {
  list: VulnList; hidden: readonly string[]; offset?: number; selected: ReadonlySet<string>; onSelect: (next: Set<string>) => void;
}) {
  const s = list.summary;
  const parts = [
    { count: s.open_rows, text: `open on ${plural(s.hosts, "host")}` }, { count: s.exploited, text: "known exploited" },
    { count: s.with_due, text: "with a due date" }, { count: s.no_fix, text: "without a fix" }, { count: s.unassigned, text: "unassigned" },
  ];
  return (
    <>
      <div className="view-pad host-summary"><SummaryLine parts={parts} /></div>
      <DataTable label="Vulnerabilities" rows={list.items} rowKey={(r) => r.key} serverSort serverPaged
        selection={{ selected, onChange: onSelect }} onOpen={(r) => nav.view(vulnPath(r.key))}
        columns={columns.filter((c) => c.key === "severity" || c.key === "advisory" || !hidden.includes(c.key))} />
      <Pager offset={offset} shown={list.items.length} total={list.total} />
    </>
  );
}

function VulnListView() {
  const { params } = useLocation();
  const list = useResource<VulnList>(`/api/v1/vulnerability-list?${apiQuery(params)}`);
  const hidden = useHiddenColumns("vulnerabilities");
  const host = params.get("host");
  const hostName = useHostName(host);
  // The last page stays on screen (and its counts in the chips) while the next loads.
  const [kept, setKept] = useState<VulnList>();
  if (list.data && list.data !== kept) setKept(list.data);
  const data = list.data ?? kept;
  // A selection is of this page in this order, and only of the rows on it.
  const [picked, setSelected] = useSelection(apiQuery(params));
  const chosen = (data?.items ?? []).filter((r) => picked.has(r.key));
  const selected = new Set(chosen.map((r) => r.key));
  // Views saved in this browser before saved views lived on the console.
  useEffect(() => { void importBrowserViews("vulnerabilities", "openvibes.v2.views./vulnerabilities", vulnerabilitiesQuery); }, []);

  return (
    <div className="view">
      <header className="view-header">
        <div className="view-header__top">
          <div className="view-header__title">
            <h1>Vulnerabilities</h1>
            {data && <span className="view-header__count num">{data.total.toLocaleString()}</span>}
          </div>
          <button type="button" className="icon-button" title="Refresh" aria-label="Refresh" onClick={() => invalidate("/api/v1/vulnerability-list")}>
            <Icon name="refresh" size={16} />
          </button>
        </div>
        <FilterBar page="vulnerabilities" label="Search vulnerabilities" placeholder="Search CVE, advisory or package…"
          filters={vulnFilters(data, { host, hostName, advisory: params.get("advisory") })} columns={COLUMNS} />
      </header>
      {list.error ? <div className="view-pad"><ErrorBox error={list.error} /></div> : !data ? <Loading /> : data.total === 0 ? (
        hasFilters(params)
          ? <Empty icon="vulnerabilities" title="No advisory matches these filters">Mitigated, accepted, false-positive and fixed ones are hidden unless State says otherwise; clear a filter to see more.</Empty>
          : <Empty icon="vulnerabilities" title="No open vulnerabilities">Every package in your scope is up to date against the advisories the platform knows.</Empty>
      ) : (
        <VulnListBody list={data} hidden={hidden ?? []} offset={Math.max(0, Number(params.get(PAGE)) || 0)} selected={selected} onSelect={setSelected} />
      )}
      <BulkBar kind="vulnerabilities" noun={selected.size === 1 ? "vulnerability" : "vulnerabilities"} count={selected.size} onClear={() => setSelected(new Set())}
        items={() => bulkItems(chosen, host)} confirm={<Reach rows={chosen} />}
        newCase={() => ({ title: `${chosen.length} vulnerabilities: ${chosen[0]?.key ?? ""} ${chosen[0]?.title ?? ""}`.trim(), severity: highest(chosen.map((r) => r.severity)) })} />
    </div>
  );
}

/** The key in a /vulnerabilities/{key} path; null when the path is not one (bad escapes, a sub-path). */
export function vulnKeyOf(view: string): string | null {
  const raw = view.slice("/vulnerabilities/".length);
  if (!raw || raw.includes("/")) return null;
  try {
    return decodeURIComponent(raw);
  } catch {
    return null;
  }
}

export function Vulnerabilities() {
  const { view } = useLocation();
  if (!view.startsWith("/vulnerabilities/")) return <VulnListView />;
  const key = vulnKeyOf(view);
  return key ? <VulnPage key={key} id={key} /> : <NoSuchVuln />;
}
