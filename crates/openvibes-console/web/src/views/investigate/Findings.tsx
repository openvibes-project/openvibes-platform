// The Compliance list (approved screen 27; roles spec §10.3, step 5c
// rulings 2–10): one row per check (a rule of a rule set), search and filter
// chips whose values and counts come from the server, saved views, the
// person's columns, a summary line, paging by offset (all in the URL) and the
// bulk bar (Set state, Assign, Add to case; no Reopen). A row opens the
// check's page at /compliance/{rule_set}/{rule}.
import { useEffect, useState } from "react";

import { invalidate, useResource } from "../../api/client";
import type { CheckList, CheckListRow } from "../../api/types";
import { checkPath, complianceQuery } from "../../app/location";
import { nav, useLocation, viewLink } from "../../app/nav";
import { CaseBadge, useCaseBadges } from "../../panels/cases/CaseBadge";
import { highest } from "../../panels/triage/bulk";
import type { BulkAction } from "../../panels/triage/bulk";
import { BulkBar } from "../../panels/triage/BulkBar";
import { Empty, ErrorBox, Loading, SeverityBadge } from "../../ui/bits";
import { type Column, DataTable } from "../../ui/DataTable";
import { date, plural, triageLabel } from "../../ui/format";
import { Icon } from "../../ui/Icon";
import { FilterBar } from "../../ui/list/FilterBar";
import { type ListFilter, PAGE, hasFilters } from "../../ui/list/filters";
import { importBrowserViews, useHiddenColumns } from "../../ui/list/savedViews";
import { SummaryLine } from "../../ui/list/SummaryLine";
import { useSelection } from "../../ui/selection";
import { useHostName } from "../lists/HostChip";
import { isTest } from "../lists/testRules";
import { CheckPage, NoSuchCheck } from "./check/CheckPage";
import { Pager } from "./Hosts";

const PAGE_SIZE = 50;
/** The list's columns (keys as the console keeps hidden ones); Severity and Check are never hidden. */
const COLUMNS = [
  { key: "severity", label: "Severity" }, { key: "check", label: "Check", fixed: true }, { key: "area", label: "Area" },
  { key: "failing", label: "Failing" }, { key: "hosts", label: "Hosts" }, { key: "since", label: "Since" }, { key: "assignee", label: "Assignee" },
] as const;
const header = (key: (typeof COLUMNS)[number]["key"]) => COLUMNS.find((c) => c.key === key)?.label ?? key;

/** The URL's sort (a column key) in the API's spelling; none is the API's severity order. */
const API_SORT: Record<string, string> = { severity: "severity", check: "title", failing: "failing", since: "since" };
const API_PARAMS = ["q", "state", "severity", "rule_set", "area", "group", "host", "assignee", "dir", PAGE];

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

const SEVERITY: Record<string, string> = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info" };
const STATE: Record<string, string> = { ...triageLabel, passing: "Passing", all: "All states" };
const named = (labels: Record<string, string>) => (c: { value: string; count: number }) => ({ value: c.value, label: labels[c.value] ?? c.value, count: c.count });

/** The filter chips, their values and counts from the list (none until it loads); Host only while set. */
export function checkFilters(list: CheckList | undefined, set: { host: string | null; hostName: string | undefined }): ListFilter[] {
  const c = list?.counts;
  return [
    { param: "severity", label: "Severity", values: (c?.severity ?? []).map(named(SEVERITY)) },
    { param: "state", label: "State", values: (c?.state ?? []).map(named(STATE)) },
    { param: "rule_set", label: "Rule set", values: (c?.rule_set ?? []).map(named({})) },
    { param: "area", label: "Area", values: (c?.area ?? []).map(named({})) },
    { param: "group", label: "Group", values: (c?.group ?? []).map((g) => ({ value: g.value, label: g.name, count: g.count })) },
    { param: "assignee", label: "Assignee", values: c ? [{ value: "me", label: "Me", count: c.assignee.me }, { value: "unassigned", label: "Unassigned", count: c.assignee.unassigned },
      ...c.assignee.people.map((p) => ({ value: p.value, label: p.name, count: p.count }))] : [] },
    { param: "host", label: "Host", chipOnly: true, values: set.host ? [{ value: set.host, label: set.hostName ?? set.host, count: list?.total ?? 0 }] : [] },
  ];
}

/** A check no host fails changes nothing: no open pair to triage, none to add to a case. */
const canChange = (r: CheckListRow) => r.failing > 0;

/** What a bulk action sends for these rows (ruling 10): each failing check, on the Host chip's host when set,
 * open pairs only (`open_only`), so passing hosts and closed pairs are never touched. */
export function bulkItems(rows: readonly CheckListRow[], host: string | null) {
  const on = host ? { agent_id: host } : {};
  return rows.filter(canChange).map((r) => ({ rule_set_id: r.rule_set_id, rule_id: r.rule_id, ...on, open_only: true }));
}

/** The ticked rows a bulk action can change, how many, their open hosts, and the actions to leave out:
 * all when none fails anywhere; Set state and Assign when no failing host is open (Add to case still adds them). */
export function listBulk(chosen: readonly CheckListRow[]) {
  const rows = chosen.filter(canChange);
  const open = rows.reduce((n, r) => n + r.open, 0);
  const without: BulkAction[] = rows.length === 0 ? ["state", "assign", "case"] : open === 0 ? ["state", "assign"] : [];
  return { rows, changes: rows.length, open, without,
    note: "Nothing selected can be triaged: every host in reach passes these checks." };
}

const none = (text: string) => <span className="subtle" title={text}><span aria-hidden="true">—</span><span className="sr-only">{text}</span></span>;

/** "3 open · 2 mitigated · 6 pass": open always, the other states only when they hold a host. */
function hostsText(r: CheckListRow): string {
  const parts = [`${r.open} open`, ...([[r.mitigated, "mitigated"], [r.accepted_risk, "accepted"], [r.false_positive, "false positive"]] as const)
    .filter(([n]) => n > 0).map(([n, word]) => `${n} ${word}`), `${r.passing} pass`];
  return parts.join(" · ");
}

const TONES = [["open", "var(--bad)"], ["mitigated", "var(--ok)"], ["accepted_risk", "var(--info)"], ["false_positive", "var(--text-3)"]] as const;

function HostsBar({ row }: { row: CheckListRow }) {
  const text = hostsText(row);
  const total = row.failing + row.passing;
  return (
    <div className="stack hosts-cell">
      <span className="triage-bar" role="progressbar" aria-label={`Hosts: ${text}`} aria-valuetext={text} aria-valuemin={0} aria-valuemax={total} aria-valuenow={row.passing}>
        {TONES.map(([state, tone]) => row[state] > 0 && <span key={state} style={{ flexGrow: row[state], background: tone }} />)}
        {row.passing > 0 && <span style={{ flexGrow: row.passing }} />}
      </span>
      <span className="subtle hosts-cell__words">{text}</span>
    </div>
  );
}

function columns(cases: Map<string, number[]>): Column<CheckListRow>[] {
  return [
    { key: "severity", header: header("severity"), width: "100px", sort: (r) => r.severity ?? null, render: (r) => (r.severity ? <SeverityBadge severity={r.severity} /> : none("No severity")) },
    { key: "check", header: header("check"), sort: (r) => r.title, render: (r) => (
      <div className="cell-two">
        <span className="row">{isTest(r.rule_set_id, r.rule_id) && <span className="badge badge--plain">Test</span>}
          <a className="truncate" {...viewLink(checkPath(r.rule_set_id, r.rule_id))}>{r.title}<span className="sr-only"> ({r.rule_id})</span></a>
          <CaseBadge numbers={cases.get(`${r.rule_set_id}/${r.rule_id}`)} /></span>
        <span className="subtle truncate"><span className="mono">{r.rule_id}</span> · {r.rule_set_id}</span>
      </div>
    ) },
    { key: "area", header: header("area"), width: "150px", hideBelow: 760, render: (r) => r.area },
    { key: "failing", header: header("failing"), numeric: true, width: "90px", sort: (r) => r.failing, render: (r) => (
      <span className="num"><b>{r.failing.toLocaleString()}</b> <span className="subtle">of {(r.failing + r.passing).toLocaleString()}</span></span>
    ) },
    { key: "hosts", header: header("hosts"), width: "220px", hideBelow: 640, render: (r) => <HostsBar row={r} /> },
    { key: "since", header: header("since"), width: "80px", hideBelow: 960, sort: (r) => r.since ?? null, render: (r) => (r.since ? <span className="subtle">{date(r.since)}</span> : none("Not failing")) },
    { key: "assignee", header: header("assignee"), width: "130px", hideBelow: 1000, render: (r) => r.assignee.kind === "one"
      ? <span className="truncate">{r.assignee.name}</span> : r.assignee.kind === "several" ? <span>{r.assignee.count} people</span> : none("Unassigned") },
  ];
}

/** The summary line, the table and the pager for one loaded page. */
export function CheckListBody({ list, hidden, offset = 0, selected, onSelect, cases = new Map() }: {
  list: CheckList; hidden: readonly string[]; offset?: number; selected: ReadonlySet<string>; onSelect: (next: Set<string>) => void; cases?: Map<string, number[]>;
}) {
  const s = list.summary;
  const parts = [
    { count: s.failing_checks, text: `${s.failing_checks === 1 ? "check" : "checks"} failing on ${plural(s.hosts, "host")}` },
    { count: s.critical, text: "critical" }, { count: s.unassigned, text: "unassigned" },
  ];
  return (
    <>
      <div className="view-pad host-summary"><SummaryLine parts={parts} tail={s.rule_sets.map((r) => `${r.value} ${r.count.toLocaleString()}`).join(", ")} /></div>
      <DataTable label="Compliance" rows={list.items} rowKey={(r) => `${r.rule_set_id}/${r.rule_id}`} serverSort serverPaged
        selection={{ selected, onChange: onSelect }} onOpen={(r) => nav.view(checkPath(r.rule_set_id, r.rule_id))}
        columns={columns(cases).filter((c) => c.key === "severity" || c.key === "check" || !hidden.includes(c.key))} />
      <Pager offset={offset} shown={list.items.length} total={list.total} />
    </>
  );
}

function CheckListView() {
  const { params } = useLocation();
  const list = useResource<CheckList>(`/api/v1/compliance-list?${apiQuery(params)}`);
  const hidden = useHiddenColumns("compliance");
  const host = params.get("host");
  const hostName = useHostName(host);
  const cases = useCaseBadges("compliance_finding");
  // The last page stays on screen (and its counts in the chips) while the next loads.
  const [kept, setKept] = useState<CheckList>();
  if (list.data && list.data !== kept) setKept(list.data);
  const data = list.data ?? kept;
  // A selection is of this page in this order, and only of the rows on it.
  const [picked, setSelected] = useSelection(apiQuery(params));
  const chosen = (data?.items ?? []).filter((r) => picked.has(`${r.rule_set_id}/${r.rule_id}`));
  const selected = new Set(chosen.map((r) => `${r.rule_set_id}/${r.rule_id}`));
  const bulk = listBulk(chosen);
  // Views saved in this browser before saved views lived on the console (and before the rename from /findings).
  useEffect(() => {
    void importBrowserViews("compliance", "openvibes.v2.views./compliance", complianceQuery)
      .then(() => importBrowserViews("compliance", "openvibes.v2.views./findings", complianceQuery));
  }, []);

  return (
    <div className="view">
      <header className="view-header">
        <div className="view-header__top">
          <div className="view-header__title">
            <h1>Compliance</h1>
            {data && <span className="view-header__count num">{data.total.toLocaleString()}</span>}
          </div>
          <button type="button" className="icon-button" title="Refresh" aria-label="Refresh" onClick={() => invalidate("/api/v1/compliance")}>
            <Icon name="refresh" size={16} />
          </button>
        </div>
        <FilterBar page="compliance" label="Search checks" placeholder="Search check, rule or rule set…"
          filters={checkFilters(data, { host, hostName })} columns={COLUMNS} />
      </header>
      {list.error ? <div className="view-pad"><ErrorBox error={list.error} /></div> : !data ? <Loading /> : data.total === 0 ? (
        hasFilters(params)
          ? <Empty icon="findings" title="No check matches these filters.">Mitigated, accepted, false-positive and passing ones are hidden unless State says otherwise; clear a filter to see more.</Empty>
          : <Empty icon="findings" title="No failing checks">Every host in your scope passes the checks it runs. New failures appear here within a minute of the next scan.</Empty>
      ) : (
        <CheckListBody list={data} hidden={hidden ?? []} offset={Math.max(0, Number(params.get(PAGE)) || 0)} selected={selected} onSelect={setSelected} cases={cases} />
      )}
      <BulkBar kind="compliance" noun={selected.size === 1 ? "check" : "checks"} count={selected.size} onClear={() => setSelected(new Set())}
        items={() => bulkItems(chosen, host)} changes={bulk.changes} without={bulk.without} note={bulk.note}
        confirm={<p>Changes up to {plural(bulk.open, "open host")}. Mitigated, accepted and false-positive hosts are left as they are, and passing hosts are never touched.</p>}
        newCase={() => ({ title: `${chosen.length} ${chosen.length === 1 ? "check" : "checks"}: ${chosen[0]?.rule_id ?? ""} ${chosen[0]?.title ?? ""}`.trim(),
          severity: highest(chosen.flatMap((r) => (r.severity ? [r.severity] : []))) })} />
    </div>
  );
}

/** The rule set and rule in a /compliance/{set}/{rule} path; null when the path is not one (bad escapes, other depths). */
export function checkKeyOf(view: string): [string, string] | null {
  const parts = view.slice("/compliance/".length).split("/");
  if (parts.length !== 2 || parts.some((p) => !p)) return null;
  try {
    return [decodeURIComponent(parts[0] as string), decodeURIComponent(parts[1] as string)];
  } catch {
    return null;
  }
}

export function Findings() {
  const { view } = useLocation();
  if (!view.startsWith("/compliance/")) return <CheckListView />;
  const key = checkKeyOf(view);
  return key ? <CheckPage key={view} set={key[0]} rule={key[1]} /> : <NoSuchCheck />;
}
