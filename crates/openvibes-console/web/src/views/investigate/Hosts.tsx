// The Hosts list (approved screen 16; roles spec §10.3): search and filter
// chips whose values and counts come from the server, saved views, the
// person's columns, a summary line and paging by offset (all in the URL).
// A host opens its page at /hosts/{id}.
import { useEffect, useState } from "react";

import { invalidate, useResource } from "../../api/client";
import type { HostList, HostRow } from "../../api/types";
import { hostPath, hostsQuery } from "../../app/location";
import { nav, useLocation, viewLink } from "../../app/nav";
import { Ago, Empty, ErrorBox, Loading, SAVED_HEARTBEAT_HINT, StatusBadge } from "../../ui/bits";
import { type Column, DataTable } from "../../ui/DataTable";
import { Icon } from "../../ui/Icon";
import { FilterBar } from "../../ui/list/FilterBar";
import { HostPage, NoSuchHost } from "./host/HostPage";
import { HostSubPage, SUB_PAGES, type SubPage } from "./host/HostSubPage";
import { type ListFilter, PAGE, hasFilters } from "../../ui/list/filters";
import { importBrowserViews, useHiddenColumns } from "../../ui/list/savedViews";
import { SummaryLine } from "../../ui/list/SummaryLine";

const PAGE_SIZE = 50;
const ALARMS_OFF = "Threat alarms are off on this host because of a fault, not by choice. Its page says why and how to turn them on.";
/** The list's columns (keys as the console keeps hidden ones), Host first. */
const COLUMNS = [
  { key: "host", label: "Host" }, { key: "os", label: "OS" }, { key: "groups", label: "Groups" }, { key: "labels", label: "Labels" },
  { key: "problems", label: "Open problems" }, { key: "heartbeat", label: "Last heartbeat" }, { key: "agent", label: "Agent" },
] as const;
const header = (key: (typeof COLUMNS)[number]["key"]) => COLUMNS.find((c) => c.key === key)?.label ?? key;

/** The URL's sort (a column key) in the API's spelling. */
const API_SORT: Record<string, string> = { host: "host", heartbeat: "heartbeat", agent: "version", problems: "problems" };
const API_PARAMS = ["q", "status", "os", "group", "label", "problems", "agent", "dir", PAGE];

/** The API query for the list's URL: only what the API reads. */
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

const STATUS: Record<string, string> = { online: "Online", offline: "Offline", revoked: "Revoked", imported: "Imported" };
const OS: Record<string, string> = { linux: "Linux", windows: "Windows" };
const PROBLEMS: Record<string, string> = { critical: "Has critical", alarms: "Has open alarms", none: "None open" };
const AGENT: Record<string, string> = { older: "Older than the latest", latest: "The latest" };
const named = (labels: Record<string, string>) => (c: { value: string; count: number }) => ({ value: c.value, label: labels[c.value] ?? c.value, count: c.count });

/** The filter chips, their values and counts from the list (none until it loads). */
export function hostFilters(list: HostList | undefined): ListFilter[] {
  const c = list?.counts;
  return [
    { param: "status", label: "Status", values: (c?.status ?? []).map(named(STATUS)) },
    { param: "os", label: "OS", values: (c?.os ?? []).map(named(OS)) },
    { param: "group", label: "Group", values: (c?.group ?? []).map((g) => ({ value: g.value, label: g.name, count: g.count })) },
    { param: "label", label: "Label", values: (c?.label ?? []).map(named({})) },
    { param: "problems", label: "Problems", values: (c?.problems ?? []).map(named(PROBLEMS)) },
    { param: "agent", label: "Agent", values: (c?.agent ?? []).map(named(AGENT)) },
  ];
}

/** "—" on screen, `text` for screen readers and on hover. */
function Dash({ text }: { text: string }) {
  return <span className="subtle" title={text}><span aria-hidden="true">—</span><span className="sr-only">{text}</span></span>;
}

/** One problem count; "—" where the viewer may not read that kind on the host. */
function Count({ n, what, tone }: { n: number | null | undefined; what: string; tone: string }) {
  if (n == null) return <Dash text={`You can’t see ${what} on this host`} />;
  return <span className={n > 0 ? tone : "subtle"} title={`${n.toLocaleString()} ${what}`}>{n.toLocaleString()}</span>;
}

function agentNote(row: HostRow, latest: string | null): { older: boolean; title: string } {
  if (!latest) return { older: false, title: "The latest agent release is not known: the update check is off or offline" };
  if (row.agent.older === true) return { older: true, title: `Older than the latest agent release (${latest})` };
  if (row.agent.older === false) return { older: false, title: `The latest agent release (${latest})` };
  return { older: false, title: `Not compared with the latest agent release (${latest})` };
}

function columns(latest: string | null): Column<HostRow>[] {
  return [
    { key: "host", header: header("host"), sort: (h) => h.hostname ?? h.id, render: (h) => (
      <div className="cell-two"><a className="truncate" {...viewLink(hostPath(h.id))}>{h.hostname ?? h.id}</a>{h.address ? <span className="mono subtle">{h.address}</span> : <Dash text="No address reported" />}</div>
    ) },
    { key: "os", header: header("os"), width: "150px", hideBelow: 700, render: (h) => (
      <div className="cell-two">{h.os.distribution ? <span>{h.os.distribution}</span> : <Dash text="OS not reported" />}<span className="subtle">{OS[h.os.family ?? ""] ?? h.os.family ?? ""}</span></div>
    ) },
    { key: "groups", header: header("groups"), hideBelow: 900, render: (h) => (
      <span className="row row--wrap">
        {h.groups.map((g) => <span key={g.id} className="badge badge--plain">{g.name}</span>)}
        {h.group_count > h.groups.length && <span className="subtle" title={`${h.group_count} groups`}>+{h.group_count - h.groups.length}</span>}
        {h.group_count === 0 && <Dash text="In no group" />}
      </span>
    ) },
    { key: "labels", header: header("labels"), hideBelow: 1000, render: (h) => (
      <span className="row row--wrap">{h.labels.length === 0 ? <Dash text="No labels" /> : h.labels.map((l) => <span key={l} className="badge badge--plain">{l}</span>)}</span>
    ) },
    { key: "problems", header: header("problems"), width: "210px", hideBelow: 640, sort: (h) => (h.problems.open_alarms ?? 0) + (h.problems.critical ?? 0) + (h.problems.failing ?? 0), render: (h) => (
      <span className="nowrap">
        <Count n={h.problems.open_alarms} what="open alarms" tone="bad-text" /> {h.problems.open_alarms === 1 ? "alarm" : "alarms"} ·{" "}
        <Count n={h.problems.critical} what="critical vulnerabilities" tone="bad-text" /> critical ·{" "}
        <Count n={h.problems.failing} what="failing checks" tone="warn-text" /> failing
      </span>
    ) },
    { key: "heartbeat", header: header("heartbeat"), width: "120px", sort: (h) => h.last_seen_at, render: (h) => (
      <div className="cell-two"><span className="row row--wrap"><StatusBadge status={h.status} />{h.alarms_off && (
        <span className="badge badge--warn" title={ALARMS_OFF}>Alarms off</span>
      )}</span><span className="subtle"><Ago value={h.last_seen_at} hint={SAVED_HEARTBEAT_HINT} /></span></div>
    ) },
    { key: "agent", header: header("agent"), width: "100px", hideBelow: 600, sort: (h) => h.agent.version, render: (h) => {
      if (!h.agent.version) return <Dash text="Agent version not reported" />;
      const note = agentNote(h, latest);
      return <span className={note.older ? "mono warn-text" : "mono"} title={note.title}>{h.agent.version}</span>;
    } },
  ];
}

/** Previous and next page, and which rows these are. */
export function Pager({ offset, shown, total }: { offset: number; shown: number; total: number }) {
  if (total <= PAGE_SIZE && offset === 0) return null;
  const go = (to: number) => nav.setParams({ [PAGE]: to > 0 ? String(to) : null });
  return (
    <nav className="row pager view-pad" aria-label="Pages">
      <span className="subtle num">{shown === 0 ? "None" : `${(offset + 1).toLocaleString()}–${(offset + shown).toLocaleString()}`} of {total.toLocaleString()}</span>
      <button type="button" className="button button--small" disabled={offset === 0} onClick={() => go(Math.max(0, offset - PAGE_SIZE))}>Previous</button>
      <button type="button" className="button button--small" disabled={offset + PAGE_SIZE >= total} onClick={() => go(offset + PAGE_SIZE)}>Next</button>
    </nav>
  );
}

/** The summary line, the table and the pager for one loaded page. */
export function HostListBody({ list, hidden, offset = 0 }: { list: HostList; hidden: readonly string[]; offset?: number }) {
  const latest = list.latest_agent_version ?? null;
  const parts = [
    { count: list.summary.online, text: "online" },
    // Unknown latest release: no host counts as older, so the part would mislead.
    ...(latest ? [{ count: list.summary.older_agent, text: "with an older agent" }] : []),
    { count: list.summary.critical, text: "with critical vulnerabilities" },
  ];
  return (
    <>
      <div className="view-pad host-summary"><SummaryLine parts={parts} /></div>
      <DataTable label="Hosts" rows={list.items} rowKey={(h) => h.id} serverSort defaultSort={{ key: "host", direction: "asc" }}
        onOpen={(h) => nav.view(hostPath(h.id))}
        columns={columns(latest).filter((c) => !hidden.includes(c.key))} />
      <Pager offset={offset} shown={list.items.length} total={list.total} />
    </>
  );
}

function HostListView() {
  const { params } = useLocation();
  const list = useResource<HostList>(`/api/v1/hosts?${apiQuery(params)}`);
  const hidden = useHiddenColumns("hosts");
  // The last page stays on screen (and its counts in the chips) while the next loads.
  const [kept, setKept] = useState<HostList>();
  if (list.data && list.data !== kept) setKept(list.data);
  const data = list.data ?? kept;
  // Views saved in this browser before saved views lived on the console (plan ruling 8).
  useEffect(() => { void importBrowserViews("hosts", "openvibes.v2.views./agents", hostsQuery); }, []);

  return (
    <div className="view">
      <header className="view-header">
        <div className="view-header__top">
          <div className="view-header__title">
            <h1>Hosts</h1>
            {data && <span className="view-header__count num">{data.total.toLocaleString()}</span>}
          </div>
          <button type="button" className="icon-button" title="Refresh" aria-label="Refresh" onClick={() => invalidate("/api/v1/hosts")}>
            <Icon name="refresh" size={16} />
          </button>
        </div>
        <FilterBar page="hosts" label="Search hosts" placeholder="Search by host name, IP or range…" filters={hostFilters(data)} columns={COLUMNS} />
      </header>
      {list.error ? <div className="view-pad"><ErrorBox error={list.error} /></div> : !data ? <Loading /> : data.total === 0 ? (
        <Empty icon="agents" title={hasFilters(params) ? "Nothing matches these filters" : "No hosts yet"}>
          {hasFilters(params) ? "Clear a filter to see more." : "Create an enrollment token under Enrollment, then install the agent on a host."}
        </Empty>
      ) : (
        <HostListBody list={data} hidden={hidden ?? []} offset={Math.max(0, Number(params.get(PAGE)) || 0)} />
      )}
    </div>
  );
}

/** The host id in a /hosts/{id} path; null when the path is not one (bad escapes). */
export function hostIdOf(view: string): string | null {
  try {
    return decodeURIComponent(view.slice("/hosts/".length)) || null;
  } catch {
    return null;
  }
}

/** A host's page (/hosts/{id}) or one of its lists (/hosts/{id}/software|ports|services); null for anything else. */
export function hostRoute(view: string): { id: string; page: SubPage | null } | null {
  const [raw = "", sub, ...rest] = view.slice("/hosts/".length).split("/");
  if (rest.length > 0 || (sub !== undefined && !Object.hasOwn(SUB_PAGES, sub))) return null;
  const id = hostIdOf(`/hosts/${raw}`);
  return id === null ? null : { id, page: (sub as SubPage | undefined) ?? null };
}

export function Hosts() {
  const { view } = useLocation();
  if (!view.startsWith("/hosts/")) return <HostListView />;
  const route = hostRoute(view);
  if (route === null) return <NoSuchHost />;
  return route.page ? <HostSubPage id={route.id} page={route.page} /> : <HostPage id={route.id} />;
}
