// The Ports list (approved screen 19; roles spec §10.3, step 5e rulings
// 11–17): one row per port over the hosts in the person's reach, search and
// filter chips whose values and counts come from the server, saved views,
// the person's columns, a summary line and paging by offset (all in the
// URL). A row opens the port's page at /ports/{port}/{protocol}
// (port/PortPage.tsx).
import type { PortList, PortListRow } from "../../api/types";
import { parsePortId, portPath, portsQuery } from "../../app/location";
import { nav, useLocation, viewLink } from "../../app/nav";
import { Empty } from "../../ui/bits";
import { type Column, DataTable } from "../../ui/DataTable";
import { plural } from "../../ui/format";
import { type ListFilter, PAGE } from "../../ui/list/filters";
import { Pager } from "./Hosts";
import { ListScreen, ListSummary } from "./ListScreen";
import { PortPage } from "./port/PortPage";

const PAGE_SIZE = 50;
/** The list's columns (keys as the console keeps hidden ones); Port is never hidden. */
const COLUMNS = [
  { key: "port", label: "Port", fixed: true }, { key: "hosts", label: "Hosts" }, { key: "exposed", label: "Exposed" }, { key: "services", label: "Services" },
  { key: "groups", label: "Groups" }, { key: "week", label: "This week" }, { key: "look", label: "Needs a look" },
] as const;
const header = (key: (typeof COLUMNS)[number]["key"]) => COLUMNS.find((c) => c.key === key)?.label ?? key;

const API_PARAMS = ["q", "exposure", "protocol", "group", "service", "changes", "host", "sort", "dir", PAGE];

/** The API query for the list's URL: only what the API reads (it refuses anything else). */
export function apiQuery(params: URLSearchParams): string {
  const query = new URLSearchParams();
  for (const key of API_PARAMS) {
    const value = params.get(key);
    if (value) query.set(key, value);
  }
  query.set("limit", String(PAGE_SIZE));
  return query.toString();
}

const EXPOSURE: Record<string, string> = { exposed: "Exposed", local: "Local only" };
const CHANGES: Record<string, string> = { new: "New this week", look: "Needs a look" };
const NOT_COLLECTED = "~none";
/** Ruling 10's codes as the list says them. */
export const LOOK: Record<string, string> = {
  database_exposed: "Database reachable from the network",
  remote_admin_exposed: "Remote admin reachable from the network",
  new_unusual: "New this week, not a usual port",
};
const named = (labels: Record<string, string>) => (c: { value: string; count: number }) => ({ value: c.value, label: labels[c.value] ?? c.value, count: c.count });

/** The filter chips, their values and counts from the list (none until it loads); Host only while set. */
export function portFilters(list: PortList | undefined, set: { host: string | null; hostName: string | undefined }): ListFilter[] {
  const c = list?.counts;
  return [
    { param: "exposure", label: "Exposure", values: (c?.exposure ?? []).map(named(EXPOSURE)) },
    { param: "protocol", label: "Protocol", values: (c?.protocol ?? []).map(named({ tcp: "TCP", udp: "UDP" })) },
    { param: "changes", label: "Changes", values: (c?.changes ?? []).map(named(CHANGES)) },
    { param: "group", label: "Group", values: (c?.group ?? []).map((g) => ({ value: g.value, label: g.name, count: g.count })) },
    { param: "service", label: "Service", values: (c?.service ?? []).map(named({ [NOT_COLLECTED]: "Owner not collected" })) },
    { param: "host", label: "Host", chipOnly: true, values: set.host ? [{ value: set.host, label: set.hostName ?? set.host, count: list?.total ?? 0 }] : [] },
  ];
}

const dash = (text: string) => <span className="subtle" title={text}><span aria-hidden="true">—</span><span className="sr-only">{text}</span></span>;

/** "+2 hosts" / "−1 host" / "No change" (ruling 8). */
function Week({ row }: { row: PortListRow }) {
  if (row.week_added === 0 && row.week_removed === 0) return <span className="subtle">No change</span>;
  return (
    <span className="row nowrap" style={{ gap: 6 }}>
      {row.week_added > 0 && <span className="num">+{plural(row.week_added, "host")}</span>}
      {row.week_removed > 0 && <span className="num subtle">−{plural(row.week_removed, "host")}</span>}
    </span>
  );
}

const columns: Column<PortListRow>[] = [
  { key: "port", header: header("port"), width: "190px", sort: (r) => r.port, render: (r) => (
    <div className="cell-two">
      <a className="mono" {...viewLink(portPath(r.protocol, r.port))}>{r.port}/{r.protocol}</a>
      {r.name ? <span className="subtle truncate">{r.name}</span> : <span className="subtle">Not a usual port</span>}
    </div>
  ) },
  { key: "hosts", header: header("hosts"), numeric: true, width: "110px", sort: (r) => r.hosts, render: (r) => <strong className="num">{r.hosts.toLocaleString()}</strong> },
  { key: "exposed", header: header("exposed"), width: "130px", sort: (r) => r.exposed_hosts,
    render: (r) => r.exposed_hosts > 0 ? <span className="badge badge--warn badge--plain">{plural(r.exposed_hosts, "host")}</span> : <span className="subtle">local only</span> },
  { key: "services", header: header("services"), hideBelow: 700, render: (r) => (
    <div className="cell-two">
      <span className="mono truncate">{r.services.length > 0 ? r.services.join(", ") : dash("No owner reported")}</span>
      {r.owners_missing && <span className="subtle">Owner not collected</span>}
    </div>
  ) },
  { key: "groups", header: header("groups"), hideBelow: 900, render: (r) => (
    <span className="row">
      {r.groups.map((g) => <span key={g.id} className="badge badge--plain">{g.name}</span>)}
      {r.groups_total > r.groups.length && <span className="subtle" title={`${r.groups_total} groups`}>+{r.groups_total - r.groups.length}</span>}
      {r.groups_total === 0 && dash("In no group")}
    </span>
  ) },
  { key: "week", header: header("week"), width: "150px", hideBelow: 820, sort: (r) => r.week_added, render: (r) => <Week row={r} /> },
  { key: "look", header: header("look"), width: "260px", hideBelow: 1000, render: (r) => {
    const [first, ...rest] = r.look;
    return first === undefined ? dash("Nothing to look at") : (
      <span className="row"><span className="badge badge--warn badge--plain">{LOOK[first] ?? first}</span>{rest.length > 0 && <span className="subtle" title={rest.map((c) => LOOK[c] ?? c).join(", ")}>+{rest.length}</span>}</span>
    );
  } },
];

/** The summary line, the table and the pager for one loaded page. */
export function PortListBody({ list, hidden, offset = 0 }: { list: PortList; hidden: readonly string[]; offset?: number }) {
  const s = list.summary;
  const parts = [
    { count: s.exposed, text: s.exposed === 1 ? "port reachable from the network" : "ports reachable from the network" },
    { count: s.new_this_week, text: "new this week" }, { count: s.need_a_look, text: "need a look" },
  ];
  return (
    <>
      <ListSummary parts={parts} hosts={s.reporting_hosts} />
      <DataTable label="Ports" rows={list.items} rowKey={(r) => `${r.protocol}/${r.port}`} serverSort serverPaged onOpen={(r) => nav.view(portPath(r.protocol, r.port))}
        columns={columns.filter((c) => c.key === "port" || !hidden.includes(c.key))} />
      <Pager offset={offset} shown={list.items.length} total={list.total} />
    </>
  );
}

const PortListView = () => (
  <ListScreen<PortList> page="ports" title="Ports" listPath="/api/v1/port-list" query={apiQuery} icon="activity" noun="port" columns={COLUMNS} filters={portFilters} legacyQuery={portsQuery}
    search={{ label: "Search ports", placeholder: "Search port, name or service…" }}
    body={(list, hidden, offset) => <PortListBody list={list} hidden={hidden} offset={offset} />} />
);

/** The port in a /ports/{port}/{protocol} path ("22/tcp"); null when the path is not one (bad escapes, a sub-path). */
export function portOf(view: string): [string, number] | null {
  const rest = view.slice("/ports/".length).split("/");
  if (rest.length !== 2) return null;
  try {
    return parsePortId(`${decodeURIComponent(rest[1] ?? "")}/${decodeURIComponent(rest[0] ?? "")}`);
  } catch {
    return null;
  }
}

export function Ports() {
  const { view } = useLocation();
  if (!view.startsWith("/ports/")) return <PortListView />;
  const port = portOf(view);
  return port ? <PortPage key={port.join("/")} protocol={port[0]} port={port[1]} /> : <Empty icon="activity" title="No such port">A port is a protocol and a number from 1 to 65535, such as 22/tcp.</Empty>;
}
