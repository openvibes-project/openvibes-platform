// The Services list (approved screen 21; roles spec §10.3, step 5f rulings
// 1-10): one row per unit over the hosts in the person's reach, search and
// filter chips whose values and counts come from the server, saved views, the
// person's columns, a summary line and paging by offset (all in the URL). A
// row opens the service's page at /services/{unit} (service/ServicePage.tsx).
import type { ServiceList, ServiceListRow } from "../../api/types";
import { portPath, servicePath } from "../../app/location";
import { nav, useLocation, viewLink } from "../../app/nav";
import { Empty } from "../../ui/bits";
import { type Column, DataTable } from "../../ui/DataTable";
import { plural } from "../../ui/format";
import { type ListFilter, PAGE } from "../../ui/list/filters";
import { Pager } from "./Hosts";
import { ListScreen, ListSummary } from "./ListScreen";
import { isRoot } from "./service/ServiceCards";
import { ServicePage } from "./service/ServicePage";

const PAGE_SIZE = 50;
/** The list's columns (keys as the console keeps hidden ones); Service is never hidden. */
const COLUMNS = [
  { key: "service", label: "Service", fixed: true }, { key: "hosts", label: "Hosts" }, { key: "runs_as", label: "Runs as" }, { key: "ports", label: "Ports" },
  { key: "package", label: "Programs and package" }, { key: "week", label: "This week" }, { key: "look", label: "Needs a look" },
] as const;
const header = (key: (typeof COLUMNS)[number]["key"]) => COLUMNS.find((c) => c.key === key)?.label ?? key;

const API_PARAMS = ["q", "runs_as", "listens", "packaged", "group", "changes", "host", "sort", "dir", PAGE];

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

const RUNS_AS: Record<string, string> = { root: "Root or SYSTEM", other: "Another user" };
const LISTENS: Record<string, string> = { exposed: "On an exposed port", local: "Local ports only", none: "No ports" };
const PACKAGED: Record<string, string> = { yes: "From a package", no: "Not from a package" };
const CHANGES: Record<string, string> = { new: "New this week", look: "Needs a look" };
/** Ruling 7's codes as the list says them. */
export const LOOK: Record<string, string> = {
  root_unpackaged: "Runs as root and not from a package",
  database_exposed: "Database reachable from the network",
  remote_admin_exposed: "Remote admin reachable from the network",
  new_unusual: "New this week, not a usual service",
};
const named = (labels: Record<string, string>) => (c: { value: string; count: number }) => ({ value: c.value, label: labels[c.value] ?? c.value, count: c.count });

/** The filter chips, their values and counts from the list (none until it loads); Host only while set. */
export function serviceFilters(list: ServiceList | undefined, set: { host: string | null; hostName: string | undefined }): ListFilter[] {
  const c = list?.counts;
  return [
    { param: "runs_as", label: "Runs as", values: (c?.runs_as ?? []).map(named(RUNS_AS)) },
    { param: "listens", label: "Listens", values: (c?.listens ?? []).map(named(LISTENS)) },
    { param: "packaged", label: "Package", values: (c?.packaged ?? []).map(named(PACKAGED)) },
    { param: "changes", label: "Changes", values: (c?.changes ?? []).map(named(CHANGES)) },
    { param: "group", label: "Group", values: (c?.group ?? []).map((g) => ({ value: g.value, label: g.name, count: g.count })) },
    { param: "host", label: "Host", chipOnly: true, values: set.host ? [{ value: set.host, label: set.hostName ?? set.host, count: list?.total ?? 0 }] : [] },
  ];
}

const dash = (text: string) => <span className="subtle" title={text}><span aria-hidden="true">—</span><span className="sr-only">{text}</span></span>;

/** "+2 hosts" / "−1 host" / "No change" (ruling 8). */
function Week({ row }: { row: ServiceListRow }) {
  if (row.week_added === 0 && row.week_removed === 0) return <span className="subtle">No change</span>;
  return (
    <span className="row nowrap" style={{ gap: 6 }}>
      {row.week_added > 0 && <span className="num">+{plural(row.week_added, "host")}</span>}
      {row.week_removed > 0 && <span className="num subtle">−{plural(row.week_removed, "host")}</span>}
    </span>
  );
}

/** "root" (amber) on every host, "root on 2 of 5" when only some, then the other users. */
function RunsAs({ row }: { row: ServiceListRow }) {
  const others = row.run_as.filter((u) => !isRoot(u));
  return (
    <span className="row">
      {row.root_hosts > 0 && <span className="badge badge--warn badge--plain" title={`Root or SYSTEM on ${plural(row.root_hosts, "host")}`}>{row.root_hosts === row.hosts ? "root" : `root on ${row.root_hosts.toLocaleString()} of ${row.hosts.toLocaleString()}`}</span>}
      {others.length > 0 && <span className="mono truncate">{others.join(", ")}</span>}
      {row.run_as.length === 0 && dash("User not reported")}
    </span>
  );
}

const columns: Column<ServiceListRow>[] = [
  { key: "service", header: header("service"), width: "260px", sort: (r) => r.unit, render: (r) => (
    <div className="cell-two">
      <a className="mono truncate" {...viewLink(servicePath(r.unit))}>{r.unit}</a>
      {r.name ? <span className="subtle truncate" title={r.usual_use ?? undefined}>{r.name}</span> : <span className="subtle">Not a usual service</span>}
    </div>
  ) },
  { key: "hosts", header: header("hosts"), numeric: true, width: "100px", sort: (r) => r.hosts, render: (r) => <strong className="num">{r.hosts.toLocaleString()}</strong> },
  { key: "runs_as", header: header("runs_as"), width: "170px", hideBelow: 700, render: (r) => <RunsAs row={r} /> },
  { key: "ports", header: header("ports"), width: "190px", hideBelow: 820, render: (r) => r.ports.length === 0 ? dash("Owns no port") : (
    <span className="row">
      {r.ports.map((p) => (
        <a key={`${p.protocol}/${p.port}`} className={`badge badge--plain mono${p.exposed ? " badge--warn" : ""}`} title={p.exposed ? "Exposed on at least one host" : "Local only"} {...viewLink(portPath(p.protocol, p.port))}>{p.port}/{p.protocol}</a>
      ))}
      {r.ports_total > r.ports.length && <span className="subtle" title={`${r.ports_total} ports`}>+{r.ports_total - r.ports.length}</span>}
    </span>
  ) },
  { key: "package", header: header("package"), hideBelow: 900, render: (r) => (
    <div className="cell-two">
      <span className="mono truncate">{r.programs.length > 0 ? r.programs.join(", ") : dash("Program not reported")}</span>
      {r.package_hosts === 0 ? <span className="text-warn">not from a package</span>
        : r.package_hosts < r.hosts ? <span className="subtle"><span className="mono">{r.package}</span>, <span className="text-warn">not on {r.hosts - r.package_hosts} of {r.hosts}</span></span>
        : <span className="subtle mono truncate">{r.package}</span>}
    </div>
  ) },
  { key: "week", header: header("week"), width: "150px", hideBelow: 1000, sort: (r) => r.week_added, render: (r) => <Week row={r} /> },
  { key: "look", header: header("look"), width: "260px", hideBelow: 1100, render: (r) => {
    const [first, ...rest] = r.look;
    return first === undefined ? dash("Nothing to look at") : (
      <span className="row"><span className="badge badge--warn badge--plain">{LOOK[first] ?? first}</span>{rest.length > 0 && <span className="subtle" title={rest.map((c) => LOOK[c] ?? c).join(", ")}>+{rest.length}</span>}</span>
    );
  } },
];

/** The summary line, the table and the pager for one loaded page. */
export function ServiceListBody({ list, hidden, offset = 0 }: { list: ServiceList; hidden: readonly string[]; offset?: number }) {
  const s = list.summary;
  const parts = [
    { count: s.root, text: s.root === 1 ? "service runs as root" : "services run as root" },
    { count: s.exposed, text: s.exposed === 1 ? "listens on an exposed port" : "listen on an exposed port" },
    { count: s.not_packaged, text: "not from a package" },
    { count: s.new_this_week, text: "new this week" }, { count: s.need_a_look, text: "need a look" },
  ];
  return (
    <>
      <ListSummary parts={parts} hosts={s.reporting_hosts} />
      <DataTable label="Services" rows={list.items} rowKey={(r) => r.unit} serverSort serverPaged onOpen={(r) => nav.view(servicePath(r.unit))}
        columns={columns.filter((c) => c.key === "service" || !hidden.includes(c.key))} />
      <Pager offset={offset} shown={list.items.length} total={list.total} />
    </>
  );
}

const ServiceListView = () => (
  <ListScreen<ServiceList> page="services" title="Services" listPath="/api/v1/service-list" query={apiQuery} icon="layers" noun="service" columns={COLUMNS} filters={serviceFilters} legacyQuery={(query) => query}
    search={{ label: "Search services", placeholder: "Search service, program, package or port…" }}
    body={(list, hidden, offset) => <ServiceListBody list={list} hidden={hidden} offset={offset} />} />
);

/** The unit in a /services/{unit} path; null when the path is not one (bad escapes, a sub-path, an empty unit). */
export function unitOf(view: string): string | null {
  const rest = view.slice("/services/".length);
  if (rest === "" || rest.includes("/")) return null;
  try {
    const unit = decodeURIComponent(rest);
    return unit === "" || [...unit].some((ch) => ch < " ") ? null : unit;
  } catch {
    return null;
  }
}

export function Services() {
  const { view } = useLocation();
  if (!view.startsWith("/services/")) return <ServiceListView />;
  const unit = unitOf(view);
  return unit ? <ServicePage key={unit} unit={unit} /> : <Empty icon="layers" title="No such service">A service is a unit such as sshd.service.</Empty>;
}
