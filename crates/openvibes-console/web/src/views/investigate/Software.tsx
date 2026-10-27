// The Software list (approved screen 23; roles spec §10.3, step 5g rulings
// 1-10): one row per package name over the hosts in the person's reach (rpm
// and dpkg in one row), search and filter chips whose values and counts come
// from the server, saved views, the person's columns, a summary line and
// paging by offset (all in the URL). A row opens the package's page at
// /software/{name} (software/SoftwarePage.tsx).
import type { SoftwareList, SoftwareListRow } from "../../api/types";
import { servicePath, softwarePath } from "../../app/location";
import { nav, useLocation, viewLink } from "../../app/nav";
import { Empty, SeverityBadge } from "../../ui/bits";
import { type Column, DataTable } from "../../ui/DataTable";
import { plural } from "../../ui/format";
import { Icon } from "../../ui/Icon";
import { type ListFilter, PAGE } from "../../ui/list/filters";
import { Pager } from "./Hosts";
import { ListScreen, ListSummary, dash, groupValues, hostFilter, listApiQuery, named } from "./ListScreen";
import { SoftwarePage } from "./software/SoftwarePage";

/** The list's columns (keys as the console keeps hidden ones and as the API sorts); Package is never hidden. */
const COLUMNS = [
  { key: "package", label: "Package", fixed: true }, { key: "hosts", label: "Hosts" }, { key: "versions", label: "Versions" },
  { key: "vulnerabilities", label: "Vulnerabilities" }, { key: "fix", label: "Fix" }, { key: "used_by", label: "Used by" }, { key: "week", label: "This week" },
] as const;
const header = (key: (typeof COLUMNS)[number]["key"]) => COLUMNS.find((c) => c.key === key)?.label ?? key;

const API_PARAMS = ["q", "vulns", "fix", "versions", "type", "group", "changes", "host", "sort", "dir", PAGE];

/** The API query for the list's URL: only what the API reads (it refuses anything else). */
export const apiQuery = (params: URLSearchParams) => listApiQuery(params, API_PARAMS);

const VULNS: Record<string, string> = { exploited: "Exploited", critical_high: "Critical or high", any: "Any", none: "None" };
const FIX: Record<string, string> = { available: "Update available", none: "No fix yet" };
const VERSIONS: Record<string, string> = { one: "One version", several: "Several versions" };
const TYPE: Record<string, string> = { rpm: "rpm", dpkg: "dpkg" };
const CHANGES: Record<string, string> = { new: "New this week", updated: "Updated this week", removed: "Removed this week" };

/** The filter chips, their values and counts from the list (none until it loads); Host only while set. */
export function softwareFilters(list: SoftwareList | undefined, set: { host: string | null; hostName: string | undefined }): ListFilter[] {
  const c = list?.counts;
  return [
    { param: "vulns", label: "Vulnerabilities", values: (c?.vulns ?? []).map(named(VULNS)) },
    { param: "fix", label: "Fix", values: (c?.fix ?? []).map(named(FIX)) },
    { param: "versions", label: "Versions", values: (c?.versions ?? []).map(named(VERSIONS)) },
    // A group's count is the hosts it has in reach, not packages.
    { param: "group", label: "Group", values: groupValues(c?.group).map((v) => ({ ...v, hint: plural(v.count, "host") })) },
    { param: "type", label: "Type", values: (c?.type ?? []).map(named(TYPE)) },
    { param: "changes", label: "Changes", values: (c?.changes ?? []).map(named(CHANGES)) },
    hostFilter(set, list?.total),
  ];
}

const managers = (r: { rpm: boolean; dpkg: boolean }) => [r.rpm && "rpm", r.dpkg && "dpkg"].filter(Boolean).join(" + ");

/** "1.0 to 1.3" with the count, or the one version. */
function VersionRange({ row }: { row: SoftwareListRow }) {
  if (row.versions <= 1) return <div className="cell-two"><span className="mono truncate">{row.newest}</span><span className="subtle">1 version</span></div>;
  return (
    <div className="cell-two">
      <span className="mono truncate" title={`${row.oldest} to ${row.newest}`}>{row.oldest} <span className="subtle">to</span> {row.newest}</span>
      <span className="text-warn">{row.versions} versions</span>
    </div>
  );
}

/** Worst severity, how many advisories and whether any is exploited; "no fix" counts the ones nothing fixes yet. */
function Vulnerabilities({ row }: { row: SoftwareListRow }) {
  if (row.advisories === 0) return dash("No open vulnerability");
  return (
    <span className="row row--wrap">
      {row.worst_severity && <SeverityBadge severity={row.worst_severity} />}
      <span className="num">{row.advisories}</span>
      {row.exploited && <span className="badge badge--critical badge--plain" title="An advisory is known to be exploited"><Icon name="flame" size={12} /> Exploited</span>}
    </span>
  );
}

function FixCell({ row }: { row: SoftwareListRow }) {
  if (row.update_hosts > 0) return <span className="badge badge--warn badge--plain">Update on {row.update_hosts.toLocaleString()}</span>;
  if (row.no_fix > 0) return <span className="subtle">No fix yet</span>;
  return dash("Nothing to update");
}

/** The services that run from the package; a few by name, then the count. */
function UsedBy({ row }: { row: SoftwareListRow }) {
  if (row.used_by.length === 0) return dash("No service runs from it");
  return (
    <span className="row">
      {row.used_by.map((u) => <a key={u.unit} className="badge badge--plain mono" title={`Runs on ${plural(u.hosts, "host")}`} {...viewLink(servicePath(u.unit))}>{u.unit.replace(/\.service$/, "")}</a>)}
      {row.used_by_total > row.used_by.length && <span className="subtle" title={`${row.used_by_total} services`}>+{row.used_by_total - row.used_by.length}</span>}
    </span>
  );
}

/** "+3 new · 2 updated · −1 removed" in hosts, or "No change". */
function WeekCell({ row }: { row: SoftwareListRow }) {
  if (row.week_added === 0 && row.week_updated === 0 && row.week_removed === 0) return <span className="subtle">No change</span>;
  return (
    <span className="row nowrap" style={{ gap: 6 }}>
      {row.week_added > 0 && <span className="num">+{row.week_added.toLocaleString()} new</span>}
      {row.week_updated > 0 && <span className="num">{row.week_updated.toLocaleString()} updated</span>}
      {row.week_removed > 0 && <span className="num subtle">−{row.week_removed.toLocaleString()}</span>}
    </span>
  );
}

const columns: Column<SoftwareListRow>[] = [
  { key: "package", header: header("package"), width: "240px", sort: (r) => r.name, render: (r) => (
    <div className="cell-two"><a className="mono truncate" {...viewLink(softwarePath(r.name))}>{r.name}</a><span className="subtle">{managers(r)}</span></div>
  ) },
  { key: "hosts", header: header("hosts"), numeric: true, width: "90px", sort: (r) => r.hosts, render: (r) => <strong className="num">{r.hosts.toLocaleString()}</strong> },
  { key: "versions", header: header("versions"), width: "200px", hideBelow: 640, sort: (r) => r.versions, render: (r) => <VersionRange row={r} /> },
  { key: "vulnerabilities", header: header("vulnerabilities"), width: "200px", hideBelow: 560, sort: (r) => r.advisories, render: (r) => <Vulnerabilities row={r} /> },
  { key: "fix", header: header("fix"), width: "150px", hideBelow: 760, render: (r) => <FixCell row={r} /> },
  { key: "used_by", header: header("used_by"), hideBelow: 900, render: (r) => <UsedBy row={r} /> },
  { key: "week", header: header("week"), width: "190px", hideBelow: 1000, sort: (r) => r.week_added + r.week_updated + r.week_removed, render: (r) => <WeekCell row={r} /> },
];

/** The summary line, the table and the pager for one loaded page. */
export function SoftwareListBody({ list, hidden, offset = 0 }: { list: SoftwareList; hidden: readonly string[]; offset?: number }) {
  const s = list.summary;
  const parts = [
    { count: s.exploited, text: s.exploited === 1 ? "has an exploited vulnerability" : "have an exploited vulnerability" },
    { count: s.fixable, text: s.fixable === 1 ? "has an update available" : "have an update available" },
    { count: s.several_versions, text: s.several_versions === 1 ? "has several versions in use" : "have several versions in use" },
    { count: s.new_this_week, text: "new this week" },
  ];
  return (
    <>
      <ListSummary parts={parts} hosts={s.reporting_hosts} />
      <DataTable label="Software" rows={list.items} rowKey={(r) => r.name} serverSort serverPaged onOpen={(r) => nav.view(softwarePath(r.name))}
        columns={columns.filter((c) => c.key === "package" || !hidden.includes(c.key))} />
      <Pager offset={offset} shown={list.items.length} total={list.total} />
    </>
  );
}

const SoftwareListView = () => (
  <ListScreen<SoftwareList> page="software" title="Software" listPath="/api/v1/software-list" query={apiQuery} icon="package" noun="package" columns={COLUMNS} filters={softwareFilters} legacyQuery={(query) => query}
    empty="Agents report their installed packages shortly after they enroll."
    search={{ label: "Search software", placeholder: "Search package or service…" }}
    body={(list, hidden, offset) => <SoftwareListBody list={list} hidden={hidden} offset={offset} />} />
);

/** The package in a /software/{name} path; null when the path is not one (bad escapes, a sub-path, an empty name). */
export function nameOf(view: string): string | null {
  const rest = view.slice("/software/".length);
  if (rest === "" || rest.includes("/")) return null;
  try {
    const name = decodeURIComponent(rest);
    return name === "" || [...name].some((ch) => ch < " ") ? null : name;
  } catch {
    return null;
  }
}

export function Software() {
  const { view } = useLocation();
  if (!view.startsWith("/software/")) return <SoftwareListView />;
  const name = nameOf(view);
  return name ? <SoftwarePage key={name} name={name} /> : <Empty icon="package" title="No such package">A package is a name such as openssl.</Empty>;
}
