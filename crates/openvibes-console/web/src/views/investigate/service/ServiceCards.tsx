// The cards of a service's page (approved screen 22): Details, Ports, By
// group and Recent changes on the left; Hosts (segments and the paged table)
// and Related on the right. Every card reads the summary but Hosts, which
// pages its own route.
import type { ServicePageHosts, ServicePageSummary } from "../../../api/types";
import { portPath } from "../../../app/location";
import { viewLink } from "../../../app/nav";
import { Card } from "../../../ui/detail/DetailPage";
import { RelatedCard } from "../../../ui/detail/RelatedCard";
import { plural } from "../../../ui/format";
import { ChangeList, GroupMeters, HostCell, HostsPanel, ReportedCell, failingChecks, openAlarms, openVulnerabilities, segmentIn, stale } from "../hostPageParts";

export { stale };

type Page = ServicePageSummary;
type HostRow = ServicePageHosts["items"][number];

const ROOT = new Set(["root", "0", "system", "localsystem", "nt authority\\system"]);
/** Root or SYSTEM, as the list and the server count it (ruling 5). */
export const isRoot = (user: string) => ROOT.has(user.toLowerCase());

export function DetailsCard({ page }: { page: Page }) {
  const { details, header } = page;
  const unpackaged = header.running - details.package_hosts;
  return (
    <Card title="Details">
      <dl className="kv">
        <dt>What it is</dt><dd>{header.name ? <>{header.name}{header.usual_use && <span className="subtle"> · {header.usual_use}</span>}</> : <span className="subtle">Not a usual service</span>}</dd>
        <dt>Runs as</dt>
        <dd>
          {details.run_as.length === 0 ? <span className="subtle">Not reported</span> : details.run_as.map((r, i) => (
            <span key={r.user}>{i > 0 && ", "}<span className={`mono${isRoot(r.user) ? " text-warn" : ""}`}>{r.user}</span><span className="subtle"> on {plural(r.hosts, "host")}</span></span>
          ))}
        </dd>
        <dt>Programs</dt><dd>{details.programs.length > 0 ? <span className="mono">{details.programs.join(", ")}</span> : <span className="subtle">Not reported</span>}</dd>
        <dt>Package</dt>
        <dd>
          {details.packages.length === 0 ? <span className="text-warn">Not from a package</span> : details.packages.map((p, i) => (
            <span key={p.name}>{i > 0 && ", "}<a className="object-link mono" {...viewLink("/software")}>{p.name}</a><span className="subtle"> on {plural(p.hosts, "host")}</span></span>
          ))}
          <span className="subtle"> · matched by name</span>
          {details.packages.length > 0 && unpackaged > 0 && <span className="text-warn"> · not on {plural(unpackaged, "host")}</span>}
        </dd>
        <dt>Processes</dt><dd className="num">{details.processes.toLocaleString()}</dd>
      </dl>
    </Card>
  );
}

export function PortsCard({ page }: { page: Page }) {
  return (
    <Card title="Ports">
      {page.ports.length === 0 ? <p className="subtle">It owns no port on a host whose owners were collected.</p> : (
        <ul className="list list--plain" aria-label="Ports it owns">
          {page.ports.map((p) => (
            <li key={`${p.protocol}/${p.port}`} className="list__row list__row--static">
              <a className="object-link mono" {...viewLink(portPath(p.protocol, p.port))}>{p.port}/{p.protocol}</a>
              {p.exposed ? <span className="badge badge--warn badge--plain">exposed</span> : <span className="subtle">local only</span>}
              <span className="grow" /><span className="subtle nowrap">{plural(p.hosts, "host")}</span>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}

export function GroupsCard({ page }: { page: Page }) {
  return <GroupMeters groups={page.by_group.map((g) => ({ ...g, count: g.running }))} empty="No automatic or rule group holds a host running it."
    listLabel="Hosts running it, by group" meterLabel="run it" />;
}

/** What a change says about a host (the log's two service kinds). */
export const CHANGE_TEXT: Record<string, string> = { appeared: "started running it", went_away: "stopped running it" };

export const ChangesCard = ({ page }: { page: Page }) => <ChangeList changes={page.changes} text={CHANGE_TEXT} />;

const SEGMENTS = ["all", "exposed", "root"] as const;
type Segment = (typeof SEGMENTS)[number];
const SEGMENT_LABEL: Record<Segment, string> = { all: "All", exposed: "Exposed", root: "Runs as root" };
/** The URL's `segment`; anything unknown is All. */
export const segmentOf = (value: string | null): Segment => segmentIn(SEGMENTS, value);

export const hostsPath = (unit: string, query = "") => `/api/v1/services/${encodeURIComponent(unit)}/hosts${query}`;

export function HostsCard({ page }: { page: Page; here: string }) {
  const unit = page.header.unit;
  return <HostsPanel<HostRow, Segment> hostsUrl={(query) => hostsPath(unit, query)} segments={SEGMENTS} labels={SEGMENT_LABEL} chipsLabel="Hosts by exposure and user"
    fallback={page.header.running} emptyAll="No host in your reach runs it" table={(rows) => <HostsTable rows={rows} />} />;
}

/** "3 alarms · 2 vulnerabilities", a dash when none; a count the person may not read is left out. */
function Problems({ row }: { row: HostRow }) {
  const { alarms, vulnerabilities } = row.problems;
  const parts = [alarms ? plural(alarms, "alarm") : null, vulnerabilities ? plural(vulnerabilities, "vulnerability") : null].filter(Boolean);
  if (alarms === undefined && vulnerabilities === undefined) return <span className="subtle" title="You may not read alarms or vulnerabilities here">—</span>;
  return parts.length === 0 ? <span className="subtle">None</span> : <span className="text-warn">{parts.join(" · ")}</span>;
}

export function HostsTable({ rows }: { rows: readonly HostRow[] }) {
  return (
    <div className="table-wrap">
      <table className="table table--compact" aria-label="Hosts">
        <thead><tr><th>Host</th><th>Version</th><th>Processes</th><th>Ports</th><th>Problems</th><th>Last report</th></tr></thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.agent_id}>
              <HostCell row={r} />
              <td>{r.package ? <div className="cell-two"><span className="mono truncate">{r.package.version}</span><span className="subtle mono truncate">{r.package.name}</span></div> : <span className="text-warn" title="No package matched by name">not from a package</span>}</td>
              <td><div className="cell-two"><span className="num">{r.processes.toLocaleString()}</span>{r.run_as && <span className={isRoot(r.run_as) ? "text-warn mono" : "subtle mono"}>as {r.run_as}</span>}</div></td>
              <td>{r.ports.length === 0 ? <span className="subtle" title={r.owners_partial ? "Owners not collected on this host" : "Owns no port"}>{r.owners_partial ? "not collected" : "—"}</span> : (
                <span className="row">{r.ports.map((p) => <a key={`${p.protocol}/${p.port}`} className={`badge badge--plain mono${p.exposed ? " badge--warn" : ""}`} {...viewLink(portPath(p.protocol, p.port))}>{p.port}/{p.protocol}</a>)}</span>
              )}</td>
              <td><Problems row={r} /></td>
              <ReportedCell at={r.reported_at} />
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/** Related (ruling 13): failing checks, open advisories of the matched packages and open alarms, each with its permission. */
export function RelatedServiceCard({ page }: { page: Page }) {
  const { compliance, vulnerabilities, alarms } = page.related;
  const sections = [
    ...(compliance ? [failingChecks(compliance)] : []),
    ...(vulnerabilities ? [vulnerabilities.packages.length === 0 ? { label: "Vulnerabilities", value: <span className="subtle">No package matched by name</span> } : openVulnerabilities(vulnerabilities.packages)] : []),
    ...(alarms ? [openAlarms("Open alarms from its programs", alarms.programs_not_collected && "Programs not collected", alarms)] : []),
  ];
  return <RelatedCard sections={sections} />;
}
