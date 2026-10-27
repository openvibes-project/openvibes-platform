// The cards of a port's page (approved screen 20): Details, By group and
// Recent changes on the left; Hosts (segments and the paged table) and
// Related on the right. Every card reads the summary but Hosts, which pages
// its own route.
import type { PortPageHosts, PortPageSummary } from "../../../api/types";
import { Card } from "../../../ui/detail/DetailPage";
import { RelatedCard } from "../../../ui/detail/RelatedCard";
import { plural } from "../../../ui/format";
import { ChangeList, GroupMeters, HostCell, HostsPanel, ReportedCell, failingChecks, openAlarms, openVulnerabilities, segmentIn, stale } from "../hostPageParts";

export { stale };

type Page = PortPageSummary;
type HostRow = PortPageHosts["items"][number];

export function DetailsCard({ page }: { page: Page }) {
  const { details, header } = page;
  const missing = details.owners.of - details.owners.collected;
  return (
    <Card title="Details">
      <dl className="kv">
        {header.usual_use && <><dt>Usual use</dt><dd>{header.usual_use}</dd></>}
        <dt>Programs</dt>
        <dd>
          {details.programs.length > 0 ? <span className="mono">{details.programs.join(", ")}</span> : <span className="subtle">Not collected</span>}
          {missing > 0 && details.programs.length > 0 && <span className="subtle"> · not collected on {missing.toLocaleString()} of {plural(details.owners.of, "host")}</span>}
          {missing > 0 && details.programs.length === 0 && details.owners.of > 0 && <span className="subtle"> on {plural(details.owners.of, "host")}</span>}
        </dd>
        <dt>Services</dt><dd>{header.services === 0 ? <span className="subtle">None reported</span> : header.services.toLocaleString()}</dd>
      </dl>
    </Card>
  );
}

export function GroupsCard({ page }: { page: Page }) {
  return <GroupMeters groups={page.by_group.map((g) => ({ ...g, count: g.listening }))} empty="No automatic or rule group holds a host listening on it."
    listLabel="Hosts listening, by group" meterLabel="listen" />;
}

/** What a change says about a host (ruling 20; the log's four kinds). */
export const CHANGE_TEXT: Record<string, string> = {
  appeared: "started listening", went_away: "stopped listening", local: "now listens only locally", exposed: "is now exposed",
};

export const ChangesCard = ({ page }: { page: Page }) => <ChangeList changes={page.changes} text={CHANGE_TEXT} />;

const SEGMENTS = ["all", "exposed", "local"] as const;
type Segment = (typeof SEGMENTS)[number];
const SEGMENT_LABEL: Record<Segment, string> = { all: "All", exposed: "Exposed", local: "Local only" };
/** The URL's `segment`; anything unknown is All. */
export const segmentOf = (value: string | null): Segment => segmentIn(SEGMENTS, value);

export const hostsPath = (protocol: string, port: number, query = "") => `/api/v1/ports/${encodeURIComponent(protocol)}/${port}/hosts${query}`;

export function HostsCard({ page }: { page: Page }) {
  const { protocol, port } = page.header;
  return <HostsPanel<HostRow, Segment> hostsUrl={(query) => hostsPath(protocol, port, query)} segments={SEGMENTS} labels={SEGMENT_LABEL} chipsLabel="Hosts by exposure"
    fallback={page.header.listening} emptyAll="No host in your reach listens on it" table={(rows) => <HostsTable rows={rows} />} />;
}

/** "not collected" for a host whose report leaves owners out; a dash when the report is complete and nothing owns the port. */
function Owner({ row }: { row: HostRow }) {
  const text = [row.service, row.program].filter(Boolean).join(" · ");
  if (text) return <span className="mono truncate">{text}</span>;
  return row.owners_partial ? <span className="subtle">not collected</span> : <span className="subtle" title="Nothing owns it">—</span>;
}

export function HostsTable({ rows }: { rows: readonly HostRow[] }) {
  return (
    <div className="table-wrap">
      <table className="table table--compact" aria-label="Hosts">
        <thead><tr><th>Host</th><th>Listening on</th><th>Service · program</th><th>Last report</th></tr></thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.agent_id}>
              <HostCell row={r} />
              <td><div className="cell-two"><span className="mono truncate">{r.bound.join(", ")}</span>
                {r.exposed ? <span className="badge badge--warn badge--plain">exposed</span> : <span className="subtle">local only</span>}</div></td>
              <td><Owner row={r} /></td>
              <ReportedCell at={r.reported_at} />
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/** Related (ruling 22): failing checks, open advisories of the usual server's packages and open alarms, each with its permission. */
export function RelatedPortCard({ page }: { page: Page }) {
  const { compliance, vulnerabilities, alarms } = page.related;
  const sections = [
    ...(compliance ? [failingChecks(compliance)] : []),
    ...(vulnerabilities && vulnerabilities.length > 0 ? [openVulnerabilities(vulnerabilities)] : []),
    ...(alarms ? [openAlarms("Open alarms from its program", alarms.program_not_collected && "Program not collected", alarms)] : []),
  ];
  return <RelatedCard sections={sections} />;
}
