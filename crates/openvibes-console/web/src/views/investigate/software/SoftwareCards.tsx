// The cards of a package's page (approved screen 24): Details, Versions,
// Used by, By group and Recent changes on the left; Vulnerabilities and
// Hosts (segments and the paged table) on the right. Every card reads the
// summary but Hosts, which pages its own route.
import type { SoftwarePageHosts, SoftwarePageSummary } from "../../../api/types";
import { servicePath, vulnPath } from "../../../app/location";
import { viewLink } from "../../../app/nav";
import { SeverityBadge } from "../../../ui/bits";
import { Card } from "../../../ui/detail/DetailPage";
import { plural } from "../../../ui/format";
import { Icon } from "../../../ui/Icon";
import { ChangeList, GroupMeters, HostCell, HostsPanel, ReportedCell, segmentIn } from "../hostPageParts";

type Page = SoftwarePageSummary;
type HostRow = SoftwarePageHosts["items"][number];

/** The advisory count: the full total, with how many of them the list holds when it stops at the top 50. */
const advisoryCount = (page: Page) => {
  const { vulnerabilities: total } = page.tiles;
  return page.advisories.length < total ? `${page.advisories.length.toLocaleString()} of ${total.toLocaleString()}` : total.toLocaleString();
};

export function DetailsCard({ page }: { page: Page }) {
  const { header, versions, no_fix: noFix } = page;
  const main = versions[0];
  return (
    <Card title="Details">
      <dl className="kv">
        <dt>Type</dt><dd>{header.managers.length === 0 ? <span className="subtle">Not reported</span> : header.managers.join(" + ")}</dd>
        <dt>Most hosts run</dt><dd>{main ? <><span className="mono">{main.version}</span><span className="subtle"> on {plural(main.hosts, "host")}</span></> : <span className="subtle">None</span>}</dd>
        <dt>Versions in use</dt><dd className="num">{versions.length.toLocaleString()}</dd>
        <dt>Open vulnerabilities</dt>
        <dd>{page.tiles.vulnerabilities === 0 ? <span className="subtle">None</span> : <>{page.tiles.vulnerabilities.toLocaleString()}{noFix > 0 && <span className="subtle"> · {noFix.toLocaleString()} with no fix yet</span>}</>}</dd>
      </dl>
    </Card>
  );
}

/** Versions in use, most hosts first, each with the share of hosts that run it; one with an open vulnerability is red. */
export function VersionsCard({ page }: { page: Page }) {
  const total = page.header.hosts;
  return (
    <Card title={<>Versions <span className="subtle num">{page.versions.length.toLocaleString()}</span></>}>
      <ul className="list list--plain" aria-label="Versions in use">
        {page.versions.map((v) => {
          const bad = v.advisories > 0;
          return (
            <li key={`${v.manager}.${v.version}.${v.arch}`} className="list__row list__row--static stack" style={{ alignItems: "stretch" }}>
              <span className="row row--between">
                <span className={`mono truncate${bad ? " text-bad" : ""}`}>{v.version} <span className="subtle">{v.arch}</span></span>
                <span className="num subtle nowrap">{plural(v.hosts, "host")}</span>
              </span>
              <span className={`meter meter--wide${bad ? " meter--bad" : ""}`} role="meter" aria-label={`${v.version}: ${v.hosts} of ${total} hosts`} aria-valuemin={0} aria-valuemax={total} aria-valuenow={v.hosts}>
                <span style={{ width: `${total ? Math.max(2, Math.round((100 * v.hosts) / total)) : 0}%` }} />
              </span>
              {bad && <span className="text-bad">{plural(v.advisories, "vulnerability")}<span className="subtle mono"> · {v.cves.join(", ")}{v.advisories > v.cves.length ? ", …" : ""}</span></span>}
            </li>
          );
        })}
      </ul>
    </Card>
  );
}

export function UsedByCard({ page }: { page: Page }) {
  return (
    <Card title="Used by">
      {page.used_by.length === 0 ? <p className="subtle">No running service is matched to it by name.</p> : (
        <ul className="list list--plain" aria-label="Services that run from it">
          {page.used_by.map((u) => (
            <li key={u.unit} className="list__row list__row--static">
              <a className="object-link mono" {...viewLink(servicePath(u.unit))}>{u.unit}</a>
              <span className="grow" /><span className="subtle nowrap">{plural(u.hosts, "host")}</span>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}

export function GroupsCard({ page }: { page: Page }) {
  return <GroupMeters groups={page.by_group.map((g) => ({ ...g, count: g.have }))} empty="No automatic or rule group holds a host that has it."
    listLabel="Hosts that have it, by group" meterLabel="have it" />;
}

/** What a change says about a host (the log's two package kinds); an upgrade is the old version going and the new one appearing. */
export const CHANGE_TEXT: Record<string, string> = { appeared: "installed", went_away: "removed" };

export const ChangesCard = ({ page }: { page: Page }) => <ChangeList changes={page.changes} text={CHANGE_TEXT} />;

/** Open advisories: what they affect, what fixes them and on how many hosts. */
export function VulnerabilitiesCard({ page }: { page: Page }) {
  return (
    <Card title={<>Vulnerabilities <span className="subtle num">{advisoryCount(page)}</span></>} flush={page.advisories.length > 0}>
      {page.advisories.length === 0 ? <p className="subtle">No open vulnerability on it.</p> : (
        <ul className="list" aria-label="Open vulnerabilities">
          {page.advisories.map((a) => (
            <li key={a.advisory_id}>
              <a className="list__row" {...viewLink(vulnPath(a.advisory_id))}>
                <SeverityBadge severity={a.severity} />
                <span className="cell-two grow">
                  <span className="truncate">{a.title}</span>
                  <span className="subtle mono truncate">{[a.advisory_id, ...a.cves.filter((c) => c !== a.advisory_id).slice(0, 2)].join(" · ")}</span>
                </span>
                {a.exploited && <span className="badge badge--critical badge--plain" title="Known to be exploited"><Icon name="flame" size={12} /> Exploited</span>}
                <span className="cell-two" style={{ textAlign: "right" }}>
                  {a.fixed_in ? <span className="mono nowrap" title="The version that fixes it">fixed by {a.fixed_in}</span> : <span className="subtle nowrap">No fix yet</span>}
                  <span className="subtle nowrap">{plural(a.hosts, "host")}</span>
                </span>
              </a>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}

const SEGMENTS = ["all", "update", "current"] as const;
type Segment = (typeof SEGMENTS)[number];
const SEGMENT_LABEL: Record<Segment, string> = { all: "All", update: "Need an update", current: "Up to date" };
/** The URL's `segment`; anything unknown is All. */
export const segmentOf = (value: string | null): Segment => segmentIn(SEGMENTS, value);

export const hostsPath = (name: string, query = "") => `/api/v1/software-pages/${encodeURIComponent(name)}/hosts${query}`;

export function HostsCard({ page }: { page: Page }) {
  const name = page.header.name;
  return <HostsPanel<HostRow, Segment> hostsUrl={(query) => hostsPath(name, query)} segments={SEGMENTS} labels={SEGMENT_LABEL} chipsLabel="Hosts by whether they need an update"
    fallback={page.header.hosts} emptyAll="No host in your reach has it" table={(rows) => <HostsTable rows={rows} />} />;
}

export function HostsTable({ rows }: { rows: readonly HostRow[] }) {
  return (
    <div className="table-wrap">
      <table className="table table--compact" aria-label="Hosts">
        <thead><tr><th>Host</th><th>Version</th><th>Update</th><th>Used by</th><th>Last report</th></tr></thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.agent_id}>
              <HostCell row={r} />
              <td><div className="cell-two">{r.versions.map((v) => <span key={`${v.manager}.${v.version}.${v.arch}`} className="mono truncate">{v.version}<span className="subtle"> {v.arch}</span></span>)}</div></td>
              <td>{r.update_to ? <span className="badge badge--warn badge--plain mono" title="The version that fixes an open vulnerability">Update to {r.update_to}</span> : <span className="subtle">Up to date</span>}</td>
              <td>{r.used_by.length === 0 ? <span className="subtle">—</span> : <span className="row">{r.used_by.map((u) => <a key={u} className="object-link mono" {...viewLink(servicePath(u))}>{u}</a>)}</span>}</td>
              <ReportedCell at={r.reported_at} />
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
