// The cards of a port's page (approved screen 20): Details, By group and
// Recent changes on the left; Hosts (segments and the paged table) and
// Related on the right. Every card reads the summary but Hosts, which pages
// its own route.
import { useResource } from "../../../api/client";
import type { PortPageHosts, PortPageSummary } from "../../../api/types";
import { checkPath } from "../../../app/location";
import { nav, useLocation, viewLink } from "../../../app/nav";
import { Ago, Empty, ErrorBox, Loading, ObjectLink, SeverityBadge } from "../../../ui/bits";
import { Card } from "../../../ui/detail/DetailPage";
import { RelatedCard } from "../../../ui/detail/RelatedCard";
import { SegmentChips } from "../../../ui/detail/SegmentChips";
import { plural } from "../../../ui/format";
import { PAGE } from "../../../ui/list/filters";
import { Pager } from "../Hosts";

type Page = PortPageSummary;
type HostRow = PortPageHosts["items"][number];

const DAY = 86_400_000;
const PAGE_SIZE = 50;

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
  return (
    <Card title="By group">
      {page.by_group.length === 0 ? <p className="subtle">No automatic or rule group holds a host listening on it.</p> : (
        <ul className="list list--plain" aria-label="Hosts listening, by group">
          {page.by_group.map((g) => (
            <li key={g.group_id} className="list__row list__row--static stack" style={{ alignItems: "stretch" }}>
              <span className="row row--between">
                <a className="object-link" {...viewLink("/hosts", { group: g.group_id })}>{g.name}</a>
                <span className="num subtle">{g.listening.toLocaleString()} of {g.of.toLocaleString()}</span>
              </span>
              <span className="meter meter--wide" role="meter" aria-label={`${g.name}: ${g.listening} of ${g.of} hosts listen`} aria-valuemin={0} aria-valuemax={g.of} aria-valuenow={g.listening}>
                <span style={{ width: `${g.of ? Math.round((100 * g.listening) / g.of) : 0}%` }} />
              </span>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}

/** What a change says about a host (ruling 20; the log's four kinds). */
export const CHANGE_TEXT: Record<string, string> = {
  appeared: "started listening", went_away: "stopped listening", local: "now listens only locally", exposed: "is now exposed",
};
const changeText = (change: string) => CHANGE_TEXT[change] ?? change;

export function ChangesCard({ page }: { page: Page }) {
  return (
    <Card title="Recent changes">
      {page.changes.length === 0 ? <Empty title="No change in the last 90 days" /> : (
        <ul className="list list--plain" aria-label="Changes, newest first">
          {page.changes.map((c, i) => (
            <li key={`${c.at}:${c.agent_id}:${c.change}:${i}`} className="list__row list__row--static stack" style={{ alignItems: "flex-start" }}>
              <span><ObjectLink to={{ kind: "agent", id: c.agent_id }}>{c.hostname ?? c.agent_id}</ObjectLink> {changeText(c.change)}</span>
              <span className="subtle"><Ago value={c.at} /></span>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}

const SEGMENTS = ["all", "exposed", "local"] as const;
type Segment = (typeof SEGMENTS)[number];
const SEGMENT_LABEL: Record<Segment, string> = { all: "All", exposed: "Exposed", local: "Local only" };
/** The URL's `segment`; anything unknown is All. */
export const segmentOf = (value: string | null): Segment => SEGMENTS.find((s) => s === value) ?? "all";

export const hostsPath = (protocol: string, port: number, query = "") => `/api/v1/ports/${encodeURIComponent(protocol)}/${port}/hosts${query}`;

/** A host's last services report is stale after a day (the step-4 rule). */
export const stale = (reportedAt: string | null | undefined, now = Date.now()) => reportedAt != null && now - Date.parse(reportedAt) > DAY;

export function HostsCard({ page }: { page: Page }) {
  const { params } = useLocation();
  const { protocol, port } = page.header;
  const segment = segmentOf(params.get("segment"));
  const offset = Math.max(0, Number(params.get(PAGE)) || 0);
  const hosts = useResource<PortPageHosts>(hostsPath(protocol, port, `?segment=${segment}&offset=${offset}&limit=${PAGE_SIZE}`));
  const data = hosts.data;
  const counts = data?.segments;
  return (
    <Card id="hosts" flush title={<>Hosts <span className="subtle num">{(counts?.all ?? page.header.listening).toLocaleString()}</span></>}
      aside={<SegmentChips label="Hosts by exposure" value={segment} onChange={(s) => nav.setParams({ segment: s === "all" ? null : s, [PAGE]: null })}
        options={SEGMENTS.map((s) => ({ key: s, label: SEGMENT_LABEL[s], count: counts?.[s] ?? 0 }))} />}>
      {hosts.error ? <div className="person-card__body"><ErrorBox error={hosts.error} /></div> : !data ? <Loading rows={3} /> : data.items.length === 0
        ? <Empty title={segment === "all" ? "No host in your reach listens on it" : `No ${SEGMENT_LABEL[segment].toLowerCase()} hosts`} />
        : <HostsTable rows={data.items} />}
      {data && <Pager offset={offset} shown={data.items.length} total={data.total} />}
    </Card>
  );
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
              <td><div className="cell-two"><ObjectLink to={{ kind: "agent", id: r.agent_id }} className="object-link mono">{r.hostname ?? r.agent_id}</ObjectLink>
                <span className="subtle">{[r.os, r.ip].filter(Boolean).join(" · ")}</span></div></td>
              <td><div className="cell-two"><span className="mono truncate">{r.bound.join(", ")}</span>
                {r.exposed ? <span className="badge badge--warn badge--plain">exposed</span> : <span className="subtle">local only</span>}</div></td>
              <td><Owner row={r} /></td>
              <td className={stale(r.reported_at) ? "text-warn" : "subtle"}><Ago value={r.reported_at} {...(stale(r.reported_at) ? { hint: "More than a day ago" } : {})} /></td>
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
    ...(compliance ? [{ label: "Failing checks", value: compliance.total === 0 ? <span className="subtle">None</span> : (
      <ul className="list list--plain" aria-label="Failing checks">
        {compliance.items.map((c) => (
          <li key={`${c.rule_set_id}/${c.rule_id}`} className="list__row list__row--static">
            <SeverityBadge severity={c.severity} /><a className="object-link truncate" {...viewLink(checkPath(c.rule_set_id, c.rule_id))}>{c.title}</a>
            <span className="grow" /><span className="subtle nowrap">{plural(c.hosts, "host")}</span>
          </li>
        ))}
        {compliance.total > compliance.items.length && (
          <li><a className="object-link" {...viewLink("/compliance", compliance.area ? { area: compliance.area } : undefined)}>{(compliance.total - compliance.items.length).toLocaleString()} more</a></li>
        )}
      </ul>
    ) }] : []),
    ...(vulnerabilities && vulnerabilities.length > 0 ? [{ label: "Vulnerabilities", value: (
      <ul className="list list--plain" aria-label="Open vulnerabilities by package">
        {vulnerabilities.map((v) => (
          <li key={v.package} className="list__row list__row--static">
            <a className="object-link mono" {...viewLink("/vulnerabilities", { package: v.package })}>{v.package}</a>
            <span className="grow" /><span className="subtle nowrap">{v.advisories.toLocaleString()} open on {plural(v.hosts, "host")}</span>
          </li>
        ))}
      </ul>
    ) }] : []),
    ...(alarms ? [{ label: "Open alarms from its program", value: alarms.program_not_collected ? <span className="subtle">Program not collected</span>
      : alarms.open === 0 ? <span className="subtle">None open</span> : <>{plural(alarms.open, "alarm")} on {plural(alarms.hosts, "host")}</> }] : []),
  ];
  return <RelatedCard sections={sections} />;
}
