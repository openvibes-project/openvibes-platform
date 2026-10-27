// A service's page (approved screen 22; roles spec §10.3, step 5f rulings 2
// and 11-16), at /services/{unit}, replacing the unit panel: a header with
// Export, Add to case and ⋯ (Copy link), up to four tiles, and the cards.
// The summary route is over the hosts in the person's reach; a service
// nothing in reach runs (and none changed in 90 days) is a 404.
import { request, useResource } from "../../../api/client";
import type { ServicePageHosts, ServicePageSummary } from "../../../api/types";
import { servicePath } from "../../../app/location";
import { viewLink } from "../../../app/nav";
import { useProvideTitle } from "../../../app/titles";
import { AddToCase } from "../../../panels/cases/AddToCase";
import { Empty, ErrorBox, Loading } from "../../../ui/bits";
import { downloadCsv } from "../../../ui/csv";
import { DetailPage } from "../../../ui/detail/DetailPage";
import { FactTile } from "../../../ui/detail/FactTile";
import { Tile } from "../../../ui/detail/Tile";
import { date, plural } from "../../../ui/format";
import { Icon } from "../../../ui/Icon";
import { MenuButton } from "../../../ui/Menu";
import { toast } from "../../../ui/toast";
import { copyLink } from "../alarm/AlarmPage";
import { ChangesCard, DetailsCard, GroupsCard, HostsCard, PortsCard, RelatedServiceCard, hostsPath } from "./ServiceCards";

type Page = ServicePageSummary;
type HostRow = ServicePageHosts["items"][number];

const summaryPath = (unit: string) => `/api/v1/services/${encodeURIComponent(unit)}/summary`;

export function NoSuchService() {
  return <div className="view"><Empty icon="layers" title="No such service">No host you can see runs it, or the link is wrong. <a className="object-link" {...viewLink("/services")}>Back to the list</a></Empty></div>;
}

export function ServicePage({ unit }: { unit: string }) {
  const summary = useResource<Page>(summaryPath(unit));
  useProvideTitle({ kind: "unit", id: unit }, unit);
  if (summary.error?.status === 404) return <NoSuchService />;
  if (summary.error) return <div className="view"><div className="view-pad"><ErrorBox error={summary.error} /></div></div>;
  if (!summary.data) return <div className="view"><Loading /></div>;
  return <ServiceView page={summary.data} />;
}

/** Export (ruling 15): the service's hosts in reach, one row per host. */
export function exportRows(rows: readonly HostRow[], unit: string): unknown[][] {
  return [
    ["service", "host", "agent_id", "os", "address", "runs_as", "processes", "programs", "package", "version", "ports", "last_report"],
    ...rows.map((r) => [unit, r.hostname ?? r.agent_id, r.agent_id, r.os ?? "", r.ip ?? "", r.run_as ?? "", r.processes, r.programs.join(" "), r.package?.name ?? "", r.package?.version ?? "",
      r.ports.map((p) => `${p.port}/${p.protocol}${p.exposed ? " (exposed)" : ""}`).join(" "), r.reported_at ?? ""]),
  ];
}

/** Every page of the Hosts table (the route pages by 100, up to its offset bound). */
async function allHosts(unit: string): Promise<HostRow[]> {
  const rows: HostRow[] = [];
  for (let offset = 0; offset <= 100_000; offset += 100) {
    const page = await request<ServicePageHosts>("GET", hostsPath(unit, `?segment=all&offset=${offset}&limit=100`));
    rows.push(...page.items);
    if (rows.length >= page.total || page.items.length === 0) break;
  }
  return rows;
}

export function ServiceView({ page }: { page: Page }) {
  const { header, tiles, details } = page;
  const first = header.first_seen;
  const here = servicePath(header.unit);
  const package0 = page.related.vulnerabilities?.packages[0]?.package;
  const week = details.week;
  return (
    <DetailPage
      crumb={<a {...viewLink("/services")}>Services</a>}
      icon={<Icon name="layers" size={20} />}
      title={<><span className="mono">{header.unit}</span>{header.name && <span className="subtle"> {header.name}</span>}</>}
      facts={[
        header.usual_use ?? "Not a usual service",
        `running on ${header.running.toLocaleString()} of ${plural(header.of, "host")}`,
        header.root > 0 && `as root on ${header.root.toLocaleString()}`,
        header.exposed > 0 && `owns an exposed port on ${header.exposed.toLocaleString()}`,
        (week.added > 0 || week.removed > 0) && `this week ${[week.added > 0 && `+${week.added}`, week.removed > 0 && `−${week.removed}`].filter(Boolean).join(" ")}`,
        first && `${first.before ? "before" : "first seen"} ${date(first.at)}`,
      ]}
      actions={<ServiceActions page={page} />}
      tiles={[
        <Tile key="running" label={`Running on, of ${plural(header.of, "host")}`} value={tiles.running} to="#hosts" />,
        tiles.alarms != null && <FactTile key="alarms" label="Open alarms from its programs" value={tiles.alarms.toLocaleString()} />,
        tiles.vulnerabilities != null && (package0
          ? <Tile key="vulnerabilities" label="Vulnerabilities in its package" value={tiles.vulnerabilities} to={{ view: "/vulnerabilities", params: { package: package0 } }} />
          : <FactTile key="vulnerabilities" label="Vulnerabilities in its package" value="—" />),
        <FactTile key="versions" label="Versions in use" value={tiles.versions == null ? "—" : tiles.versions.toLocaleString()} />,
      ]}
      left={<>
        <DetailsCard page={page} />
        <PortsCard page={page} />
        <GroupsCard page={page} />
        <ChangesCard page={page} />
      </>}
      right={<>
        <HostsCard page={page} here={here} />
        <RelatedServiceCard page={page} />
      </>}
    />
  );
}

/** Add to case (kind `service`) and ⋯ with Export and Copy link. */
function ServiceActions({ page }: { page: Page }) {
  const { can, header } = page;
  const label = `${header.unit}${header.name ? ` ${header.name}` : ""}`;
  const more = [
    ...(can.export ? [{ value: "export", label: "Export", description: "Its hosts, as CSV" }] : []),
    { value: "copy", label: "Copy link" },
  ];
  const pick = (value: string) => {
    if (value === "copy") { void copyLink(); return; }
    allHosts(header.unit).then((rows) => downloadCsv(`openvibes-service-${header.unit}.csv`, exportRows(rows, header.unit)), () => toast("The export failed", true));
  };
  return (
    <>
      {can.add_to_case && <AddToCase kind="service" id={header.unit} label={label} />}
      <MenuButton label="More actions" icon="more" compact items={more} onPick={pick} />
    </>
  );
}
