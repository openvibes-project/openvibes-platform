// A port's page (approved screen 20; roles spec §10.3, step 5e rulings 18
// and 20-25), at /ports/{port}/{protocol} ("22/tcp"), replacing the port
// panel: a header with Export, Add to case, Ask about this and ⋯ (Copy
// link), four tiles, and the cards. The summary route is over the hosts in
// the person's reach; a port nothing in reach listens on (and none changed
// in 90 days) is a 404.
import { request, useResource } from "../../../api/client";
import type { PortPageHosts, PortPageSummary } from "../../../api/types";
import { assistant } from "../../../app/assistant";
import { portPath } from "../../../app/location";
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
import { ChangesCard, DetailsCard, GroupsCard, HostsCard, RelatedPortCard, hostsPath } from "./PortCards";

type Page = PortPageSummary;
type HostRow = PortPageHosts["items"][number];

const summaryPath = (protocol: string, port: number) => `/api/v1/ports/${encodeURIComponent(protocol)}/${port}/summary`;

export function NoSuchPort() {
  return <div className="view"><Empty icon="activity" title="No such port">No host you can see listens on it, or the link is wrong. <a {...viewLink("/ports")}>Back to the list</a></Empty></div>;
}

export function PortPage({ protocol, port }: { protocol: string; port: number }) {
  const summary = useResource<Page>(summaryPath(protocol, port));
  useProvideTitle({ kind: "port", id: `${protocol}/${port}` }, `${port}/${protocol}`);
  if (summary.error?.status === 404) return <NoSuchPort />;
  if (summary.error) return <div className="view"><div className="view-pad"><ErrorBox error={summary.error} /></div></div>;
  if (!summary.data) return <div className="view"><Loading /></div>;
  return <PortView page={summary.data} />;
}

/** Export (ruling 23): the port's hosts in reach, one row per host. */
export function exportRows(rows: readonly HostRow[], protocol: string, port: number): unknown[][] {
  return [
    ["port", "protocol", "host", "agent_id", "os", "address", "listening_on", "exposed", "service", "program", "last_report"],
    ...rows.map((r) => [port, protocol, r.hostname ?? r.agent_id, r.agent_id, r.os ?? "", r.ip ?? "", r.bound.join(" "), r.exposed ? "yes" : "no", r.service ?? "", r.program ?? "", r.reported_at ?? ""]),
  ];
}

/** Every page of the Hosts table (the route pages by 100, up to its offset bound). */
async function allHosts(protocol: string, port: number): Promise<HostRow[]> {
  const rows: HostRow[] = [];
  for (let offset = 0; offset <= 100_000; offset += 100) {
    const page = await request<PortPageHosts>("GET", hostsPath(protocol, port, `?segment=all&offset=${offset}&limit=100`));
    rows.push(...page.items);
    if (rows.length >= page.total || page.items.length === 0) break;
  }
  return rows;
}

/** "+2 −1" for this week's hosts, or "No change" (ruling 8). */
const weekText = (w: Page["tiles"]["week"]) => (w.added === 0 && w.removed === 0 ? "No change" : [w.added > 0 && `+${w.added}`, w.removed > 0 && `−${w.removed}`].filter(Boolean).join(" "));

export function PortView({ page }: { page: Page }) {
  const { header, tiles } = page;
  const first = header.first_seen;
  const here = portPath(header.protocol, header.port);
  return (
    <DetailPage
      crumb={<a {...viewLink("/ports")}>Ports</a>}
      icon={<Icon name="activity" size={20} />}
      title={<><span className="mono">{header.port}/{header.protocol}</span>{header.name && <span className="subtle"> {header.name}</span>}</>}
      status={<span className="badge badge--plain">{header.protocol.toUpperCase()}</span>}
      facts={[
        header.usual_use ?? "Not a usual port",
        `listening on ${header.listening.toLocaleString()} of ${plural(header.of, "host")}`,
        header.exposed > 0 ? `exposed on ${header.exposed.toLocaleString()}` : "local only",
        header.services > 0 && plural(header.services, "service"),
        first && `${first.before ? "before" : "first seen"} ${date(first.at)}`,
      ]}
      actions={<PortActions page={page} />}
      tiles={[
        <Tile key="listening" label={`Listening, of ${plural(header.of, "host")}`} value={tiles.listening} to="#hosts" />,
        <Tile key="exposed" label="Exposed" value={tiles.exposed} to={{ view: here, params: { segment: "exposed" } }} />,
        <Tile key="local" label="Local only" value={tiles.local} to={{ view: here, params: { segment: "local" } }} />,
        <FactTile key="week" label="Hosts this week" value={weekText(tiles.week)} />,
      ]}
      left={<>
        <DetailsCard page={page} />
        <GroupsCard page={page} />
        <ChangesCard page={page} />
      </>}
      right={<>
        <HostsCard page={page} />
        <RelatedPortCard page={page} />
      </>}
    />
  );
}

/** Add to case (kind `port`), Ask about this, and ⋯ with Export and Copy link. */
function PortActions({ page }: { page: Page }) {
  const { can, header } = page;
  const id = `${header.protocol}/${header.port}`;
  const label = `${header.port}/${header.protocol}${header.name ? ` ${header.name}` : ""}`;
  const more = [
    ...(can.export ? [{ value: "export", label: "Export", description: "Its hosts, as CSV" }] : []),
    { value: "copy", label: "Copy link" },
  ];
  const pick = (value: string) => {
    if (value === "copy") { void copyLink(); return; }
    allHosts(header.protocol, header.port).then((rows) => downloadCsv(`openvibes-port-${header.port}-${header.protocol}.csv`, exportRows(rows, header.protocol, header.port)), () => toast("The export failed", true));
  };
  return (
    <>
      {can.add_to_case && <AddToCase kind="port" id={id} label={label} />}
      {can.ask && <button type="button" className="button" onClick={() => assistant.askAbout({ kind: "port", id }, label)}><Icon name="sparkles" size={14} /> Ask about this</button>}
      <MenuButton label="More actions" icon="more" compact items={more} onPick={pick} />
    </>
  );
}
