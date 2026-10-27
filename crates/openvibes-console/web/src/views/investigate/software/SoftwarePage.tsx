// A package's page (approved screen 24; roles spec §10.3, step 5g rulings
// 2 and 11-17), at /software/{name}, replacing the package panel: a header
// with Export, Add to case and ⋯ (Copy link), four tiles, and the cards.
// The summary route is over the hosts in the person's reach; a package
// nothing in reach has (and none changed in 90 days) is a 404.
import { request, useResource } from "../../../api/client";
import type { SoftwarePageHosts, SoftwarePageSummary } from "../../../api/types";
import { softwarePath } from "../../../app/location";
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
import { ChangesCard, DetailsCard, GroupsCard, HostsCard, UsedByCard, VersionsCard, VulnerabilitiesCard, hostsPath } from "./SoftwareCards";

type Page = SoftwarePageSummary;
type HostRow = SoftwarePageHosts["items"][number];

const summaryPath = (name: string) => `/api/v1/software-pages/${encodeURIComponent(name)}/summary`;

export function NoSuchPackage() {
  return <div className="view"><Empty icon="package" title="No such package">No host you can see has it, or the link is wrong. <a className="object-link" {...viewLink("/software")}>Back to the list</a></Empty></div>;
}

export function SoftwarePage({ name }: { name: string }) {
  const summary = useResource<Page>(summaryPath(name));
  useProvideTitle({ kind: "package", id: name }, name);
  if (summary.error?.status === 404) return <NoSuchPackage />;
  if (summary.error) return <div className="view"><div className="view-pad"><ErrorBox error={summary.error} /></div></div>;
  if (!summary.data) return <div className="view"><Loading /></div>;
  return <SoftwareView page={summary.data} />;
}

/** Export (ruling 15): the package's hosts in reach, one row per host and version. */
export function exportRows(rows: readonly HostRow[], name: string): unknown[][] {
  return [
    ["package", "host", "agent_id", "os", "address", "manager", "version", "arch", "update_to", "used_by", "last_report"],
    ...rows.flatMap((r) => (r.versions.length > 0 ? r.versions : [{ manager: "", version: "", arch: "" }]).map((v) => [
      name, r.hostname ?? r.agent_id, r.agent_id, r.os ?? "", r.ip ?? "", v.manager, v.version, v.arch, r.update_to ?? "", r.used_by.join(" "), r.reported_at ?? "",
    ])),
  ];
}

/** Every page of the Hosts table (the route pages by 100, up to its offset bound). */
async function allHosts(name: string): Promise<HostRow[]> {
  const rows: HostRow[] = [];
  for (let offset = 0; offset <= 100_000; offset += 100) {
    const page = await request<SoftwarePageHosts>("GET", hostsPath(name, `?segment=all&offset=${offset}&limit=100`));
    rows.push(...page.items);
    if (rows.length >= page.total || page.items.length === 0) break;
  }
  return rows;
}

export function SoftwareView({ page }: { page: Page }) {
  const { header, tiles, week } = page;
  const first = header.first_seen;
  const here = softwarePath(header.name);
  const changed = [week.added > 0 && `${week.added} new`, week.updated > 0 && `${week.updated} updated`, week.removed > 0 && `${week.removed} removed`].filter(Boolean);
  return (
    <DetailPage
      crumb={<a {...viewLink("/software")}>Software</a>}
      icon={<Icon name="package" size={20} />}
      title={<span className="mono">{header.name}</span>}
      facts={[
        header.managers.join(" + "),
        `on ${header.hosts.toLocaleString()} of ${plural(header.of, "host")}`,
        changed.length > 0 && `this week ${changed.join(", ")}`,
        first && `${first.before ? "before" : "first seen"} ${date(first.at)}`,
      ]}
      actions={<SoftwareActions page={page} />}
      tiles={[
        <Tile key="hosts" label={`Hosts that have it, of ${plural(header.of, "host")}`} value={tiles.hosts} to="#hosts" />,
        <Tile key="vulnerabilities" label="Open vulnerabilities" value={tiles.vulnerabilities} to={{ view: "/vulnerabilities", params: { package: header.name } }} />,
        <Tile key="update" label="Hosts that need an update" value={tiles.update_hosts} to={{ view: here, params: { segment: "update" } }} />,
        <FactTile key="versions" label="Versions in use" value={tiles.versions.toLocaleString()} />,
      ]}
      left={<>
        <DetailsCard page={page} />
        <VersionsCard page={page} />
        <UsedByCard page={page} />
        <GroupsCard page={page} />
        <ChangesCard page={page} />
      </>}
      right={<>
        <VulnerabilitiesCard page={page} />
        <HostsCard page={page} />
      </>}
    />
  );
}

/** Add to case (kind `software`, the bare name) and ⋯ with Export and Copy link. */
function SoftwareActions({ page }: { page: Page }) {
  const { can, header } = page;
  const more = [
    ...(can.export ? [{ value: "export", label: "Export", description: "Its hosts, as CSV" }] : []),
    { value: "copy", label: "Copy link" },
  ];
  const pick = (value: string) => {
    if (value === "copy") { void copyLink(); return; }
    allHosts(header.name).then((rows) => downloadCsv(`openvibes-software-${header.name}.csv`, exportRows(rows, header.name)), () => toast("The export failed", true));
  };
  return (
    <>
      {can.add_to_case && <AddToCase kind="software" id={header.name} label={header.name} />}
      <MenuButton label="More actions" icon="more" compact items={more} onPick={pick} />
    </>
  );
}
