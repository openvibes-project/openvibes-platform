// A check's page (approved screen 28; roles spec §10.3, step 5c rulings
// 8-17), one per rule of a rule set, replacing the finding panel: a header
// with Set state, Assign and Add to case on the check's open failing hosts,
// Ask about this and ⋯ (Export, Copy link), four tiles (failing on, passing,
// first seen, the last 14 days as bars) and the cards. Old links
// (`?open=finding:SET/RULE`, `nav.open({kind: "finding"})`) come here.
import { request, useResource } from "../../../api/client";
import type { CheckHostsPage, CheckSummaryPage } from "../../../api/types";
import { assistant } from "../../../app/assistant";
import { viewLink } from "../../../app/nav";
import { useProvideTitle } from "../../../app/titles";
import { BulkBar } from "../../../panels/triage/BulkBar";
import type { BulkAction } from "../../../panels/triage/bulk";
import { Empty, ErrorBox, Loading, SeverityBadge } from "../../../ui/bits";
import { HourlyBars } from "../../../ui/charts/HourlyBars";
import { downloadCsv } from "../../../ui/csv";
import { DetailPage } from "../../../ui/detail/DetailPage";
import { FactTile } from "../../../ui/detail/FactTile";
import { Tile } from "../../../ui/detail/Tile";
import { date, plural } from "../../../ui/format";
import { Icon } from "../../../ui/Icon";
import { MenuButton } from "../../../ui/Menu";
import { toast } from "../../../ui/toast";
import { copyLink } from "../alarm/AlarmPage";
import { DetailsCard, FixCard, HistoryCard, HostsCard, RelatedCheckCard, WhyCard, evidenceText } from "./CheckCards";

type Page = CheckSummaryPage;
type HostRow = CheckHostsPage["rows"][number];

const base = (set: string, rule: string) => `/api/v1/compliance/checks/${encodeURIComponent(set)}/${encodeURIComponent(rule)}`;

export function NoSuchCheck() {
  return <div className="view"><Empty icon="findings" title="No such check">No host you can see runs it, or the link is wrong. <a {...viewLink("/compliance")}>Back to the list</a></Empty></div>;
}

export function CheckPage({ set, rule }: { set: string; rule: string }) {
  const summary = useResource<Page>(`${base(set, rule)}/summary`);
  useProvideTitle({ kind: "finding", id: `${set}/${rule}` }, summary.data?.header.title);
  if (summary.error?.status === 404) return <NoSuchCheck />;
  if (summary.error) return <div className="view"><div className="view-pad"><ErrorBox error={summary.error} /></div></div>;
  if (!summary.data) return <div className="view"><Loading /></div>;
  return <CheckView page={summary.data} />;
}

/** The header's Set state, Assign and Add to case (ruling 10): the check's open failing pairs in reach. */
export const headerItems = (page: Page) => [{ rule_set_id: page.header.rule_set_id, rule_id: page.header.rule_id, open_only: true }];

/** Export (ruling 17): the check's hosts in reach, one row each. */
export function exportRows(rows: readonly HostRow[], header: Pick<Page["header"], "rule_set_id" | "rule_id">): unknown[][] {
  return [
    ["rule_set", "rule", "host", "agent_id", "os", "address", "state", "evidence", "assignee", "checked_at"],
    ...rows.map((r) => [header.rule_set_id, header.rule_id, r.hostname ?? r.agent_id, r.agent_id, r.os ?? "", r.address ?? "", r.state,
      r.evidence.map(evidenceText).join("; "), r.assignee?.name ?? "", r.checked_at ?? ""]),
  ];
}

/** Every page of the Hosts table (the route pages by 100, up to its offset bound). */
async function allHosts(set: string, rule: string): Promise<HostRow[]> {
  const rows: HostRow[] = [];
  for (let offset = 0; offset <= 100_000; offset += 100) {
    const page = await request<CheckHostsPage>("GET", `${base(set, rule)}/hosts?segment=all&offset=${offset}&limit=100`);
    rows.push(...page.rows);
    if (rows.length >= page.total || page.rows.length === 0) break;
  }
  return rows;
}

const ASSIGNED = (a: Page["header"]["assignee"]) => (a.kind === "one" ? `assigned to ${a.name ?? ""}` : a.kind === "several" ? `assigned to ${a.count ?? 0} people` : "unassigned");

export function CheckView({ page }: { page: Page }) {
  const { header, tiles } = page;
  const days = tiles.days;
  return (
    <DetailPage
      crumb={<a {...viewLink("/compliance")}>Compliance</a>}
      icon={<Icon name="findings" size={20} />}
      title={header.title}
      status={header.severity && <SeverityBadge severity={header.severity} />}
      facts={[
        <span key="rule" className="mono">{header.rule_id}</span>,
        `${header.rule_set_id}${header.rule_set_version == null ? "" : ` v${header.rule_set_version}`}`,
        header.area,
        `failing on ${header.failing.toLocaleString()} of ${plural(header.checked, "host")} checked`,
        ASSIGNED(header.assignee),
      ]}
      actions={<CheckActions page={page} />}
      tiles={[
        <Tile key="failing" label={`Failing on, of ${plural(header.checked, "host")} checked`} value={tiles.failing} to="#hosts" />,
        <FactTile key="passing" label="Passing" value={tiles.passing.toLocaleString()} />,
        <FactTile key="first" label={tiles.first_seen?.hostname ? `First seen on ${tiles.first_seen.hostname}` : "First seen"}
          value={tiles.first_seen ? date(tiles.first_seen.at) : "—"} />,
        <div key="days" className="card detail-tile">
          <HourlyBars values={days} label="Failing hosts per day, the last 14 days" unit="day" />
          <span className="detail-tile__label subtle">Last 14 days</span>
          {days.length > 0 && <span className="detail-tile__note subtle">{days[0]} → {plural(days[days.length - 1] ?? 0, "host")} failing</span>}
        </div>,
      ]}
      left={<>
        <WhyCard page={page} />
        <FixCard page={page} />
        <DetailsCard page={page} />
        <HistoryCard page={page} />
      </>}
      right={<>
        <HostsCard page={page} />
        <RelatedCheckCard page={page} />
      </>}
    />
  );
}

/** Set state ▾ and Assign ▾ with Add to case (the inline bulk bar), Ask about this, and ⋯ with Export and Copy link. */
function CheckActions({ page }: { page: Page }) {
  const { can, header } = page;
  const open = header.open > 0;
  const more = [
    ...(can.export ? [{ value: "export", label: "Export", description: "Its hosts, as CSV" }] : []),
    { value: "copy", label: "Copy link" },
  ];
  const pick = (value: string) => {
    if (value === "copy") { void copyLink(); return; }
    allHosts(header.rule_set_id, header.rule_id).then((rows) => downloadCsv(`openvibes-${header.rule_set_id}-${header.rule_id}.csv`, exportRows(rows, header)),
      () => toast("The export failed", true));
  };
  const without: BulkAction[] = [...(open ? [] : ["state", "assign"] as const), ...(can.assign ? [] : ["assign"] as const), ...(can.add_to_case ? [] : ["case"] as const)];
  return (
    <>
      {can.triage && (open || can.add_to_case) && <BulkBar inline kind="compliance" noun="check" count={1} onClear={() => undefined} items={() => headerItems(page)}
        without={without} confirm={<p>Changes up to {plural(header.open, "open failing host")}. Mitigated, accepted and false-positive hosts are left as they are, and passing hosts have nothing to change.</p>}
        newCase={() => ({ title: header.title, severity: header.severity ?? undefined })} />}
      {can.ask && <button type="button" className="button" onClick={() => assistant.askAbout({ kind: "finding", id: `${header.rule_set_id}/${header.rule_id}` }, `${header.rule_id} ${header.title}`)}>
        <Icon name="sparkles" size={14} /> Ask about this</button>}
      <MenuButton label="More actions" icon="more" compact items={more} onPick={pick} />
    </>
  );
}
