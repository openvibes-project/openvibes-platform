// An alarm's page (approved screen 30; roles spec §10.3, rulings 6, 7 and 9),
// replacing the alarm panel: a header with Set state, Assign, Suppress…, Ask
// about this and ⋯ (Export, Copy link), four tiles, and the cards. The
// summary route decides what this person may see and do on the alarm's host.
import { useState } from "react";

import { useResource } from "../../../api/client";
import type { AlarmSummaryPage, AlarmSuppression } from "../../../api/types";
import { assistant } from "../../../app/assistant";
import { viewLink } from "../../../app/nav";
import { useSession } from "../../../app/session";
import { useProvideTitle } from "../../../app/titles";
import { SuppressDialog } from "../../../panels/alarms/SuppressForm";
import { caseNumber } from "../../../panels/cases/cases";
import { BulkBar } from "../../../panels/triage/BulkBar";
import { Ago, Empty, ErrorBox, Loading, ObjectLink, SeverityBadge, TriageBadge } from "../../../ui/bits";
import { downloadCsv } from "../../../ui/csv";
import { DetailPage } from "../../../ui/detail/DetailPage";
import { FactTile } from "../../../ui/detail/FactTile";
import { Tile } from "../../../ui/detail/Tile";
import { Icon } from "../../../ui/Icon";
import { MenuButton } from "../../../ui/Menu";
import { toast } from "../../../ui/toast";
import { shortDate } from "../host/HostPage";
import { CommandsCard, DetailsCard, HistoryCard, ProcessCard, RelatedCard, TimelineCard, WhatHappenedCard } from "./AlarmCards";

const summaryPath = (id: string) => `/api/v1/alarms/${encodeURIComponent(id)}/summary`;

export function NoSuchAlarm() {
  return <div className="view"><Empty icon="alarm" title="No such alarm">This alarm does not exist, or it is on a host outside the ones you can see. Check the link, or find the alarm in the list.</Empty></div>;
}

export function AlarmPage({ id }: { id: string }) {
  const summary = useResource<AlarmSummaryPage>(summaryPath(id));
  useProvideTitle({ kind: "alarm", id }, summary.data?.alarm.message);
  if (summary.error?.status === 404) return <NoSuchAlarm />;
  if (summary.error) return <div className="view"><div className="view-pad"><ErrorBox error={summary.error} /></div></div>;
  if (!summary.data) return <div className="view"><Loading /></div>;
  return <AlarmView page={summary.data} />;
}

/** Export (ruling 7): this alarm and its siblings, one row per command line. */
export function exportRows(page: AlarmSummaryPage): unknown[][] {
  const a = page.alarm;
  return [
    ["alarm_id", "host", "rule_set", "rule", "program", "parent", "command", "count", "first_seen", "last_seen", "state", "suppressed_by", "case"],
    ...page.commands.map((c) => [c.id, a.host.name ?? a.host.id, a.rule_set_id, a.rule_id, a.program, a.parent_program ?? "", c.args.join(" "),
      c.count, c.first_seen, c.last_seen, c.state, c.suppressed_by ?? "", c.case ? caseNumber(c.case.number) : ""]),
  ];
}

export function AlarmView({ page }: { page: AlarmSummaryPage }) {
  const { can: allows } = useSession();
  const { alarm, tiles } = page;
  const reads = allows("alarms.suppressions.read");
  const requests = useResource<{ items: AlarmSuppression[] }>(reads ? `/api/v1/alarm-suppressions?alarm_id=${encodeURIComponent(String(alarm.id))}&state=waiting` : null);
  // The caller's own request first: it is the one they can withdraw.
  const waiting = [...(requests.data?.items ?? [])].sort((a, b) => Number(b.can_withdraw) - Number(a.can_withdraw))[0];
  // Not knowing whether a request waits, it offers no Suppress… (no duplicate).
  const known = !reads || requests.data !== undefined;
  const host = alarm.host.name ?? alarm.host.id;
  return (
    <DetailPage
      crumb={<a {...viewLink("/alarms")}>Alarms</a>}
      icon={<Icon name="alarm" size={20} />}
      title={alarm.message}
      status={<><SeverityBadge severity={alarm.severity} /><TriageBadge state={alarm.triage.state} /></>}
      facts={[
        <ObjectLink key="host" to={{ kind: "agent", id: alarm.host.id }}>{host}</ObjectLink>,
        <span key="chain" className="mono">{alarm.parent_program ? `${alarm.parent_program} → ${alarm.program}` : alarm.program}</span>,
        <>last seen <Ago value={alarm.last_seen} /></>,
      ]}
      actions={<AlarmActions page={page} canSuppress={known && !waiting} />}
      tiles={[
        <Tile key="starts" label="Starts matched" value={tiles.starts} to="#timeline" />,
        <Tile key="commands" label="Different commands" value={tiles.different_commands} to="#commands" />,
        <FactTile key="first" label="First seen" value={shortDate(tiles.first_seen)} />,
        <FactTile key="confidence" label="Confidence" value={`${tiles.confidence}%`} />,
      ]}
      left={<>
        <WhatHappenedCard page={page} />
        <DetailsCard page={page} waiting={waiting} waitingError={requests.error} />
        <HistoryCard id={alarm.id} />
      </>}
      right={<>
        <CommandsCard page={page} />
        <ProcessCard page={page} />
        <TimelineCard page={page} />
        <RelatedCard page={page} />
      </>}
    />
  );
}

/** Set state ▾ and Assign ▾ (the inline bulk bar), Suppress…, Ask about this, and ⋯ with Export and Copy link. */
function AlarmActions({ page, canSuppress }: { page: AlarmSummaryPage; canSuppress: boolean }) {
  const { alarm, can } = page;
  const [suppressing, setSuppressing] = useState(false);
  const id = String(alarm.id);
  const more = [
    ...(can.export ? [{ value: "export", label: "Export", description: "This alarm and its other commands, as CSV" }] : []),
    { value: "copy", label: "Copy link" },
  ];
  const pick = (value: string) => {
    if (value === "export") downloadCsv(`openvibes-alarm-${id}.csv`, exportRows(page));
    else { void navigator.clipboard?.writeText(window.location.href); toast("Link copied"); }
  };
  return (
    <>
      {can.triage && <BulkBar inline kind="alarms" noun="alarm" count={1} onClear={() => undefined} items={() => [{ id }]} without={["case", "suppress"]}
        assignee={alarm.triage.assigned_to ?? null} newCase={() => ({ title: alarm.message, severity: alarm.severity })} />}
      {can.suppress && canSuppress && !alarm.suppressed && <button type="button" className="button" onClick={() => setSuppressing(true)}>Suppress…</button>}
      {can.ask && <button type="button" className="button" onClick={() => assistant.askAbout({ kind: "alarm", id }, alarm.message)}><Icon name="sparkles" size={14} /> Ask about this</button>}
      <MenuButton label="More actions" icon="more" compact items={more} onPick={pick} />
      {suppressing && <SuppressDialog alarmId={id} onClose={() => setSuppressing(false)} />}
    </>
  );
}
