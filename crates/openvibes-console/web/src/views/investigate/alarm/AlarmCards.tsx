// The cards of an alarm's page (approved screen 30): What happened, Details
// and History on the left; Commands seen, the process chain, the last 24
// hours and Related on the right. Each reads the alarm's summary; the
// evidence keeps its own route (GET /alarms/{id}/rule, ruling 8).
import { useState } from "react";

import { apiMessage, invalidate, request, useResource } from "../../../api/client";
import type { AlarmDetail, AlarmProcess, AlarmSummaryPage, AlarmSuppression } from "../../../api/types";
import { alarmPath } from "../../../app/location";
import { viewLink } from "../../../app/nav";
import { useSession } from "../../../app/session";
import { AddToCase } from "../../../panels/cases/AddToCase";
import { caseNumber } from "../../../panels/cases/cases";
import { DetectionEvidence } from "../../../panels/alarms/DetectionEvidence";
import { SuppressDialog } from "../../../panels/alarms/SuppressForm";
import { HistoryTab } from "../../../panels/triage/TriageDetail";
import { HourlyBars } from "../../../ui/charts/HourlyBars";
import { Ago, Empty, ErrorBox, ObjectLink, SeverityBadge, TriageBadge } from "../../../ui/bits";
import { Card } from "../../../ui/detail/DetailPage";
import { date, triageLabel } from "../../../ui/format";
import { Icon } from "../../../ui/Icon";
import { toast } from "../../../ui/toast";

type Page = AlarmSummaryPage;
type Command = Page["commands"][number];

const commandLine = (c: Command) => c.args.join(" ");

/** A suppression request from this alarm waiting for approval; its requester may withdraw it. */
export function WaitingRequest({ request: waiting }: { request: AlarmSuppression }) {
  const [busy, setBusy] = useState(false);
  const withdraw = async () => {
    if (busy) return;
    setBusy(true);
    try {
      await request("POST", `/api/v1/alarm-suppressions/${encodeURIComponent(waiting.id)}/withdraw`);
      invalidate("/api/v1/alarm");
      toast("Request withdrawn · recorded in the audit log");
    } catch (error) {
      toast(apiMessage(error, "Withdraw failed"), true);
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="callout callout--warn" role="status">
      <Icon name="clock" size={16} /><span className="grow">Suppression requested, waiting for approval… these alarms keep arriving</span>
      {waiting.can_withdraw && <button type="button" className="button button--small" disabled={busy} onClick={() => void withdraw()}>Withdraw request</button>}
    </div>
  );
}

/** "What happened" from the rule's text, else its title and message; then how it was detected. */
export function WhatHappenedCard({ page }: { page: Page }) {
  const { rule, alarm } = page;
  const detail = useResource<AlarmDetail>(`/api/v1/alarms/${encodeURIComponent(String(alarm.id))}`);
  return (
    <Card title="What happened">
      <div className="stack">
        {rule.explain ? <p className="pre-line">{rule.explain}</p> : <>
          <strong>{rule.title}</strong>
          {rule.message !== rule.title && <p className="pre-line">{rule.message}</p>}
        </>}
        {rule.check && <><h3 className="section-title">What to check</h3><p className="pre-line">{rule.check}</p></>}
        {detail.error ? <ErrorBox error={detail.error} /> : detail.data && (
          <DetectionEvidence key={alarm.id} detection={detail.data.detection} ruleId={alarm.rule_id} ruleUrl={`/api/v1/alarms/${encodeURIComponent(String(alarm.id))}/rule`} />
        )}
      </div>
    </Card>
  );
}

/** Reopens a closed alarm at once (no note needed). */
async function reopen(id: number) {
  try {
    await request("POST", "/api/v1/alarms/bulk", { action: "state", state: "open", items: [{ id: String(id) }] });
    toast("Alarm reopened");
    invalidate("/api/v1/alarm");
    invalidate("/api/v1/triage-history");
  } catch (error) {
    toast(apiMessage(error, "Reopen failed"), true);
  }
}

/** The decision of a closed alarm, the rule and its versions, when it arrived, its case and suppression. */
export function DetailsCard({ page, waiting, waitingError }: { page: Page; waiting: AlarmSuppression | undefined; waitingError?: Parameters<typeof ErrorBox>[0]["error"] | undefined }) {
  const { alarm, can } = page;
  const { triage } = alarm;
  const suppressedBy = page.commands.find((c) => c.id === alarm.id)?.suppressed_by;
  return (
    <Card title="Details">
      <div className="stack">
        {triage.state !== "open" && (
          <div className="decision">
            {triage.note && <span>{triage.note}</span>}
            <div className="decision__foot">
              <span className="subtle">{triageLabel[triage.state] ?? triage.state}{triage.updated_by && <> by {triage.updated_by}</>}{triage.updated_at && <> · <Ago value={triage.updated_at} /></>}
                {triage.accepted_until && <> · until {date(triage.accepted_until)}</>}</span>
              {can.triage && <button type="button" className="button button--small" onClick={() => void reopen(alarm.id)}><Icon name="refresh" size={14} />Reopen</button>}
            </div>
          </div>
        )}
        <dl className="kv person-page__kv">
          <dt>Rule</dt><dd className="mono">{alarm.rule_id} <span className="subtle">v{alarm.rule_version}</span></dd>
          <dt>Rule set</dt><dd className="mono">{alarm.rule_set_id} <span className="subtle">v{alarm.rule_set_version}</span></dd>
          {alarm.techniques.length > 0 && <><dt>ATT&CK</dt><dd className="row row--wrap">{alarm.techniques.map((t) => <a key={t} className="tag" {...viewLink("/coverage", { technique: t })}>{t}</a>)}</dd></>}
          <dt>First seen</dt><dd>{date(alarm.first_seen)}</dd>
          <dt>Last seen</dt><dd><Ago value={alarm.last_seen} /></dd>
          <dt>Received</dt><dd>{date(alarm.received_at)}</dd>
          <dt>Assignee</dt><dd>{alarm.assignee?.name ?? <span className="subtle">Unassigned</span>}</dd>
          <dt>Case</dt><dd>{can.add_to_case ? <AddToCase kind="alarm" id={String(alarm.id)} label={alarm.message} inCase={alarm.case?.number} />
            : alarm.case ? <ObjectLink to={{ kind: "case", id: alarm.case.id }}>{caseNumber(alarm.case.number)}</ObjectLink> : <span className="subtle">None</span>}</dd>
          <dt>Suppression</dt><dd>{suppressedBy != null ? <>By suppression #{suppressedBy}</>
            : waitingError ? <ErrorBox error={waitingError} /> : waiting ? <WaitingRequest request={waiting} /> : <span className="subtle">None</span>}</dd>
        </dl>
      </div>
    </Card>
  );
}

export const HistoryCard = ({ id }: { id: number }) => (
  <Card title="History"><HistoryTab showHost={false} query={`kind=alarm&id=${encodeURIComponent(String(id))}`} /></Card>
);

/** "Suppress this command…": the screen-12 form for THIS sibling's command line, not the opened alarm's.
 * A request already waiting for that sibling is said instead of a second form. */
function SuppressCommand({ command }: { command: Command }) {
  const { can } = useSession();
  const [open, setOpen] = useState(false);
  const [waits, setWaits] = useState(false);
  const [busy, setBusy] = useState(false);
  const id = String(command.id);
  const press = async () => {
    if (!can("alarms.suppressions.read")) { setOpen(true); return; }
    setBusy(true);
    try {
      const found = await request<{ items: AlarmSuppression[] }>("GET", `/api/v1/alarm-suppressions?alarm_id=${encodeURIComponent(id)}&state=waiting`);
      if (found.items.length > 0) setWaits(true); else setOpen(true);
    } catch (error) {
      toast(apiMessage(error, "Could not check for a waiting request"), true);
    } finally {
      setBusy(false);
    }
  };
  if (waits) return <span className="subtle" role="status">A request for this command is waiting for approval</span>;
  return (
    <>
      <button type="button" className="button button--small" disabled={busy} onClick={() => void press()}>Suppress this command…</button>
      {open && <SuppressDialog alarmId={id} initial={{ what: "command" }} onClose={() => setOpen(false)} />}
    </>
  );
}

/** Every distinct command line with its count, the usual one first. */
export function CommandsCard({ page }: { page: Page }) {
  const { commands, alarm, can } = page;
  return (
    <Card flush id="commands" title={<>Commands seen <span className="subtle num">{commands.length.toLocaleString()}</span></>}>
      <div className="table-wrap"><table className="table table--compact" aria-label="Commands seen">
        <thead><tr><th>Command</th><th className="num">Count</th><th>Last seen</th><th>State</th><th><span className="sr-only">Actions</span></th></tr></thead>
        <tbody>
          {commands.map((c, index) => {
            const once = c.count === 1;
            const line = commandLine(c);
            return (
              <tr key={c.id} className={once ? "cmd-once" : undefined}>
                <td className="alarm-command">
                  <div className="mono">{c.id === alarm.id ? line : <a {...viewLink(alarmPath(String(c.id)))}>{line}</a>}</div>
                  <div className="row row--wrap">
                    {c.id === alarm.id && <span className="badge badge--plain">This alarm</span>}
                    {index === 0 && commands.length > 1 && <span className="badge badge--plain">Usual</span>}
                    {once && <span className="badge badge--warn badge--plain">Seen once</span>}
                  </div>
                </td>
                <td className="num">{c.count.toLocaleString()}</td>
                <td className="subtle nowrap"><Ago value={c.last_seen} /></td>
                <td><TriageBadge state={c.state} /></td>
                <td><div className="row row--wrap">
                  {index === 0 && can.suppress && c.suppressed_by == null && <SuppressCommand command={c} />}
                  {c.suppressed_by != null && <span className="subtle">Suppressed #{c.suppressed_by}</span>}
                  {once && can.add_to_case ? <AddToCase compact={c.case == null} kind="alarm" id={String(c.id)} label={line} inCase={c.case?.number} />
                    : c.case && <ObjectLink to={{ kind: "case", id: c.case.id }}>{caseNumber(c.case.number)}</ObjectLink>}
                </div></td>
              </tr>
            );
          })}
        </tbody>
      </table></div>
    </Card>
  );
}

function Process({ process, current }: { process: AlarmProcess; current: boolean }) {
  return (
    <li className={current ? "process process--current" : "process"}>
      <div className="mono"><strong>{process.exe}</strong>{process.seeded && <span className="subtle"> (seen before the agent started)</span>}</div>
      <div className="mono subtle process__args">{process.args.join(" ")}{process.truncated && " …(cut)"}</div>
      <div className="subtle">
        pid {process.pid} · user {process.uid}{process.euid !== process.uid && <> as {process.euid}</>}
        {process.cwd && <> · in {process.cwd}</>}
      </div>
    </li>
  );
}

export function ProcessCard({ page }: { page: Page }) {
  // The same (cached) record What happened reads for its evidence.
  const detail = useResource<AlarmDetail>(`/api/v1/alarms/${encodeURIComponent(String(page.alarm.id))}`).data;
  // Ancestors arrive nearest first; the tree reads top-down.
  const tree = [...(page.alarm.ancestors as unknown as AlarmProcess[])].reverse();
  return (
    <Card title="Process chain">
      <div className="stack">
        <ol className="process-tree" aria-label="Process tree, oldest ancestor first">
          {tree.map((process, index) => <Process key={`${index}-${process.pid}`} process={process} current={false} />)}
          <Process process={page.alarm.process as unknown as AlarmProcess} current />
        </ol>
        <p className="subtle">{detail && (detail.detection ? "Process sample from the recorded evidence time. " : "Recorded process sample; its individual timestamp was not retained. ")}Repeated starts are counted; every occurrence is not retained. Command-line secrets may be masked.</p>
      </div>
    </Card>
  );
}

export const TimelineCard = ({ page }: { page: Page }) => (
  <Card id="timeline" title="Last 24 hours">
    <HourlyBars values={page.hourly} label="Starts per hour of this alarm and its other commands, the last 24 hours" />
  </Card>
);

/** Other open alarms on the host, its vulnerabilities, and the same rule on other hosts. */
export function RelatedCard({ page }: { page: Page }) {
  const { host_alarms: alarms, host_vulnerabilities: vulns, same_rule_elsewhere: elsewhere } = page.related;
  const host = { host: page.alarm.host.id };
  return (
    <Card title="Related">
      <div className="stack">
        <h3 className="section-title">Alarms on this host <span className="subtle num">{alarms.total.toLocaleString()}</span></h3>
        {alarms.total === 0 ? <Empty title="No other open alarms" /> : <ul className="list list--plain" aria-label="Alarms on this host">
          {alarms.items.map((a) => <li key={a.id} className="list__row list__row--static">
            <SeverityBadge severity={a.severity} /><ObjectLink to={{ kind: "alarm", id: String(a.id) }}>{a.message}</ObjectLink>
            <span className="grow" /><span className="subtle nowrap"><Ago value={a.last_seen} /></span>
          </li>)}
        </ul>}
        {alarms.total > alarms.items.length && <a className="detail-more" {...viewLink("/alarms", host)}>Show all {alarms.total.toLocaleString()} alarms</a>}
        {vulns && <>
          <h3 className="section-title">Vulnerabilities on this host <span className="subtle num">{vulns.total.toLocaleString()}</span></h3>
          {vulns.total === 0 ? <Empty title="No open vulnerabilities" /> : <ul className="list list--plain" aria-label="Vulnerabilities on this host">
            {vulns.items.map((v) => <li key={v.advisory} className="list__row list__row--static" title={v.title}>
              <SeverityBadge severity={v.severity} /><ObjectLink to={{ kind: "advisory", id: v.advisory }}>{v.advisory}</ObjectLink>
              {v.exploited && <span className="badge badge--critical badge--plain"><Icon name="flame" size={12} /> Exploited</span>}
            </li>)}
          </ul>}
          {vulns.total > vulns.items.length && <a className="detail-more" {...viewLink("/vulnerabilities", host)}>Show all {vulns.total.toLocaleString()} vulnerabilities</a>}
        </>}
        <h3 className="section-title">Same rule elsewhere</h3>
        {elsewhere.hosts === 0 ? <p className="subtle">No other host has an open alarm from this rule.</p>
          : <>
            <p>{elsewhere.open.toLocaleString()} open on {elsewhere.hosts.toLocaleString()} other {elsewhere.hosts === 1 ? "host" : "hosts"}</p>
            <a className="detail-more" {...viewLink("/alarms", { q: page.alarm.rule_id })}>Show alarms from this rule</a>
          </>}
      </div>
    </Card>
  );
}
