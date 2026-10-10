// One threat alarm in the one detail template (triage v2): the summary
// with its triage actions and "don't alarm on this again", then the
// process tree, the evidence and the triage history.
import { useResource } from "../api/client";
import type { AlarmDetail, AlarmProcess } from "../api/types";
import { useSession } from "../app/session";
import { useProvideTitle } from "../app/titles";
import { Ago, ErrorBox, Loading, SeverityBadge, TriageBadge } from "../ui/bits";
import { date } from "../ui/format";
import { PanelHeader } from "../ui/panel";
import { QuietMenu } from "../views/Alarms";
import { AddToCase } from "./AddToCase";
import { BulkBar } from "./BulkBar";
import { CaseBadge, useCaseBadges } from "./CaseBadge";
import { DetectionEvidence } from "./DetectionEvidence";
import { HistoryTab, TriageDetail } from "./TriageDetail";

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

export function AlarmPanel({ id }: { id: string }) {
  const { can } = useSession();
  const alarm = useResource<AlarmDetail>(`/api/v1/alarms/${encodeURIComponent(id)}`);
  const cases = useCaseBadges("alarm");
  useProvideTitle({ kind: "alarm", id }, alarm.data?.message);

  if (alarm.error) return <div className="panel-body"><ErrorBox error={alarm.error} /></div>;
  if (!alarm.data) return <Loading />;
  const a = alarm.data;
  // Ancestors arrive nearest first; the tree reads top-down.
  const tree = [...(a.ancestors as unknown as AlarmProcess[])].reverse();

  const summary = <>
    <dl className="kv">
      <dt>First seen</dt><dd>{date(a.first_seen)}</dd>
      <dt>Last seen</dt><dd><Ago value={a.last_seen} /></dd>
      <dt>Starts matched</dt><dd className="num">{a.count}</dd>
      <dt>Confidence</dt><dd className="num">{a.confidence}</dd>
      {a.suppressed_by && <><dt>Suppressed</dt><dd>by suppression #{a.suppressed_by}</dd></>}
      {a.triage.assigned_to && <><dt>Assignee</dt><dd>{a.triage.assigned_to}</dd></>}
      {a.triage.note && <><dt>Note</dt><dd>{a.triage.note}</dd></>}
      {a.triage.updated_by && <><dt>Changed by</dt><dd>{a.triage.updated_by}{a.triage.updated_at && <>, <Ago value={a.triage.updated_at} /></>}</dd></>}
    </dl>
    <BulkBar inline kind="alarms" noun="alarm" count={1} onClear={() => undefined} items={() => [{ id: a.id }]} without={["case", "suppress"]}
      newCase={() => ({ title: a.message, severity: a.severity })} />
    <QuietMenu alarm={a} />
  </>;

  return (
    <>
      <PanelHeader
        icon="alarm" kind={`Alarm · ${a.hostname ?? a.agent_id}`} title={a.message}
        subtitle={<span className="mono subtle">{a.rule_id} · {a.rule_set_id} (rule v{a.rule_version}, set v{a.rule_set_version})</span>}
        badges={<><SeverityBadge severity={a.severity} /><TriageBadge state={a.triage.state} /><span className="badge badge--plain">{a.count}×</span><CaseBadge numbers={cases.get(a.id)} /></>}
        actions={can("cases.manage") && <AddToCase kind="alarm" id={a.id} label={a.message} />}
      />
      <TriageDetail summary={summary} tabs={[
        { key: "process", label: "Process", body: (
          <div className="panel-body stack">
            <p className="subtle">{a.detection ? "Process sample from the recorded evidence time. " : "Recorded process sample; its individual timestamp was not retained. "}Repeated starts are counted; every occurrence is not retained. Command-line secrets may be masked.</p>
            <ol className="process-tree" aria-label="Process tree, oldest ancestor first">
              {tree.map((process, index) => <Process key={`${index}-${process.pid}`} process={process} current={false} />)}
              <Process process={a.process as unknown as AlarmProcess} current />
            </ol>
          </div>
        ) },
        { key: "evidence", label: "Evidence", body: (
          <div className="panel-body"><DetectionEvidence key={a.id} detection={a.detection} ruleId={a.rule_id} ruleUrl={`/api/v1/alarms/${encodeURIComponent(id)}/rule`} /></div>
        ) },
        { key: "history", label: "History", body: <HistoryTab showHost={false} query={`kind=alarm&id=${encodeURIComponent(a.id)}`} /> },
      ]} />
    </>
  );
}
