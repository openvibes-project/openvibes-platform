// One threat alarm: the process tree top-down, the rule, its triage, and
// "don't alarm on this again" when it is a false positive.
import { useState } from "react";

import { ApiError, invalidate, request, useResource } from "../api/client";
import type { AlarmDetail, AlarmProcess } from "../api/types";
import { useSession } from "../app/session";
import { useProvideTitle } from "../app/titles";
import { Ago, ErrorBox, Loading, SeverityBadge, TriageBadge } from "../ui/bits";
import { date, triageLabel } from "../ui/format";
import { PanelHeader, Section } from "../ui/panel";
import { Select } from "../ui/Select";
import { toast } from "../ui/toast";
import { DetectionEvidence } from "./DetectionEvidence";
import { quiet, quietScopes } from "../views/Alarms";
import { AddToCase } from "./AddToCase";
import { allowedStates, noteRequired, triageBody } from "./triage";

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
  useProvideTitle({ kind: "alarm", id }, alarm.data?.message);
  const [state, setState] = useState("");
  const [note, setNote] = useState("");
  const [assignee, setAssignee] = useState("");
  const [acceptedUntil, setAcceptedUntil] = useState("");
  const [scope, setScope] = useState("");
  const [busy, setBusy] = useState(false);

  if (alarm.error) return <div className="panel-body"><ErrorBox error={alarm.error} /></div>;
  if (!alarm.data) return <Loading />;
  const a = alarm.data;
  // Ancestors arrive nearest first; the tree reads top-down.
  const tree = [...(a.ancestors as unknown as AlarmProcess[])].reverse();
  const options = allowedStates([a.triage.state]).filter((s) => s !== a.triage.state);
  const choice = options.includes(state) ? state : options[0] ?? "";
  const scopes = quietScopes.filter((s) => can("alarms.suppress", s.global));

  const save = async () => {
    setBusy(true);
    try {
      await request("PUT", `/api/v1/alarms/${encodeURIComponent(id)}/triage`,
        triageBody({ state: choice, assignee, note, acceptedUntil }), { "if-match": `"${a.triage.version}"` });
      invalidate("/api/v1/alarm");
      toast(`Alarm ${triageLabel[choice] ?? choice}`);
    } catch (error) {
      toast(error instanceof ApiError ? error.message : "Save failed", true);
      setBusy(false);
      return;
    }
    // The triage is saved; a failed suppression must not read as if it weren't.
    try {
      if (choice === "false_positive" && scope) await quiet(id, scope, note.trim());
      setNote("");
      setScope("");
    } catch (error) {
      toast(`Saved as false positive; quieting failed: ${error instanceof ApiError ? error.message : "try again"}`, true);
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <PanelHeader
        icon="alarm" kind={`Alarm · ${a.hostname ?? a.agent_id}`} title={a.message}
        subtitle={<span className="mono subtle">{a.rule_id} · {a.rule_set_id} (rule v{a.rule_version}, set v{a.rule_set_version})</span>}
        badges={<><SeverityBadge severity={a.severity} /><TriageBadge state={a.triage.state} /><span className="badge badge--plain">{a.count}×</span></>}
        actions={can("cases.manage") && <AddToCase kind="alarm" id={a.id} label={a.message} />}
      />
      <div className="panel-body stack">
        <DetectionEvidence key={a.id} detection={a.detection} ruleId={a.rule_id} ruleUrl={`/api/v1/alarms/${encodeURIComponent(id)}/rule`} />
        <Section title="Process tree">
          <p className="subtle">{a.detection ? "Process sample from the recorded evidence time. " : "Recorded process sample; its individual timestamp was not retained. "}Repeated starts are counted; every occurrence is not retained. Command-line secrets may be masked.</p>
          <ol className="process-tree" aria-label="Process tree, oldest ancestor first">
            {tree.map((process, index) => <Process key={`${index}-${process.pid}`} process={process} current={false} />)}
            <Process process={a.process as unknown as AlarmProcess} current />
          </ol>
        </Section>
        <dl className="kv">
          <dt>First seen</dt><dd>{date(a.first_seen)}</dd>
          <dt>Last seen</dt><dd><Ago value={a.last_seen} /></dd>
          <dt>Starts matched</dt><dd className="num">{a.count}</dd>
          <dt>Confidence</dt><dd className="num">{a.confidence}</dd>
          {a.suppressed_by && <><dt>Suppressed</dt><dd>by suppression #{a.suppressed_by}</dd></>}
          {a.triage.note && <><dt>Note</dt><dd>{a.triage.note}</dd></>}
          {a.triage.updated_by && <><dt>Changed by</dt><dd>{a.triage.updated_by}{a.triage.updated_at && <>, <Ago value={a.triage.updated_at} /></>}</dd></>}
        </dl>
      </div>
      {can("alarms.triage") && options.length > 0 && (
        <form className="bulk-bar" onSubmit={(event) => { event.preventDefault(); void save(); }}>
          <Select label="New triage state" value={choice} onChange={setState} options={options.map((value) => ({ value, label: triageLabel[value] ?? value }))} />
          {choice === "accepted_risk" && (
            <input className="input" type="date" required value={acceptedUntil} onChange={(event) => setAcceptedUntil(event.target.value)} aria-label="Accepted until" />
          )}
          {choice === "false_positive" && scopes.length > 0 && (
            <Select label="Don't alarm on this again" value={scope} onChange={setScope}
              options={[{ value: "", label: "Keep alarming on it" }, ...scopes.map((s) => ({ value: s.scope, label: `Don't alarm again: ${s.label.toLowerCase()}` }))]} />
          )}
          <input className="input" value={assignee} onChange={(event) => setAssignee(event.target.value)} placeholder="Assignee (username)" aria-label="Assignee" autoComplete="off" spellCheck={false} />
          <input className="input grow" value={note} onChange={(event) => setNote(event.target.value)} required={noteRequired.has(choice)}
            placeholder={noteRequired.has(choice) ? "Note (required)" : "Note (optional)"} aria-label="Triage note" />
          <button className="button button--primary button--small" type="submit" disabled={busy}>{busy ? "Saving…" : "Apply"}</button>
        </form>
      )}
    </>
  );
}
