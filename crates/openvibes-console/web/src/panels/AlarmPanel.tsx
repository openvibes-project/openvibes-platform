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
import { toast } from "../ui/toast";
import { quiet, quietScopes } from "../views/Alarms";
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
      if (choice === "false_positive" && scope) await quiet(id, scope, note.trim());
      invalidate("/api/v1/alarm");
      setNote("");
      setScope("");
      toast(`Alarm ${triageLabel[choice] ?? choice}`);
    } catch (error) {
      toast(error instanceof ApiError ? error.message : "Save failed", true);
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
      />
      <div className="panel-body stack">
        <Section title="Process tree">
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
          <select className="select" value={choice} onChange={(event) => setState(event.target.value)} aria-label="New triage state">
            {options.map((value) => <option key={value} value={value}>{triageLabel[value]}</option>)}
          </select>
          {choice === "accepted_risk" && (
            <input className="input" type="date" required value={acceptedUntil} onChange={(event) => setAcceptedUntil(event.target.value)} aria-label="Accepted until" />
          )}
          {choice === "false_positive" && scopes.length > 0 && (
            <select className="select" value={scope} onChange={(event) => setScope(event.target.value)} aria-label="Don't alarm on this again">
              <option value="">Keep alarming on it</option>
              {scopes.map((s) => <option key={s.scope} value={s.scope}>Don't alarm again: {s.label.toLowerCase()}</option>)}
            </select>
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
