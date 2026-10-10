// A finding: one rule (in one rule set) and every host that matches it,
// with triage for one host or many at once.
import { useMemo, useRef, useState } from "react";

import { ApiError, invalidate, request, useAllPages, useResource } from "../api/client";
import type { Finding, FindingGroup, GroupEndpoint } from "../api/types";
import { useSession } from "../app/session";
import { useProvideTitle } from "../app/titles";
import { Ago, Empty, ErrorBox, Loading, ObjectLink, SeverityBadge, TriageBadge } from "../ui/bits";
import { date, daysAgo, isPast, triageLabel } from "../ui/format";
import { Trend, dailyHosts } from "../ui/trend";
import { Select } from "../ui/Select";
import { PanelHeader, Section } from "../ui/panel";
import { toast } from "../ui/toast";
import { AddToCase } from "./AddToCase";
import { findingRef } from "./cases";
import { DetectionEvidence } from "./DetectionEvidence";
import { allowedStates, noteRequired, triageBody, triageStates } from "./triage";

export function splitFindingId(id: string): [string, string] {
  const split = id.indexOf("/");
  return split < 0 ? ["", id] : [id.slice(0, split), id.slice(split + 1)];
}

export function TriageBar({ counts }: { counts: FindingGroup["triage_counts"] }) {
  const total = Object.values(counts).reduce((sum, value) => sum + value, 0) || 1;
  const tone: Record<string, string> = { open: "var(--bad)", mitigated: "var(--ok)", accepted_risk: "var(--info)", false_positive: "var(--text-3)" };
  return (
    <div className="triage-bar" role="img" aria-label={triageStates.map((s) => `${counts[s]} ${triageLabel[s]}`).join(", ")}>
      {triageStates.map((state) => counts[state] > 0 && (
        <span key={state} style={{ flexGrow: counts[state], background: tone[state] }} title={`${counts[state]} ${triageLabel[state]}`} />
      ))}
      <span className="sr-only">{total}</span>
    </div>
  );
}

export function FindingPanel({ id }: { id: string }) {
  const [ruleSetId, ruleId] = splitFindingId(id);
  const { can } = useSession();
  const groups = useAllPages<FindingGroup>("/api/v1/compliance/groups");
  const endpoints = useAllPages<GroupEndpoint>(`/api/v1/compliance/groups/${encodeURIComponent(ruleSetId)}/${encodeURIComponent(ruleId)}/endpoints`);
  const group = groups.data?.find((candidate) => candidate.rule_set_id === ruleSetId && candidate.rule_id === ruleId);
  // ponytail: the chart pages raw history (at most 3,000 rows); a
  // per-day count endpoint would scale it to large fleets.
  const since = daysAgo(13);
  const history = useAllPages<{ agent_id: string; observed_day: string }>(
    `/api/v1/compliance/history?since=${encodeURIComponent(since)}&rule_set_id=${encodeURIComponent(ruleSetId)}&rule_id=${encodeURIComponent(ruleId)}`, 3000);
  const trend = useMemo(() => dailyHosts(history.data ?? [], 14), [history.data]);
  const [evidenceHost, setEvidenceHost] = useState("");
  const detailsTop = useRef<HTMLDivElement>(null);
  // The evidence opens above the host list, so bring it into view.
  const showEvidence = (agentId: string) => {
    setEvidenceHost(agentId);
    detailsTop.current?.scrollIntoView({ block: "start", behavior: window.matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth" });
  };
  const host = endpoints.data?.some((item) => item.agent_id === evidenceHost) ? evidenceHost
    : endpoints.data?.length === 1 ? (endpoints.data[0]?.agent_id ?? "") : "";
  const evidencePath = host ? `/api/v1/compliance/latest/${encodeURIComponent(host)}/${encodeURIComponent(ruleSetId || "~unknown")}/${encodeURIComponent(ruleId)}` : null;
  const observation = useResource<Finding>(evidencePath);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [state, setState] = useState<string>("mitigated");
  const [note, setNote] = useState("");
  const [assignee, setAssignee] = useState("");
  const [acceptedUntil, setAcceptedUntil] = useState("");
  const [tomorrow] = useState(() => localDay(new Date(Date.now() + 86_400_000)));
  // One host selected: its saved triage fills the form, as a per-host editor.
  const single = selected.size === 1 ? [...selected][0] : undefined;
  const current = useResource<{ state: string; assigned_to: string | null; note: string | null; accepted_until: string | null; version: number }>(single === undefined ? null
    : `/api/v1/compliance/latest/${encodeURIComponent(single)}/${encodeURIComponent(ruleSetId)}/${encodeURIComponent(ruleId)}/triage`);
  const [filledFrom, setFilledFrom] = useState<unknown>(undefined);
  // Until that host's triage is in, the fields stay disabled so a late load can't overwrite an edit.
  const filling = single !== undefined && current.data === undefined && current.error === undefined;
  if (single !== undefined && current.data !== undefined && current.data !== filledFrom) {
    setFilledFrom(current.data);
    setState(current.data.state);
    setAssignee(current.data.assigned_to ?? "");
    setNote(current.data.note ?? "");
    setAcceptedUntil(current.data.accepted_until ? localDay(new Date(current.data.accepted_until)) : "");
  }
  const [filter, setFilter] = useState<string>("all");
  const [busy, setBusy] = useState(false);
  const items = useMemo(() => (endpoints.data ?? []).filter((item) => filter === "all" || item.triage_state === filter), [endpoints.data, filter]);

  // The server's workflow limits where the selected hosts can go together.
  const options = allowedStates((endpoints.data ?? []).filter((item) => selected.has(item.agent_id)).map((item) => item.triage_state));
  const choice = options.includes(state) ? state : options.includes("mitigated") ? "mitigated" : options[0] ?? "";

  useProvideTitle({ kind: "finding", id }, group?.latest_message);
  if (endpoints.error) return <div className="panel-body"><ErrorBox error={endpoints.error} /></div>;
  if (!group && groups.loading) return <Loading />;
  if (!group) return <div className="panel-body"><Empty icon="findings" title="Compliance finding not found">It may have been resolved, or it is outside your access.</Empty></div>;

  const apply = async (agentIds: string[]) => {
    const all = endpoints.data ?? [];
    const changes = all.filter((item) => agentIds.includes(item.agent_id)).map((item) => ({ agent_id: item.agent_id, version: item.triage_version }));
    setBusy(true);
    try {
      await request("POST", `/api/v1/compliance/groups/${encodeURIComponent(ruleSetId)}/${encodeURIComponent(ruleId)}/triage`, { ...triageBody({ state: choice, assignee, note, acceptedUntil }), changes });
      toast(`${changes.length === 1 ? "1 host" : `${changes.length} hosts`} set to ${triageLabel[choice]?.toLowerCase()}`);
      setSelected(new Set());
      setNote("");
      setAssignee("");
      setAcceptedUntil("");
      setFilledFrom(undefined);
      invalidate("/api/v1/compliance");
    } catch (error) {
      toast(error instanceof ApiError ? error.message : "Triage failed", true);
      if (error instanceof ApiError && (error.status === 409 || error.status === 412)) invalidate("/api/v1/compliance");
    } finally {
      setBusy(false);
    }
  };

  const canTriage = can("compliance.triage");
  const canCase = can("cases.manage");
  return (
    <>
      <PanelHeader
        icon="findings" kind={`Compliance finding · ${ruleSetId}`} title={group.latest_message}
        subtitle={<span className="mono subtle">{ruleId} · rule version {group.rule_versions.join(", ")}</span>}
        badges={<><SeverityBadge severity={group.severity} /><span className="badge badge--plain">{group.endpoint_count} hosts</span></>}
        askAbout={{ ref: { kind: "finding", id }, label: `${ruleId} ${group.latest_message}` }}
      />
      <div className="panel-body stack">
        <div ref={detailsTop}><Section title="Detection details">
          <div className="field">Host
            <Select label="Host" placeholder="Choose a host to inspect its evidence" value={host} onChange={setEvidenceHost}
              options={(endpoints.data ?? []).map((item) => ({ value: item.agent_id, label: item.hostname ?? item.agent_id }))} />
          </div>
        </Section></div>
        {host && (observation.error ? <ErrorBox error={observation.error} /> : !observation.data ? <Loading rows={3} /> : <>
          <p>{observation.data.message}</p>
          <p className="subtle">Rule version {observation.data.rule_version} · {observation.data.origin === "import" ? "Imported observation" : "Agent observation"}</p>
          <DetectionEvidence key={observation.data.id} detection={observation.data.detection} references={observation.data.evidence}
            ruleId={ruleId} ruleUrl={`${evidencePath}/rule/${encodeURIComponent(observation.data.id)}`} />
        </>)}
        <Section title="Triage">
          <TriageBar counts={group.triage_counts} />
          <div className="row row--wrap" role="group" aria-label="Show hosts by triage state">
            {(["all", ...triageStates] as const).map((value) => {
              const n = value === "all" ? group.endpoint_count : group.triage_counts[value];
              if (value !== "all" && n === 0) return null;
              return (
                <button key={value} type="button" className="chip" aria-pressed={filter === value} onClick={() => setFilter(value)}>
                  {value === "all" ? "All" : triageLabel[value]} <span className="chip__count">{n}</span>
                </button>
              );
            })}
          </div>
        </Section>
        {history.data && history.data.length > 0 && history.data.length < 3000 && <Section title="Hosts reporting it, last 14 days"><Trend counts={trend} label="hosts per day" /></Section>}
        <dl className="kv">
          <dt>First seen</dt><dd>{date(group.first_observed_at)}</dd>
          <dt>Last seen</dt><dd><Ago value={group.last_observed_at} /></dd>
        </dl>
      </div>
      {canTriage && selected.size > 0 && (
        <form className="bulk-bar" onSubmit={(event) => { event.preventDefault(); void apply([...selected]); }}>
          <strong className="num">{selected.size} selected</strong>
          {options.length === 0 && <span className="subtle">These hosts have no next state in common; select fewer.</span>}
          <Select label="New triage state" disabled={filling || options.length === 0} value={choice} onChange={setState} options={options.map((value) => ({ value, label: triageLabel[value] ?? value }))} />
          {choice === "accepted_risk" && (
            <label className="row">
              <span className="subtle">until</span>
              <input className="input" type="date" required disabled={filling} min={tomorrow} value={acceptedUntil}
                onChange={(event) => setAcceptedUntil(event.target.value)} aria-label="Accepted until" />
            </label>
          )}
          <input className="input" disabled={filling} value={assignee} onChange={(event) => setAssignee(event.target.value)} placeholder="Assignee (username)" aria-label="Assignee"
            autoComplete="off" spellCheck={false} />
          <input className="input grow" disabled={filling} value={note} onChange={(event) => setNote(event.target.value)} required={noteRequired.has(choice)}
            placeholder={noteRequired.has(choice) ? "Note (required)" : "Note (optional)"} aria-label="Triage note" />
          <button className="button button--primary button--small" type="submit" disabled={busy || filling || options.length === 0}>{busy ? "Saving…" : "Apply"}</button>
        </form>
      )}
      <Section title="Hosts" flush>
        {endpoints.loading && !endpoints.data ? <Loading rows={4} /> : items.length === 0 ? <Empty title="No hosts in this state" /> : (
          <table className="table table--compact">
            <thead>
              <tr>
                {canTriage && <th className="check"><input type="checkbox" className="checkbox" aria-label="Select all hosts" checked={items.length > 0 && items.every((item) => selected.has(item.agent_id))}
                  onChange={(event) => setSelected(event.target.checked ? new Set(items.map((item) => item.agent_id)) : new Set())} /></th>}
                <th>Host</th><th>Evidence</th><th>State</th><th className="hide-narrow">Assignee</th><th>Last seen</th>
              </tr>
            </thead>
            <tbody>
              {items.map((item) => (
                <tr key={item.agent_id} aria-selected={selected.has(item.agent_id) || undefined}>
                  {canTriage && <td className="check"><input type="checkbox" className="checkbox" aria-label={`Select ${item.hostname ?? item.agent_id}`} checked={selected.has(item.agent_id)}
                    onChange={() => setSelected((current) => { const next = new Set(current); if (next.has(item.agent_id)) next.delete(item.agent_id); else next.add(item.agent_id); return next; })} /></td>}
                  <td><span className="row"><ObjectLink to={{ kind: "agent", id: item.agent_id }}>{item.hostname ?? item.agent_id}</ObjectLink>{canCase && <AddToCase compact kind="compliance_finding" id={findingRef(item.agent_id, ruleSetId, ruleId)} label={`${group.latest_message} on ${item.hostname ?? item.agent_id}`} />}</span>{item.origin === "import" && <span className="badge badge--info badge--plain gap-start">imported</span>}</td>
                  <td><button type="button" className="link-button" onClick={() => showEvidence(item.agent_id)}>View evidence</button></td>
                  <td><TriageBadge state={item.triage_state} />{item.accepted_until && (isPast(item.accepted_until)
                    ? <span className="badge badge--bad badge--plain gap-start">expired {date(item.accepted_until)}</span>
                    : <span className="subtle gap-start">until {date(item.accepted_until)}</span>)}
                    {item.ended_at && <span className="badge badge--ok badge--plain gap-start"
                      title="The agent reported this match ended">fixed {item.end_approximate ? "about " : ""}{date(item.ended_at)}</span>}</td>
                  <td className={item.assigned_to ? "hide-narrow" : "subtle hide-narrow"}>{item.assigned_to ?? "—"}</td>
                  <td className="subtle"><Ago value={item.last_observed_at} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Section>
    </>
  );
}

function localDay(value: Date) {
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${value.getFullYear()}-${pad(value.getMonth() + 1)}-${pad(value.getDate())}`;
}
