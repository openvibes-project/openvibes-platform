// A finding: one rule (in one rule set) and every host that matches it,
// with triage for one host or many at once.
import { useMemo, useState } from "react";

import { ApiError, invalidate, request, useAllPages } from "../api/client";
import type { FindingGroup, GroupEndpoint } from "../api/types";
import { useSession } from "../app/session";
import { useProvideTitle } from "../app/titles";
import { Ago, Empty, ErrorBox, Loading, ObjectLink, SeverityBadge, TriageBadge } from "../ui/bits";
import { date, daysAgo, triageLabel } from "../ui/format";
import { Trend, dailyHosts } from "../ui/trend";
import { PanelHeader, Section } from "../ui/panel";
import { toast } from "../ui/toast";

export const triageStates = ["open", "investigating", "mitigated", "accepted_risk", "false_positive"] as const;

export function splitFindingId(id: string): [string, string] {
  const split = id.indexOf("/");
  return split < 0 ? ["", id] : [id.slice(0, split), id.slice(split + 1)];
}

export function TriageBar({ counts }: { counts: FindingGroup["triage_counts"] }) {
  const total = Object.values(counts).reduce((sum, value) => sum + value, 0) || 1;
  const tone: Record<string, string> = { open: "var(--bad)", investigating: "var(--warn)", mitigated: "var(--ok)", accepted_risk: "var(--info)", false_positive: "var(--text-3)" };
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
  const groups = useAllPages<FindingGroup>("/api/v1/findings/groups");
  const endpoints = useAllPages<GroupEndpoint>(`/api/v1/findings/groups/${encodeURIComponent(ruleSetId)}/${encodeURIComponent(ruleId)}/endpoints`);
  const group = groups.data?.find((candidate) => candidate.rule_set_id === ruleSetId && candidate.rule_id === ruleId);
  // ponytail: the chart pages raw history (at most 3,000 rows); a
  // per-day count endpoint would scale it to large fleets.
  const since = daysAgo(13);
  const history = useAllPages<{ agent_id: string; observed_day: string }>(
    `/api/v1/findings/history?since=${encodeURIComponent(since)}&rule_set_id=${encodeURIComponent(ruleSetId)}&rule_id=${encodeURIComponent(ruleId)}`, 3000);
  const trend = useMemo(() => dailyHosts(history.data ?? [], 14), [history.data]);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [state, setState] = useState<string>("investigating");
  const [note, setNote] = useState("");
  const [filter, setFilter] = useState<string>("all");
  const [busy, setBusy] = useState(false);
  const items = useMemo(() => (endpoints.data ?? []).filter((item) => filter === "all" || item.triage_state === filter), [endpoints.data, filter]);

  useProvideTitle({ kind: "finding", id }, group?.latest_message);
  if (endpoints.error) return <div className="panel-body"><ErrorBox error={endpoints.error} /></div>;
  if (!group && groups.loading) return <Loading />;
  if (!group) return <div className="panel-body"><Empty icon="findings" title="Finding not found">It may have been resolved, or it is outside your access.</Empty></div>;

  const apply = async (agentIds: string[]) => {
    const all = endpoints.data ?? [];
    const changes = all.filter((item) => agentIds.includes(item.agent_id)).map((item) => ({ agent_id: item.agent_id, version: item.triage_version }));
    setBusy(true);
    try {
      await request("POST", `/api/v1/findings/groups/${encodeURIComponent(ruleSetId)}/${encodeURIComponent(ruleId)}/triage`, { state, note: note.trim() || null, changes });
      toast(`${changes.length === 1 ? "1 host" : `${changes.length} hosts`} set to ${triageLabel[state]?.toLowerCase()}`);
      setSelected(new Set());
      setNote("");
      invalidate("/api/v1/findings");
    } catch (error) {
      toast(error instanceof ApiError ? error.message : "Triage failed", true);
      if (error instanceof ApiError && error.status === 409) invalidate("/api/v1/findings");
    } finally {
      setBusy(false);
    }
  };

  const canTriage = can("findings.triage");
  return (
    <>
      <PanelHeader
        icon="findings" kind={`Finding · ${ruleSetId}`} title={group.latest_message}
        subtitle={<span className="mono subtle">{ruleId} · rule version {group.rule_versions.join(", ")}</span>}
        badges={<><SeverityBadge severity={group.severity} /><span className="badge badge--plain">{group.endpoint_count} hosts</span></>}
        askAbout={{ ref: { kind: "finding", id }, label: `${ruleId} ${group.latest_message}` }}
      />
      <div className="panel-body stack">
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
          <select className="select" value={state} onChange={(event) => setState(event.target.value)} aria-label="New triage state">
            {triageStates.map((value) => <option key={value} value={value}>{triageLabel[value]}</option>)}
          </select>
          <input className="input grow" value={note} onChange={(event) => setNote(event.target.value)} placeholder="Note (optional)" aria-label="Triage note" />
          <button className="button button--primary button--small" type="submit" disabled={busy}>{busy ? "Saving…" : "Apply"}</button>
        </form>
      )}
      <Section title="Hosts" flush>
        {endpoints.loading && !endpoints.data ? <Loading rows={4} /> : items.length === 0 ? <Empty title="No hosts in this state" /> : (
          <table className="table table--compact">
            <thead>
              <tr>
                {canTriage && <th className="check"><input type="checkbox" aria-label="Select all hosts" checked={items.length > 0 && items.every((item) => selected.has(item.agent_id))}
                  onChange={(event) => setSelected(event.target.checked ? new Set(items.map((item) => item.agent_id)) : new Set())} /></th>}
                <th>Host</th><th>State</th><th>Last seen</th>
              </tr>
            </thead>
            <tbody>
              {items.map((item) => (
                <tr key={item.agent_id} aria-selected={selected.has(item.agent_id) || undefined}>
                  {canTriage && <td className="check"><input type="checkbox" aria-label={`Select ${item.hostname ?? item.agent_id}`} checked={selected.has(item.agent_id)}
                    onChange={() => setSelected((current) => { const next = new Set(current); if (next.has(item.agent_id)) next.delete(item.agent_id); else next.add(item.agent_id); return next; })} /></td>}
                  <td><ObjectLink to={{ kind: "agent", id: item.agent_id }}>{item.hostname ?? item.agent_id}</ObjectLink>{item.origin === "import" && <span className="badge badge--info badge--plain" style={{ marginLeft: 6 }}>imported</span>}</td>
                  <td><TriageBadge state={item.triage_state} /></td>
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

