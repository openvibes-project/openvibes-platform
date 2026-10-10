// A finding: one rule (in one rule set) and every host that matches it, in
// the one detail template (triage v2): the summary acts on every open
// host; the Hosts tab selects some; Evidence and History follow.
import { useMemo, useState } from "react";

import { useAllPages, useResource } from "../api/client";
import type { Finding, FindingGroup, GroupEndpoint } from "../api/types";
import { useSession } from "../app/session";
import { useProvideTitle } from "../app/titles";
import { Ago, Empty, ErrorBox, Loading, SeverityBadge } from "../ui/bits";
import { date, daysAgo, isPast, triageLabel } from "../ui/format";
import { SelectField } from "../ui/Field";
import { Trend, dailyHosts } from "../ui/trend";
import { Select } from "../ui/Select";
import { PanelHeader, Section } from "../ui/panel";
import { AddToCase } from "./AddToCase";
import { highest } from "./bulk";
import { BulkBar } from "./BulkBar";
import { useHostCaseBadges } from "./CaseBadge";
import { findingRef } from "./cases";
import { DetectionEvidence } from "./DetectionEvidence";
import { triageStates } from "./triage";
import { HistoryTab, type HostRow, HostsTab, TriageDetail } from "./TriageDetail";

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
  const [tab, setTab] = useState("hosts");
  const [evidenceHost, setEvidenceHost] = useState("");
  const host = endpoints.data?.some((item) => item.agent_id === evidenceHost) ? evidenceHost
    : endpoints.data?.length === 1 ? (endpoints.data[0]?.agent_id ?? "") : "";
  const evidencePath = host ? `/api/v1/compliance/latest/${encodeURIComponent(host)}/${encodeURIComponent(ruleSetId || "~unknown")}/${encodeURIComponent(ruleId)}` : null;
  const observation = useResource<Finding>(evidencePath);
  const cases = useHostCaseBadges("compliance_finding", `${ruleSetId}/${ruleId}`);

  useProvideTitle({ kind: "finding", id }, group?.latest_message);
  if (endpoints.error) return <div className="panel-body"><ErrorBox error={endpoints.error} /></div>;
  if (!group && groups.loading) return <Loading />;
  if (!group) return <div className="panel-body"><Empty icon="findings" title="Compliance finding not found">It may have been resolved, or it is outside your access.</Empty></div>;

  const all = endpoints.data ?? [];
  const open = all.filter((item) => item.triage_state === "open");
  const canCase = can("cases.manage");
  const label = (item: GroupEndpoint) => item.hostname ?? item.agent_id;
  const hosts: HostRow[] = all.map((item) => ({
    agent_id: item.agent_id, hostname: item.hostname ?? null, triage_state: item.triage_state, assigned_to: item.assigned_to ?? null, seen: item.last_observed_at,
    extra: <>
      {item.origin === "import" && <span className="badge badge--info badge--plain">imported</span>}
      {item.accepted_until && (isPast(item.accepted_until)
        ? <span className="badge badge--bad badge--plain">expired {date(item.accepted_until)}</span>
        : <span className="subtle">until {date(item.accepted_until)}</span>)}
      {item.ended_at && <span className="badge badge--ok badge--plain" title="The agent reported this match ended">fixed {item.end_approximate ? "about " : ""}{date(item.ended_at)}</span>}
      <button type="button" className="link-button" onClick={() => { setEvidenceHost(item.agent_id); setTab("evidence"); }}>Evidence</button>
      {canCase && <AddToCase compact kind="compliance_finding" id={findingRef(item.agent_id, ruleSetId, ruleId)} label={`${group.latest_message} on ${label(item)}`} />}
    </>,
  }));

  const summary = <>
    <TriageBar counts={group.triage_counts} />
    <p className="subtle">{open.length.toLocaleString()} open of {group.endpoint_count.toLocaleString()} hosts · first seen {date(group.first_observed_at)} · last seen <Ago value={group.last_observed_at} /></p>
    {history.data && history.data.length > 0 && history.data.length < 3000 && <Section title="Hosts reporting it, last 14 days"><Trend counts={trend} label="hosts per day" /></Section>}
    {open.length > 0 && (
      <BulkBar inline kind="compliance" noun={open.length === 1 ? "open host" : "open hosts"} count={open.length} onClear={() => undefined}
        items={() => open.map((item) => ({ rule_set_id: ruleSetId, rule_id: ruleId, agent_id: item.agent_id }))}
        newCase={() => ({ title: group.latest_message, severity: highest([group.severity]) })} />
    )}
  </>;

  const evidence = (
    <div className="panel-body stack">
      <SelectField label="Host">
        <Select label="Host" placeholder="Choose a host to inspect its evidence" value={host} onChange={setEvidenceHost}
          options={all.map((item) => ({ value: item.agent_id, label: label(item) }))} />
      </SelectField>
      {host && (observation.error ? <ErrorBox error={observation.error} /> : !observation.data ? <Loading rows={3} /> : <>
        <p>{observation.data.message}</p>
        <p className="subtle">Rule version {observation.data.rule_version} · {observation.data.origin === "import" ? "Imported observation" : "Agent observation"}</p>
        <DetectionEvidence key={observation.data.id} detection={observation.data.detection} references={observation.data.evidence}
          ruleId={ruleId} ruleUrl={`${evidencePath}/rule/${encodeURIComponent(observation.data.id)}`} />
      </>)}
    </div>
  );

  return (
    <>
      <PanelHeader
        icon="findings" kind={`Compliance finding · ${ruleSetId}`} title={group.latest_message}
        subtitle={<span className="mono subtle">{ruleId} · rule version {group.rule_versions.join(", ")}</span>}
        badges={<><SeverityBadge severity={group.severity} /><span className="badge badge--plain">{group.endpoint_count} hosts</span></>}
        askAbout={{ ref: { kind: "finding", id }, label: `${ruleId} ${group.latest_message}` }}
      />
      <TriageDetail summary={summary} tab={tab} onTab={setTab} tabs={[
        { key: "hosts", label: `Hosts (${all.length.toLocaleString()})`, body: endpoints.loading && !endpoints.data ? <Loading rows={4} />
          : <HostsTab kind="compliance" hosts={hosts} cases={cases} title={group.latest_message} severity={group.severity}
              item={(agentId) => ({ rule_set_id: ruleSetId, rule_id: ruleId, agent_id: agentId })} /> },
        { key: "evidence", label: "Evidence", body: evidence },
        { key: "history", label: "History", body: <HistoryTab showHost query={`kind=compliance&rule_set_id=${encodeURIComponent(ruleSetId)}&rule_id=${encodeURIComponent(ruleId)}`} /> },
      ]} />
    </>
  );
}
