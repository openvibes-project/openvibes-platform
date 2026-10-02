// Compare two hosts (#120): only what differs, section by section (system,
// open ports, services, software, findings). The panel id is "A B" (agent
// ids never contain a space); with only "A", it asks for the second host.
import { useMemo } from "react";

import { useAllPages, useResource } from "../api/client";
import type { Agent, Finding, HostPackage, HostServices } from "../api/types";
import { nav } from "../app/nav";
import { useSession } from "../app/session";
import { Empty, ErrorBox, Loading, ObjectLink } from "../ui/bits";
import { PanelHeader, Section } from "../ui/panel";
import { diff } from "./compare";


type Side = { agent: Agent | undefined; ports: Map<string, string>; services: Map<string, string>; software: Map<string, string>; findings: Map<string, string>; loading: boolean; error: Error | undefined };

function useSide(id: string, findings: readonly Finding[] | undefined): Side {
  const path = `/api/v1/agents/${encodeURIComponent(id)}`;
  const agent = useResource<Agent>(path);
  const report = useResource<HostServices>(`${path}/services`);
  const packages = useAllPages<HostPackage>(`${path}/packages`, 20_000);
  return useMemo(() => ({
    agent: agent.data,
    ports: new Map((report.data?.listeners ?? []).map((l) => [`${l.port}/${l.protocol}`, l.exposed ? "exposed" : "local"])),
    services: new Map((report.data?.services ?? []).map((s) => [s.unit, s.programs.join(" ")])),
    software: new Map((packages.data ?? []).map((p) => [`${p.name}.${p.arch}`, `${p.version}${p.release ? `-${p.release}` : ""}`])),
    findings: new Map((findings ?? []).filter((f) => f.agent_id === id).map((f) => [`${f.rule_set_id}/${f.rule_id}`, f.message])),
    loading: agent.loading || report.loading || packages.loading,
    error: agent.error ?? packages.error,
  }), [agent.data, agent.loading, agent.error, report.data, report.loading, packages.data, packages.loading, packages.error, findings, id]);
}

function Differences({ title, a, b, nameA, nameB, show }: { title: string; a: Map<string, string>; b: Map<string, string>; nameA: string; nameB: string; show: (key: string, value?: string) => string }) {
  const { onlyA, onlyB, changed } = diff(a, b);
  const total = onlyA.length + onlyB.length + changed.length;
  return (
    <Section title={`${title}${total ? ` · ${total} different` : ""}`}>
      {total === 0 ? <p className="subtle">The same on both ({a.size}).</p> : (
        <table className="table table--compact" aria-label={`${title} differences`}>
          <thead><tr><th>{title}</th><th>{nameA}</th><th>{nameB}</th></tr></thead>
          <tbody>
            {onlyA.map((k) => <tr key={`a${k}`}><td className="mono">{k}</td><td>{show(k, a.get(k))}</td><td className="subtle">—</td></tr>)}
            {onlyB.map((k) => <tr key={`b${k}`}><td className="mono">{k}</td><td className="subtle">—</td><td>{show(k, b.get(k))}</td></tr>)}
            {changed.map((k) => <tr key={`c${k}`}><td className="mono">{k}</td><td>{show(k, a.get(k))}</td><td>{show(k, b.get(k))}</td></tr>)}
          </tbody>
        </table>
      )}
    </Section>
  );
}

function PickSecond({ first }: { first: string }) {
  const hosts = useAllPages<Agent>("/api/v1/agents");
  const others = (hosts.data ?? []).filter((a) => a.id !== first && a.status !== "revoked");
  return (
    <>
      <PanelHeader icon="agents" kind="Compare" title="Compare with…" />
      <div className="panel-body">
        {hosts.error ? <ErrorBox error={hosts.error} /> : hosts.loading && !hosts.data ? <Loading rows={4} /> : others.length === 0 ? <Empty title="No other host to compare with" /> : (
          <ul className="list" aria-label="Hosts to compare with">
            {others.map((a) => (
              <li key={a.id}><button type="button" className="list__row" onClick={() => nav.open({ kind: "compare", id: `${first} ${a.id}` })}>
                <span className="grow truncate">{a.hostname ?? a.id}</span><span className="subtle mono">{a.os_id ?? ""} {a.os_version ?? ""}</span>
              </button></li>
            ))}
          </ul>
        )}
      </div>
    </>
  );
}

export function ComparePanel({ id }: { id: string }) {
  const [first = "", second] = id.split(" ");
  return second ? <Compare a={first} b={second} /> : <PickSecond first={first} />;
}

function Compare({ a, b }: { a: string; b: string }) {
  const { can } = useSession();
  const findings = useAllPages<Finding>(can("findings.read") ? "/api/v1/findings/latest" : null);
  const left = useSide(a, findings.data);
  const right = useSide(b, findings.data);
  const nameA = left.agent?.hostname ?? a;
  const nameB = right.agent?.hostname ?? b;
  if (left.error || right.error) return <div className="panel-body"><ErrorBox error={(left.error ?? right.error) as never} /></div>;
  if ((left.loading && !left.agent) || (right.loading && !right.agent)) return <Loading />;
  const system = (s: Side) => new Map([["system", `${s.agent?.os_id ?? ""} ${s.agent?.os_version ?? ""}`.trim()], ["running kernel", s.agent?.running_kernel ?? ""], ["agent version", s.agent?.scanner_version ?? ""]]);
  return (
    <>
      <PanelHeader icon="agents" kind="Compare" title={`${nameA} ↔ ${nameB}`} subtitle={<span className="subtle">Only what differs · <ObjectLink to={{ kind: "agent", id: a }}>{nameA}</ObjectLink> · <ObjectLink to={{ kind: "agent", id: b }}>{nameB}</ObjectLink></span>} />
      <div className="panel-body stack">
        {(left.loading || right.loading) && <p className="subtle">Loading…</p>}
        <Differences title="System" a={system(left)} b={system(right)} nameA={nameA} nameB={nameB} show={(_, v) => v || "—"} />
        <Differences title="Open ports" a={left.ports} b={right.ports} nameA={nameA} nameB={nameB} show={(_, v) => v ?? ""} />
        <Differences title="Services" a={left.services} b={right.services} nameA={nameA} nameB={nameB} show={(_, v) => v || "running"} />
        <Differences title="Software" a={left.software} b={right.software} nameA={nameA} nameB={nameB} show={(_, v) => v ?? ""} />
        {can("findings.read") && <Differences title="Findings" a={left.findings} b={right.findings} nameA={nameA} nameB={nameB} show={(_, v) => v ?? ""} />}
      </div>
    </>
  );
}
