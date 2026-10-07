// Compare two hosts (#120): only what differs, section by section (system,
// open ports, services, software, findings). The panel id is "A B" (agent
// ids never contain a space); with only "A", it asks for the second host.
import { useMemo, useState } from "react";

import { useAllPages, useResource } from "../api/client";
import type { Agent, Finding, HostPackage, HostServices } from "../api/types";
import { nav } from "../app/nav";
import { useSession } from "../app/session";
import { Empty, ErrorBox, Loading, ObjectLink, StatusBadge } from "../ui/bits";
import { PanelHeader, Section } from "../ui/panel";
import { Icon } from "../ui/Icon";
import { filterRows, type Kind, pickable, rows } from "./compare";


/** Lists longer than this are cut: a cut side can't be compared honestly. */
const MAX_SOFTWARE = 20_000;
const MAX_FINDINGS = 5_000;

type Side = { agent: Agent | undefined; reported: boolean; refused: boolean; ports: Map<string, string>; services: Map<string, string>; software: Map<string, string>; findings: Map<string, string>; cut: { software: boolean; findings: boolean }; loading: boolean; error: Error | undefined };

function useSide(id: string, withFindings: boolean): Side {
  const path = `/api/v1/agents/${encodeURIComponent(id)}`;
  const agent = useResource<Agent>(path);
  const report = useResource<HostServices>(`${path}/services`);
  const packages = useAllPages<HostPackage>(`${path}/packages`, MAX_SOFTWARE);
  const findingRows = useAllPages<Finding>(withFindings ? `/api/v1/compliance/latest?agent_id=${encodeURIComponent(id)}` : null, MAX_FINDINGS);
  const findings = findingRows.data;
  return useMemo(() => ({
    agent: agent.data,
    reported: Boolean(report.data?.reported_at),
    refused: Boolean(report.data?.refused_at),
    ports: new Map((report.data?.listeners ?? []).map((l) => [`${l.port}/${l.protocol}`, l.exposed ? "exposed" : "local"])),
    services: new Map((report.data?.services ?? []).map((s) => [s.unit, s.programs.join(" ")])),
    software: new Map((packages.data ?? []).map((p) => [`${p.name}.${p.arch}`, `${p.version}${p.release ? `-${p.release}` : ""}`])),
    findings: new Map((findings ?? []).map((f) => [`${f.rule_set_id}/${f.rule_id}`, f.message])),
    cut: { software: (packages.data?.length ?? 0) >= MAX_SOFTWARE, findings: (findings?.length ?? 0) >= MAX_FINDINGS },
    loading: agent.loading || report.loading || packages.loading || findingRows.loading,
    // Any failed request is an error, never an empty list ("the same on both").
    error: agent.error ?? report.error ?? packages.error ?? findingRows.error,
  }), [agent.data, agent.loading, agent.error, report.data, report.loading, report.error, packages.data, packages.loading, packages.error, findings, findingRows.loading, findingRows.error]);
}

const PAGE = 200;

function Differences({ title, a, b, nameA, nameB, show, cut = false, missing }: { title: string; a: Map<string, string>; b: Map<string, string>; nameA: string; nameB: string; show: (key: string, value?: string) => string; cut?: boolean; missing?: string | undefined }) {
  const [text, setText] = useState("");
  const [kind, setKind] = useState<Kind>();
  const [limit, setLimit] = useState(PAGE);
  const all = useMemo(() => rows(a, b), [a, b]);
  // A host that never reported this has nothing to compare: say so.
  if (missing) return <Section title={title}><p className="notice notice--warn">Can't compare: {missing}.</p></Section>;
  // A cut list would show false "only on one" rows: say so instead.
  if (cut) return <Section title={title}><p className="notice notice--warn">Comparison incomplete: one host has more than can be compared here. Use Export to compare the full lists.</p></Section>;
  if (all.length === 0) return <Section title={title}><p className="notice notice--ok"><Icon name="check" size={14} /> The same on both ({a.size.toLocaleString()})</p></Section>;
  const count = (k: Kind) => all.filter((r) => r.kind === k).length;
  const kinds = (["onlyA", "onlyB", "changed"] as const).filter((k) => count(k) > 0).length;
  const shown = filterRows(all, text, kind);
  const chip = (k: Kind, label: string) => (
    <button key={k} type="button" className="chip" aria-pressed={kind === k} onClick={() => { setKind(kind === k ? undefined : k); setLimit(PAGE); }}>
      {label} <span className="chip__count">{count(k).toLocaleString()}</span>
    </button>
  );
  return (
    <Section title={`${title} · ${all.length.toLocaleString()} different`}>
      <div className="compare-tools">
        {all.length > 8 && (
          <label className="search">
            <Icon name="search" size={14} />
            <input className="input" type="search" placeholder={`Filter ${title.toLowerCase()}`} aria-label={`Filter ${title.toLowerCase()}`} value={text} onChange={(e) => { setText(e.target.value); setLimit(PAGE); }} />
          </label>
        )}
        {kinds > 1 && <div className="row row--wrap">
          {count("onlyA") > 0 && chip("onlyA", "Only on A")}
          {count("onlyB") > 0 && chip("onlyB", "Only on B")}
          {count("changed") > 0 && chip("changed", "Changed")}
        </div>}
      </div>
      {shown.length === 0 ? <p className="subtle">Nothing matches.</p> : (
        <table className="table table--compact compare-table" aria-label={`${title} differences`}>
          <thead><tr><th>{title}</th><th title={nameA}>A · {nameA}</th><th title={nameB}>B · {nameB}</th></tr></thead>
          <tbody>
            {shown.slice(0, limit).map((r) => (
              <tr key={`${r.kind}${r.key}`} className={`compare-row compare-row--${r.kind}`}>
                <td><span className="mono">{r.key}</span> <span className={`badge badge--plain ${r.kind === "changed" ? "badge--warn" : "badge--info"}`}>{r.kind === "changed" ? "Changed" : `Only on ${r.kind === "onlyA" ? "A" : "B"}`}</span></td>
                <td className={r.kind === "onlyB" ? "subtle" : undefined}>{r.kind === "onlyB" ? "—" : show(r.key, a.get(r.key))}</td>
                <td className={r.kind === "onlyA" ? "subtle" : undefined}>{r.kind === "onlyA" ? "—" : show(r.key, b.get(r.key))}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {shown.length > limit && <button type="button" className="button button--small" onClick={() => setLimit(limit + PAGE)}>Show {Math.min(PAGE, shown.length - limit).toLocaleString()} more of {(shown.length - limit).toLocaleString()}</button>}
    </Section>
  );
}

function HostCard({ side, id, label }: { side: Side; id: string; label: string }) {
  const agent = side.agent;
  const os = `${agent?.os_id ?? ""} ${agent?.os_version ?? ""}`.trim();
  return (
    <div className="compare-host">
      <span className="compare-host__label">{label}</span>
      <ObjectLink to={{ kind: "agent", id }}>{agent?.hostname ?? id}</ObjectLink>
      <span className="subtle truncate">{os || "—"}{agent?.running_kernel ? ` · ${agent.running_kernel}` : ""}</span>
    </div>
  );
}

function PickSecond({ first }: { first: string }) {
  const hosts = useAllPages<Agent>("/api/v1/agents");
  const [text, setText] = useState("");
  const firstName = (hosts.data ?? []).find((a) => a.id === first)?.hostname ?? first;
  const hasOthers = pickable(hosts.data ?? [], first, "").length > 0;
  const others = pickable(hosts.data ?? [], first, text);
  return (
    <>
      <PanelHeader icon="agents" kind="Compare" title="Compare with…" subtitle={<span className="subtle">Pick the host to compare {firstName} with</span>} />
      <div className="panel-body stack">
        {hosts.error ? <ErrorBox error={hosts.error} /> : hosts.loading && !hosts.data ? <Loading rows={4} /> : !hasOthers ? <Empty title="No other host to compare with" /> : (
          <>
            <label className="search">
              <Icon name="search" size={14} />
              <input className="input" type="search" autoFocus placeholder="Filter by host name, ID or OS…" aria-label="Filter hosts" value={text} onChange={(e) => setText(e.target.value)} />
            </label>
            {others.length === 0 ? <p className="subtle">No host matches.</p> : (
              <ul className="pick-host" aria-label="Hosts to compare with">
                {others.map((a) => (
                  <li key={a.id}>
                    <button type="button" className="pick-host__row" onClick={() => nav.open({ kind: "compare", id: `${first} ${a.id}` })}>
                      <span className="cell-two grow">
                        <span className="truncate">{a.hostname ?? a.id}</span>
                        <span className="subtle truncate">{`${a.os_id ?? ""} ${a.os_version ?? ""}`.trim() || a.id}</span>
                      </span>
                      <StatusBadge status={a.status} />
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </>
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
  const left = useSide(a, can("compliance.read"));
  const right = useSide(b, can("compliance.read"));
  const nameA = left.agent?.hostname ?? a;
  const nameB = right.agent?.hostname ?? b;
  if (left.error || right.error) return <div className="panel-body"><ErrorBox error={(left.error ?? right.error) as never} /></div>;
  if ((left.loading && !left.agent) || (right.loading && !right.agent)) return <Loading />;
  const why = (s: Side, name: string) => s.refused ? `${name}'s last report was refused (see its Host page)` : `${name} hasn't reported its ports and services yet`;
  const notReported = !left.reported && !right.reported ? "neither host has reported its ports and services yet"
    : !left.reported ? why(left, nameA) : !right.reported ? why(right, nameB) : undefined;
  const system = (s: Side) => new Map([["system", `${s.agent?.os_id ?? ""} ${s.agent?.os_version ?? ""}`.trim()], ["running kernel", s.agent?.running_kernel ?? ""], ["agent version", s.agent?.scanner_version ?? ""]]);
  return (
    <>
      <PanelHeader icon="agents" kind="Compare" title={`${nameA} ↔ ${nameB}`} subtitle={<span className="subtle">Only what differs</span>} />
      <div className="panel-body stack">
        <div className="compare-hosts"><HostCard side={left} id={a} label="A" /><span className="compare-hosts__vs" aria-hidden="true">↔</span><HostCard side={right} id={b} label="B" /></div>
        {(left.loading || right.loading) && <p className="subtle">Loading…</p>}
        <Differences title="System" a={system(left)} b={system(right)} nameA={nameA} nameB={nameB} show={(_, v) => v || "—"} />
        <Differences title="Open ports" a={left.ports} b={right.ports} nameA={nameA} nameB={nameB} show={(_, v) => v ?? ""} missing={notReported} />
        <Differences title="Services" a={left.services} b={right.services} nameA={nameA} nameB={nameB} show={(_, v) => v || "running"} missing={notReported} />
        <Differences title="Software" a={left.software} b={right.software} nameA={nameA} nameB={nameB} show={(_, v) => v ?? ""} cut={left.cut.software || right.cut.software} />
        {can("compliance.read") && <Differences title="Compliance findings" a={left.findings} b={right.findings} nameA={nameA} nameB={nameB} show={(_, v) => v ?? ""} cut={left.cut.findings || right.cut.findings} />}
      </div>
    </>
  );
}
