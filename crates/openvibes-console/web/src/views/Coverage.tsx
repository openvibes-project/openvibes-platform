// MITRE ATT&CK coverage of the platform's rules (spec
// 2026-10-09-attack-coverage-design.md §4): a matrix of covered techniques
// per tactic (or per kill-chain phase), and the rules below it.
import { useMemo } from "react";

import { useResource } from "../api/client";
import type { AttackCoverage, CoverageRule } from "../api/types";
import type { Column } from "./coverage";
import { nav, useLocation } from "../app/nav";
import { Empty, ErrorBox, Loading, SeverityBadge } from "../ui/bits";
import { DataTable } from "../ui/DataTable";
import { severityOrder } from "../ui/format";
import { ViewHeader } from "../ui/ViewHeader";
import { columns, selectRules } from "./coverage";

function openRule(rule: CoverageRule) {
  nav.open(rule.draft
    ? { kind: "site-rule", id: `${rule.rule_set_id}/${rule.rule_id}` }
    : { kind: "rule-set", id: rule.rule_set_id }, true);
}

function pairs(rule: CoverageRule) {
  if (rule.attack.length === 0) return <span className="subtle">Not mapped</span>;
  return (
    <span className="attack-chips">
      {rule.attack.map((p) => (
        <span key={`${p.tactic}/${p.technique ?? ""}`} className={`attack-chip${p.known ? "" : " attack-chip--unknown"}`}
          title={p.known ? p.technique_name ?? p.tactic : "Not in the bundled ATT&CK release"}>
          {p.technique ?? p.tactic}
        </span>
      ))}
    </span>
  );
}

type Toggle = (name: string, value: string) => void;

const cls = (...parts: (string | false)[]) => parts.filter(Boolean).join(" ");

function MatrixColumn({ col, tactic, technique, byPhase, toggle }: Readonly<{ col: Column; tactic: string | null; technique: string | null; byPhase: boolean; toggle: Toggle }>) {
  const empty = col.rules === 0 ? "No rules" : "Tactic only";
  return (
    <div className={cls("coverage-col", col.rules === 0 && "coverage-col--gap")}>
      <button type="button" className={cls("coverage-col__head", tactic === col.key && "is-on")}
        disabled={byPhase} onClick={() => toggle("tactic", col.key)}>
        <span>{col.title}</span><span className="num subtle">{col.rules}</span>
      </button>
      {col.cells.map((cell) => (
        <button key={cell.technique} type="button"
          className={cls("coverage-cell", cell.sub && "coverage-cell--sub", technique === cell.technique && "is-on")}
          title={`${cell.technique} ${cell.name}`} onClick={() => toggle("technique", cell.technique)}>
          <span className="mono">{cell.technique}</span>
          <span className="coverage-cell__name">{cell.name}</span>
          <span className="num">{cell.rules}</span>
        </button>
      ))}
      {col.cells.length === 0 && <span className="coverage-col__none subtle">{empty}</span>}
    </div>
  );
}

function Matrix({ data, cols, unmapped, byPhase, params, toggle }: Readonly<{ data: AttackCoverage; cols: Column[]; unmapped: number; byPhase: boolean; params: URLSearchParams; toggle: Toggle }>) {
  const legend = byPhase ? "Coverage by kill-chain phase" : "Coverage by ATT&CK tactic";
  const rulesAre = unmapped === 1 ? "rule is" : "rules are";
  return (
    <section className="view-pad">
      <fieldset className="coverage-matrix">
        <legend className="sr-only">{legend}</legend>
        {cols.map((col) => (
          <MatrixColumn key={col.key} col={col} tactic={params.get("tactic")} technique={params.get("technique")} byPhase={byPhase} toggle={toggle} />
        ))}
      </fieldset>
      <p className="subtle coverage-foot">
        {unmapped > 0 && <><button type="button" className="link-button" onClick={() => toggle("unmapped", "true")}>{unmapped} {rulesAre} not mapped</button> · </>}
        {data.unverified_sets.length > 0 && <>Not verified, left out: {data.unverified_sets.join(", ")} · </>}
        ATT&CK {data.attack_version}. {data.notice}
      </p>
    </section>
  );
}

function RuleTable({ rows }: Readonly<{ rows: CoverageRule[] }>) {
  if (rows.length === 0) return <Empty icon="rules" title="Nothing matches these filters">Clear a filter to see more.</Empty>;
  return (
    <DataTable label="Rules" rows={rows} rowKey={(r) => `${r.rule_set_id}/${r.rule_id}`} onOpen={openRule}
      defaultSort={{ key: "set", direction: "asc" }}
      columns={[
        { key: "rule", header: "Rule", sort: (r) => r.title, render: (r) => <div className="cell-two"><span>{r.title}{r.draft && <span className="badge badge--plain"> Draft</span>}</span><span className="mono subtle">{r.rule_id}</span></div> },
        { key: "set", header: "Rule set", width: "140px", hideBelow: 900, sort: (r) => r.rule_set_id, render: (r) => <span className="mono">{r.rule_set_id}</span> },
        { key: "kind", header: "Kind", width: "90px", hideBelow: 700, sort: (r) => r.kind, render: (r) => r.kind === "process_event" ? "Alarm" : "Finding" },
        { key: "severity", header: "Severity", width: "110px", hideBelow: 560, sort: (r) => severityOrder[r.severity] ?? 9, render: (r) => <SeverityBadge severity={r.severity} /> },
        { key: "attack", header: "ATT&CK", render: pairs },
      ]} />
  );
}

/** The matrix shows everything the other filters allow; the technique,
 * tactic and unmapped filters only narrow the list below it. */
function matrixParams(params: URLSearchParams) {
  const p = new URLSearchParams(params);
  for (const key of ["technique", "tactic", "unmapped"]) p.delete(key);
  return p;
}

export function Coverage() {
  const { params } = useLocation();
  const coverage = useResource<AttackCoverage>("/api/v1/rules/coverage");
  const data = coverage.data;
  const byPhase = params.get("view") === "killchain";
  const base = useMemo(() => selectRules(data?.rules ?? [], matrixParams(params)), [data, params]);
  const rows = useMemo(() => selectRules(data?.rules ?? [], params), [data, params]);
  const cols = useMemo(() => columns(data?.tactics ?? [], base, byPhase), [data, base, byPhase]);
  const unmapped = base.filter((r) => r.attack.length === 0).length;
  const toggle: Toggle = (name, value) =>
    nav.setParams({ technique: null, tactic: null, unmapped: null, [name]: params.get(name) === value ? null : value });

  let content;
  if (coverage.error) content = <div className="view-pad"><ErrorBox error={coverage.error} /></div>;
  else if (!data) content = <Loading />;
  else if (data.rules.length === 0) content = <Empty icon="rules" title="No rules yet">Publish a rule set or write site rules; their MITRE ATT&CK mappings show here.</Empty>;
  else content = <>
    <Matrix data={data} cols={cols} unmapped={unmapped} byPhase={byPhase} params={params} toggle={toggle} />
    <RuleTable rows={rows} />
  </>;

  return (
    <div className="view">
      <ViewHeader title="Coverage" count={rows.length} total={data?.rules.length} refresh="/api/v1/rules/coverage" placeholder="Filter by rule, technique or name…"
        chips={[
          { label: "Kill chain", param: "view", value: "killchain" },
          { label: "Findings", param: "kind", value: "snapshot" },
          { label: "Alarms", param: "kind", value: "process_event" },
          { label: "Include drafts", param: "drafts", value: "true" },
        ]} />
      {content}
    </div>
  );
}
