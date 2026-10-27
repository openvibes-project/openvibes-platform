// The cards of a check's page (approved screen 28): Why it matters, How to
// fix, Details and History on the left; Hosts (segments, the paged table with
// each failing host's evidence, ticks for bulk triage of host and check pairs,
// Reopen included) and Related on the right. Every card reads the summary but
// Hosts, which pages its own route.
import { Fragment, useState } from "react";

import { useResource } from "../../../api/client";
import type { CheckHostsPage, CheckSummaryPage, Finding } from "../../../api/types";
import { nav, useLocation, viewLink } from "../../../app/nav";
import { DetectionEvidence } from "../../../panels/alarms/DetectionEvidence";
import { AddToCase } from "../../../panels/cases/AddToCase";
import { CaseBadge, useHostCaseBadges } from "../../../panels/cases/CaseBadge";
import { findingRef, storedRuleSet } from "../../../panels/cases/cases";
import { BulkBar } from "../../../panels/triage/BulkBar";
import { Ago, Empty, ErrorBox, Loading, ObjectLink, SeverityBadge, TriageBadge } from "../../../ui/bits";
import { Card } from "../../../ui/detail/DetailPage";
import { RelatedCard } from "../../../ui/detail/RelatedCard";
import { SegmentChips } from "../../../ui/detail/SegmentChips";
import { date, isPast, plural, triageLabel } from "../../../ui/format";
import { PAGE } from "../../../ui/list/filters";
import { useSelection } from "../../../ui/selection";
import { Pager } from "../Hosts";

type Page = CheckSummaryPage;
type HostRow = CheckHostsPage["rows"][number];
type Evidence = HostRow["evidence"][number];

/** Why it matters: the rule's `explain`, else its message (user decision 4). */
export function WhyCard({ page }: { page: Page }) {
  return <Card title="Why it matters"><p>{page.text.explain ?? page.text.message}</p></Card>;
}

/** Findings from before rule sets: the API's `~unknown`, a rule set no page shows. */
const LEGACY = "~unknown";

/** How to fix: the rule's `check` (the exact setting and command); without one, the rule to read (when it has a rule set). */
export function FixCard({ page }: { page: Page }) {
  const fix = page.text.check;
  const set = page.header.rule_set_id;
  return (
    <Card title="How to fix">
      {fix ? <p style={{ whiteSpace: "pre-wrap" }}>{fix}</p>
        : <p className="subtle">No fix text yet.{set !== LEGACY && <> See the rule in <ObjectLink to={{ kind: "rule-set", id: set }}>{set}</ObjectLink>.</>}</p>}
    </Card>
  );
}

export function DetailsCard({ page }: { page: Page }) {
  const { header, details } = page;
  return (
    <Card title="Details">
      <dl className="kv">
        <dt>Rule</dt><dd><span className="mono">{header.rule_id}</span>{header.rule_version != null && ` · version ${header.rule_version}`}</dd>
        <dt>Rule set</dt><dd>{header.rule_set_id === LEGACY ? <span className="subtle">No rule set (from before rule sets)</span>
          : <><ObjectLink to={{ kind: "rule-set", id: header.rule_set_id }}>{header.rule_set_id}</ObjectLink>{header.rule_set_version != null && ` v${header.rule_set_version}`}</>}</dd>
        <dt>Applies to</dt><dd>{details.applies_to}</dd>
        <dt>Reference</dt><dd>{details.techniques.length > 0 ? <span className="mono">{details.techniques.join(", ")}</span> : <span className="subtle">None</span>}</dd>
      </dl>
    </Card>
  );
}

const host = (e: Page["history"][number]) => e.agent_id ? <ObjectLink to={{ kind: "agent", id: e.agent_id }}>{e.hostname ?? e.agent_id}</ObjectLink> : <>{e.hostname ?? "A host"}</>;

/** One History event (ruling 14): a triage change, a host starting to fail or passing again, a rule-set version published. */
function eventLine(e: Page["history"][number], set: string) {
  switch (e.kind) {
    case "triage": return <>{e.actor ?? "Someone"} set {host(e)} to {e.to_state ? <TriageBadge state={e.to_state} /> : "a new state"}{e.note && <> “{e.note}”</>}</>;
    case "failing": return <>{host(e)} started failing</>;
    case "passes_again": return <>{host(e)} passes again</>;
    default: return <>Rule set {set}{e.version != null && ` v${e.version}`} published{e.actor && ` by ${e.actor}`}</>;
  }
}

export function HistoryCard({ page }: { page: Page }) {
  return (
    <Card title="History">
      {page.history.length === 0 ? <Empty title="Nothing has changed yet" /> : (
        <ul className="list list--plain" aria-label="History, newest first">
          {page.history.map((e, i) => (
            <li key={`${e.at}:${e.kind}:${e.agent_id ?? ""}:${i}`} className="list__row list__row--static stack">
              <span>{eventLine(e, page.header.rule_set_id)}</span>
              <span className="subtle"><Ago value={e.at} /></span>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}

const SEGMENTS = ["all", "failing", "passing"] as const;
type Segment = (typeof SEGMENTS)[number];
const SEGMENT_LABEL: Record<Segment, string> = { all: "All", failing: "Failing", passing: "Passing" };
/** The URL's `segment`; anything unknown is All. */
export const segmentOf = (value: string | null): Segment => SEGMENTS.find((s) => s === value) ?? "all";
/** A failing pair's triage state, narrowing the Failing segment (the old panel's state chips). */
const STATES = ["open", "mitigated", "accepted_risk", "false_positive"] as const;
type State = (typeof STATES)[number];
/** The URL's `state`; anything unknown is every failing host. */
export const stateOf = (value: string | null): State | null => STATES.find((s) => s === value) ?? null;
/** The state chips: All failing, then each state with its count. */
export const stateOptions = (counts: CheckHostsPage["states"], failing: number) =>
  [{ key: "", label: "All failing", count: failing }, ...STATES.map((s) => ({ key: s, label: triageLabel[s] ?? s, count: counts[s] }))];
const PAGE_SIZE = 50;
const CLOSED = new Set(["mitigated", "accepted_risk", "false_positive"]);

/** What the Hosts table's bulk bar sends (ruling 10): each ticked host and check pair, whatever its state (Reopen included). */
export const hostItems = (rows: readonly HostRow[], set: string, rule: string) => rows.map((r) => ({ agent_id: r.agent_id, rule_set_id: set, rule_id: rule }));

/** One input as user decision 3 shows it: `fact = value` and the file; a masked, summarized or truncated value only as its status. */
export const evidenceText = (e: Evidence) => `${e.fact}${e.value != null ? ` = ${e.value}` : e.status ? ` (${e.status})` : ""}${e.file ? ` (${e.file})` : ""}`;

export function HostsCard({ page }: { page: Page }) {
  const { params } = useLocation();
  const { rule_set_id: set, rule_id: rule } = page.header;
  const segment = segmentOf(params.get("segment"));
  const state = segment === "failing" ? stateOf(params.get("state")) : null;
  const offset = Math.max(0, Number(params.get(PAGE)) || 0);
  const hosts = useResource<CheckHostsPage>(`/api/v1/compliance/checks/${encodeURIComponent(set)}/${encodeURIComponent(rule)}/hosts?segment=${segment}${state ? `&state=${state}` : ""}&offset=${offset}&limit=${PAGE_SIZE}`);
  const [selected, setSelected] = useSelection(`${segment}:${state ?? ""}:${offset}`);
  const cases = useHostCaseBadges("compliance_finding", `${storedRuleSet(set)}/${rule}`);
  const data = hosts.data;
  const rows = data?.rows ?? [];
  const chosen = rows.filter((r) => selected.has(r.agent_id) && r.state !== "passing");
  const closed = chosen.filter((r) => CLOSED.has(r.state));
  const counts = data?.segments;
  return (
    <Card id="hosts" flush title={<>Hosts <span className="subtle num">{(counts?.all ?? page.header.checked).toLocaleString()}</span></>}
      aside={<SegmentChips label="Hosts by state" value={segment} onChange={(s) => nav.setParams({ segment: s === "all" ? null : s, state: null, [PAGE]: null })}
        options={SEGMENTS.map((s) => ({ key: s, label: SEGMENT_LABEL[s], count: counts?.[s] ?? 0 }))} />}>
      {segment === "failing" && data && <div className="person-card__body">
        <SegmentChips label="Failing hosts by triage state" value={state ?? ""} onChange={(s) => nav.setParams({ state: s || null, [PAGE]: null })}
          options={stateOptions(data.states, data.segments.failing)} /></div>}
      {hosts.error ? <div className="person-card__body"><ErrorBox error={hosts.error} /></div> : !data ? <Loading rows={3} /> : rows.length === 0
        ? <Empty title={`No ${segment === "all" ? "" : `${SEGMENT_LABEL[segment].toLowerCase()} `}hosts`} />
        : <HostsTable rows={rows} selected={selected} onSelect={setSelected} triage={page.can.triage} addToCase={page.can.add_to_case} title={page.header.title}
            set={set} rule={rule} cases={cases} />}
      {data && <Pager offset={offset} shown={rows.length} total={data.total} />}
      <BulkBar kind="compliance" noun={chosen.length === 1 ? "host" : "hosts"} count={chosen.length} onClear={() => setSelected(new Set())}
        items={() => hostItems(chosen, set, rule)} closed={closed.length} reopenItems={() => hostItems(closed, set, rule)}
        without={page.can.add_to_case ? [] : ["case"]}
        newCase={() => ({ title: `${page.header.title} on ${plural(chosen.length, "host")}`, severity: page.header.severity ?? undefined })} />
    </Card>
  );
}

/** The state, an acceptance's end (kept after it expires, as the old panel showed) and the open cases. */
function StateCell({ r, cases }: { r: HostRow; cases: number[] | undefined }) {
  const until = r.accepted_until;
  return (
    <span className="row">
      {r.state === "passing" ? <span className="badge badge--ok">Passing</span> : <TriageBadge state={r.state} />}
      {r.origin === "import" && <span className="badge badge--info badge--plain" title="From an agent export file">imported</span>}
      {until && (r.state === "accepted_risk" && !isPast(until) ? <span className="subtle">until {date(until)}</span>
        : r.state !== "passing" && isPast(until) && <span className="badge badge--bad badge--plain">acceptance expired {date(until)}</span>)}
      <CaseBadge numbers={cases} />
    </span>
  );
}

/** One page of hosts. Failing rows (never passing ones: nothing to triage) have a tick with `triage`, or their own Add to case
 * with only `addToCase` (the bulk route asks for `compliance.triage` even to add to a case), and View evidence: the observation
 * and why it triggered, as the old panel's Evidence tab. `cases`: the open cases holding each host's pair, by agent id. */
export function HostsTable({ rows, selected, onSelect, triage, addToCase = false, title = "", set, rule, cases }: {
  rows: readonly HostRow[]; selected: ReadonlySet<string>; onSelect: (next: Set<string>) => void; triage: boolean; addToCase?: boolean; title?: string;
  set: string; rule: string; cases?: ReadonlyMap<string, number[]>;
}) {
  const [shown, setShown] = useState<ReadonlySet<string>>(new Set());
  const tickable = triage ? rows.filter((r) => r.state !== "passing") : [];
  const perRow = !triage && addToCase;
  const all = tickable.length > 0 && tickable.every((r) => selected.has(r.agent_id));
  const flip = (from: ReadonlySet<string>, key: string) => { const next = new Set(from); if (next.has(key)) next.delete(key); else next.add(key); return next; };
  const columns = 5 + (triage ? 1 : 0) + (perRow ? 1 : 0);
  return (
    <div className="table-wrap">
      <table className="table table--compact" aria-label="Hosts">
        <thead><tr>
          {triage && <th style={{ width: 36 }}><input type="checkbox" className="checkbox" aria-label="Select the failing hosts on screen" checked={all} disabled={tickable.length === 0}
            onChange={() => onSelect(all ? new Set() : new Set(tickable.map((r) => r.agent_id)))} /></th>}
          <th>Host</th><th>State</th><th>Evidence</th><th>Assignee</th><th className="hide-narrow">Checked</th>
          {perRow && <th style={{ width: 44 }}><span className="sr-only">Add to case</span></th>}
        </tr></thead>
        <tbody>
          {rows.map((r) => {
            const name = r.hostname ?? r.agent_id;
            const failing = r.state !== "passing";
            const open = shown.has(r.agent_id);
            return (
              <Fragment key={r.agent_id}>
                <tr aria-selected={selected.has(r.agent_id) || undefined}>
                  {triage && <td>{failing && <input type="checkbox" className="checkbox" aria-label={`Select ${name}`} checked={selected.has(r.agent_id)} onChange={() => onSelect(flip(selected, r.agent_id))} />}</td>}
                  <td><div className="cell-two"><ObjectLink to={{ kind: "agent", id: r.agent_id }} className="object-link mono">{name}</ObjectLink>
                    <span className="subtle">{[r.os, r.address].filter(Boolean).join(" · ")}</span></div></td>
                  <td><StateCell r={r} cases={cases?.get(r.agent_id)} /></td>
                  <td><div className="stack">
                    {r.evidence.map((e, i) => <span key={`${e.fact}:${i}`}><span className="mono">{e.fact}{e.value != null ? ` = ${e.value}` : <span className="subtle"> ({e.status ?? "no value"})</span>}</span>
                      {e.file && <span className="subtle"> in <span className="mono">{e.file}</span></span>}</span>)}
                    {failing && <button type="button" className="link-button" aria-label={`View evidence on ${name}`} aria-expanded={open} onClick={() => setShown(flip(shown, r.agent_id))}>View evidence</button>}
                  </div></td>
                  <td>{r.assignee?.name ?? <span className="subtle">—</span>}</td>
                  <td className="hide-narrow subtle"><Ago value={r.checked_at} /></td>
                  {perRow && <td>{failing && <AddToCase compact kind="compliance_finding" id={findingRef(r.agent_id, set, rule)} label={`${title} on ${name}`} />}</td>}
                </tr>
                {open && <tr><td colSpan={columns}><Observation agent={r.agent_id} set={set} rule={rule} /></td></tr>}
              </Fragment>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

/** A failing host's latest observation and why it triggered (the old panel's Evidence tab). */
function Observation({ agent, set, rule }: { agent: string; set: string; rule: string }) {
  const path = `/api/v1/compliance/latest/${encodeURIComponent(agent)}/${encodeURIComponent(set || "~unknown")}/${encodeURIComponent(rule)}`;
  const observation = useResource<Finding>(path);
  if (observation.error) return <ErrorBox error={observation.error} />;
  if (!observation.data) return <Loading rows={3} />;
  const o = observation.data;
  return (
    <div className="stack">
      <p>{o.message}</p>
      <p className="subtle">Rule version {o.rule_version} · {o.origin === "import" ? "Imported observation" : "Agent observation"} · seen <Ago value={o.last_observed_at} /></p>
      <DetectionEvidence key={o.id} detection={o.detection} references={o.evidence} ruleId={rule} ruleUrl={`${path}/rule/${encodeURIComponent(o.id)}`} />
    </div>
  );
}

/** Related (ruling 15): the exposed port, the service, and other failing checks in the same area. */
export function RelatedCheckCard({ page }: { page: Page }) {
  const { port, service, same_area: same } = page.related;
  const area = page.header.area;
  const sections = [
    ...(port ? [{ label: "Port", value: <><ObjectLink to={{ kind: "port", id: `${port.protocol}/${port.port}` }}>{port.port}/{port.protocol}</ObjectLink>, exposed on {plural(port.hosts, "host")}</> }] : []),
    ...(service ? [{ label: "Service", value: <><ObjectLink to={{ kind: "unit", id: service.unit }}>{service.unit}</ObjectLink>, on {plural(service.hosts, "host")}</> }] : []),
    { label: "Same area", value: same.checks === 0 ? <span className="subtle">No other failing checks in {area}</span>
      : <span className="row"><a className="object-link" {...viewLink("/compliance", { area })}>{plural(same.checks, "other failing check")} in {area}</a>
        {same.worst && <SeverityBadge severity={same.worst} />}</span> },
  ];
  return <RelatedCard sections={sections} />;
}
