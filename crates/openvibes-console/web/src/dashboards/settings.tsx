// Widget editors, drawn with the console's own controls (Select, Segmented,
// Switch). A stored value outside a control's options shows as a selected
// extra and is kept on save: editors read the raw config value, not the
// tile's clamped one.
import { type ReactElement, cloneElement, useEffect, useMemo, useRef, useState } from "react";

import { useAllPages } from "../api/client";
import type { FindingGroup } from "../api/types";
import { useSession } from "../app/session";
import { SelectField } from "../ui/Field";
import { Icon } from "../ui/Icon";
import { Segmented } from "../ui/Segmented";
import { Select, type SelectGroup } from "../ui/Select";
import { Switch } from "../ui/Switch";
import { LIST_FILTERS, LIST_LABELS, chipsOf, dropUnsupported, queryOf, setFilter } from "../views/filters";
import { LIST_VIEWS, type ListView } from "../views/rows";
import { ATTENTION_KINDS } from "./attention";
import { noteLines } from "./config";
import { GRAPH_MAX_LINES, METRIC_GROUPS, TREND_DAYS } from "./metrics";
import { BREAKDOWN_SOURCES } from "./tiles";
import { GRAPH_DAYS } from "./tiles2";
import type { SettingsProps } from "./widgets";

// The label text names the control exactly (a wrapping label alone would
// also read out a select's option texts).
const field = (label: string, control: ReactElement<{ "aria-label"?: string }>) =>
  <label className="field">{label}{cloneElement(control, { "aria-label": label })}</label>;
const selectField = (label: string, control: ReactElement) => <SelectField label={label}>{control}</SelectField>;
const group = (label: string, control: ReactElement, hint?: string) =>
  <div className="field"><span className="field__label">{label}{hint && <em className="subtle">{hint}</em>}</span>{control}</div>;

const rawStr = (c: Record<string, unknown>, key: string, fallback: string) => (typeof c[key] === "string" ? (c[key] as string) : fallback);
const rawInt = (c: Record<string, unknown>, key: string, fallback: number) => (typeof c[key] === "number" && Number.isInteger(c[key]) ? (c[key] as number) : fallback);
const nums = (values: number[], label = String) => values.map((value) => ({ value, label: label(value) }));
const days = (d: number) => `${d} d`;
const lineOptions = [{ value: "smooth", label: "Smooth" }, { value: "stepped", label: "Stepped" }];

export function GraphSettings({ widget, onChange }: SettingsProps) {
  const raw: unknown = widget.config.metrics;
  const metrics = Array.isArray(raw) && raw.length ? raw.filter((m): m is string => typeof m === "string").slice(0, GRAPH_MAX_LINES) : ["alarms.active"];
  // Removing a count or adding the last one unmounts the focused button: focus moves on to "Add a count" or the first Select.
  const [tick, setTick] = useState(0);
  const refocus = useRef(false);
  const box = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!refocus.current) return;
    refocus.current = false;
    (box.current?.querySelector<HTMLElement>(".link-add") ?? box.current?.querySelector<HTMLElement>(".sel__button"))?.focus();
  }, [tick]);
  const set = (next: string[], move = false) => { onChange({ ...widget.config, metrics: next }); if (move) { refocus.current = true; setTick((t) => t + 1); } };
  const options = (own: string): SelectGroup[] => METRIC_GROUPS.map((g) => ({ group: g.group, options: g.options.map((o) => ({ ...o, disabled: o.value !== own && metrics.includes(o.value) })) }));
  return (
    <div className="stack">
      {group("Counts", <div ref={box} className="stack stack--tight">
        {metrics.map((m, i) => (
          <div key={i} className="editor-count">
            <span className="editor-count__dot" style={{ background: `var(--series-${i + 1})` }} aria-hidden="true" />
            <Select label={`Count ${i + 1}`} value={m} options={options(m)} onChange={(v) => set(metrics.map((x, j) => (j === i ? v : x)))} />
            {metrics.length > 1 && <button type="button" className="icon-button editor-count__remove" aria-label={`Remove count ${i + 1}`} onClick={() => set(metrics.filter((_, j) => j !== i), true)}><Icon name="close" size={14} /></button>}
          </div>
        ))}
        {metrics.length < GRAPH_MAX_LINES && (
          <button type="button" className="link-add" onClick={() => set([...metrics, METRIC_GROUPS.flatMap((g) => g.options).find((o) => !metrics.includes(o.value) && !o.value.startsWith("all."))?.value ?? "alarms.active"], true)}><Icon name="plus" size={14} /> Add a count</button>
        )}
      </div>, `up to ${GRAPH_MAX_LINES}`)}
      {group("Period", <Segmented label="Period" value={rawInt(widget.config, "days", 30)} options={[...GRAPH_DAYS].map((d) => ({ value: d as number, label: d === 365 ? "1 y" : days(d) }))} unknownLabel={days} onChange={(d) => onChange({ ...widget.config, days: d })} />)}
      {group("Line", <Segmented label="Line" value={rawStr(widget.config, "line", "smooth")} options={lineOptions} onChange={(line) => onChange({ ...widget.config, line })} />)}
    </div>
  );
}

export function NumberSettings({ widget, onChange }: SettingsProps) {
  const trend = rawInt(widget.config, "trend", 0);
  return (
    <div className="stack">
      {selectField("Count", <Select label="Count" value={rawStr(widget.config, "metric", "agents.active")} options={METRIC_GROUPS} onChange={(metric) => onChange({ ...widget.config, metric })} />)}
      {group("Trend", <Segmented label="Trend" value={trend} options={TREND_DAYS.map((d) => ({ value: d as number, label: d === 0 ? "Off" : days(d) }))} unknownLabel={days} onChange={(t) => onChange({ ...widget.config, trend: t })} />)}
      {(TREND_DAYS as readonly number[]).includes(trend) && trend > 0 && group("Line", <Segmented label="Line" value={rawStr(widget.config, "line", "smooth")} options={lineOptions} onChange={(line) => onChange({ ...widget.config, line })} />)}
    </div>
  );
}

const SOURCE_LABELS: Record<(typeof BREAKDOWN_SOURCES)[number], string> = { alarms: "Alarms", vulnerabilities: "Vulnerabilities", compliance: "Compliance", agents: "Hosts" };
export function BreakdownSettings({ widget, onChange }: SettingsProps) {
  return group("Break down", <Segmented label="Break down" value={rawStr(widget.config, "source", "compliance")} onChange={(source) => onChange({ ...widget.config, source })}
    options={BREAKDOWN_SOURCES.map((value) => ({ value: value as string, label: SOURCE_LABELS[value] }))} />);
}

const ATTENTION_LABELS = { alarms: "Active threat alarms (medium and above)", exploited: "Exploited vulnerabilities", serious: "Open critical and high vulnerabilities", compliance: "Open critical and high compliance findings", stale: "Hosts that stopped reporting" };
/** The stored include list after switching one kind; unknown entries stay, and no known kind stored means all are on. */
export function toggledKinds(include: string[], kind: string): string[] {
  const base = include.some((v) => (ATTENTION_KINDS as readonly string[]).includes(v)) ? include : [...include, ...ATTENTION_KINDS];
  return base.includes(kind) ? base.filter((v) => v !== kind) : [...base, kind];
}
export function AttentionSettings({ widget, onChange }: SettingsProps) {
  const stored: unknown = widget.config.include;
  const include = Array.isArray(stored) ? stored.filter((v): v is string => typeof v === "string") : [];
  // An empty (or all-unknown) list means every kind; unknown stored entries are kept on save.
  const known = include.filter((v) => (ATTENTION_KINDS as readonly string[]).includes(v));
  const on = known.length ? known : [...ATTENTION_KINDS];
  const toggle = (kind: string) => onChange({ ...widget.config, include: toggledKinds(include, kind) });
  return (
    <div className="stack">
      <div className="stack stack--tight">
        {ATTENTION_KINDS.map((kind) => <Switch key={kind} label={ATTENTION_LABELS[kind]} checked={on.includes(kind)} disabled={on.length === 1 && on.includes(kind)} onChange={() => toggle(kind)} />)}
      </div>
      {group("Show at most", <Segmented label="Show at most" value={rawInt(widget.config, "limit", 8)} options={nums([5, 8, 10, 15])} onChange={(limit) => onChange({ ...widget.config, limit })} />)}
    </div>
  );
}

export function ListSettings({ widget, onChange }: SettingsProps) {
  const [adding, setAdding] = useState<string>();
  // Focus goes to the new value Select or back to "Add filter", never to the body when a control unmounts.
  const want = useRef<"value" | "add">(undefined);
  const [tick, setTick] = useState(0);
  const setWant = (w: "value" | "add") => { want.current = w; setTick((t) => t + 1); };
  const box = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!want.current) return;
    const el = box.current?.querySelector<HTMLElement>(want.current === "value" ? '[aria-label$=" value"]' : '[aria-label="Add filter"]') ?? box.current;
    el?.focus();
    want.current = undefined;
  }, [tick]);
  const view = rawStr(widget.config, "view", "/compliance");
  const valid = (LIST_VIEWS as readonly string[]).includes(view);
  const query = rawStr(widget.config, "query", "");
  const setQuery = (q: string) => onChange({ ...widget.config, query: q });
  // An unrecognised list cannot label its filters: show them plain.
  const chips = valid ? chipsOf(view as ListView, query) : [...new URLSearchParams(query)].map(([param, value]) => ({ param, value, label: `${param}=${value}`, known: false }));
  const defs = valid ? LIST_FILTERS[view as ListView] : [];
  // A used choice filter stays offered: picking a value replaces the old one.
  const unused = defs.filter((d) => d.kind === "choice" || !chips.some((c) => c.known && c.param === d.param));
  const pending = unused.find((d) => d.param === adding);
  return (
    <div className="stack">
      {selectField("List", <Select label="List" value={view} options={LIST_VIEWS.map((v) => ({ value: v as string, label: LIST_LABELS[v] }))}
        onChange={(v) => { setAdding(undefined); onChange({ ...widget.config, view: v, query: dropUnsupported(v as ListView, query) }); }} />)}
      {group("Filters", <div ref={box} tabIndex={-1} className="stack stack--tight">
        {chips.length > 0 && (
          <ul className="fchips">
            {chips.map((c, i) => (
              <li key={`${c.param}=${c.value}#${i}`} className="fchip">
                <span>{c.label}</span>
                <button type="button" aria-label={`Remove filter ${c.label}`} onClick={() => { setQuery(queryOf(chips.filter((x) => x !== c))); setWant("add"); }}><Icon name="close" size={12} /></button>
              </li>
            ))}
          </ul>
        )}
        {pending && pending.kind === "choice" ? (
          <div className="editor-count editor-count--filter">
            <Select label={`${pending.label} value`} value="" placeholder={`${pending.label}…`} options={pending.values}
              onChange={(v) => { setAdding(undefined); setQuery(setFilter(view as ListView, query, pending.param, v)); setWant("add"); }} />
            <button type="button" className="icon-button editor-count__remove" aria-label="Cancel adding filter" onClick={() => { setAdding(undefined); setWant("add"); }}><Icon name="close" size={14} /></button>
          </div>
        ) : unused.length > 0 && (
          <div className="link-add link-add--menu">
            <Select label="Add filter" value="" small placeholder="＋ Add filter" options={unused.map((d) => ({ value: d.param, label: d.label }))}
              onChange={(param) => { const d = unused.find((x) => x.param === param); if (d?.kind === "flag") { setQuery(setFilter(view as ListView, query, d.param, d.value)); setWant("add"); } else { setAdding(param); setWant("value"); } }} />
          </div>
        )}
        {chips.length === 0 && !pending && <span className="subtle">No filters: every row.</span>}
      </div>)}
      {group("Rows", <Segmented label="Rows" value={rawInt(widget.config, "limit", 8)} options={nums([5, 8, 10, 15])} onChange={(limit) => onChange({ ...widget.config, limit })} />)}
    </div>
  );
}

/** The compliance rules as Select groups: one group per rule set, rows titled by their latest message. */
export function ruleGroups(groups: { rule_set_id: string; rule_id: string; latest_message?: string | null }[]): SelectGroup[] {
  const bySet = new Map<string, Map<string, string>>();
  for (const g of groups) {
    const rules = bySet.get(g.rule_set_id) ?? new Map<string, string>();
    rules.set(`${g.rule_set_id}/${g.rule_id}`, g.latest_message ? `${g.latest_message} · ${g.rule_id}` : g.rule_id);
    bySet.set(g.rule_set_id, rules);
  }
  return [...bySet].sort(([a], [b]) => a.localeCompare(b)).map(([set, rules]) => ({
    group: set, options: [...rules].map(([value, label]) => ({ value, label })).sort((a, b) => a.label.localeCompare(b.label)),
  }));
}
export const ruleUnknownLabel = (v: string, failed: boolean, loaded: boolean) => (failed ? `${v} (could not load)` : loaded ? `${v} (not found)` : v);

export function TrendSettings({ widget, onChange }: SettingsProps) {
  const { can } = useSession();
  const groups = useAllPages<FindingGroup>(can("compliance.read") ? "/api/v1/compliance/groups" : null);
  const finding = rawStr(widget.config, "finding", "");
  const options = useMemo(() => ruleGroups(groups.data ?? []), [groups.data]);
  const unknownLabel = (v: string) => ruleUnknownLabel(v, !!groups.error, !!groups.data);
  return (
    <div className="stack">
      {selectField("Compliance rule", <Select label="Compliance rule" value={finding} options={options} placeholder="Choose a rule" unknownLabel={unknownLabel}
        onChange={(v) => onChange({ ...widget.config, finding: v })} />)}
      {group("Days", <Segmented label="Days" value={rawInt(widget.config, "days", 14)} options={nums([7, 14, 30])} onChange={(d) => onChange({ ...widget.config, days: d })} />)}
    </div>
  );
}

export function TopHostsSettings({ widget, onChange }: SettingsProps) {
  return (
    <div className="stack">
      {group("Count", <Segmented label="Count" value={rawStr(widget.config, "kinds", "all")} onChange={(kinds) => onChange({ ...widget.config, kinds })}
        options={[{ value: "all", label: "All kinds" }, { value: "vulnerabilities", label: "Vulnerabilities only" }]} />)}
      {group("Hosts", <Segmented label="Hosts" value={rawInt(widget.config, "limit", 6)} options={nums([3, 6, 10])} onChange={(limit) => onChange({ ...widget.config, limit })} />)}
    </div>
  );
}

export function NoteSettings({ widget, onChange }: SettingsProps) {
  const text = Array.isArray(widget.config.text) ? (widget.config.text as string[]).join("\n") : "";
  return field("Text (plain; https:// links become clickable)", <textarea className="textarea" rows={6} maxLength={16 * 257} value={text}
    onChange={(e) => onChange({ ...widget.config, text: noteLines(e.target.value) })} />);
}
