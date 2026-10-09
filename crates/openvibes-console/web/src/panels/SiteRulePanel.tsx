// One site rule: a form with a live check against the agent's own rule
// loader, saved as a draft. Publishing the set comes later.
import { useEffect, useState } from "react";

import { ApiError, invalidate, request, useResource } from "../api/client";
import type { Agent, AttackCatalog, AttackPairInput, RuleCheck, RuleDraft, RuleDraftInput, RuleTestResult } from "../api/types";
import { nav } from "../app/nav";
import { useSession } from "../app/session";
import { Empty, ErrorBox, Loading } from "../ui/bits";
import { Icon } from "../ui/Icon";
import { Confirm, PanelHeader, Section } from "../ui/panel";
import { Select } from "../ui/Select";
import { SelectField } from "../ui/Field";
import { toast } from "../ui/toast";

const SEVERITIES = ["info", "low", "medium", "high", "critical"] as const;
const FACTS = "process.names, process.count, package.names, package.count, port.tcp.exposed, port.tcp.local, port.udp.exposed, port.udp.local";
const EVENT_KEYS = "process.exe, process.name, process.cmdline, process.cwd, process.uid, process.euid, parent.exe, parent.name, parent.cmdline, ancestors.names, ancestors.exes";

type Form = { title: string; severity: string; confidence: string; expression: string; finding_message: string; programs: string; attack: AttackPairInput[] };
const BLANK: Form = { title: "", severity: "medium", confidence: "80", expression: "", finding_message: "", programs: "", attack: [] };

const toInput = (form: Form, alarm: boolean): RuleDraftInput => ({
  title: form.title,
  severity: form.severity,
  confidence: Math.max(0, Math.min(255, Math.round(Number(form.confidence) || 0))),
  expression: form.expression,
  finding_message: form.finding_message,
  programs: alarm ? form.programs.split(/[\s,]+/).filter(Boolean) : null,
  attack: form.attack.length > 0 ? form.attack : null,
});

const fromDraft = (draft: RuleDraft): Form => ({
  title: draft.title,
  severity: draft.severity,
  confidence: String(draft.confidence),
  expression: draft.expression,
  finding_message: draft.finding_message,
  programs: (draft.programs ?? []).join(" "),
  attack: draft.attack.map((p) => ({ tactic: p.tactic, technique: p.technique ?? null })),
});

const pairKey = (p: AttackPairInput) => `${p.tactic}|${p.technique ?? ""}`;

// The rule's MITRE ATT&CK pairs (P18): chips to remove, a picker to add.
// A technique under several tactics is offered once per tactic.
function AttackField({ value, onChange, disabled }: Readonly<{ value: AttackPairInput[]; onChange: (next: AttackPairInput[]) => void; disabled: boolean }>) {
  const catalog = useResource<AttackCatalog>("/api/v1/attack");
  const data = catalog.data;
  const tactic = (id: string) => data?.tactics.find((t) => t.id === id)?.name ?? id;
  // One group per tactic, in matrix order: the tactic itself, then its techniques.
  const taken = new Set(value.map(pairKey));
  const groups = !data ? [] : data.tactics.map((t) => ({
    group: `${t.name} (${t.id})`,
    options: [
      { value: `${t.id}|`, label: `${t.name}, tactic only` },
      ...data.techniques.filter((te) => te.tactics.includes(t.id)).map((te) => ({ value: `${t.id}|${te.id}`, label: `${te.id} ${te.name}` })),
    ].filter((o) => !taken.has(o.value)),
  }));
  const name = (p: AttackPairInput) => data?.techniques.find((t) => t.id === p.technique)?.name;
  const chipTitle = (p: AttackPairInput, primary: boolean) =>
    [p.technique ? name(p) ?? p.technique : null, tactic(p.tactic), primary ? "(primary)" : null].filter(Boolean).join(" · ");
  return (
    <div className="stack">
      {value.length > 0 && <span className="attack-chips">
        {value.map((p, i) => (
          <span key={pairKey(p)} className="attack-chip" title={chipTitle(p, i === 0)}>
            {p.technique ?? p.tactic}
            {!disabled && <button type="button" className="link-button" aria-label={`Remove ${p.technique ?? p.tactic}`} onClick={() => onChange(value.filter((q) => pairKey(q) !== pairKey(p)))}><Icon name="close" size={11} /></button>}
          </span>
        ))}
      </span>}
      {catalog.error ? <ErrorBox error={catalog.error} /> : !disabled && value.length < 16 && (
        <Select label="Add an ATT&CK technique" placeholder={data ? "Add a technique or tactic…" : "Loading ATT&CK…"} value="" options={groups}
          disabled={!data} onChange={(v) => { const [ta = "", te = ""] = v.split("|"); onChange([...value, { tactic: ta, technique: te || null }]); }} />
      )}
    </div>
  );
}


const OUTCOMES: Record<string, string> = {
  match: "Matches: the rule would raise a compliance finding on this host.",
  no_match: "No match on this host.",
  unavailable: "Unavailable here.",
  failed: "The rule failed on this host.",
};

// Runs the typed rule over the facts the platform can rebuild for one host:
// packages and listening ports.
function RuleTest({ set, ruleId, input, enabled }: { set: string; ruleId: string; input: RuleDraftInput; enabled: boolean }) {
  const hosts = useResource<{ items: Agent[] }>("/api/v1/agents?state=active&limit=100");
  const [agent, setAgent] = useState("");
  const [result, setResult] = useState<RuleTestResult>();
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);
  const run = () => {
    setBusy(true);
    setError(undefined);
    setResult(undefined);
    request<RuleTestResult>("POST", `/api/v1/rule-drafts/${set}/${encodeURIComponent(ruleId)}/test`, { agent_id: agent, rule: input })
      .then(setResult, (e: unknown) => setError(e instanceof ApiError ? e.message : "Could not test the rule"))
      .finally(() => setBusy(false));
  };
  if (set !== "site") {
    return <Section title="Test against a host"><p className="subtle">Alarm rules run on process starts, which the platform doesn't hold. They are checked as you type; test one on a host.</p></Section>;
  }
  return (
    <Section title="Test against a host">
      <p className="subtle">Runs the rule on what the platform holds for a host: its package names and listening ports. A rule over anything else shows as unavailable here; the agent evaluates it.</p>
      <div className="row">
        <SelectField label="Host" className="grow">
          <Select label="Host" value={agent} onChange={(v) => { setAgent(v); setResult(undefined); }}
            options={[{ value: "", label: "Choose a host" }, ...(hosts.data?.items ?? []).map((host) => ({ value: host.id, label: host.hostname ?? host.id }))]} />
        </SelectField>
        <button type="button" className="button" disabled={busy || agent === "" || !enabled} onClick={run}>Test</button>
      </div>
      {error && <p className="confirm__error" role="alert">{error}</p>}
      {result && (
        <div className="callout" role="status">
          <span>
            {OUTCOMES[result.outcome] ?? result.outcome}
            {result.evidence.length > 0 && <> Evidence: <span className="mono">{result.evidence.join(", ")}</span>.</>}
            {result.message && <> {result.message}</>}
            {" "}Ran on {result.facts.packages} packages and {result.facts.listeners} listeners
            {result.facts.listeners_reported_at ? "." : "; this host has not reported its listeners."}
          </span>
        </div>
      )}
    </Section>
  );
}

export function SiteRulePanel({ id }: { id: string }) {
  const slash = id.indexOf("/");
  const set = id.slice(0, slash);
  const ruleId = id.slice(slash + 1);
  const isNew = ruleId === "new";
  const alarm = set === "site-alarms";
  const { can } = useSession();
  const drafts = useResource<{ items: RuleDraft[] }>(`/api/v1/rule-drafts/${set}`);
  const draft = drafts.data?.items.find((item) => item.rule_id === ruleId);
  const [form, setForm] = useState<Form>();
  const [typedId, setTypedId] = useState("");
  const [check, setCheck] = useState<RuleCheck>();
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);
  const current = form ?? (draft ? fromDraft(draft) : BLANK);
  const effectiveId = isNew ? typedId.trim() : ruleId;
  const write = can("rules.write", true);

  // Live check: the server runs the agent's own loader on what is typed.
  const body = JSON.stringify(toInput(current, alarm));
  const ready = effectiveId !== "" && (draft !== undefined || isNew);
  useEffect(() => {
    if (!ready || !write) return;
    let live = true;
    const timer = setTimeout(() => {
      request<RuleCheck>("POST", `/api/v1/rule-drafts/${set}/${encodeURIComponent(effectiveId)}/check`, JSON.parse(body) as RuleDraftInput)
        .then((result) => { if (live) setCheck(result); }, () => { if (live) setCheck(undefined); });
    }, 400);
    return () => { live = false; clearTimeout(timer); };
  }, [ready, write, set, effectiveId, body]);

  if (slash < 0 || (set !== "site" && set !== "site-alarms")) return <div className="panel-body"><Empty title="Unknown rule set" /></div>;
  if (drafts.error) return <div className="panel-body"><ErrorBox error={drafts.error} /></div>;
  if (!drafts.data) return <Loading />;
  if (!isNew && !draft) return <div className="panel-body"><Empty title="No such rule">It may have been deleted.</Empty></div>;

  const update = (patch: Partial<Form>) => setForm({ ...current, ...patch });
  const problem = (field: string) => check?.problems.filter((p) => p.field === field).map((p) => p.message).join("; ");
  // A Select never sits in a <label> (invalid HTML): `box` renders a div + span instead.
  const field = (name: string, label: string, control: React.ReactNode, box = false) => {
    const Tag = box ? "div" : "label";
    return (
      <Tag className="field">{box ? <span>{label}</span> : label}
        {control}
        {problem(name) && <span className="confirm__error" role="alert">{problem(name)}</span>}
      </Tag>
    );
  };
  const save = () => {
    setBusy(true);
    setError(undefined);
    request<RuleDraft>("PUT", `/api/v1/rule-drafts/${set}/${encodeURIComponent(effectiveId)}`, toInput(current, alarm))
      .then((saved) => {
        invalidate(`/api/v1/rule-drafts/${set}`);
        toast(`${saved.rule_id} saved as version ${saved.version}`);
        setForm(undefined);
        if (isNew) nav.open({ kind: "site-rule", id: `${set}/${saved.rule_id}` });
      }, (e: unknown) => setError(e instanceof ApiError ? e.message : "Could not save the rule"))
      .finally(() => setBusy(false));
  };
  return (
    <>
      <PanelHeader icon="rules" kind={alarm ? "Alarm rule" : "Compliance rule"} title={isNew ? "New rule" : ruleId}
        subtitle={draft ? `Version ${draft.version}, saved by ${draft.updated_by}. A draft: it reaches hosts only once published.` : "Saved as a draft: it reaches hosts only once published."} />
      <div className="panel-body stack">
        {!write && <div className="callout callout--warn">Writing rules needs the rules.write permission.</div>}
        <form className="stack" onSubmit={(event) => { event.preventDefault(); save(); }}>
          {isNew && field("id", "Rule id", <input className="input mono" required value={typedId} onChange={(e) => setTypedId(e.target.value)} placeholder={alarm ? "alarm.nginx.shell" : "port.redis.exposed"} />)}
          {field("title", "Title", <input className="input" required value={current.title} onChange={(e) => update({ title: e.target.value })} disabled={!write} />)}
          <div className="grid--stacked">
            {field("severity", "Severity", <Select label="Severity" value={current.severity} onChange={(v) => update({ severity: v })} disabled={!write} options={SEVERITIES.map((s) => ({ value: s, label: s }))} />, true)}
            {field("confidence", "Confidence (0 to 100)", <input className="input" type="number" min={0} max={100} value={current.confidence} onChange={(e) => update({ confidence: e.target.value })} disabled={!write} />)}
          </div>
          {alarm && field("programs", "Programs (one to eight, space or comma separated)", <input className="input mono" value={current.programs} onChange={(e) => update({ programs: e.target.value })} placeholder="nginx httpd" disabled={!write} />)}
          {field("expression", "Expression", <textarea className="textarea mono" rows={4} required value={current.expression} onChange={(e) => update({ expression: e.target.value })} disabled={!write} spellCheck={false}
            placeholder={alarm ? "event['process.name'] in ['sh', 'bash']" : "'6379' in facts['port.tcp.exposed']"} />)}
          <p className="subtle">{alarm ? `Keys: ${EVENT_KEYS}.` : `Facts: ${FACTS}.`}</p>
          {field("attack", "MITRE ATT&CK (first is primary)", <AttackField value={current.attack} onChange={(attack) => update({ attack })} disabled={!write} />, true)}
          {field("finding_message", alarm ? "Alarm message" : "Compliance finding message", <textarea className="textarea" rows={3} required value={current.finding_message} onChange={(e) => update({ finding_message: e.target.value })} disabled={!write} />)}
          {problem("rule") && <p className="confirm__error" role="alert">{problem("rule")}</p>}
          {check?.ok && <p className="subtle">Hosts would accept this rule.</p>}
          {error && <p className="confirm__error" role="alert">{error}</p>}
          {write && (
            <div className="row">
              <button className="button button--primary" type="submit" disabled={busy || !ready || (check !== undefined && !check.ok)}>Save draft</button>
            </div>
          )}
        </form>
        {write && !isNew && (
          <Confirm label={`Delete ${ruleId}?`} danger onConfirm={() => request("DELETE", `/api/v1/rule-drafts/${set}/${encodeURIComponent(ruleId)}`).then(() => {
            invalidate(`/api/v1/rule-drafts/${set}`);
            toast(`${ruleId} deleted`);
            nav.remove({ kind: "site-rule", id });
          })}>Delete</Confirm>
        )}
        <RuleTest set={set} ruleId={effectiveId} input={toInput(current, alarm)} enabled={write && ready && check?.ok === true} />
        <Section title="Publishing">
          <p className="subtle">Saved rules are drafts. Publish the set from the Site rules page.</p>
        </Section>
      </div>
    </>
  );
}
