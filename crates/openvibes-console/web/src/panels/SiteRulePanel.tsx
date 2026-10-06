// One site rule: a form with a live check against the agent's own rule
// loader, saved as a draft. Publishing the set comes later.
import { useEffect, useState } from "react";

import { ApiError, invalidate, request, useResource } from "../api/client";
import type { RuleCheck, RuleDraft, RuleDraftInput } from "../api/types";
import { nav } from "../app/nav";
import { useSession } from "../app/session";
import { Empty, ErrorBox, Loading } from "../ui/bits";
import { Confirm, PanelHeader, Section } from "../ui/panel";
import { toast } from "../ui/toast";

const SEVERITIES = ["info", "low", "medium", "high", "critical"] as const;
const FACTS = "process.names, process.count, package.names, package.count, port.tcp.exposed, port.tcp.local, port.udp.exposed, port.udp.local";
const EVENT_KEYS = "process.exe, process.name, process.cmdline, process.cwd, process.uid, process.euid, parent.exe, parent.name, parent.cmdline, ancestors.names, ancestors.exes";

type Form = { title: string; severity: string; confidence: string; expression: string; finding_message: string; programs: string };
const BLANK: Form = { title: "", severity: "medium", confidence: "80", expression: "", finding_message: "", programs: "" };

const toInput = (form: Form, alarm: boolean): RuleDraftInput => ({
  title: form.title,
  severity: form.severity,
  confidence: Math.max(0, Math.min(255, Math.round(Number(form.confidence) || 0))),
  expression: form.expression,
  finding_message: form.finding_message,
  programs: alarm ? form.programs.split(/[\s,]+/).filter(Boolean) : null,
});

const fromDraft = (draft: RuleDraft): Form => ({
  title: draft.title,
  severity: draft.severity,
  confidence: String(draft.confidence),
  expression: draft.expression,
  finding_message: draft.finding_message,
  programs: (draft.programs ?? []).join(" "),
});

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
  const field = (name: string, label: string, control: React.ReactNode) => (
    <label className="field">{label}
      {control}
      {problem(name) && <span className="confirm__error" role="alert">{problem(name)}</span>}
    </label>
  );
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
            {field("severity", "Severity", <select className="select" value={current.severity} onChange={(e) => update({ severity: e.target.value })} disabled={!write}>{SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}</select>)}
            {field("confidence", "Confidence (0 to 100)", <input className="input" type="number" min={0} max={100} value={current.confidence} onChange={(e) => update({ confidence: e.target.value })} disabled={!write} />)}
          </div>
          {alarm && field("programs", "Programs (one to eight, space or comma separated)", <input className="input mono" value={current.programs} onChange={(e) => update({ programs: e.target.value })} placeholder="nginx httpd" disabled={!write} />)}
          {field("expression", "Expression", <textarea className="textarea mono" rows={4} required value={current.expression} onChange={(e) => update({ expression: e.target.value })} disabled={!write} spellCheck={false}
            placeholder={alarm ? "event['process.name'] in ['sh', 'bash']" : "'6379' in facts['port.tcp.exposed']"} />)}
          <p className="subtle">{alarm ? `Keys: ${EVENT_KEYS}.` : `Facts: ${FACTS}.`}</p>
          {field("finding_message", alarm ? "Alarm message" : "Finding message", <textarea className="textarea" rows={3} required value={current.finding_message} onChange={(e) => update({ finding_message: e.target.value })} disabled={!write} />)}
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
        <Section title="Not yet">
          <p className="subtle">Testing a rule against a host and publishing the set are the next steps.</p>
        </Section>
      </div>
    </>
  );
}
