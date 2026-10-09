import { useState } from "react";
import { useResource } from "../api/client";
import { nav } from "../app/nav";
import type { components } from "../api/generated";
import { ErrorBox, Loading } from "../ui/bits";
import { date } from "../ui/format";
import { Section } from "../ui/panel";

type Detection = components["schemas"]["DetectionView"];
type Rule = components["schemas"]["DetectionRuleView"];

// One ATT&CK pair; opens the Coverage page filtered to it.
function AttackChip({ technique, tactic, name }: Readonly<{ technique: string | null; tactic: string; name: string | null }>) {
  return <button type="button" className="attack-chip attack-chip--link" title={name ?? tactic}
    onClick={() => nav.view("/coverage", technique ? { technique } : { tactic })}>{technique ?? tactic}</button>;
}

export function DetectionEvidence({ detection, references = [], ruleId, ruleUrl }: {
  detection?: Detection | null | undefined; references?: string[]; ruleId: string; ruleUrl: string;
}) {
  const [showRule, setShowRule] = useState(false);
  const rule = useResource<Rule>(ruleUrl);
  const steps = detection?.steps ?? [];
  const matched = steps.filter((step) => step.result).length;
  const definition = rule.data?.rule;
  return <Section title="Why it triggered">
    <div className="stack detection">
      {detection && steps.length > 0 ? <>
        <p className="detection-verdict">Matched {matched} of {steps.length} {steps.length === 1 ? "condition" : "conditions"}</p>
        <ol className="detection-steps" aria-label="Conditions evaluated at detection time">{steps.map((step, index) => <li key={index}>
          <span className={`detection-mark detection-mark--${step.result ? "yes" : "no"}`} role="img" aria-label={step.result ? "True" : "False"}>{step.result ? "✓" : "✗"}</span>
          <code>{step.expression}</code>
        </li>)}</ol>
        <p className="subtle detection-note">Skipped branches are not listed.</p>
      </> : <p className="subtle">Condition results were not retained. The rule's source can still be inspected when its historical bundle is available.</p>}
      {detection ? <>
        {detection.inputs.length > 0 && <div className="stack detection-values">
          <h4 className="detection-sub">Values seen · captured {date(new Date(detection.observed_at_unix_ms).toISOString())}</h4>
          <dl className="kv detection-inputs">
            {detection.inputs.map((input) => <div className="detection-input" key={input.key}>
              <dt className="mono">{input.key}</dt>
              <dd>{input.status === "masked" ? "Masked — original value withheld" : input.status === "summarized"
                ? `Complete list of ${input.item_count ?? "unknown number of"} values; see membership results above`
                : <><span className="mono">{typeof input.value === "string" ? input.value : JSON.stringify(input.value)}</span>{input.status === "truncated" && " … (truncated)"}</>}</dd>
            </div>)}
          </dl>
        </div>}
        {detection.truncated && <p className="subtle">Some evidence was omitted or shortened to stay within the agent's limits. The recorded detection still matched.</p>}
      </> : <div className="stack">
        <p>Detection-time input values were not recorded for this observation.</p>
        {references.length > 0 && <><p className="subtle">Referenced facts (these are names, not matched values):</p><ul>{references.map((key) => <li className="mono" key={key}>{key}</li>)}</ul></>}
      </div>}
      <div className="detection-rule-line">
        <span className="subtle">
          <span className="mono">{ruleId}</span>
          {rule.data && <> · {rule.data.rule_set_id}{definition && <> · rule v{definition.version}</>}{rule.data.rule_set_version != null && ` · set v${rule.data.rule_set_version}`}{definition && <> · {definition.kind === "process_event" ? "Process event" : "Snapshot"} · {definition.severity}, {definition.confidence}% confidence</>}</>}
        </span>
        <button className="link-button" type="button" aria-expanded={showRule} onClick={() => setShowRule(!showRule)}>
          {showRule ? "Hide rule" : "Show rule"}
        </button>
      </div>
      {showRule && <div className="stack">
        {rule.error ? <ErrorBox error={rule.error} /> : !rule.data ? <Loading rows={2} /> : !definition
          ? <p>Exact rule version unavailable. The original bundle may not have been published here, or its historical definition cannot be identified safely.</p>
          : <>
            {rule.data.status === "legacy" && <p className="subtle">The original bundle version was not recorded. All stored definitions for this rule version agree.</p>}
            <pre className="detection-code"><code>{definition.expression}</code></pre>
            {definition.programs && <p>Applies to programs: <span className="mono">{definition.programs.join(", ")}</span></p>}
            {definition.attack.length > 0 && <p>MITRE ATT&CK: <span className="attack-chips">{definition.attack.map((p) => (
              <AttackChip key={`${p.tactic}/${p.technique ?? ""}`} technique={p.technique ?? null} tactic={p.tactic} name={p.technique_name ?? null} />
            ))}</span></p>}
          </>}
      </div>}
      {detection && <details className="detection-raw"><summary>Raw recorded evidence</summary><pre className="detection-code">{JSON.stringify(detection, null, 2)}</pre></details>}
    </div>
  </Section>;
}
