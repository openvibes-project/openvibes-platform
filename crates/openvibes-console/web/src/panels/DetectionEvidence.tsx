import { useState } from "react";
import { useResource } from "../api/client";
import type { components } from "../api/generated";
import { ErrorBox, Loading } from "../ui/bits";
import { date } from "../ui/format";
import { Section } from "../ui/panel";

type Detection = components["schemas"]["DetectionView"];
type Rule = components["schemas"]["DetectionRuleView"];

export function DetectionEvidence({ detection, references = [], ruleId, ruleUrl }: {
  detection?: Detection | null | undefined; references?: string[]; ruleId: string; ruleUrl: string;
}) {
  const [showRule, setShowRule] = useState(false);
  const rule = useResource<Rule>(showRule ? ruleUrl : null);
  return <>
    <Section title="What was found">
      {detection ? <div className="stack">
        <p className="subtle">Evidence captured {date(new Date(detection.observed_at_unix_ms).toISOString())}.</p>
        {detection.inputs.length > 0 && <dl className="kv detection-inputs">
          {detection.inputs.map((input) => <div className="detection-input" key={input.key}>
            <dt className="mono">{input.key}</dt>
            <dd>{input.status === "masked" ? "Masked — original value withheld" : input.status === "summarized"
              ? `Complete list of ${input.item_count ?? "unknown number of"} values; see membership results below`
              : <><span className="mono">{typeof input.value === "string" ? input.value : JSON.stringify(input.value)}</span>{input.status === "truncated" && " … (truncated)"}</>}</dd>
          </div>)}
        </dl>}
        {detection.truncated && <p className="subtle">Some evidence was omitted or shortened to stay within the agent's limits. The recorded detection still matched.</p>}
      </div> : <div className="stack">
        <p>Detection-time input values were not recorded for this observation.</p>
        {references.length > 0 && <><p className="subtle">Referenced facts (these are names, not matched values):</p><ul>{references.map((key) => <li className="mono" key={key}>{key}</li>)}</ul></>}
      </div>}
    </Section>
    <Section title="Why it triggered">
      <div className="stack">
        <button className="object-link" type="button" aria-expanded={showRule} onClick={() => setShowRule(!showRule)}>
          {showRule ? "Hide rule" : "View rule"}: {ruleId}
        </button>
        {showRule && <div className="detection-rule stack">
          {rule.error ? <ErrorBox error={rule.error} /> : !rule.data ? <Loading rows={2} /> : !rule.data.rule
            ? <p>Exact rule version unavailable. The original bundle may not have been published here, or its historical definition cannot be identified safely.</p>
            : <>
              <strong>{rule.data.rule.title}</strong>
              <p className="subtle">{rule.data.rule_set_id} · rule v{rule.data.rule.version}{rule.data.rule_set_version != null && ` · set v${rule.data.rule_set_version}`} · {rule.data.rule.kind === "process_event" ? "Process event" : "Snapshot"}</p>
              {rule.data.status === "legacy" && <p className="subtle">The original bundle version was not recorded. All stored definitions for this rule version agree.</p>}
              <p>{rule.data.rule.finding_message}</p>
              <pre className="detection-code"><code>{rule.data.rule.expression}</code></pre>
              <p className="subtle">Severity: {rule.data.rule.severity} · confidence: {rule.data.rule.confidence}%</p>
              {rule.data.rule.programs && <p>Applies to programs: <span className="mono">{rule.data.rule.programs.join(", ")}</span></p>}
            </>}
        </div>}
        {detection && detection.steps.length > 0 ? <>
          <p className="subtle">Conditions evaluated at detection time. Skipped branches are not listed. Expressions contain rule text; input values are above.</p>
          <ol className="detection-steps">{detection.steps.map((step, index) => <li key={index}>
            <code>{step.expression}</code><span className={`badge badge--${step.result ? "info" : "plain"}`}>{step.result ? "True" : "False"}</span>
          </li>)}</ol>
        </> : <p className="subtle">Condition results were not retained. The rule's source can still be inspected when its historical bundle is available.</p>}
        {detection && <details><summary>Raw recorded evidence</summary><pre className="detection-code">{JSON.stringify(detection, null, 2)}</pre></details>}
      </div>
    </Section>
  </>;
}
