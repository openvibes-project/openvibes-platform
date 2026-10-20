// The Rule card's body: "Where" / "and" rows of field, operator and values,
// read-only until Edit; in edit mode the values are a chip input and each row
// can be removed.
import { useState } from "react";

import { Icon } from "../../../ui/Icon";
import { Select } from "../../../ui/Select";
import { type Action, type Draft, FIELDS, fieldDef, valueLabel } from "./groupState";

const HINTS: Record<string, string> = { ip: "The address OpenVIBES sees; behind NAT this is the router." };
const PLACEHOLDER: Record<string, string> = { os_family: "linux or windows", distribution: "e.g. debian 12", hostname: "e.g. web-*", ip: "e.g. 10.0.0.0/16" };

/** Values as chips; Enter or a comma adds what is typed. */
function ValuesInput({ field, label, values, onChange }: { field: string; label: string; values: string[]; onChange: (values: string[]) => void }) {
  const [text, setText] = useState("");
  const add = () => {
    const v = text.trim().replace(/,$/, "").trim();
    if (v && !values.includes(v)) onChange([...values, v]);
    setText("");
  };
  return (
    <span className="rule-values">
      {values.map((v) => (
        <span key={v} className="chip rule-values__chip">{valueLabel(field, v)}
          <button type="button" className="icon-button" aria-label={`Remove ${valueLabel(field, v)} from ${label.toLowerCase()}`} onClick={() => onChange(values.filter((x) => x !== v))}><Icon name="close" size={12} /></button>
        </span>
      ))}
      <input className="input rule-values__input" aria-label={label}
        placeholder={values.length ? "" : PLACEHOLDER[field]} value={text}
        onChange={(e) => setText(e.target.value)} onBlur={add}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === ",") { e.preventDefault(); add(); }
          else if (e.key === "Backspace" && !text && values.length) onChange(values.slice(0, -1));
        }} />
    </span>
  );
}

export function RuleEditor({ draft, dispatch, editing }: { draft: Draft; dispatch: (a: Action) => void; editing: boolean }) {
  return (
    <div className="stack rule-editor">
      {draft.conditions.map((c, index) => {
        const def = fieldDef(c.field);
        const op = def.ops[c.negate ? 1 : 0];
        return (
          <div key={draft.keys[index] ?? index} className="stack rule-row">
            <div className="row rule-row__line">
              <span className="subtle rule-row__join">{index ? "and" : "Where"}</span>
              {editing ? (
                <>
                  <span className="rule-row__field"><Select label={`Field of condition ${index + 1}`} small value={c.field} options={FIELDS.map((f) => ({ value: f.id, label: f.label }))}
                    onChange={(field) => dispatch({ type: "field", index, field })} /></span>
                  <span className="rule-row__op"><Select label={`Operator of condition ${index + 1}`} small value={c.negate ? "1" : "0"} options={def.ops.map((o, i) => ({ value: String(i), label: o }))}
                    onChange={(v) => dispatch({ type: "negate", index, negate: v === "1" })} /></span>
                  <ValuesInput field={c.field} label={`Values of condition ${index + 1}`} values={c.values} onChange={(values) => dispatch({ type: "values", index, values })} />
                  <button type="button" className="icon-button" aria-label="Remove this condition" title="Remove this condition" onClick={() => dispatch({ type: "remove", index })}>
                    <Icon name="close" size={14} />
                  </button>
                </>
              ) : (
                <>
                  <span className="rule-row__cell rule-row__field">{def.label}</span>
                  <span className="rule-row__cell rule-row__op">{op}</span>
                  <span className="rule-row__cell rule-row__values">{c.values.map((v) => valueLabel(c.field, v)).join(", ")}</span>
                </>
              )}
            </div>
            {editing && HINTS[c.field] && <span className="subtle rule-row__hint">{HINTS[c.field]}</span>}
          </div>
        );
      })}
      {editing && <div><button type="button" className="button button--ghost button--small" onClick={() => dispatch({ type: "add" })}>+ Add condition</button></div>}
      <span className="subtle rule-editor__note">Rules use what agents report: OS family, distribution, hostname and IP address. Labels never count. Hosts join and leave by themselves as they change.</span>
    </div>
  );
}
