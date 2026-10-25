// The Items card of a case's page (approved screen 32): each item opens its
// own page, with its kind, host and severity; alarms, compliance findings
// and vulnerabilities take an Outcome (ruling 1: Fixed only once the
// evidence is gone, a note for every outcome but Fixed, a re-open date for
// Risk accepted). Remove item and Add item, as the old case panel had them.
import { type FormEvent, useState } from "react";

import { invalidate, request } from "../../../api/client";
import type { CaseDetail, CaseItem } from "../../../api/types";
import {
  CASE_KINDS, type CaseKind, caseErrorText, isStale, itemPanel, kindIcon, kindLabel, localDay, needsOutcome, outcomeBody, outcomeChoices, outcomeLabel,
  outcomeNeedsNote, refHint, refLabel,
} from "../../../panels/cases/cases";
import { ObjectLink, SeverityBadge } from "../../../ui/bits";
import { Card } from "../../../ui/detail/DetailPage";
import { SelectField } from "../../../ui/Field";
import { when } from "../../../ui/format";
import { Icon } from "../../../ui/Icon";
import { Confirm } from "../../../ui/panel";
import { Select } from "../../../ui/Select";
import { toast } from "../../../ui/toast";
import { attempt, caseApi } from "./CaseCards";

const DAY = 86_400_000;

function OutcomeBadge({ item }: { item: CaseItem }) {
  if (!item.outcome) return null;
  const stale = item.outcome === "resolved" && !item.evidence_gone;
  return (
    <>
      <span className={`badge badge--plain ${item.outcome === "resolved" ? "badge--ok" : item.outcome === "accepted_risk" ? "badge--info" : ""}`}>{outcomeLabel[item.outcome] ?? item.outcome}</span>
      {item.outcome_until && <span title="The outcome clears then, and a closed case reopens">until {when(item.outcome_until)}</span>}
      {stale && <span className="badge badge--bad badge--plain" title="The evidence is back, so this item blocks closing until it has another outcome">Evidence is back</span>}
    </>
  );
}

function OutcomeControl({ c, item, label }: { c: CaseDetail; item: CaseItem; label: string }) {
  const saved = item.outcome_until ? localDay(new Date(item.outcome_until)) : "";
  const [outcome, setOutcome] = useState(item.outcome ?? "");
  const [note, setNote] = useState(item.outcome_note ?? "");
  const [until, setUntil] = useState(saved);
  // Risk accepted: a future day, at most 365 days ahead (ruling 1).
  const [[tomorrow, latest]] = useState(() => [localDay(new Date(Date.now() + DAY)), localDay(new Date(Date.now() + 365 * DAY))]);
  const [busy, setBusy] = useState(false);
  const changed = outcome !== (item.outcome ?? "") || (outcome !== "" && note.trim() !== (item.outcome_note ?? ""))
    || (outcome === "accepted_risk" && until !== saved);
  const save = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    await attempt(() => request("PUT", `${caseApi(c.case_id)}/items/${encodeURIComponent(item.item_id)}/outcome`, outcomeBody(outcome, note, until)),
      outcome === "" ? "Outcome cleared" : "Outcome saved");
    setBusy(false);
  };
  return (
    <form className="row row--wrap grow" onSubmit={(event) => void save(event)}>
      <Select small label={`Outcome for ${label}`} value={outcome} onChange={setOutcome}
        options={[{ value: "", label: "Needs an outcome" }, ...outcomeChoices(item).map((choice) => ({
          value: choice.value,
          label: `${choice.label}${choice.disabled ? " (evidence still there)" : ""}`,
          disabled: choice.disabled && choice.value !== item.outcome,
          hint: choice.hint,
        }))]} />
      {outcome !== "" && (
        <input className="input grow" value={note} onChange={(event) => setNote(event.target.value)} required={outcomeNeedsNote(outcome)} maxLength={4000}
          placeholder={outcomeNeedsNote(outcome) ? "Why (required)" : "Note (optional)"} aria-label={`Note for ${label}`} />
      )}
      {outcome === "accepted_risk" && (
        <input className="input" type="date" required min={tomorrow} max={latest} value={until} onChange={(event) => setUntil(event.target.value)} aria-label={`Re-open date for ${label}`} />
      )}
      <button type="submit" className="button button--small" disabled={busy || !changed}>{busy ? "Saving…" : outcome === "" ? "Clear" : "Save outcome"}</button>
    </form>
  );
}

function ItemRow({ c, item, editable }: { c: CaseDetail; item: CaseItem; editable: boolean }) {
  const kind = item.kind as CaseKind;
  const panel = itemPanel(item.kind, item.ref);
  const label = item.title ?? refLabel(item.kind, item.ref);
  return (
    <li className="case-item">
      <div className="case-item__main">
        <Icon name={kindIcon[kind] ?? "layers"} size={16} />
        <span className="case-item__title grow">{panel ? <ObjectLink to={panel}>{label}</ObjectLink> : label}</span>
        {item.severity && <SeverityBadge severity={item.severity} />}
      </div>
      <div className="case-item__meta">
        <span>{kindLabel[kind] ?? item.kind}</span>
        {item.hostname && kind !== "host" && <span>on {item.agent_id ? <ObjectLink to={{ kind: "agent", id: item.agent_id }} className="object-link mono">{item.hostname}</ObjectLink> : item.hostname}</span>}
        <OutcomeBadge item={item} />
        {needsOutcome(item) && !item.outcome && item.evidence_gone && <span className="badge badge--ok badge--plain" title="The evidence is gone, so it can be marked fixed">Evidence gone</span>}
        {needsOutcome(item) && !item.outcome && !item.evidence_gone && c.status !== "closed" && <span className="badge badge--warn badge--plain">Needs an outcome</span>}
      </div>
      {item.outcome_note && <p className="case-item__note">{item.outcome_note}</p>}
      {editable && (
        <div className="case-item__controls row row--wrap">
          {needsOutcome(item) && <OutcomeControl key={`${item.outcome}:${item.outcome_note}:${item.outcome_until}:${item.evidence_gone}`} c={c} item={item} label={label} />}
          <Confirm label={`Remove ${label} from this case? The timeline keeps that it was here.`} buttonLabel={`Remove ${label}`}
            onConfirm={async () => {
              try {
                await request("DELETE", `${caseApi(c.case_id)}/items/${encodeURIComponent(item.item_id)}`);
              } catch (error) {
                if (isStale(error)) invalidate("/api/v1/case");
                throw new Error(caseErrorText(error), { cause: error });
              }
              invalidate("/api/v1/case");
              toast("Item removed");
            }}>Remove</Confirm>
        </div>
      )}
    </li>
  );
}

function AddItem({ c, onDone }: { c: CaseDetail; onDone: () => void }) {
  const [kind, setKind] = useState<CaseKind>("host");
  const [ref, setRef] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (busy) return;
    setBusy(true);
    setError(undefined);
    request("POST", `${caseApi(c.case_id)}/items`, { kind, ref: ref.trim() })
      .then(() => { invalidate("/api/v1/case"); toast("Item added"); onDone(); },
        (e: unknown) => { setError(caseErrorText(e)); if (isStale(e)) invalidate("/api/v1/case"); })
      .finally(() => setBusy(false));
  };
  return (
    <form className="confirm" onSubmit={submit} aria-label="Add an item">
      <p className="confirm__text">Paste the item's id. Each page's <strong>Add to case</strong> button does this for you.</p>
      <SelectField label="Kind">
        <Select label="Kind" value={kind} onChange={(k) => setKind(k as CaseKind)} options={CASE_KINDS.map((k) => ({ value: k, label: kindLabel[k] }))} />
      </SelectField>
      <label className="field">Id<input className="input mono" required autoFocus autoComplete="off" spellCheck={false} value={ref} onChange={(event) => setRef(event.target.value)} placeholder={refHint[kind]} /></label>
      {error && <p className="confirm__error" role="alert">{error}</p>}
      <div className="row">
        <button type="submit" className="button button--small button--primary" disabled={busy || ref.trim() === ""}>{busy ? "Adding…" : "Add"}</button>
        <button type="button" className="button button--small button--ghost" onClick={onDone}>Cancel</button>
      </div>
    </form>
  );
}

/** `editable`: outcomes, Remove and Add item (`can.outcome`: cases.write on a case not closed). */
export function ItemsCard({ detail, editable }: { detail: CaseDetail; editable: boolean }) {
  const [adding, setAdding] = useState(false);
  return (
    <Card id="items" title={<>Items <span className="subtle num">{detail.items.length.toLocaleString()}</span></>}
      aside={editable && !adding && <button type="button" className="button button--small" onClick={() => setAdding(true)}><Icon name="plus" size={14} /> Add item</button>}>
      <div className="stack">
        {adding && <AddItem c={detail} onDone={() => setAdding(false)} />}
        {detail.items.length === 0 ? <p className="subtle">No items yet. Hosts, alarms, vulnerabilities, compliance findings and software can all be added.</p> : (
          <ul className="case-items" aria-label="Items">
            {detail.items.map((item) => <ItemRow key={item.item_id} c={detail} item={item} editable={editable} />)}
          </ul>
        )}
      </div>
    </Card>
  );
}
