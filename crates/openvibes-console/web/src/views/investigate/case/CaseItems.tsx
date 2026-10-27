// The Items card of a case's page, as approved screen 32's table: Kind,
// Item (its title, opening its own page, and a line with its outcome), Severity,
// Host, Outcome and ✕ (Remove, confirmed in a sub-row). Alarms, compliance
// findings and vulnerabilities take an Outcome (ruling 1: Fixed only once the
// evidence is gone, a note for every outcome but Fixed, a re-open date for
// Risk accepted); a changed choice opens a full-width sub-row with the note,
// the date and Save. + Add item, as the old case panel had it.
import { type FormEvent, Fragment, useCallback, useRef, useState } from "react";

import { invalidate, request } from "../../../api/client";
import type { CaseDetail, CaseItem } from "../../../api/types";
import {
  acceptRange, CASE_KINDS, type CaseKind, caseErrorText, isStale, itemPanel, kindLabel, localDay, needsOutcome, outcomeBody, outcomeChoices, outcomeLabel,
  outcomeNeedsNote, refHint, refLabel,
} from "../../../panels/cases/cases";
import { ObjectLink, SeverityBadge } from "../../../ui/bits";
import { Card } from "../../../ui/detail/DetailPage";
import { SelectField } from "../../../ui/Field";
import { when } from "../../../ui/format";
import { Icon } from "../../../ui/Icon";
import { Select } from "../../../ui/Select";
import { toast } from "../../../ui/toast";
import { attempt, caseApi } from "./CaseCards";

/** The table's columns; Kind, Severity and Host hide below their widths (px of the card), as the lists' columns do. */
export const ITEM_COLUMNS = [
  { key: "kind", label: "Kind", width: "120px", hideBelow: 560 },
  { key: "item", label: "Item" },
  { key: "severity", label: "Severity", width: "100px", hideBelow: 700 },
  { key: "host", label: "Host", width: "120px", hideBelow: 620 },
  { key: "outcome", label: "Outcome", width: "190px" },
] as const;

/** The card's width, for `hideBelow` (as DataTable measures its own). A
 * callback ref, as the table first mounts when a case gets its first item. */
function useWidth() {
  const [width, setWidth] = useState(1200);
  const observer = useRef<ResizeObserver>(null);
  const ref = useCallback((node: HTMLDivElement | null) => {
    observer.current?.disconnect();
    observer.current = null;
    if (!node) return;
    observer.current = new ResizeObserver(([entry]) => setWidth(entry?.contentRect.width ?? 1200));
    observer.current.observe(node);
  }, []);
  return [ref, width] as const;
}

/** The line under an item's title: its outcome, the note, its re-open date, and the evidence. */
function ItemLine({ item, closed }: { item: CaseItem; closed: boolean }) {
  const takes = needsOutcome(item);
  return (
    <span className="subtle row row--wrap" style={{ gap: 6 }}>
      {item.outcome && <span>{outcomeLabel[item.outcome] ?? item.outcome}</span>}
      {item.outcome_until && <span title="The outcome clears then, and a closed case reopens">until {when(item.outcome_until)}</span>}
      {item.outcome_note && <span className="truncate">“{item.outcome_note}”</span>}
      {item.outcome === "resolved" && !item.evidence_gone && <span className="badge badge--bad badge--plain" title="The evidence is back, so this item blocks closing until it has another outcome">Evidence is back</span>}
      {takes && !item.outcome && item.evidence_gone && <span className="badge badge--ok badge--plain">Evidence gone</span>}
      {takes && !item.outcome && !closed && <span className="badge badge--warn badge--plain">Needs an outcome</span>}
      {!takes && <span>Context: takes no outcome</span>}
    </span>
  );
}

type Draft = { outcome: string; note: string; until: string };

function ItemRow({ c, item, editable, shown, span }: { c: CaseDetail; item: CaseItem; editable: boolean; shown: (key: string) => boolean; span: number }) {
  const kind = item.kind as CaseKind;
  const panel = itemPanel(item.kind, item.ref);
  const label = item.title ?? refLabel(item.kind, item.ref);
  const saved: Draft = { outcome: item.outcome ?? "", note: item.outcome_note ?? "", until: item.outcome_until ? localDay(new Date(item.outcome_until)) : "" };
  const [draft, setDraft] = useState(saved);
  const [removing, setRemoving] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  // Risk accepted: a future day, at most 365 days ahead (ruling 1).
  const [[tomorrow, latest]] = useState(() => acceptRange(Date.now()));
  const takes = editable && needsOutcome(item);
  const changed = draft.outcome !== saved.outcome || (draft.outcome !== "" && draft.note.trim() !== saved.note)
    || (draft.outcome === "accepted_risk" && draft.until !== saved.until);
  const save = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    await attempt(() => request("PUT", `${caseApi(c.case_id)}/items/${encodeURIComponent(item.item_id)}/outcome`, outcomeBody(draft.outcome, draft.note, draft.until)),
      draft.outcome === "" ? "Outcome cleared" : "Outcome saved");
    setBusy(false);
  };
  const remove = async () => {
    setBusy(true);
    setError(undefined);
    try {
      await request("DELETE", `${caseApi(c.case_id)}/items/${encodeURIComponent(item.item_id)}`);
      invalidate("/api/v1/case");
      toast("Item removed");
    } catch (e) {
      setError(caseErrorText(e));
      if (isStale(e)) invalidate("/api/v1/case");
    } finally {
      setBusy(false);
    }
  };
  return (
    <Fragment>
      <tr className="case-row">
        {shown("kind") && <td><span className="badge badge--plain">{kindLabel[kind] ?? item.kind}</span></td>}
        <td><div className="cell-two">
          <span className="truncate">{panel ? <ObjectLink to={panel}>{label}</ObjectLink> : label}</span>
          <ItemLine item={item} closed={c.status === "closed"} />
        </div></td>
        {shown("severity") && <td>{item.severity ? <SeverityBadge severity={item.severity} /> : <span className="subtle">—</span>}</td>}
        {shown("host") && <td>{item.agent_id && item.hostname
          ? <ObjectLink to={{ kind: "agent", id: item.agent_id }} className="object-link mono">{item.hostname}</ObjectLink> : <span className="subtle">{item.hostname ?? "—"}</span>}</td>}
        <td>{takes ? (
          <Select small label={`Outcome for ${label}`} value={draft.outcome} onChange={(outcome) => setDraft({ ...draft, outcome })}
            options={[{ value: "", label: "Needs an outcome" }, ...outcomeChoices(item).map((choice) => ({
              value: choice.value,
              label: `${choice.label}${choice.disabled ? " (evidence still there)" : ""}`,
              disabled: choice.disabled && choice.value !== item.outcome,
              hint: choice.hint,
            }))]} />
        ) : <span className="subtle">{item.outcome ? outcomeLabel[item.outcome] ?? item.outcome : "—"}</span>}</td>
        {editable && <td>
          <button type="button" className="icon-button" aria-label={`Remove ${label}`} title="Remove from case" aria-expanded={removing} onClick={() => setRemoving(!removing)}>
            <Icon name="close" size={16} /></button>
        </td>}
      </tr>
      {takes && changed && (
        <tr className="case-row__more"><td colSpan={span}>
          <form className="row row--wrap" onSubmit={(event) => void save(event)} aria-label={`Outcome for ${label}`}>
            {draft.outcome !== "" && (
              <input className="input grow" value={draft.note} onChange={(event) => setDraft({ ...draft, note: event.target.value })} required={outcomeNeedsNote(draft.outcome)} maxLength={4000}
                placeholder={outcomeNeedsNote(draft.outcome) ? "Why (required)" : "Note (optional)"} aria-label={`Note for ${label}`} />
            )}
            {draft.outcome === "accepted_risk" && (
              <input className="input" type="date" required min={tomorrow} max={latest} value={draft.until} onChange={(event) => setDraft({ ...draft, until: event.target.value })}
                aria-label={`Re-open date for ${label}`} />
            )}
            <button type="submit" className="button button--small button--primary" disabled={busy}>{busy ? "Saving…" : draft.outcome === "" ? "Clear outcome" : "Save outcome"}</button>
            <button type="button" className="button button--small button--ghost" onClick={() => setDraft(saved)}>Cancel</button>
          </form>
        </td></tr>
      )}
      {editable && removing && (
        <tr className="case-row__more"><td colSpan={span}>
          <div className="row row--wrap" role="group" aria-label={`Remove ${label}`}>
            <span className="grow">Remove {label} from this case? The timeline keeps that it was here.</span>
            {error && <span className="confirm__error" role="alert">{error}</span>}
            <button type="button" className="button button--small button--danger" disabled={busy} onClick={() => void remove()}>{busy ? "Removing…" : "Remove"}</button>
            <button type="button" className="button button--small button--ghost" onClick={() => setRemoving(false)}>Cancel</button>
          </div>
        </td></tr>
      )}
    </Fragment>
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
  const [wrap, width] = useWidth();
  const columns = ITEM_COLUMNS.filter((col) => !("hideBelow" in col) || width >= col.hideBelow);
  const shown = (key: string) => columns.some((col) => col.key === key);
  const span = columns.length + (editable ? 1 : 0);
  return (
    <Card id="items" flush title={<>Items <span className="subtle num">{detail.items.length.toLocaleString()}</span></>}
      aside={editable && !adding && <button type="button" className="button button--small" onClick={() => setAdding(true)}><Icon name="plus" size={14} /> Add item</button>}>
      {adding && <div className="person-card__body"><AddItem c={detail} onDone={() => setAdding(false)} /></div>}
      {detail.items.length === 0 ? <p className="person-card__body subtle">No items yet. Hosts, alarms, vulnerabilities, compliance findings, software, ports and services can all be added.</p> : (
        <div className="table-wrap" ref={wrap}>
          <table className="table table--compact" aria-label="Items">
            <thead><tr>
              {columns.map((col) => <th key={col.key} style={"width" in col ? { width: col.width } : undefined}>{col.label}</th>)}
              {editable && <th style={{ width: 44 }}><span className="sr-only">Remove</span></th>}
            </tr></thead>
            <tbody>
              {detail.items.map((item) => <ItemRow key={`${item.item_id}:${item.outcome}:${item.outcome_note}:${item.outcome_until}:${item.evidence_gone}`}
                c={detail} item={item} editable={editable} shown={shown} span={span} />)}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}
