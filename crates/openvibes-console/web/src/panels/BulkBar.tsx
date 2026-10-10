// The bar at the bottom of a list with selected rows: how many, the bulk
// actions the user may take, and Clear. Each action opens one small dialog
// (the note, the expiry, the person, or the case) whose confirm button
// names the count; the result says what changed and why anything was
// skipped (spec 2026-10-10-bulk-triage §3, §4).
import { type FormEvent, useState } from "react";

import { ApiError, invalidate, request, useAllPages, useResource } from "../api/client";
import type { CaseSummary, CaseUser } from "../api/types";
import { useSession } from "../app/session";
import { SelectField } from "../ui/Field";
import { Icon } from "../ui/Icon";
import { Select } from "../ui/Select";
import { toast } from "../ui/toast";
import { type BulkAction, type BulkForm, type BulkItem, type BulkKind, type BulkResult, NEW_CASE, bulkBody, bulkProblem, confirmLabel, resultText } from "./bulk";
import { caseNumber } from "./cases";
import { noteRequired } from "./triage";

const triagePermission = { alarms: "alarms.triage", compliance: "compliance.triage", vulnerabilities: "vulnerabilities.triage" } as const;

type Choice = { action: BulkAction; state?: string; label: string };
const stateChoices: Choice[] = [
  { action: "state", state: "mitigated", label: "Mitigate…" },
  { action: "state", state: "accepted_risk", label: "Accept risk…" },
  { action: "state", state: "false_positive", label: "False positive…" },
  { action: "state", state: "open", label: "Reopen" },
];

const day = (offset: number) => new Date(Date.now() + offset * 86_400_000).toISOString().slice(0, 10);

/** `items` builds the request's rows when an action is confirmed; `noun`
 * names them ("alarms"); `newCase` prefills a new case; `partial` says the
 * list holds only its first results. `inline`: the detail view's action
 * row, acting on every open host, with no count or Clear. */
export function BulkBar({ kind, noun, count, items, newCase, partial, onClear, inline }: {
  kind: BulkKind; noun: string; count: number; items: () => BulkItem[];
  newCase: () => { title: string; severity?: string | undefined }; partial?: boolean; onClear: () => void; inline?: boolean;
}) {
  const { can } = useSession();
  const [choice, setChoice] = useState<Choice | null>(null);
  if (count === 0 || !can(triagePermission[kind])) return null;
  const choices: Choice[] = [...stateChoices, { action: "assign", label: "Assign…" },
    ...(can("cases.manage") ? [{ action: "case" as const, label: "Add to case…" }] : []),
    ...(kind === "alarms" && can("alarms.suppress", true) ? [{ action: "suppress" as const, label: "Suppress…" }] : [])];
  return (
    <div className={inline ? "row row--wrap" : "bulk-bar bulk-bar--bottom"} role="region" aria-label={inline ? "Triage actions" : "Bulk actions"}>
      {!inline && <strong className="num">{count.toLocaleString()} selected</strong>}
      {partial && <span className="subtle">(of the first results only)</span>}
      {choices.map((c) => (
        <button key={c.label} type="button" className="button button--small" onClick={() => setChoice(c)}>{c.label}</button>
      ))}
      {!inline && <button type="button" className="button button--small button--ghost" onClick={onClear}>Clear</button>}
      {choice && <BulkDialog kind={kind} noun={noun} choice={choice} items={items} count={count} newCase={newCase}
        onClose={() => setChoice(null)} onDone={onClear} />}
    </div>
  );
}

function BulkDialog({ kind, noun, choice, items, count, newCase, onClose, onDone }: {
  kind: BulkKind; noun: string; choice: Choice; items: () => BulkItem[]; count: number;
  newCase: () => { title: string; severity?: string | undefined }; onClose: () => void; onDone: () => void;
}) {
  const { session } = useSession();
  const { action } = choice;
  const [form, setForm] = useState<BulkForm>(() => {
    const suggested = newCase();
    return { action, state: choice.state ?? "", note: "", acceptedUntil: day(90), assignee: "", caseId: "",
      newCaseTitle: suggested.title.slice(0, 120), newCaseSeverity: suggested.severity };
  });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const assignees = useResource<{ items: CaseUser[] }>(action === "assign" ? "/api/v1/cases/assignees" : null).data?.items;
  const cases = useAllPages<CaseSummary>(action === "case" ? "/api/v1/cases" : null);
  const set = (patch: Partial<BulkForm>) => { setForm((current) => ({ ...current, ...patch })); setError(undefined); };
  const me = session?.principal?.username;
  const people = assignees ?? (me ? [{ username: me, display_name: me }] : []);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    const problem = bulkProblem(form);
    if (problem) { setError(problem); return; }
    setBusy(true);
    try {
      const result = await request<BulkResult>("POST", `/api/v1/${kind}/bulk`, bulkBody(form, items()));
      const where = result.case_number != null ? ` in ${caseNumber(result.case_number)}` : "";
      toast(`${resultText(result)}${where}`, result.changed === 0 && result.skipped.length > 0);
      invalidate(`/api/v1/${kind}`);
      if (action === "case") invalidate("/api/v1/cases");
      if (kind === "alarms") invalidate("/api/v1/alarm-suppressions");
      onClose();
      onDone();
    } catch (failure) {
      setError(failure instanceof ApiError ? failure.message : "The bulk action failed");
    } finally {
      setBusy(false);
    }
  };

  const needsNote = (action === "state" && noteRequired.has(form.state)) || action === "suppress";
  const title = choice.label.replace(/…$/, "");
  return (
    <div className="palette-backdrop" onMouseDown={onClose}>
      <form className="palette bulk-dialog" role="dialog" aria-modal="true" aria-label={title} onSubmit={(event) => void submit(event)}
        onMouseDown={(event) => event.stopPropagation()} onKeyDown={(event) => { if (event.key === "Escape") onClose(); }}>
        <div className="row row--between"><h2>{title}: {count.toLocaleString()} {noun}</h2>
          <button type="button" className="icon-button" aria-label="Close" onClick={onClose}><Icon name="close" size={16} /></button></div>
        {action === "state" && form.state === "accepted_risk" && (
          <label className="field"><span>Accepted until</span>
            <input className="input" type="date" required min={day(1)} max={day(365)} value={form.acceptedUntil} onChange={(event) => set({ acceptedUntil: event.target.value })} />
          </label>
        )}
        {action === "assign" && (
          <SelectField label="Assignee">
            <Select label="Assignee" value={form.assignee} onChange={(assignee) => set({ assignee })}
              options={[{ value: "", label: "Unassigned" }, ...people.map((p) => ({ value: p.username, label: p.display_name || p.username }))]} />
          </SelectField>
        )}
        {action === "case" && (
          <SelectField label="Case">
            <Select label="Case" placeholder="Choose an open case" value={form.caseId} onChange={(caseId) => set({ caseId })}
              options={[{ value: NEW_CASE, label: "New case…" },
                ...(cases.data ?? []).filter((c) => c.status !== "closed").map((c) => ({ value: c.case_id, label: `${caseNumber(c.number)} ${c.title}` }))]} />
          </SelectField>
        )}
        {action === "case" && form.caseId === NEW_CASE && (
          <label className="field"><span>New case title</span>
            <input className="input" autoFocus maxLength={120} value={form.newCaseTitle} onChange={(event) => set({ newCaseTitle: event.target.value })} />
          </label>
        )}
        {action === "case" && <p className="subtle">Items already in another open case are skipped.</p>}
        {action === "suppress" && <p className="subtle">Closes these alarms and quiets new ones from the same rule and program, on every host.</p>}
        {(action === "state" || action === "suppress") && (
          <label className="field"><span>{needsNote ? "Note (required)" : "Note (optional)"}</span>
            <textarea className="input" rows={3} autoFocus value={form.note} onChange={(event) => set({ note: event.target.value })}
              placeholder={needsNote ? "Why: goes on every item's history" : undefined} />
          </label>
        )}
        {error && <p className="confirm__error" role="alert">{error}</p>}
        <div className="row row--end">
          <button type="button" className="button" onClick={onClose}>Cancel</button>
          <button type="submit" className="button button--primary" disabled={busy}>{busy ? "Applying…" : confirmLabel(form, count, noun)}</button>
        </div>
      </form>
    </div>
  );
}
