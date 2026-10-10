// The triage actions (#253): Set state (a menu), Reopen (only when closed
// items are selected), the assignee (a picker with search, applied on
// pick) and Add to case. In a detail panel's header they act on the item
// or its open hosts (`inline`); under a list they are the bulk bar, with
// the count and Clear. Closing asks for a note in one small dialog whose
// button names the count; the toast says what changed and why anything was
// skipped (spec 2026-10-10-bulk-triage §3, §4).
import { type FormEvent, useEffect, useRef, useState } from "react";

import { ApiError, invalidate, request, useAllPages, useResource } from "../api/client";
import type { CaseSummary, CaseUser } from "../api/types";
import { useSession } from "../app/session";
import { SelectField } from "../ui/Field";
import { Icon } from "../ui/Icon";
import { MenuButton, type MenuItem } from "../ui/Menu";
import { Select } from "../ui/Select";
import { toast } from "../ui/toast";
import { type BulkAction, type BulkForm, type BulkItem, type BulkKind, type BulkResult, NEW_CASE, bulkBody, bulkProblem, confirmLabel, resultText } from "./bulk";
import { caseNumber } from "./cases";
import { noteRequired } from "./triage";

const triagePermission = { alarms: "alarms.triage", compliance: "compliance.triage", vulnerabilities: "vulnerabilities.triage" } as const;

type Choice = { action: BulkAction; state?: string; label: string };
const STATE_ITEMS: (MenuItem & { choice: Choice })[] = [
  { value: "mitigated", label: "Mitigate…", description: "Fixed or worked around; reopens if it comes back", dot: "var(--ok)",
    choice: { action: "state", state: "mitigated", label: "Mitigate" } },
  { value: "accepted_risk", label: "Accept risk…", description: "Accepted until a date, 90 days unless you change it", dot: "var(--info)",
    choice: { action: "state", state: "accepted_risk", label: "Accept risk" } },
  { value: "false_positive", label: "False positive…", description: "Not a real problem here", dot: "var(--text-3)",
    choice: { action: "state", state: "false_positive", label: "False positive" } },
];
const SUPPRESS_ITEM = { value: "suppress", label: "Suppress…", description: "Close them and quiet the same rule and program on every host", dot: "var(--text-3)",
  choice: { action: "suppress" as const, label: "Suppress" } };

/** The assignee picker's value for "nobody". */
const NOBODY = "__nobody";

const day = (offset: number) => new Date(Date.now() + offset * 86_400_000).toISOString().slice(0, 10);
const initials = (name: string) => name.split(/[\s._-]+/).filter(Boolean).slice(0, 2).map((w) => w[0]?.toUpperCase()).join("") || "?";
const avatar = (name: string | null) => <span className={name ? "initials" : "initials initials--none"} aria-hidden="true">{name ? initials(name) : "—"}</span>;

/** `items` builds the request's rows when an action is applied; `noun`
 * names them ("alarms"); `newCase` prefills a new case; `closed` counts
 * the closed ones among them (Reopen shows only then), `reopenItems` gives
 * just those; `assignee` is the current one when it is one item;
 * `stateLabel` renames Set state ("Set state: 12 open"); `partial` says the
 * list holds only its first results; `inline` draws the actions for a
 * panel header (no count or Clear); `without` leaves out actions the panel
 * offers elsewhere. */
export function BulkBar({ kind, noun, count, items, newCase, closed = 0, reopenItems, assignee, stateLabel, partial, onClear, inline, without = [] }: Readonly<{
  kind: BulkKind; noun: string; count: number; items: () => BulkItem[];
  newCase: () => { title: string; severity?: string | undefined };
  closed?: number; reopenItems?: () => BulkItem[]; assignee?: string | null; stateLabel?: string;
  partial?: boolean; onClear: () => void; inline?: boolean; without?: BulkAction[];
}>) {
  const { can, session } = useSession();
  const [choice, setChoice] = useState<Choice | null>(null);
  const [busy, setBusy] = useState(false);
  const people = useResource<{ items: CaseUser[] }>(can("cases.manage") ? "/api/v1/cases/assignees" : null).data?.items;
  if (count === 0 || !can(triagePermission[kind])) return null;

  const menu = [...STATE_ITEMS, ...(kind === "alarms" && !inline && can("alarms.suppress", true) && !without.includes("suppress") ? [SUPPRESS_ITEM] : [])];
  const me = session?.principal?.username;
  // The current assignee is listed even when the people list lacks them
  // (no cases.manage, or no longer assignable), so it shows with initials.
  const known = people ?? [];
  const listed = assignee && assignee !== me && !known.some((p) => p.username === assignee)
    ? [...known, { user_id: assignee, username: assignee, display_name: assignee }] : known;
  const others = listed.filter((p) => p.username !== me);
  const assignOptions = [
    { group: "", options: [
      ...(me ? [{ value: me, label: "Assign to me", hint: me, icon: avatar(me) }] : []),
      { value: NOBODY, label: "Unassigned", icon: avatar(null) },
    ] },
    ...(others.length > 0 ? [{ group: "People", options: others.map((p) => ({ value: p.username, label: p.display_name || p.username, hint: p.username, icon: avatar(p.display_name || p.username) })) }] : []),
  ];

  // Reopen and assign apply at once: no note is needed.
  const apply = async (body: Record<string, unknown>, rows: BulkItem[]) => {
    setBusy(true);
    try {
      const result = await request<BulkResult>("POST", `/api/v1/${kind}/bulk`, { ...body, items: rows });
      toast(resultText(result), result.changed === 0 && result.skipped.length > 0);
      invalidate(`/api/v1/${kind}`);
      invalidate("/api/v1/triage-history");
      if (!inline) onClear();
    } catch (error) {
      toast(error instanceof ApiError ? error.message : "The change failed", true);
    } finally {
      setBusy(false);
    }
  };
  const assign = (value: string) => void apply({ action: "assign", assignee: value === NOBODY ? null : value }, items());
  const reopen = () => void apply({ action: "state", state: "open" }, (reopenItems ?? items)());

  const actions = (
    <>
      <MenuButton label={stateLabel ?? "Set state"} icon="check" items={menu} disabled={busy}
        onPick={(value) => setChoice(menu.find((m) => m.value === value)?.choice ?? null)} />
      {closed > 0 && !inline && (
        <button type="button" className="button" disabled={busy} onClick={reopen}><Icon name="refresh" size={15} />Reopen {closed.toLocaleString()} closed</button>
      )}
      <Select button search label={inline && assignee !== undefined ? "Assignee" : `Assign ${noun}`} placeholder="Assign"
        value={assignee === undefined ? "" : assignee ?? NOBODY} onChange={assign} disabled={busy}
        options={assignOptions} unknownLabel={(v) => v} />
      {can("cases.manage") && !without.includes("case") && (
        <button type="button" className={inline ? "button push" : "button"} disabled={busy} onClick={() => setChoice({ action: "case", label: "Add to case" })}>
          <Icon name="cases" size={15} />Add to case
        </button>
      )}
      {choice && <BulkDialog kind={kind} noun={noun} choice={choice} items={items} count={count} newCase={newCase}
        onClose={() => setChoice(null)} onDone={inline ? () => undefined : onClear} />}
    </>
  );
  if (inline) return actions;
  return (
    <section className="bulk-bar bulk-bar--bottom" aria-label="Bulk actions">
      <strong className="num">{count.toLocaleString()} selected</strong>
      {partial && <span className="subtle">(of the first results only)</span>}
      {actions}
      <button type="button" className="button button--ghost push" onClick={onClear}>Clear</button>
    </section>
  );
}

function BulkDialog({ kind, noun, choice, items, count, newCase, onClose, onDone }: Readonly<{
  kind: BulkKind; noun: string; choice: Choice; items: () => BulkItem[]; count: number;
  newCase: () => { title: string; severity?: string | undefined }; onClose: () => void; onDone: () => void;
}>) {
  const { action } = choice;
  const [form, setForm] = useState<BulkForm>(() => {
    const suggested = newCase();
    return { action, state: choice.state ?? "", note: "", acceptedUntil: day(90), assignee: "", caseId: "",
      newCaseTitle: suggested.title.slice(0, 120), newCaseSeverity: suggested.severity };
  });
  const [busy, setBusy] = useState(false);
  const [problemText, setProblemText] = useState<string>();
  const dialog = useRef<HTMLDialogElement>(null);
  useEffect(() => { if (!dialog.current?.open) dialog.current?.showModal(); }, []);
  const cases = useAllPages<CaseSummary>(action === "case" ? "/api/v1/cases" : null);
  const set = (patch: Partial<BulkForm>) => { setForm((current) => ({ ...current, ...patch })); setProblemText(undefined); };

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    const problem = bulkProblem(form);
    if (problem) { setProblemText(problem); return; }
    setBusy(true);
    try {
      const result = await request<BulkResult>("POST", `/api/v1/${kind}/bulk`, bulkBody(form, items()));
      const where = result.case_number != null ? ` in ${caseNumber(result.case_number)}` : "";
      toast(`${resultText(result)}${where}`, result.changed === 0 && result.skipped.length > 0);
      invalidate(`/api/v1/${kind}`);
      invalidate("/api/v1/triage-history");
      if (action === "case") invalidate("/api/v1/cases");
      if (kind === "alarms") invalidate("/api/v1/alarm-suppressions");
      onClose();
      onDone();
    } catch (error) {
      setProblemText(error instanceof ApiError ? error.message : "The change failed");
    } finally {
      setBusy(false);
    }
  };

  const needsNote = (action === "state" && noteRequired.has(form.state)) || action === "suppress";
  return (
    // A native modal dialog: focus trapped, Escape closes it (onClose).
    <dialog ref={dialog} className="palette bulk-modal" aria-label={choice.label} onClose={onClose}>
      <form className="bulk-dialog stack" onSubmit={(event) => void submit(event)}>
        <div className="row row--between"><h2>{choice.label}: {count.toLocaleString()} {noun}</h2>
          <button type="button" className="icon-button" aria-label="Close" onClick={onClose}><Icon name="close" size={16} /></button></div>
        {action === "state" && form.state === "accepted_risk" && (
          <label className="field"><span>Accepted until</span>
            <input className="input" type="date" required min={day(1)} max={day(365)} value={form.acceptedUntil} onChange={(event) => set({ acceptedUntil: event.target.value })} />
          </label>
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
          <label className="field"><span>{needsNote ? "Why (required)" : "Note (optional)"}</span>
            <textarea className="input" rows={3} autoFocus value={form.note} onChange={(event) => set({ note: event.target.value })}
              placeholder={needsNote ? "Goes on every item's history" : undefined} />
          </label>
        )}
        {problemText && <p className="confirm__error" role="alert">{problemText}</p>}
        <div className="row row--end">
          <button type="button" className="button button--ghost" onClick={onClose}>Cancel</button>
          <button type="submit" className="button button--primary" disabled={busy}>{busy ? "Applying…" : confirmLabel(form, count, noun)}</button>
        </div>
      </form>
    </dialog>
  );
}
