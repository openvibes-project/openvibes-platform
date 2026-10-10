// The bar over a list with selected rows: how many, the bulk actions the
// user may take, and Clear. Each action opens one dialog (state with its
// note and expiry, assignee, case, or quiet); the result says what changed
// and why anything was skipped (spec 2026-10-10-bulk-triage §4).
import { type FormEvent, useState } from "react";

import { ApiError, invalidate, request, useAllPages, useResource } from "../api/client";
import type { CaseSummary, CaseUser } from "../api/types";
import { useSession } from "../app/session";
import { SelectField } from "../ui/Field";
import { triageLabel } from "../ui/format";
import { Icon } from "../ui/Icon";
import { Select } from "../ui/Select";
import { toast } from "../ui/toast";
import { type BulkAction, type BulkForm, type BulkItem, type BulkKind, type BulkResult, NEW_CASE, bulkBody, bulkProblem, resultText } from "./bulk";
import { caseNumber } from "./cases";
import { noteRequired, triageStates } from "./triage";

const triagePermission = { alarms: "alarms.triage", compliance: "compliance.triage", vulnerabilities: "vulnerabilities.triage" } as const;

const titles: Record<BulkAction, string> = { state: "Set triage state", assign: "Assign", case: "Add to case", suppress: "Quiet these alarms" };

export function BulkBar({ kind, items, count, onClear }: { kind: BulkKind; items: () => BulkItem[]; count: number; onClear: () => void }) {
  const { can } = useSession();
  const [action, setAction] = useState<BulkAction | null>(null);
  if (count === 0 || !can(triagePermission[kind])) return null;
  const actions: BulkAction[] = ["state", "assign",
    ...(can("cases.manage") ? ["case" as const] : []),
    ...(kind === "alarms" && can("alarms.suppress", true) ? ["suppress" as const] : [])];
  return (
    <div className="bulk-bar" role="region" aria-label="Bulk actions">
      <strong className="num">{count.toLocaleString()} selected</strong>
      {actions.map((a) => (
        <button key={a} type="button" className="button button--small" onClick={() => setAction(a)}>{titles[a]}</button>
      ))}
      <button type="button" className="button button--small button--ghost" onClick={onClear}>Clear</button>
      {action && <BulkDialog kind={kind} action={action} items={items} count={count} onClose={() => setAction(null)} onDone={onClear} />}
    </div>
  );
}

function BulkDialog({ kind, action, items, count, onClose, onDone }: {
  kind: BulkKind; action: BulkAction; items: () => BulkItem[]; count: number; onClose: () => void; onDone: () => void;
}) {
  const { session } = useSession();
  const [form, setForm] = useState<BulkForm>({ action, state: "mitigated", note: "", acceptedUntil: "", assignee: "", caseId: "", newCaseTitle: "" });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const [tomorrow] = useState(() => new Date(Date.now() + 86_400_000).toISOString().slice(0, 10));
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
  return (
    <div className="palette-backdrop" onMouseDown={onClose}>
      <form className="palette bulk-dialog" role="dialog" aria-modal="true" aria-label={titles[action]} onSubmit={(event) => void submit(event)}
        onMouseDown={(event) => event.stopPropagation()} onKeyDown={(event) => { if (event.key === "Escape") onClose(); }}>
        <div className="row row--between"><h2>{titles[action]}: {count.toLocaleString()} {count === 1 ? "item" : "items"}</h2>
          <button type="button" className="icon-button" aria-label="Close" onClick={onClose}><Icon name="close" size={16} /></button></div>
        {action === "state" && (
          <SelectField label="New state">
            <Select label="New state" value={form.state} onChange={(state) => set({ state })}
              options={triageStates.map((value) => ({ value, label: triageLabel[value] ?? value }))} />
          </SelectField>
        )}
        {action === "state" && form.state === "accepted_risk" && (
          <label className="field"><span>Accepted until</span>
            <input className="input" type="date" required min={tomorrow} value={form.acceptedUntil} onChange={(event) => set({ acceptedUntil: event.target.value })} />
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
            <textarea className="input" rows={3} value={form.note} onChange={(event) => set({ note: event.target.value })}
              placeholder={needsNote ? "Why: goes on every item" : undefined} />
          </label>
        )}
        {error && <p className="confirm__error" role="alert">{error}</p>}
        <div className="row row--end">
          <button type="button" className="button" onClick={onClose}>Cancel</button>
          <button type="submit" className="button button--primary" disabled={busy}>{busy ? "Applying…" : "Apply"}</button>
        </div>
      </form>
    </div>
  );
}
