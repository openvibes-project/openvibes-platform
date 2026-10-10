// One bulk action on selected alarms, findings or vulnerabilities (triage
// v2, spec 2026-10-10-bulk-triage §4): the request body the server takes,
// the checks it would refuse with, and the result as one sentence.
import { severityOrder } from "../ui/format";
import { noteRequired, triageBody } from "./triage";

export type BulkKind = "alarms" | "compliance" | "vulnerabilities";
export type BulkAction = "state" | "assign" | "case" | "suppress";

/** One selected row, as the server wants it for its list. */
export type BulkItem = { id?: string; rule_set_id?: string; rule_id?: string; advisory_id?: string; agent_id?: string };

export type BulkForm = {
  action: BulkAction;
  state: string;
  note: string;
  acceptedUntil: string;
  assignee: string;
  /** An open case's id, or NEW_CASE. */
  caseId: string;
  newCaseTitle: string;
  /** The selection's highest item severity, for a new case. */
  newCaseSeverity?: string | undefined;
};

export const NEW_CASE = "__new";

export type BulkResult = { changed: number; skipped: { id: string; reason: string }[]; case_id?: string | null; case_number?: number | null };

function stateProblem(form: BulkForm, note: string): string | null {
  if (!form.state) return "Choose a state";
  if (noteRequired.has(form.state) && !note) return "Closing needs a note: say why";
  if (form.state === "accepted_risk" && !form.acceptedUntil) return "Choose until when the risk is accepted";
  return null;
}

function caseProblem(form: BulkForm): string | null {
  if (!form.caseId) return "Choose a case";
  if (form.caseId === NEW_CASE && !form.newCaseTitle.trim()) return "Give the new case a title";
  return null;
}

/** Why the server would refuse this form, or null. */
export function bulkProblem(form: BulkForm): string | null {
  const note = form.note.trim();
  switch (form.action) {
    case "state": return stateProblem(form, note);
    case "suppress": return note ? null : "Quieting needs a note: say why";
    case "case": return caseProblem(form);
    case "assign": return null;
  }
}

export function bulkBody(form: BulkForm, items: BulkItem[]) {
  const note = form.note.trim() || null;
  switch (form.action) {
    case "state": {
      const triage = triageBody({ state: form.state, assignee: "", note: form.note, acceptedUntil: form.acceptedUntil });
      return { action: "state", state: form.state, note, accepted_until: triage.accepted_until, items };
    }
    case "assign":
      return { action: "assign", assignee: form.assignee || null, items };
    case "case":
      return form.caseId === NEW_CASE
        ? { action: "case", new_case_title: form.newCaseTitle.trim(), new_case_severity: form.newCaseSeverity ?? null, items }
        : { action: "case", case_id: form.caseId, items };
    case "suppress":
      return { action: "suppress", note, items };
  }
}

const verbs: Record<string, string> = { open: "Reopen", mitigated: "Mitigate", accepted_risk: "Accept risk for", false_positive: "Mark as false positive:" };

/** The confirm button, naming the count: "Mitigate 12 alarms". */
export function confirmLabel(form: BulkForm, count: number, noun: string): string {
  const what = `${count.toLocaleString()} ${noun}`;
  switch (form.action) {
    case "state": return `${verbs[form.state] ?? "Set"} ${what}`;
    case "assign": return form.assignee ? `Assign ${what}` : `Unassign ${what}`;
    case "case": return `Add ${what} to the case`;
    case "suppress": return `Quiet ${what}`;
  }
}

/** "12 changed; 3 skipped (2 in another open case, 1 not found or out of scope)". */
export function resultText(result: BulkResult): string {
  const changed = `${result.changed.toLocaleString()} changed`;
  if (result.skipped.length === 0) return changed;
  const reasons = new Map<string, number>();
  for (const skip of result.skipped) reasons.set(skip.reason, (reasons.get(skip.reason) ?? 0) + 1);
  const why = [...reasons].map(([reason, n]) => `${n.toLocaleString()} ${reason}`).join(", ");
  return `${changed}; ${result.skipped.length.toLocaleString()} skipped (${why})`;
}

/** The most severe of these severities (for a new case). */
export function highest(severities: readonly string[]): string | undefined {
  return [...severities].sort((a, b) => (severityOrder[a] ?? 9) - (severityOrder[b] ?? 9))[0];
}
