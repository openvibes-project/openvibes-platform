// The triage form's fields as the API wants them: an expiry only for
// accepted risk (through the end of the chosen local day), blanks as null.
// States that close or accept a finding; a change of many hosts to one of
// them must say why (the server refuses it without a note).
export const noteRequired = new Set(["mitigated", "accepted_risk", "false_positive"]);

// The server's workflow: a host keeps its state or moves one step forward.
const next: Record<string, string[]> = {
  open: ["investigating"],
  investigating: ["mitigated", "accepted_risk", "false_positive"],
};
const order = ["open", "investigating", "mitigated", "accepted_risk", "false_positive"];

/** States that every host in `from` may move to, in display order. */
export function allowedStates(from: string[]): string[] {
  return order.filter((to) => from.every((state) => state === to || (next[state] ?? []).includes(to)));
}

export type TriageForm = { state: string; assignee: string; note: string; acceptedUntil: string };

export function triageBody(form: TriageForm) {
  const [year, month, day] = form.acceptedUntil.split("-").map(Number);
  const until = form.state === "accepted_risk" && year && month && day ? new Date(year, month - 1, day, 23, 59, 59).toISOString() : null;
  return { state: form.state, assigned_to: form.assignee.trim() || null, note: form.note.trim() || null, accepted_until: until };
}
