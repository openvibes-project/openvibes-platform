// The demo cases' rules that need no state: the problem answers and their
// messages (cases/responses.rs), and the checks the store makes on titles,
// notes, ids, outcomes and closing (platform-store console_cases).
import type { CaseKind } from "../panels/cases/cases";

export type Result = { status: number; body?: unknown; etag?: string };
export type Body = Record<string, unknown>;

export const DAY = 86_400_000;
/** Accepted risk's re-open date is at most this far ahead (MAX_ACCEPT_DAYS). */
export const MAX_ACCEPT_DAYS = 365;
/** Closed cases whose resolved evidence returns reopen within this window (EVIDENCE_WATCH_DAYS). */
export const EVIDENCE_WATCH_DAYS = 30;
/** An item's outcomes (step 5d ruling 1). */
export const OUTCOMES = ["resolved", "false_positive", "accepted_risk", "confirmed_malicious", "expected"];

const messages: Record<string, string> = {
  invalid_title: "Use 1 to 120 characters, without control characters",
  invalid_severity: "Use critical, high, medium or low",
  invalid_status: "Use open, investigating or closed",
  invalid_kind: "Use alarm, compliance_finding, vulnerability, host, software or port",
  invalid_ref: "The id does not have the shape of this kind of item",
  too_many_items: "A case is created with at most 50 items",
  closing_note_required: "A closing note is required to close a case",
  closing_note_not_allowed: "Only closing a case takes a closing note",
  invalid_note: "Use 1 to 4000 characters of plain text",
  note_required: "A note is required for this outcome",
  invalid_outcome: "Use resolved, false_positive, accepted_risk, confirmed_malicious or expected",
  outcome_not_applicable: "Hosts, software and ports need no outcome",
  outcome_until_required: "Accepted risk needs a re-open date",
  outcome_until_past: "The date must be in the future",
  outcome_until_too_far: "The date must be within 365 days",
  outcome_until_not_allowed: "Only accepted risk has a re-open date",
  invalid_timestamp: "Use an RFC 3339 time",
  assignee_unavailable: "The assignee must be an enabled user who can read cases",
};

export const problem = (status: number, code: string, title: string, extra: Body = {}): Result =>
  ({ status, body: { status, code, title, request_id: "demo", ...extra } });
export const invalid = (field: string, code: string): Result =>
  problem(422, "invalid_case", "The request is invalid", { field_errors: [{ field, code, message: messages[code] ?? "The value is not valid" }] });
export const badBody = () => problem(400, "invalid_request", "The request body is invalid");
/** A request field step 5d removed (responses.rs removed_field). */
export const removedField = (field: string) => problem(400, "invalid_request", "The request body is invalid",
  { field_errors: [{ field, code: "not_supported", message: "Cases close with a closing note only; each item carries its outcome" }] });
export const notFound = () => problem(404, "case_not_found", "Case not found");
export const itemNotFound = () => problem(404, "item_not_found", "Item not found");
export const closed = () => problem(409, "case_closed", "The case is closed; reopen it first");

export const hasControl = (value: string) => [...value].some((ch) => ch < " " && ch !== "\n" && ch !== "\t" && ch !== "\r");
export const titleOk = (title: string) => title.length >= 1 && [...title].length <= 120 && !hasControl(title);
export const noteOk = (note: string) => note.trim() !== "" && [...note].length <= 4000 && !hasControl(note);
export const severityOk = (severity: string) => ["critical", "high", "medium", "low"].includes(severity);
const identifier = /^[\w.:-]{1,128}$/;
const freeText = (value: string) => value.length >= 1 && value.length <= 256 && !hasControl(value);

/** The shape each kind's id has in the console's panels. */
export function refOk(kind: CaseKind, ref: string): boolean {
  const [head = "", ...rest] = ref.split("/");
  switch (kind) {
    case "alarm": return /^[1-9]\d{0,17}$/.test(ref);
    case "compliance_finding": return rest.length === 2 && identifier.test(head) && (rest[0] === "" || identifier.test(rest[0] ?? "")) && identifier.test(rest[1] ?? "");
    case "vulnerability": return rest.length >= 1 && identifier.test(head) && freeText(rest.join("/"));
    case "host": return identifier.test(ref);
    case "software": return rest.length >= 1 && identifier.test(head) && freeText(rest.join("/"));
    case "port": return rest.length === 1 && (head === "tcp" || head === "udp") && /^[1-9]\d{0,4}$/.test(rest[0] ?? "") && Number(rest[0]) <= 65535;
    case "service": return ref.length >= 1 && ref.length <= 200 && !hasControl(ref) && !ref.includes("/");
  }
}

export const caseSeverityOf = (severity: string | null | undefined) =>
  ({ critical: "critical", high: "high", important: "high", medium: "medium", moderate: "medium", low: "low", info: "low", unrated: "low" } as Record<string, string>)[severity ?? ""];
export const rank = (severity: string) => ["low", "medium", "high", "critical"].indexOf(severity);
export const defaultSeverity = (severities: (string | null)[]) =>
  severities.map(caseSeverityOf).filter((s): s is string => s !== undefined).sort((a, b) => rank(b) - rank(a))[0] ?? "medium";

/** An outcome's own fields (outcomes.rs outcome_valid): [field, code] when wrong. */
export function outcomeError(outcome: string, note: string | null, until: number | null, now: number): [string, string] | null {
  if (!OUTCOMES.includes(outcome)) return ["outcome", "invalid_outcome"];
  if (note === null && outcome !== "resolved") return ["note", "note_required"];
  if (note !== null && !noteOk(note)) return ["note", "invalid_note"];
  if (outcome === "accepted_risk") {
    if (until === null) return ["outcome_until", "outcome_until_required"];
    if (until <= now) return ["outcome_until", "outcome_until_past"];
    if (until > now + MAX_ACCEPT_DAYS * DAY) return ["outcome_until", "outcome_until_too_far"];
  } else if (until !== null) return ["outcome_until", "outcome_until_not_allowed"];
  return null;
}

/** The closing note a new status takes (close.rs closing_valid): required with `closed`, absent otherwise. */
export function closingError(status: string, note: string | null): [string, string] | null {
  if (status !== "closed") return note === null ? null : ["closing_note", "closing_note_not_allowed"];
  if (note === null) return ["closing_note", "closing_note_required"];
  return noteOk(note) ? null : ["closing_note", "invalid_note"];
}
