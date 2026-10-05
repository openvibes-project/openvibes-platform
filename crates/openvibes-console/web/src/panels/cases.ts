// Cases, the parts that need no React: the item kinds and where each opens,
// the list's query and filters, the rules that decide when a case can close,
// the request bodies and how the timeline and the API's refusals read.
import { ApiError } from "../api/client";
import type { CaseEvent, CaseItem, CaseSummary } from "../api/types";
import type { PanelRef } from "../app/location";
import { date, plural } from "../ui/format";
import type { IconName } from "../ui/Icon";
import { matches } from "../ui/table";

export const CASE_KINDS = ["alarm", "finding", "vulnerability", "host", "software"] as const;
export type CaseKind = (typeof CASE_KINDS)[number];
export const isCaseKind = (value: string): value is CaseKind => (CASE_KINDS as readonly string[]).includes(value);
/** Kinds that can be in one open case only, and that need an outcome to close. */
export const EXCLUSIVE_KINDS: ReadonlySet<string> = new Set(["alarm", "finding", "vulnerability"]);

export const kindLabel: Record<CaseKind, string> = { alarm: "Alarm", finding: "Finding", vulnerability: "Vulnerability", host: "Host", software: "Software" };
export const kindIcon: Record<CaseKind, IconName> = { alarm: "alarm", finding: "findings", vulnerability: "vulnerabilities", host: "agents", software: "package" };
/** What to paste to add an item by id, per kind. */
export const refHint: Record<CaseKind, string> = {
  alarm: "Alarm id, e.g. 9001",
  finding: "agent-id/rule-set/rule-id",
  vulnerability: "agent-id/advisory-id",
  host: "Agent id, e.g. agent-00008",
  software: "manager/name, e.g. rpm/openssh",
};
export const statusLabel: Record<string, string> = { open: "Open", investigating: "Investigating", closed: "Closed" };
export const statusTone: Record<string, string> = { open: "bad", investigating: "warn", closed: "ok" };
export const resolutionLabel: Record<string, string> = { mitigated: "Mitigated", false_positive: "False positive", accepted_risk: "Accepted risk" };
export const outcomeLabel: Record<string, string> = { resolved: "Resolved", false_positive: "False positive", accepted_risk: "Accepted risk" };
export const severities = ["critical", "high", "medium", "low"] as const;

export const caseNumber = (number: number) => `C-${number}`;

/** The pieces of an item's id: finding `agent/rule_set/rule` (the rule set may be empty), vulnerability `agent/advisory`. */
export function splitRef(ref: string): [string, string] {
  const split = ref.indexOf("/");
  return split < 0 ? [ref, ""] : [ref.slice(0, split), ref.slice(split + 1)];
}

export const findingRef = (agentId: string, ruleSetId: string, ruleId: string) => `${agentId}/${ruleSetId}/${ruleId}`;
export const vulnerabilityRef = (agentId: string, advisoryId: string) => `${agentId}/${advisoryId}`;

/** The existing panel that shows an item, with the id that panel already uses. */
export function itemPanel(kind: string, ref: string): PanelRef | undefined {
  switch (kind) {
    case "alarm": return { kind: "alarm", id: ref };
    case "finding": return { kind: "finding", id: splitRef(ref)[1] };
    case "vulnerability": return { kind: "advisory", id: splitRef(ref)[1] };
    case "host": return { kind: "agent", id: ref };
    case "software": return { kind: "package", id: ref };
    default: return undefined;
  }
}

/** A short name for an item when its own title is gone (a removed item in the timeline). */
export function refLabel(kind: string, ref: string): string {
  switch (kind) {
    case "alarm": return `#${ref}`;
    case "finding": { const [agent, rest] = splitRef(ref); return `${splitRef(rest)[1]} on ${agent}`; }
    case "vulnerability": { const [agent, advisory] = splitRef(ref); return `${advisory} on ${agent}`; }
    case "software": return splitRef(ref)[1] || ref;
    default: return ref;
  }
}

/** The API path for the list's filters; the text filter stays local. */
export function caseQuery(params: URLSearchParams): string {
  const query = new URLSearchParams();
  const status = params.get("status");
  if (status && ["open", "investigating", "closed", "all"].includes(status)) query.set("status", status);
  const severity = params.get("severity");
  if (severity && (severities as readonly string[]).includes(severity)) query.set("severity", severity);
  const assignee = params.get("assignee");
  if (assignee === "me" || assignee === "none") query.set("assignee", assignee);
  const text = query.toString();
  return text === "" ? "/api/v1/cases" : `/api/v1/cases?${text}`;
}

/** The loaded cases that match the text filter (title, `C-104`, assignee). */
export function selectCases(loaded: readonly CaseSummary[], params: URLSearchParams): CaseSummary[] {
  const q = params.get("q") ?? "";
  return loaded.filter((c) => matches([c.title, caseNumber(c.number), c.assignee?.username, c.assignee?.display_name ?? "unassigned"], q));
}

export const needsOutcome = (item: Pick<CaseItem, "kind">) => EXCLUSIVE_KINDS.has(item.kind);

/** Items that stop the case from closing: no outcome yet, or "resolved" while the evidence is back. */
export function blockingItems(items: readonly CaseItem[]): CaseItem[] {
  return items.filter((item) => needsOutcome(item) && (item.outcome == null || (item.outcome === "resolved" && !item.evidence_gone)));
}

export type OutcomeChoice = { value: string; label: string; disabled: boolean; hint: string | undefined };

/** The outcomes an item can take: "resolved" only while its evidence is gone. */
export function outcomeChoices(item: Pick<CaseItem, "evidence_gone">): OutcomeChoice[] {
  return [
    { value: "resolved", label: "Resolved", disabled: !item.evidence_gone, hint: item.evidence_gone ? undefined : "Only when the evidence is gone" },
    { value: "false_positive", label: "False positive", disabled: false, hint: undefined },
    { value: "accepted_risk", label: "Accepted risk", disabled: false, hint: undefined },
  ];
}

/** Outcomes other than "resolved" need a note saying why. */
export const outcomeNeedsNote = (outcome: string) => outcome !== "resolved";

/** The end of a local day (`YYYY-MM-DD` from a date input) as the API wants it. */
export function endOfLocalDay(day: string): string | null {
  const [year, month, d] = day.split("-").map(Number);
  return year && month && d ? new Date(year, month - 1, d, 23, 59, 59).toISOString() : null;
}

export type CloseForm = { resolution: string; note: string; acceptedUntil: string };

/** What still prevents closing, in words; empty when the case can close. */
export function closeProblems(form: CloseForm, items: readonly CaseItem[], now = Date.now()): string[] {
  const problems: string[] = [];
  if (!(form.resolution in resolutionLabel)) problems.push("Choose how the case ended.");
  if (form.note.trim() === "") problems.push("Add a note saying why.");
  if (form.resolution === "accepted_risk") {
    const until = endOfLocalDay(form.acceptedUntil);
    if (until === null) problems.push("Choose the date the risk is accepted until.");
    else if (Date.parse(until) <= now) problems.push("The date must be in the future.");
  }
  const blocking = blockingItems(items);
  if (blocking.length > 0) problems.push(`${plural(blocking.length, "item")} still ${blocking.length === 1 ? "needs" : "need"} an outcome.`);
  return problems;
}

export type CaseFields = { title: string; severity: string; assignee: string };
export type Ending = { resolution: string; note: string; accepted_until: string | null };

/** The PUT body: the API replaces every editable field, so all are sent. */
export function updateBody(fields: CaseFields, status: string, ending?: Ending) {
  return {
    title: fields.title.trim(), severity: fields.severity, status, assignee_user_id: fields.assignee || null,
    ...(status === "closed" && ending ? { resolution: ending.resolution, resolution_note: ending.note.trim(), accepted_until: ending.accepted_until } : {}),
  };
}

/** The closing form as an `Ending` (accepted risk carries its date). */
export function endingOf(form: CloseForm): Ending {
  return { resolution: form.resolution, note: form.note, accepted_until: form.resolution === "accepted_risk" ? endOfLocalDay(form.acceptedUntil) : null };
}

type Detail = Record<string, unknown>;
const text = (value: unknown) => typeof value === "string" ? value : undefined;

/** One timeline entry as a sentence after the actor's name; a note's text is shown by the caller. */
export function eventText(event: CaseEvent, titleOf: (itemId: string) => string | undefined = () => undefined): string {
  const d = event.detail as Detail;
  const item = () => {
    const kind = text(d.item_kind) ?? "item";
    const label = titleOf(text(d.item_id) ?? "") ?? refLabel(kind, text(d.item_ref) ?? "");
    return `${kind} ${label}`;
  };
  switch (event.kind) {
    case "created": return "opened the case";
    case "note": return "added a note";
    case "status": return `moved the case from ${statusLabel[text(d.from) ?? ""] ?? text(d.from) ?? "?"} to ${statusLabel[text(d.to) ?? ""] ?? text(d.to) ?? "?"}`;
    case "assigned": return text(d.to) ? `assigned the case to ${text(d.to)}` : `unassigned the case${text(d.from) ? ` (was ${text(d.from)})` : ""}`;
    case "severity": return `changed the severity from ${text(d.from) ?? "?"} to ${text(d.to) ?? "?"}`;
    case "item_added": return `added ${item()}`;
    case "item_removed": return `removed ${item()}`;
    case "item_outcome": return text(d.to) ? `marked ${item()} as ${(outcomeLabel[text(d.to) ?? ""] ?? "").toLowerCase()}` : `cleared the outcome of ${item()}`;
    case "resolved": {
      const until = text(d.accepted_until);
      return `closed the case as ${(resolutionLabel[text(d.resolution) ?? ""] ?? "resolved").toLowerCase()}${until ? ` until ${date(until)}` : ""}`;
    }
    case "reopened":
      if (d.reason === "accepted_risk_expired") return "reopened the case because the accepted risk ran out";
      return d.reason === "evidence_returned" ? "reopened the case because the evidence returned" : "reopened the case";
    default: return event.kind;
  }
}

/** What to tell the user about a refused request. */
export function caseErrorText(error: unknown): string {
  if (!(error instanceof ApiError)) return "Something went wrong; try again";
  if (error.status === 412) return "Someone else changed this case. It was reloaded; review it and try again.";
  if (error.code === "item_in_case") return error.caseNumber === undefined ? error.message : `${error.message}: ${caseNumber(error.caseNumber)}`;
  const field = error.fieldErrors?.[0];
  return field ? field.message : error.message;
}

/** True when a refusal means the data on screen is out of date. */
export const isStale = (error: unknown) => error instanceof ApiError && (error.status === 412 || error.status === 404 || error.code === "items_unresolved" || error.code === "evidence_present");

/** A local date as `YYYY-MM-DD`, the value of a date input. */
export function localDay(value: Date): string {
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${value.getFullYear()}-${pad(value.getMonth() + 1)}-${pad(value.getDate())}`;
}

/** The status badge's text and tone: a closed case also says how it ended. */
export function statusBadge(status: string, resolution: string | null | undefined): { label: string; tone: string } {
  if (status !== "closed") return { label: statusLabel[status] ?? status, tone: statusTone[status] ?? "plain" };
  const tone = resolution === "mitigated" ? "ok" : resolution === "accepted_risk" ? "info" : "plain";
  return { label: resolution ? `Closed · ${(resolutionLabel[resolution] ?? resolution).toLowerCase()}` : "Closed", tone };
}
