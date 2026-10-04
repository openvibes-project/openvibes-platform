import { describe, expect, it } from "vitest";

import { ApiError } from "../api/client";
import type { CaseEvent, CaseItem, CaseSummary } from "../api/types";
import { blockingItems, caseErrorText, caseQuery, closeProblems, endOfLocalDay, endingOf, eventText, findingRef, itemPanel, outcomeChoices, refLabel, selectCases, updateBody, vulnerabilityRef } from "./cases";

const item = (over: Partial<CaseItem>): CaseItem => ({
  item_id: "i", kind: "alarm", ref: "1", active: true, added_at: "2026-01-01T00:00:00Z", added_by: { user_id: "u", username: "sam", display_name: "Sam" },
  evidence_gone: false, ...over,
});
const summary = (over: Partial<CaseSummary>): CaseSummary => ({
  case_id: "c", number: 104, title: "SSH on web-02", status: "open", severity: "high", opened_by: { user_id: "u", username: "sam", display_name: "Sam" },
  created_at: "", updated_at: "", version: 1, item_count: 1, pending_item_count: 1, ...over,
});
const event = (kind: string, detail: Record<string, unknown>, body: string | null = null) => ({ event_id: 1, at: "", kind, body, detail } as unknown as CaseEvent);

describe("itemPanel", () => {
  it("opens each item in the panel that already shows it, with that panel's id", () => {
    expect(itemPanel("alarm", "9001")).toEqual({ kind: "alarm", id: "9001" });
    expect(itemPanel("finding", findingRef("agent-1", "hardening-ssh", "SSH-002"))).toEqual({ kind: "finding", id: "hardening-ssh/SSH-002" });
    expect(itemPanel("finding", "agent-1//LNX-1")).toEqual({ kind: "finding", id: "/LNX-1" });
    expect(itemPanel("vulnerability", vulnerabilityRef("agent-1", "FEDORA-2026-3a2036b8"))).toEqual({ kind: "advisory", id: "FEDORA-2026-3a2036b8" });
    expect(itemPanel("host", "agent-1")).toEqual({ kind: "agent", id: "agent-1" });
    expect(itemPanel("software", "rpm/openssh")).toEqual({ kind: "package", id: "rpm/openssh" });
    expect(itemPanel("software", "deb/lib/x")).toEqual({ kind: "package", id: "deb/lib/x" });
    expect(itemPanel("port", "tcp/22")).toBeUndefined();
  });

  it("names an item by its id when the object is gone", () => {
    expect(refLabel("alarm", "9001")).toBe("#9001");
    expect(refLabel("finding", "agent-1/hardening-ssh/SSH-002")).toBe("SSH-002 on agent-1");
    expect(refLabel("vulnerability", "agent-1/FEDORA-1")).toBe("FEDORA-1 on agent-1");
    expect(refLabel("software", "rpm/openssh")).toBe("openssh");
    expect(refLabel("host", "agent-1")).toBe("agent-1");
  });
});

describe("list filters", () => {
  it("sends status, severity and assignee to the API and ignores anything else", () => {
    expect(caseQuery(new URLSearchParams())).toBe("/api/v1/cases");
    expect(caseQuery(new URLSearchParams("status=all&severity=high&assignee=me&q=ssh"))).toBe("/api/v1/cases?status=all&severity=high&assignee=me");
    expect(caseQuery(new URLSearchParams("status=gone&severity=urgent&assignee=someone"))).toBe("/api/v1/cases");
    expect(caseQuery(new URLSearchParams("assignee=none"))).toBe("/api/v1/cases?assignee=none");
  });

  it("filters the loaded cases by title, number and assignee text", () => {
    const rows = [summary({}), summary({ case_id: "d", number: 105, title: "Patch openssh", assignee: { user_id: "u", username: "ola", display_name: "Ola Operator" } })];
    const pick = (q: string) => selectCases(rows, new URLSearchParams({ q })).map((c) => c.number);
    expect(pick("")).toEqual([104, 105]);
    expect(pick("c-104")).toEqual([104]);
    expect(pick("openssh")).toEqual([105]);
    expect(pick("ola")).toEqual([105]);
    expect(pick("unassigned")).toEqual([104]);
  });
});

describe("closing", () => {
  const stuck = [item({ item_id: "a" }), item({ item_id: "b", kind: "finding", outcome: "resolved", evidence_gone: true }), item({ item_id: "c", kind: "host" })];

  it("blocks on alarms, findings and vulnerabilities without an outcome, or resolved while the evidence is back", () => {
    expect(blockingItems(stuck).map((i) => i.item_id)).toEqual(["a"]);
    expect(blockingItems([item({ outcome: "resolved", evidence_gone: false })])).toHaveLength(1);
    expect(blockingItems([item({ outcome: "false_positive" }), item({ kind: "software" }), item({ kind: "host" })])).toEqual([]);
  });

  it("says what is missing, in the order of the form", () => {
    const done = [item({ outcome: "false_positive" })];
    const now = Date.parse("2026-10-04T12:00:00Z");
    expect(closeProblems({ resolution: "", note: "", acceptedUntil: "" }, stuck, now)).toEqual([
      "Choose how the case ended.", "Add a note saying why.", "1 item still needs an outcome.",
    ]);
    expect(closeProblems({ resolution: "mitigated", note: " fixed ", acceptedUntil: "" }, done, now)).toEqual([]);
    expect(closeProblems({ resolution: "accepted_risk", note: "n", acceptedUntil: "" }, done, now)).toEqual(["Choose the date the risk is accepted until."]);
    expect(closeProblems({ resolution: "accepted_risk", note: "n", acceptedUntil: "2026-10-03" }, done, now)).toEqual(["The date must be in the future."]);
    expect(closeProblems({ resolution: "accepted_risk", note: "n", acceptedUntil: "2026-10-30" }, done, now)).toEqual([]);
    expect(closeProblems({ resolution: "mitigated", note: "n", acceptedUntil: "" }, [item({}), item({ item_id: "z" })], now)).toEqual(["2 items still need an outcome."]);
  });

  it("builds the PUT body with every editable field, the ending only when closing, and accepted risk's date at the end of the day", () => {
    const fields = { title: " Title ", severity: "high", assignee: "" };
    expect(updateBody(fields, "investigating")).toEqual({ title: "Title", severity: "high", status: "investigating", assignee_user_id: null });
    expect(updateBody(fields, "open", { resolution: "mitigated", note: "x", accepted_until: null })).not.toHaveProperty("resolution");
    expect(updateBody({ ...fields, assignee: "u-sam" }, "closed", endingOf({ resolution: "mitigated", note: " done ", acceptedUntil: "2031-01-15" })))
      .toEqual({ title: "Title", severity: "high", status: "closed", assignee_user_id: "u-sam", resolution: "mitigated", resolution_note: "done", accepted_until: null });
    expect(updateBody(fields, "closed", endingOf({ resolution: "accepted_risk", note: "n", acceptedUntil: "2031-01-15" })).accepted_until)
      .toBe(new Date(2031, 0, 15, 23, 59, 59).toISOString());
    expect(endOfLocalDay("")).toBeNull();
  });

  it("offers 'resolved' only while the evidence is gone", () => {
    const resolved = (gone: boolean) => outcomeChoices({ evidence_gone: gone }).find((c) => c.value === "resolved");
    expect(resolved(false)).toMatchObject({ disabled: true });
    expect(resolved(true)).toMatchObject({ disabled: false });
    expect(outcomeChoices({ evidence_gone: false }).filter((c) => !c.disabled).map((c) => c.value)).toEqual(["false_positive", "accepted_risk"]);
  });
});

describe("timeline and errors", () => {
  it("reads each kind of entry as a sentence", () => {
    const titles = (id: string) => (id === "i1" ? "nginx → sh" : undefined);
    expect(eventText(event("created", {}))).toBe("opened the case");
    expect(eventText(event("status", { from: "open", to: "investigating" }))).toBe("moved the case from Open to Investigating");
    expect(eventText(event("assigned", { from: null, to: "sam" }))).toBe("assigned the case to sam");
    expect(eventText(event("assigned", { from: "sam", to: null }))).toBe("unassigned the case (was sam)");
    expect(eventText(event("severity", { from: "high", to: "critical" }))).toBe("changed the severity from high to critical");
    expect(eventText(event("item_added", { item_id: "i1", item_kind: "alarm", item_ref: "9" }), titles)).toBe("added alarm nginx → sh");
    expect(eventText(event("item_removed", { item_id: "gone", item_kind: "alarm", item_ref: "9" }), titles)).toBe("removed alarm #9");
    expect(eventText(event("item_outcome", { item_id: "i1", item_kind: "finding", item_ref: "a//R", to: "false_positive" }), titles)).toBe("marked finding nginx → sh as false positive");
    expect(eventText(event("item_outcome", { item_id: "i1", item_kind: "alarm", item_ref: "9", to: null }), titles)).toBe("cleared the outcome of alarm nginx → sh");
    expect(eventText(event("resolved", { resolution: "false_positive", accepted_until: null }))).toBe("closed the case as false positive");
    expect(eventText(event("resolved", { resolution: "accepted_risk", accepted_until: "2031-01-15T12:00:00Z" }))).toMatch(/^closed the case as accepted risk until .*2031/);
    expect(eventText(event("reopened", { reason: "manual" }))).toBe("reopened the case");
    expect(eventText(event("reopened", { reason: "accepted_risk_expired" }))).toBe("reopened the case because the accepted risk ran out");
  });

  it("explains refusals, naming the other case for a clash", () => {
    expect(caseErrorText(new ApiError(412, "stale_case", "The case changed since you loaded it"))).toMatch(/reloaded/);
    expect(caseErrorText(new ApiError(409, "item_in_case", "The item is already in another open case", undefined, 103))).toBe("The item is already in another open case: C-103");
    expect(caseErrorText(new ApiError(409, "item_in_case", "The item is already in another open case"))).toBe("The item is already in another open case");
    expect(caseErrorText(new ApiError(422, "invalid_case", "The request is invalid", [{ field: "ref", code: "invalid_ref", message: "The id does not have the shape of this kind of item" }])))
      .toBe("The id does not have the shape of this kind of item");
    expect(caseErrorText(new ApiError(409, "case_closed", "The case is closed; reopen it first"))).toBe("The case is closed; reopen it first");
    expect(caseErrorText(new Error("boom"))).toBe("Something went wrong; try again");
  });
});
