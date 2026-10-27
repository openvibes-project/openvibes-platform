import { describe, expect, it } from "vitest";

import { ApiError } from "../../api/client";
import type { CaseEvent, CaseItem } from "../../api/types";
import { outcomeError } from "../../demo/caseRules";
import { acceptRange, afterAgent, caseBadges, statusBadge, localDay, blockingItems, caseErrorText, closeProblems, endOfLocalDay, eventText, findingRef, itemPanel, outcomeBody, outcomeChoices, refLabel, updateBody, vulnerabilityRef } from "./cases";

const item = (over: Partial<CaseItem>): CaseItem => ({
  item_id: "i", kind: "alarm", ref: "1", active: true, added_at: "2026-01-01T00:00:00Z", added_by: { user_id: "u", username: "sam", display_name: "Sam" },
  evidence_gone: false, ...over,
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
    expect(itemPanel("port", "tcp/22")).toEqual({ kind: "port", id: "tcp/22" });
    expect(itemPanel("service", "sshd.service")).toBeUndefined();
  });

  it("names an item by its id when the object is gone", () => {
    expect(refLabel("alarm", "9001")).toBe("#9001");
    expect(refLabel("finding", "agent-1/hardening-ssh/SSH-002")).toBe("SSH-002 on agent-1");
    expect(refLabel("vulnerability", "agent-1/FEDORA-1")).toBe("FEDORA-1 on agent-1");
    expect(refLabel("software", "rpm/openssh")).toBe("openssh");
    expect(refLabel("host", "agent-1")).toBe("agent-1");
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
    expect(closeProblems({ note: "" }, stuck)).toEqual(["Add a closing note.", "1 item still needs an outcome."]);
    expect(closeProblems({ note: " fixed " }, done)).toEqual([]);
    expect(closeProblems({ note: "n" }, [item({}), item({ item_id: "z" })])).toEqual(["2 items still need an outcome."]);
  });

  it("builds the PUT body with every editable field and the closing note only for a closed case", () => {
    const fields = { title: " Title ", severity: "high", assignee: "" };
    expect(updateBody(fields, "investigating")).toEqual({ title: "Title", severity: "high", status: "investigating", assignee_user_id: null });
    expect(updateBody(fields, "open", "x")).not.toHaveProperty("closing_note");
    expect(updateBody({ ...fields, assignee: "u-sam" }, "closed", " done "))
      .toEqual({ title: "Title", severity: "high", status: "closed", assignee_user_id: "u-sam", closing_note: "done" });
    expect(endOfLocalDay("")).toBeNull();
  });

  it("sends accepted risk's re-open date at the end of the chosen day, and no date otherwise", () => {
    expect(outcomeBody("accepted_risk", " n ", "2031-01-15")).toEqual({ outcome: "accepted_risk", note: "n", outcome_until: new Date(2031, 0, 15, 23, 59, 59).toISOString() });
    expect(outcomeBody("expected", "n", "2031-01-15")).toEqual({ outcome: "expected", note: "n" });
    expect(outcomeBody("", "n", "")).toEqual({ outcome: null });
  });

  it("offers 'resolved' only while the evidence is gone", () => {
    const resolved = (gone: boolean) => outcomeChoices({ evidence_gone: gone }).find((c) => c.value === "resolved");
    expect(resolved(false)).toMatchObject({ disabled: true });
    expect(resolved(true)).toMatchObject({ disabled: false });
    expect(outcomeChoices({ evidence_gone: false }).filter((c) => !c.disabled).map((c) => c.value)).toEqual(["false_positive", "accepted_risk", "confirmed_malicious", "expected"]);
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
    expect(eventText(event("item_outcome", { item_id: "i1", item_kind: "finding", item_ref: "a//R", to: "false_positive" }), titles)).toBe("marked compliance finding nginx → sh as false positive");
    expect(eventText(event("item_added", { item_id: "gone", item_kind: "compliance_finding", item_ref: "a/base/R-1" }), titles)).toBe("added compliance finding R-1 on a");
    expect(eventText(event("item_outcome", { item_id: "i1", item_kind: "alarm", item_ref: "9", to: null }), titles)).toBe("cleared the outcome of alarm nginx → sh");
    expect(eventText(event("item_outcome", { item_id: "i1", item_kind: "alarm", item_ref: "9", from: "accepted_risk", to: null, reason: "accepted_risk_expired" }), titles))
      .toBe("cleared the outcome of alarm nginx → sh: the risk acceptance ran out, so it needs an outcome again");
    expect(eventText(event("item_outcome", { item_id: "i1", item_kind: "alarm", item_ref: "9", from: "resolved", to: null, reason: "evidence_returned" }), titles))
      .toBe("cleared the outcome of alarm nginx → sh: the evidence returned, so it needs an outcome again");
    expect(eventText(event("resolved", {}))).toBe("closed the case");
    expect(eventText(event("resolved", { resolution: "false_positive", accepted_until: null }))).toBe("closed the case as false positive");
    expect(eventText(event("resolved", { resolution: "accepted_risk", accepted_until: "2031-01-15T12:00:00Z" }))).toMatch(/^closed the case as accepted risk until .*2031/);
    expect(eventText(event("reopened", { reason: "manual" }))).toBe("reopened the case");
    expect(eventText(event("reopened", { reason: "accepted_risk_expired" }))).toBe("reopened the case because the accepted risk ran out");
    expect(eventText(event("reopened", { reason: "evidence_returned" }))).toBe("reopened the case because the evidence returned");
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

describe("Risk accepted's date range", () => {
  it("offers as its last day one the API takes, at any time of day", () => {
    for (const [h, m, sec] of [[0, 0, 1], [9, 30, 0], [23, 59, 58]]) {
      const now = new Date(2026, 9, 25, h, m, sec).getTime();
      const [first, last] = acceptRange(now);
      expect(outcomeError("accepted_risk", "ok", Date.parse(endOfLocalDay(last) ?? ""), now), `${h}:${m}`).toBeNull();
      expect(outcomeError("accepted_risk", "ok", Date.parse(endOfLocalDay(first) ?? ""), now)).toBeNull();
    }
  });
});

describe("blocking items", () => {
  it("counts an acceptance that ran out but is not cleared yet (visibility.rs blocking_item)", () => {
    const past = new Date(Date.now() - 60_000).toISOString();
    const future = new Date(Date.now() + 86_400_000).toISOString();
    expect(blockingItems([item({ outcome: "accepted_risk", outcome_until: past })])).toHaveLength(1);
    expect(blockingItems([item({ outcome: "accepted_risk", outcome_until: future })])).toHaveLength(0);
  });
});

describe("status badge", () => {
  it("names the way a closed case ended", () => {
    expect(statusBadge("open", null)).toEqual({ label: "Open", tone: "bad" });
    expect(statusBadge("investigating", null)).toEqual({ label: "Investigating", tone: "warn" });
    expect(statusBadge("closed", "mitigated")).toEqual({ label: "Closed · mitigated", tone: "ok" });
    expect(statusBadge("closed", "accepted_risk")).toEqual({ label: "Closed · accepted risk", tone: "info" });
    expect(statusBadge("closed", "false_positive")).toEqual({ label: "Closed · false positive", tone: "plain" });
    expect(localDay(new Date(2031, 0, 5))).toBe("2031-01-05");
  });
});

describe("caseBadges", () => {
  it("collects each row's open cases once", () => {
    const items = [{ ref: "a1/FEDORA-1", case_number: 4 }, { ref: "a2/FEDORA-1", case_number: 4 }, { ref: "a2/FEDORA-2", case_number: 7 }, { ref: "a3/FEDORA-1", case_number: 9 }];
    const badges = caseBadges(items, afterAgent);
    expect(badges.get("FEDORA-1")).toEqual([4, 9]);
    expect(badges.get("FEDORA-2")).toEqual([7]);
    expect(caseBadges([{ ref: "a1/baseline/ssh", case_number: 2 }], afterAgent).get("baseline/ssh")).toEqual([2]);
  });
});

describe("findings from before rule sets", () => {
  it("are referenced with an empty rule set, as stored", () => {
    expect(findingRef("a1", "~unknown", "ssh.root_login")).toBe("a1//ssh.root_login");
    expect(findingRef("a1", "baseline", "ssh.root_login")).toBe("a1/baseline/ssh.root_login");
  });
});
