import { describe, expect, it } from "vitest";

import { type BulkForm, NEW_CASE, bulkBody, bulkProblem, resultText } from "./bulk";

const form = (patch: Partial<BulkForm>): BulkForm =>
  ({ action: "state", state: "open", note: "", acceptedUntil: "", assignee: "", caseId: "", newCaseTitle: "", ...patch });
const items = [{ id: "7" }];

describe("bulk actions", () => {
  it("every close needs a note; reopening does not", () => {
    for (const state of ["mitigated", "accepted_risk", "false_positive"]) {
      expect(bulkProblem(form({ state }))).toMatch(/note/);
    }
    expect(bulkProblem(form({ state: "open" }))).toBeNull();
    expect(bulkProblem(form({ state: "mitigated", note: "  " }))).toMatch(/note/);
    expect(bulkProblem(form({ state: "mitigated", note: "patched" }))).toBeNull();
  });

  it("accepted risk needs an expiry, sent as the end of that local day", () => {
    expect(bulkProblem(form({ state: "accepted_risk", note: "later" }))).toMatch(/until/);
    const body = bulkBody(form({ state: "accepted_risk", note: " later ", acceptedUntil: "2031-01-15" }), items);
    expect(body).toEqual({ action: "state", state: "accepted_risk", note: "later", accepted_until: new Date(2031, 0, 15, 23, 59, 59).toISOString(), items });
  });

  it("a case is an open one or a new one with a title; quieting needs a note", () => {
    expect(bulkProblem(form({ action: "case" }))).toMatch(/case/);
    expect(bulkProblem(form({ action: "case", caseId: NEW_CASE }))).toMatch(/title/);
    expect(bulkBody(form({ action: "case", caseId: NEW_CASE, newCaseTitle: " Web shells " }), items)).toEqual({ action: "case", new_case_title: "Web shells", items });
    expect(bulkBody(form({ action: "case", caseId: "c1" }), items)).toEqual({ action: "case", case_id: "c1", items });
    expect(bulkProblem(form({ action: "suppress" }))).toMatch(/note/);
    expect(bulkBody(form({ action: "assign" }), items)).toEqual({ action: "assign", assignee: null, items });
  });

  it("says what changed and why the rest was skipped", () => {
    expect(resultText({ changed: 3, skipped: [] })).toBe("3 changed");
    expect(resultText({ changed: 1, skipped: [{ id: "a", reason: "in another open case" }, { id: "b", reason: "in another open case" }, { id: "c", reason: "not found or out of scope" }] }))
      .toBe("1 changed; 3 skipped (2 in another open case, 1 not found or out of scope)");
  });
});
