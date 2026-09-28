import { describe, expect, it } from "vitest";

import { allowedStates, triageBody } from "./triage";

describe("triageBody", () => {
  it("sends accepted risk until the end of the chosen local day", () => {
    const body = triageBody({ state: "accepted_risk", assignee: " sam ", note: "", acceptedUntil: "2031-01-15" });
    expect(body).toMatchObject({ state: "accepted_risk", assigned_to: "sam", note: null });
    expect(body.accepted_until).toBe(new Date(2031, 0, 15, 23, 59, 59).toISOString());
  });

  it("drops the expiry for any other state and leaves a blank assignee unassigned", () => {
    expect(triageBody({ state: "investigating", assignee: "  ", note: " look ", acceptedUntil: "2031-01-15" }))
      .toEqual({ state: "investigating", assigned_to: null, note: "look", accepted_until: null });
  });
});

describe("allowedStates", () => {
  it("follows the workflow: open to investigating, investigating to a closing state", () => {
    expect(allowedStates(["open"])).toEqual(["open", "investigating"]);
    expect(allowedStates(["investigating"])).toEqual(["investigating", "mitigated", "accepted_risk", "false_positive"]);
    expect(allowedStates(["mitigated"])).toEqual(["mitigated"]);
  });

  it("offers only the states every selected host can move to", () => {
    expect(allowedStates(["open", "investigating"])).toEqual(["investigating"]);
    expect(allowedStates(["open", "mitigated"])).toEqual([]);
  });
});
