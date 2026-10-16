import { describe, expect, it } from "vitest";

import { allowedStates, triageBody } from "./triage";

describe("triageBody", () => {
  it("sends accepted risk until the end of the chosen local day", () => {
    const body = triageBody({ state: "accepted_risk", assignee: " sam ", note: "", acceptedUntil: "2031-01-15" });
    expect(body).toMatchObject({ state: "accepted_risk", assigned_to: "sam", note: null });
    expect(body.accepted_until).toBe(new Date(2031, 0, 15, 23, 59, 59).toISOString());
  });

  it("drops the expiry for any other state and leaves a blank assignee unassigned", () => {
    expect(triageBody({ state: "mitigated", assignee: "  ", note: " look ", acceptedUntil: "2031-01-15" }))
      .toEqual({ state: "mitigated", assigned_to: null, note: "look", accepted_until: null });
  });
});

describe("allowedStates", () => {
  it("lets any state move to any other (triage v2)", () => {
    const all = ["open", "mitigated", "accepted_risk", "false_positive"];
    expect(allowedStates(["open"])).toEqual(all);
    expect(allowedStates(["mitigated", "false_positive"])).toEqual(all);
  });

  it("offers nothing for a retired state", () => {
    expect(allowedStates(["open", "investigating"])).toEqual([]);
  });
});
