// The Rule sets list without rules.assignment.read (Viewer and Analyst
// templates): no "Runs on" column, so nothing needs the assignments.
import { describe, expect, it, vi } from "vitest";

// nav.ts reads the location when loaded.
vi.hoisted(() => {
  Object.assign(globalThis, { window: { location: { pathname: "/", search: "" }, history: { replaceState() {} }, addEventListener() {} } });
});

import { ruleSetColumns } from "./RuleSets";

describe("rule set columns", () => {
  it("shows Runs on only with rules.assignment.read", () => {
    expect(ruleSetColumns(true).map((c) => c.header)).toContain("Runs on");
    expect(ruleSetColumns(false).map((c) => c.header)).toEqual(["Rule set", "Version", "Signed by", "Expires", "State"]);
  });
});
