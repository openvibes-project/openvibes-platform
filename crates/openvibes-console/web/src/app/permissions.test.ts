import { describe, expect, it } from "vitest";
import { CATALOGUE, TEMPLATES, turnOff, turnOn } from "./permissions";

describe("permission helpers", () => {
  it("turning on Assign cases brings what it needs", () => {
    const { next, added } = turnOn(new Set(), "cases.assign");
    expect([...next].sort()).toEqual(["cases.assign", "cases.read", "cases.write"]);
    expect(added.sort()).toEqual(["cases.read", "cases.write"]);
  });
  it("turning off View cases takes what depends on it", () => {
    const { next, removed } = turnOff(new Set(["cases.read", "cases.write", "cases.assign"]), "cases.read");
    expect(next.size).toBe(0);
    expect(removed.sort()).toEqual(["cases.assign", "cases.write"]);
  });
  it("has 48 permissions and six templates", () => {
    expect(CATALOGUE).toHaveLength(48);
    expect(TEMPLATES.map((t) => t.name)).toEqual(["Viewer", "Analyst", "Operator", "Team lead", "Auditor", "Rule author"]);
  });
});
