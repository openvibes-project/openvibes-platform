import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { LIST_FILTERS, chipsOf, dropUnsupported, queryOf, setFilter } from "./filters";

describe("filters", () => {
  it("labels known chips and keeps unknown ones", () => {
    const chips = chipsOf("/vulnerabilities", "severity=critical&exploited=true&bad=1");
    expect(chips.map((c) => [c.label, c.known])).toEqual([
      ["Known exploited", true], ["Severity: Critical", true], ["bad=1", false],
    ]);
  });
  it("round-trips in catalogue order", () => {
    const q = queryOf(chipsOf("/vulnerabilities", "severity=critical&bad=1&exploited=true"));
    expect(q).toBe("exploited=true&severity=critical&bad=1");
    expect(queryOf(chipsOf("/vulnerabilities", q))).toBe(q);
  });
  it("treats a value outside the catalogue as unknown", () => {
    expect(chipsOf("/agents", "status=gone")[0]).toMatchObject({ known: false, label: "status=gone" });
  });
  it("drops known params the view lacks, keeps unknown", () => {
    expect(dropUnsupported("/agents", "severity=critical&bad=1&status=stale")).toBe("status=stale&bad=1");
  });
  it("drops a known param whose value the new list does not offer", () => {
    expect(dropUnsupported("/compliance", "severity=important&state=all")).toBe("state=all");
    expect(dropUnsupported("/compliance", "severity=high")).toBe("severity=high");
  });
  it("an empty query has no chips", () => {
    expect(chipsOf("/compliance", "")).toEqual([]);
    expect(queryOf([])).toBe("");
  });
  it("the first occurrence of a param is its chip, later duplicates are unknown", () => {
    const chips = chipsOf("/compliance", "severity=high&severity=low");
    expect(chips.map((c) => [c.label, c.known])).toEqual([["Severity: High", true], ["severity=low", false]]);
  });
  it("a value with a space and an ampersand survives queryOf", () => {
    const q = queryOf(chipsOf("/compliance", "a=x+y%26z&severity=low"));
    expect(new URLSearchParams(q).get("a")).toBe("x y&z");
    expect(chipsOf("/compliance", q).find((c) => c.param === "a")?.value).toBe("x y&z");
  });
  it("setFilter replaces the param's value and keeps unknown chips", () => {
    expect(setFilter("/compliance", "severity=low&bad=1", "severity", "high")).toBe("severity=high&bad=1");
    expect(setFilter("/compliance", "", "state", "all")).toBe("state=all");
  });
  it.each([
    ["/compliance", "Findings"], ["/vulnerabilities", "Vulnerabilities"], ["/agents", "Agents"], ["/audit", "Admin"],
  ] as const)("%s view builds its chips from the catalogue", (view, file) => {
    expect(LIST_FILTERS[view].length).toBeGreaterThan(0);
    expect(readFileSync(new URL(`./${file}.tsx`, import.meta.url), "utf8")).toContain(`"${view}"`);
  });
});
