import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { LIST_FILTERS, chipsOf, dropUnsupported, queryOf } from "./filters";

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
  it.each([
    ["/compliance", "Findings"], ["/vulnerabilities", "Vulnerabilities"], ["/agents", "Agents"], ["/audit", "Admin"],
  ] as const)("%s view builds its chips from the catalogue", (view, file) => {
    expect(LIST_FILTERS[view].length).toBeGreaterThan(0);
    expect(readFileSync(new URL(`./${file}.tsx`, import.meta.url), "utf8")).toContain(`"${view}"`);
  });
});
