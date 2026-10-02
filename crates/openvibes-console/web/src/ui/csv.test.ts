import { describe, expect, it } from "vitest";

import { csvCell, csvText } from "./csv";

describe("csv", () => {
  it("quotes cells and doubles quotes", () => {
    expect(csvCell('say "hi"')).toBe('"say ""hi"""');
    expect(csvCell(null)).toBe('""');
    expect(csvCell(443)).toBe('"443"');
  });

  it("never lets a spreadsheet run a cell as a formula", () => {
    for (const bad of ["=1+1", "+cmd", "-2", "@SUM(A1)", "\tx"]) expect(csvCell(bad).startsWith(`"'`)).toBe(true);
  });

  it("joins rows with a header", () => {
    expect(csvText([["a", "b"], [1, 2]])).toBe('"a","b"\n"1","2"\n');
  });
});
