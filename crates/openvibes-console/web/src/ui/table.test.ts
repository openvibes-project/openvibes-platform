import { describe, expect, it } from "vitest";

import { matches, sortRows } from "./table";

const rows = [
  { name: "b", n: 2, when: null },
  { name: "a", n: 10, when: "2026-01-02" },
  { name: "c", n: 1, when: "2026-01-01" },
];

describe("table", () => {
  it("sorts numbers numerically and strings naturally, both ways", () => {
    expect(sortRows(rows, (r) => r.n, "asc").map((r) => r.name)).toEqual(["c", "b", "a"]);
    expect(sortRows(rows, (r) => r.n, "desc").map((r) => r.name)).toEqual(["a", "b", "c"]);
    expect(sortRows(rows, (r) => r.name, "asc").map((r) => r.name)).toEqual(["a", "b", "c"]);
  });

  it("puts missing values last in either direction", () => {
    expect(sortRows(rows, (r) => r.when, "asc").map((r) => r.name)).toEqual(["c", "a", "b"]);
    expect(sortRows(rows, (r) => r.when, "desc").map((r) => r.name)).toEqual(["a", "c", "b"]);
  });

  it("matches every word of a filter against any searchable field, ignoring case", () => {
    expect(matches(["web-01.prod.example.test", "Online"], "WEB prod")).toBe(true);
    expect(matches(["web-01.prod.example.test"], "web lab")).toBe(false);
    expect(matches(["x"], "  ")).toBe(true);
  });
});
