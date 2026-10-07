import { describe, expect, it } from "vitest";

import { monotonePath, niceMax, segments, steppedPath, ticks } from "./linechart";

const ys = (d: string) => [...d.matchAll(/[ -]?\d+(?:\.\d+)?,(-?\d+(?:\.\d+)?)/g)].map((m) => Number(m[1]));

describe("linechart", () => {
  it("monotone curve never leaves the range of its neighbours", () => {
    const pts = [0, 5, 0, 0, 3, 3, 1].map((v, i) => ({ x: i * 10, y: 100 - v * 10 }));
    for (const y of ys(monotonePath(pts))) {
      expect(y).toBeGreaterThanOrEqual(50);
      expect(y).toBeLessThanOrEqual(100);
    }
  });
  it("flat input gives a flat curve", () => {
    expect(new Set(ys(monotonePath([0, 1, 2].map((i) => ({ x: i, y: 7 })))))).toEqual(new Set([7]));
  });
  it("stepped path moves horizontally then vertically", () => {
    expect(steppedPath([{ x: 0, y: 5 }, { x: 10, y: 2 }])).toBe("M0,5H10V2");
  });
  it("splits at missing days", () => {
    const s = segments([{ day: "2026-10-01" }, { day: "2026-10-02" }, { day: "2026-10-05" }]);
    expect(s.map((g) => g.length)).toEqual([2, 1]);
  });
  it("uses whole-number ticks", () => {
    expect(niceMax(0)).toBe(2);
    expect(niceMax(5)).toBe(6);
    expect(niceMax(11)).toBe(20);
    expect(ticks(niceMax(1))).toEqual([0, 1, 2]);
  });
});
