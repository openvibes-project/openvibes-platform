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
  it("each segment's control points stay within its endpoint range (limiter engaged)", () => {
    const yv = [0, 0.1, 100.1, 102];
    const pts = yv.map((y, i) => ({ x: i * 10, y }));
    // Each "C" chunk is c1x,c1y c2x,c2y x,y.
    const out = monotonePath(pts).split("C").slice(1).map((s) => s.split(/[ ,]/).map(Number));
    expect(out).toHaveLength(3);
    out.forEach((seg, i) => {
      const y0 = yv[i] ?? Number.NaN;
      const y1 = yv[i + 1] ?? Number.NaN;
      const lo = Math.min(y0, y1) - 1e-9;
      const hi = Math.max(y0, y1) + 1e-9;
      expect(seg[5]).toBe(yv[i + 1]);
      expect(seg[1]).toBeGreaterThanOrEqual(lo);
      expect(seg[1]).toBeLessThanOrEqual(hi);
      expect(seg[3]).toBeGreaterThanOrEqual(lo);
      expect(seg[3]).toBeLessThanOrEqual(hi);
    });
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
  it("powers of ten and the decades above them", () => {
    expect(niceMax(100)).toBe(100);
    expect(niceMax(101)).toBe(200);
    expect(niceMax(1000)).toBe(1000);
    expect(niceMax(1001)).toBe(2000);
    expect(niceMax(4500)).toBe(6000);
    for (const x of [100, 101, 1000, 1001, 4500]) {
      for (const t of ticks(niceMax(x))) expect(Number.isInteger(t)).toBe(true);
    }
  });
});
