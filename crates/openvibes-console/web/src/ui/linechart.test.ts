import { describe, expect, it } from "vitest";

import { ariaLabel, clampIndex, collectingNote, emptyNote, runPoints, spansYears, axisDays, dayLabel, indexAt, layout, monotonePath, niceMax, segments, spreadLabels, steppedPath, tableRows, ticks, tipLeft, xAt, yAt } from "./linechart";

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

describe("chart layout helpers", () => {
  const day = (n: number) => new Date(Date.UTC(2026, 9, n)).toISOString().slice(0, 10);
  const a = { label: "Alarms", points: [1, 2, 4].map((v, i) => ({ day: day(5 + i), value: v })) };
  const b = { label: "High", points: [{ day: day(5), value: 9 }, { day: day(7), value: 3 }] };

  it("axisDays spans the earliest to the latest day of all series", () => {
    expect(axisDays([a, b])).toEqual([day(5), day(6), day(7)]);
    expect(axisDays([])).toEqual([]);
  });
  it("x and y scales hit the padded edges", () => {
    const l = layout("full", 300);
    expect(xAt(0, 3, l)).toBe(l.padL);
    expect(xAt(2, 3, l)).toBe(300 - l.padR);
    expect(xAt(0, 1, l)).toBe(300 - l.padR);
    expect(yAt(0, 4, l)).toBe(l.H - l.padB);
    expect(yAt(4, 4, l)).toBe(l.padT);
  });
  it("indexAt snaps to the nearest day and clamps outside the plot", () => {
    const l = layout("full", 300);
    expect(indexAt(-50, 31, l)).toBe(0);
    expect(indexAt(999, 31, l)).toBe(30);
    expect(indexAt(xAt(12, 31, l) + 1, 31, l)).toBe(12);
    expect(indexAt(10, 1, l)).toBe(0);
  });
  it("tipLeft keeps the tooltip inside the tile", () => {
    expect(tipLeft(290, 80, 300)).toBe(300 - 80 - 6);
    expect(tipLeft(10, 80, 300)).toBe(18);
    expect(tipLeft(0, 400, 300)).toBe(0);
  });
  it("ariaLabel names the range and the latest value", () => {
    expect(ariaLabel([a])).toBe("Alarms: 5 Oct to 7 Oct, now 4");
    expect(ariaLabel([a])).not.toContain("Today");
    expect(ariaLabel([a, b])).toBe("Alarms 4, High 3: 5 Oct to 7 Oct");
    expect(ariaLabel([{ label: "X", points: [] }])).toBe("X: no data");
  });
  it("dayLabel says Today for today", () => {
    expect(dayLabel("2026-10-07", "2026-10-07")).toBe("Today");
    expect(dayLabel("2026-10-06", "2026-10-07")).toBe("6 Oct");
  });
  it("tableRows has one row per day with a dash for gaps", () => {
    expect(tableRows([a, b])).toEqual([
      ["2026-10-05", "1", "9"],
      ["2026-10-06", "2", "–"],
      ["2026-10-07", "4", "3"],
    ]);
  });
  it("spreadLabels keeps end labels apart and in order", () => {
    expect(spreadLabels([50, 52, 100], 12)).toEqual([45, 57, 100]);
    expect(spreadLabels([10], 12)).toEqual([10]);
  });
  it("dayLabel adds the year on request, and spansYears detects a year boundary", () => {
    expect(dayLabel("2025-10-09", "2026-10-07", true)).toBe("9 Oct 2025");
    expect(spansYears(["2025-10-09", "2026-10-07"])).toBe(true);
    expect(spansYears(["2026-01-09", "2026-10-07"])).toBe(false);
  });
  it("emptyNote: only no data at all replaces the chart; one point draws (#238)", () => {
    expect(emptyNote([])).toBe("No data yet");
    expect(emptyNote([{ label: "X", points: [] }])).toBe("No data yet");
    expect(emptyNote([{ label: "X", points: [{ day: "2026-10-07", value: 1 }] }])).toBeNull();
    expect(emptyNote([a])).toBeNull();
  });
  it("collectingNote: a caption under the chart while there is under two days of history", () => {
    expect(collectingNote([{ label: "X", points: [{ day: "2026-10-07", value: 1 }] }])).toBe("Collecting since 7 Oct");
    expect(collectingNote([a])).toBeNull();
    expect(collectingNote([])).toBeNull();
  });
  it("runPoints: a single day is a flat line across the plot, at its value (#238)", () => {
    const l = layout("full", 300);
    const flat = runPoints([{ day: "2026-10-07", value: 4 }], new Map([["2026-10-07", 0]]), 1, 8, l);
    expect(flat).toHaveLength(2);
    expect(flat[0]).toEqual({ x: l.padL, y: yAt(4, 8, l) });
    expect(flat[1]).toEqual({ x: l.W - l.padR, y: yAt(4, 8, l) });
    // With more days, each point keeps its own day's position.
    const two = runPoints([{ day: "2026-10-06", value: 1 }, { day: "2026-10-07", value: 2 }], new Map([["2026-10-06", 0], ["2026-10-07", 1]]), 2, 8, l);
    expect(two.map((p) => p.x)).toEqual([xAt(0, 2, l), xAt(1, 2, l)]);
  });
  it("clampIndex follows a shrinking series", () => {
    expect(clampIndex(29, 10)).toBe(9);
    expect(clampIndex(3, 10)).toBe(3);
    expect(clampIndex(3, 0)).toBeNull();
    expect(clampIndex(null, 10)).toBeNull();
  });
});
