import { describe, expect, it } from "vitest";

import { validateLayout, validateName } from "./layout";

const widget = (id: string, type: string, x: number, w: number) =>
  ({ id, type, x, y: 0, w, h: 2, config: { metric: "agents.active" } });
const fields = (layout: unknown) => validateLayout(layout).map((p) => p.field);

describe("validateLayout (mirrors the server)", () => {
  it("accepts a small layout and an empty one", () => {
    expect(validateLayout({ schema: 1, widgets: [widget("w1", "number", 0, 3), widget("w2", "note", 3, 9)] })).toEqual([]);
    expect(validateLayout({ schema: 1, widgets: [] })).toEqual([]);
  });

  it("needs an object", () => {
    expect(fields([1, 2])).toEqual(["layout"]);
    expect(fields(7)).toEqual(["layout"]);
  });

  it("bounds schema, widget count and size", () => {
    expect(fields({ schema: 2, widgets: [] })).toEqual(["layout.schema"]);
    expect(fields({ schema: 1, widgets: Array.from({ length: 41 }, (_, i) => widget(`w${i}`, "number", 0, 1)) })).toEqual(["layout.widgets"]);
    const long = "x".repeat(256);
    const heavy = Array.from({ length: 40 }, (_, i) => ({ id: `w${i}`, type: "note", x: 0, y: 0, w: 1, h: 1, config: { text: Array(7).fill(long) } }));
    expect(fields({ schema: 1, widgets: heavy })).toEqual(["layout"]);
  });

  it("gives the server's field paths for each widget problem", () => {
    const layout = { schema: 1, widgets: [
      widget("w1", "pie-chart", 0, 3),
      widget("w1", "number", 10, 3),
      widget("Bad Id", "number", 0, 13),
      { id: "w4", type: "number", x: 0, y: 200, w: 1, h: 13, config: {} },
      { id: "w5", type: "number", x: 0, y: 0, w: 1, h: 1, config: { nested: { a: 1 } } },
    ] };
    expect(fields(layout)).toEqual([
      "layout.widgets[0].type",
      "layout.widgets[1].id", "layout.widgets[1].x",
      "layout.widgets[2].id", "layout.widgets[2].w",
      "layout.widgets[3].y", "layout.widgets[3].h",
      "layout.widgets[4].config.nested",
    ]);
  });
});

describe("validateName", () => {
  it("trims and bounds", () => {
    expect(validateName("  Morning  ")).toBe("Morning");
    expect(validateName("   ")).toMatchObject({ field: "name" });
    expect(validateName("n".repeat(81))).toMatchObject({ field: "name" });
    expect(validateName("tab\there")).toMatchObject({ field: "name" });
    expect(validateName("é".repeat(80))).toBe("é".repeat(80));
  });
});
