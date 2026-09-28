import { describe, expect, it } from "vitest";

import { type Layout, addWidget, moveWidget, overlaps, readingOrder, removeWidget, resizeWidget, validateLayout } from "./layout";

const tile = (id: string, x: number, y: number, w = 4, h = 2) => ({ id, type: "number" as const, x, y, w, h, config: {} });
const at = (layout: Layout, id: string) => layout.widgets.find((w) => w.id === id);
const noOverlap = (layout: Layout) => layout.widgets.every((a) => layout.widgets.every((b) => a === b || !overlaps(a, b)));

describe("grid", () => {
  it("moves a tile and pushes the one it lands on down", () => {
    const layout: Layout = { schema: 1, widgets: [tile("a", 0, 0), tile("b", 4, 0)] };
    const moved = moveWidget(layout, "a", 4, 0);
    expect(at(moved, "a")).toMatchObject({ x: 4, y: 0 });
    expect(at(moved, "b")).toMatchObject({ x: 4, y: 2 });
    expect(noOverlap(moved)).toBe(true);
  });

  it("pushes a chain of tiles down", () => {
    const layout: Layout = { schema: 1, widgets: [tile("a", 0, 4), tile("b", 0, 0), tile("c", 0, 2)] };
    const moved = moveWidget(layout, "a", 0, 0);
    expect([at(moved, "a")?.y, at(moved, "b")?.y, at(moved, "c")?.y]).toEqual([0, 2, 4]);
    expect(noOverlap(moved)).toBe(true);
  });

  it("clamps into the grid", () => {
    const layout: Layout = { schema: 1, widgets: [tile("a", 0, 0)] };
    expect(at(moveWidget(layout, "a", 11, -3), "a")).toMatchObject({ x: 8, y: 0 });
    expect(at(resizeWidget(layout, "a", 20, 0), "a")).toMatchObject({ w: 12, h: 1 });
    expect(validateLayout(moveWidget(layout, "a", 99, 999))).toEqual([]);
  });

  it("resizing pushes tiles below out of the way", () => {
    const layout: Layout = { schema: 1, widgets: [tile("a", 0, 0), tile("b", 0, 2)] };
    const resized = resizeWidget(layout, "a", 4, 5);
    expect(at(resized, "b")?.y).toBe(5);
  });

  it("adds at the bottom with a unique id and removes", () => {
    const layout: Layout = { schema: 1, widgets: [tile("number-1", 0, 0, 4, 3)] };
    const { layout: added, id } = addWidget(layout, "number", { w: 3, h: 2 }, { metric: "agents.active" });
    expect(id).toBe("number-2");
    expect(at(added, id)).toMatchObject({ x: 0, y: 3, w: 3, h: 2 });
    expect(removeWidget(added, id).widgets).toHaveLength(1);
  });

  it("reads tiles row by row for phones", () => {
    expect(readingOrder([tile("c", 0, 4), tile("b", 6, 0), tile("a", 0, 0)]).map((w) => w.id)).toEqual(["a", "b", "c"]);
  });
});
