import { describe, expect, it } from "vitest";

import { MAX_SELECTION, selectAll, selectRange } from "./selection";

const keys = ["a", "b", "c", "d", "e"];

describe("selection", () => {
  it("a shift-click range selects or clears every row between, either way round", () => {
    expect([...selectRange(keys, 1, 3, new Set(["a"]), true)].sort()).toEqual(["a", "b", "c", "d"]);
    expect([...selectRange(keys, 3, 1, new Set(), true)].sort()).toEqual(["b", "c", "d"]);
    expect([...selectRange(keys, 0, 4, new Set(keys), false)]).toEqual([]);
  });

  it("select all matching stops at the server's limit", () => {
    const many = Array.from({ length: MAX_SELECTION + 5 }, (_, i) => `k${i}`);
    expect(selectAll(many).size).toBe(MAX_SELECTION);
    expect(selectAll(keys).size).toBe(5);
  });
});
