import { describe, expect, it } from "vitest";

import { cropFor, cropQuery, dragCentre, MAX_ZOOM } from "./picture";

describe("picture crop", () => {
  it("keeps the whole short side at zoom 1, centred", () => {
    expect(cropFor(200, 100, 1, 100, 50)).toEqual({ x: 50, y: 0, size: 100 });
    expect(cropFor(100, 200, 1, 50, 100)).toEqual({ x: 0, y: 50, size: 100 });
  });
  it("zooms in on the centre and never leaves the picture", () => {
    expect(cropFor(200, 100, 2, 100, 50)).toEqual({ x: 75, y: 25, size: 50 });
    expect(cropFor(200, 100, 2, 0, 0)).toEqual({ x: 0, y: 0, size: 50 });
    expect(cropFor(200, 100, 2, 999, 999)).toEqual({ x: 150, y: 50, size: 50 });
    expect(cropFor(200, 100, 99, 100, 50).size).toBe(Math.floor(100 / MAX_ZOOM));
    expect(cropFor(200, 100, 0.2, 100, 50).size).toBe(100);
  });
  it("is never smaller than one pixel", () => {
    expect(cropFor(2, 2, 4, 1, 1).size).toBe(1);
  });
  it("drags the picture the way the pointer goes", () => {
    const crop = cropFor(400, 200, 2, 200, 100); // 100 px square, shown at 240 px
    const moved = dragCentre(400, 200, crop, 240, 24, 0);
    // Dragging right shows more of the left: the centre moves left by 24 * 100 / 240 = 10.
    expect(moved).toEqual({ cx: 190, cy: 100 });
    expect(dragCentre(400, 200, crop, 240, -99999, 99999)).toEqual({ cx: 400, cy: 0 });
  });
  it("sends the square as the query", () => {
    expect(cropQuery({ x: 3, y: 4, size: 50 })).toBe("x=3&y=4&size=50");
  });
});
