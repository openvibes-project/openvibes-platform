// No DOM library in vitest: markup plus the pure key handling (see ui/controls.test.tsx).
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { chipTarget, SegmentChips } from "./SegmentChips";

const options = [{ key: "all", label: "All", count: 12 }, { key: "web", label: "Web", count: 3 }, { key: "db", label: "DB", count: 0 }];

describe("SegmentChips", () => {
  it("is a named radiogroup, one checked radio, counts after labels, roving tabindex", () => {
    const html = renderToStaticMarkup(<SegmentChips label="Segment" options={options} value="web" onChange={() => {}} />);
    expect(html).toContain('role="radiogroup"');
    expect(html).toContain('aria-label="Segment"');
    expect(html.match(/role="radio"/g)).toHaveLength(3);
    expect(html).toMatch(/aria-checked="true"[^>]*tabindex="0"[^>]*>Web[^<]*<span[^>]*>3</);
    expect(html.match(/tabindex="-1"/g)).toHaveLength(2);
    expect(html).toMatch(/>All[^<]*<span[^>]*>12</);
  });
  it("arrows wrap, Home and End jump, other keys do nothing", () => {
    expect(chipTarget("ArrowRight", 2, 3)).toBe(0);
    expect(chipTarget("ArrowLeft", 0, 3)).toBe(2);
    expect(chipTarget("ArrowDown", 0, 3)).toBe(1);
    expect(chipTarget("Home", 2, 3)).toBe(0);
    expect(chipTarget("End", 0, 3)).toBe(2);
    expect(chipTarget("a", 0, 3)).toBeNull();
  });
});
