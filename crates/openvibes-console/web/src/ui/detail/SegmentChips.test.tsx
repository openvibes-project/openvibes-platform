// No DOM library in vitest: markup plus the pure key handling (see ui/controls.test.tsx).
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { keyTarget } from "../segmented";
import { SegmentChips } from "./SegmentChips";

const options = [{ key: "all", label: "All", count: 12 }, { key: "web", label: "Web", count: 3 }, { key: "db", label: "DB", count: 0 }];

describe("SegmentChips", () => {
  it("is a named radiogroup, one checked radio, counts after labels, roving tabindex", () => {
    const html = renderToStaticMarkup(<SegmentChips label="Segment" options={options} value="web" onChange={() => {}} />);
    expect(html).toContain('role="radiogroup"');
    expect(html).toContain('aria-label="Segment"');
    expect(html.match(/role="radio"/g)).toHaveLength(3);
    const buttons = html.match(/<button[^>]*>/g) ?? [];
    const checked = buttons.filter((b) => b.includes('aria-checked="true"'));
    expect(checked).toHaveLength(1);
    expect(checked[0]).toContain('tabindex="0"');
    expect(buttons.filter((b) => b.includes('tabindex="-1"'))).toHaveLength(2);
    expect(html).toMatch(/>Web[^<]*<span[^>]*>3</);
    expect(html).toMatch(/>All[^<]*<span[^>]*>12</);
  });
  it("arrows wrap, Home and End jump, other keys do nothing", () => {
    expect(keyTarget("ArrowRight", 2, 3)).toBe(0);
    expect(keyTarget("ArrowLeft", 0, 3)).toBe(2);
    expect(keyTarget("ArrowDown", 0, 3)).toBe(1);
    expect(keyTarget("Home", 2, 3)).toBe(0);
    expect(keyTarget("End", 0, 3)).toBe(2);
    expect(keyTarget("a", 0, 3)).toBeNull();
  });
});
