// No DOM library is installed (vitest runs in node), so markup is checked with
// react-dom/server and the keyboard/search/placement rules through ui/select.ts;
// the click-and-key flow runs in e2e/demo/detection.spec.ts.
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { Select } from "./Select";
import { enabledCount, filterSections, firstEnabled, placement, step, toSections, SEARCH_ABOVE } from "./select";

const groups = [
  { group: "Alpha", options: [{ value: "a1", label: "One" }, { value: "a2", label: "Two", disabled: true }, { value: "a3", label: "Three" }] },
  { group: "Beta", options: [{ value: "b1", label: "Four" }] },
];
const noop = () => {};

describe("Select markup", () => {
  it("closed: a combobox button showing the selected label", () => {
    const html = renderToStaticMarkup(<Select label="Pick" value="b1" onChange={noop} options={groups} />);
    expect(html).toContain('role="combobox"');
    expect(html).toContain('aria-expanded="false"');
    expect(html).toContain("Four");
    expect(html).not.toContain('role="listbox"');
  });
  it("shows the placeholder, and unknownLabel for a value outside the options", () => {
    expect(renderToStaticMarkup(<Select label="Pick" value="" placeholder="Choose" onChange={noop} options={groups} />)).toContain("Choose");
    const html = renderToStaticMarkup(<Select label="Pick" value="zz" unknownLabel={(v) => `Gone: ${v}`} onChange={noop} options={groups} />);
    expect(html).toContain("Gone: zz");
  });
  it("small and disabled reach the button", () => {
    const html = renderToStaticMarkup(<Select label="Pick" value="" small disabled onChange={noop} options={groups} />);
    expect(html).toContain("select--small");
    expect(html).toContain("disabled");
  });
});

describe("Select rules", () => {
  const flat = toSections(groups).flatMap((s) => s.options);
  it("arrows skip disabled options and stay at the ends", () => {
    expect(firstEnabled(flat)).toBe(0);
    expect(step(flat, 0, 1)).toBe(2);
    expect(step(flat, 2, -1)).toBe(0);
    expect(step(flat, 3, 1)).toBe(3);
    expect(step(flat, 0, -1)).toBe(0);
  });
  it("search filters across groups and drops empty ones", () => {
    const sections = toSections(groups);
    expect(filterSections(sections, "o").map((s) => s.group)).toEqual(["Alpha", "Beta"]);
    expect(filterSections(sections, "four").map((s) => s.group)).toEqual(["Beta"]);
    expect(filterSections(sections, "zzz")).toEqual([]);
  });
  it("search appears above 8 enabled options only", () => {
    const make = (n: number) => toSections(Array.from({ length: n }, (_, i) => ({ value: `v${i}`, label: `L${i}` })));
    expect(enabledCount(make(8)) > SEARCH_ABOVE).toBe(false);
    expect(enabledCount(make(9)) > SEARCH_ABOVE).toBe(true);
    expect(enabledCount(toSections(groups))).toBe(3);
  });
  it("opens down with room, up when under 220 px below and more above, clamped to the viewport", () => {
    const view = { width: 390, height: 800 };
    expect(placement({ left: 20, right: 220, top: 100, bottom: 132 }, view)).toMatchObject({ top: 136, left: 20, width: 200 });
    expect(placement({ left: 20, right: 220, top: 700, bottom: 732 }, view)).toMatchObject({ bottom: 104 });
    expect(placement({ left: 300, right: 500, top: 100, bottom: 132 }, view)).toMatchObject({ left: 182, width: 200 });
    expect(placement({ left: -50, right: 600, top: 100, bottom: 132 }, view)).toMatchObject({ left: 8, width: 374 });
  });
});
