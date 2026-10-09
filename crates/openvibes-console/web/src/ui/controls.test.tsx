// No DOM library (vitest runs in node): markup via react-dom/server, key rules as pure helpers.
// Click / arrow / Space flows are covered by the editor e2e in Task 4.
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { Segmented } from "./Segmented";
import { withUnknown, wrapStep } from "./segmented";
import { Switch } from "./Switch";

const opts = [{ value: 7, label: "7 d" }, { value: 30, label: "30 d" }];
const noop = () => {};

describe("Segmented", () => {
  it("is a radiogroup of radios with the right aria-checked", () => {
    const html = renderToStaticMarkup(<Segmented label="Period" value={30} onChange={noop} options={opts} />);
    expect(html).toContain('role="radiogroup"');
    expect(html.match(/role="radio"/g)).toHaveLength(2);
    expect(html).toMatch(/aria-checked="false"[^>]*>7 d/);
    expect(html).toMatch(/aria-checked="true"[^>]*>30 d/);
  });
  it("arrows wrap", () => {
    expect(wrapStep(1, 1, 2)).toBe(0);
    expect(wrapStep(0, -1, 4)).toBe(3);
    expect(wrapStep(1, 1, 4)).toBe(2);
  });
  it("a value outside the options becomes an extra checked option", () => {
    expect(withUnknown(opts, 9, String)).toHaveLength(3);
    expect(withUnknown(opts, 7, String)).toBe(opts);
    const html = renderToStaticMarkup(<Segmented label="P" value={9} unknownLabel={(v) => `${v} (old)`} onChange={noop} options={opts} />);
    expect(html).toMatch(/aria-checked="true"[^>]*>9 \(old\)/);
  });
});

describe("Switch", () => {
  it("is a switch with aria-checked", () => {
    const html = renderToStaticMarkup(<Switch label="Smooth" checked onChange={noop} />);
    expect(html).toContain('role="switch"');
    expect(html).toContain('aria-checked="true"');
    expect(html).not.toContain("disabled");
  });
  it("disabled reaches the button", () => {
    expect(renderToStaticMarkup(<Switch label="x" checked={false} disabled onChange={noop} />)).toContain("disabled");
  });
});
