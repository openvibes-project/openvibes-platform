// The shared detail page, as markup (no DOM library in vitest; see ui/controls.test.tsx).
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

// nav.ts reads the location when loaded.
vi.hoisted(() => {
  Object.assign(globalThis, { window: { location: { pathname: "/", search: "" }, history: { replaceState() {} }, addEventListener() {}, removeEventListener() {} } });
});

import { SummaryLine } from "../list/SummaryLine";
import { DetailPage } from "./DetailPage";
import { Tile } from "./Tile";

describe("DetailPage", () => {
  it("renders its slots in the shared layout", () => {
    const html = renderToStaticMarkup(
      <DetailPage icon={<span>LX</span>} title="web-01" status={<span className="badge">Online</span>}
        facts={["agent-1", "Debian 12", null, "10.0.0.5"]} actions={<button type="button">Export</button>}
        tiles={[<Tile key="a" label="Open alarms" value={3} to={{ view: "/alarms", params: { host: "agent-1" } }} />]}
        left={<p>LEFT</p>} right={<p>RIGHT</p>} />,
    ).replace(/<!-- -->/g, "");
    const at = (s: string) => html.indexOf(s);
    expect(html).toContain("<h1>web-01</h1>");
    expect(html).toContain("agent-1 · Debian 12 · 10.0.0.5");
    expect(at("LX")).toBeLessThan(at("web-01"));
    expect(at("Online")).toBeGreaterThan(at("web-01"));
    expect(at("Export")).toBeGreaterThan(at("10.0.0.5"));
    expect(at("Open alarms")).toBeLessThan(at("LEFT"));
    expect(at("LEFT")).toBeLessThan(at("RIGHT"));
  });

  it("makes tiles links to their full list, named by label and number", () => {
    const html = renderToStaticMarkup(<Tile label="Open alarms" value={3} to={{ view: "/alarms", params: { host: "agent-1" } }} />);
    expect(html).toMatch(/^<a [^>]*href="\/alarms\?host=agent-1"/);
    expect(html).toContain('aria-label="Open alarms: 3"');
    expect(renderToStaticMarkup(<Tile label="Software" value={1234} to={{ view: "/software" }} />)).toContain('aria-label="Software: 1,234"');
  });

  it("renders nothing for empty slots", () => {
    const html = renderToStaticMarkup(<DetailPage title="web-01" facts={[]} tiles={[]} />);
    expect(html).toContain("web-01");
    expect(html).not.toContain("detail-tiles");
    expect(html).not.toContain("person-page__cols");
    expect(html).not.toContain("person-page__actions");
    expect(html).not.toContain("·");
    expect(html).not.toContain('role="alert"');
    const one = renderToStaticMarkup(<DetailPage title="x" right={<p>R</p>} />);
    expect(one).toContain("detail-page__cols--one");
  });
});

describe("SummaryLine", () => {
  it("joins its parts with a middle dot and can skip zeros", () => {
    const parts = [{ count: 9, text: "online" }, { count: 0, text: "with an older agent" }, { count: 4, text: "with critical vulnerabilities" }];
    expect(renderToStaticMarkup(<SummaryLine parts={parts} />)).toContain("9 online · 0 with an older agent · 4 with critical vulnerabilities");
    const skipped = renderToStaticMarkup(<SummaryLine parts={parts} skipZero />);
    expect(skipped).toContain("9 online · 4 with critical vulnerabilities");
    // A live region stays in the page even when there is nothing to say, so changes are announced.
    expect(renderToStaticMarkup(<SummaryLine parts={[{ count: 0, text: "online" }]} skipZero />)).toMatch(/role="status"[^>]*><\/p>/);
  });
});
