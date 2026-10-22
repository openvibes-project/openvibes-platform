// The host filter of Alarms, Compliance and Vulnerabilities (plan ruling 9), as markup.
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

// nav.ts reads the location when loaded.
vi.hoisted(() => {
  Object.assign(globalThis, { window: { location: { pathname: "/", search: "" }, history: { replaceState() {} }, addEventListener() {}, removeEventListener() {} } });
});

import { HostChip } from "./HostChip";

describe("host filter", () => {
  it("shows a removable chip naming the host, or nothing without one", () => {
    const html = renderToStaticMarkup(<HostChip id="agent-00005" />).replace(/<!-- -->/g, "");
    expect(html).toContain("Host: agent-00005");
    expect(html).toContain('aria-label="Remove filter Host: agent-00005"');
    expect(renderToStaticMarkup(<HostChip id={null} />)).toBe("");
  });
});
