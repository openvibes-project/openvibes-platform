// A package page's cards as markup (no DOM library in vitest; see ui/controls.test.tsx).
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

// nav.ts reads the location when loaded.
vi.hoisted(() => {
  Object.assign(globalThis, { window: { location: { pathname: "/software/openssl", search: "" }, history: { replaceState() {} }, addEventListener() {}, removeEventListener() {} } });
});

import type { SoftwarePageSummary } from "../../../api/types";
import { DetailsCard, VulnerabilitiesCard } from "./SoftwareCards";

const advisory = (n: number) => ({ advisory_id: `OS-${n}`, severity: "low", title: "t", cves: [], exploited: false, epss: null, cvss: null, fixed_in: null, hosts: 1 });
const page = (shown: number, total: number) => ({
  header: { name: "openssl", managers: ["dpkg"], hosts: 3, of: 3, first_seen: null },
  tiles: { hosts: 3, vulnerabilities: total, update_hosts: 0, versions: 1 },
  versions: [],
  advisories: Array.from({ length: shown }, (_, i) => advisory(i)),
  no_fix: 0,
}) as unknown as SoftwarePageSummary;

describe("the advisory count", () => {
  it("is the full total, with how many the list holds when it stops at 50", () => {
    expect(renderToStaticMarkup(<VulnerabilitiesCard page={page(50, 73)} />)).toContain("50 of 73");
    expect(renderToStaticMarkup(<DetailsCard page={page(50, 73)} />)).toContain(">73<");
  });

  it("is just the number when the list holds them all", () => {
    const html = renderToStaticMarkup(<VulnerabilitiesCard page={page(2, 2)} />);
    expect(html).toContain(">2<");
    expect(html).not.toContain(" of ");
  });
});
