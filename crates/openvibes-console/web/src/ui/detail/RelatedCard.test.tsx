import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { RelatedCard } from "./RelatedCard";

describe("RelatedCard", () => {
  it("draws nothing without sections", () => {
    expect(renderToStaticMarkup(<RelatedCard sections={[]} />)).toBe("");
  });
  it("titles the card; a section with href links its value, one without does not", () => {
    const html = renderToStaticMarkup(<RelatedCard sections={[{ label: "Advisory", value: "CVE-1", href: "/x?y=1" }, { label: "Vendor", value: "Acme" }]} />);
    expect(html).toContain("Related");
    expect(html).toMatch(/<a [^>]*href="\/x\?y=1"[^>]*>CVE-1<\/a>/);
    expect(html).toContain("Acme");
    expect(html.match(/<a /g)).toHaveLength(1);
  });
});
