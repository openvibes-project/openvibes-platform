import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { FactTile } from "./FactTile";

describe("FactTile", () => {
  it("shows a label and a value without being a link", () => {
    const html = renderToStaticMarkup(<FactTile label="Confidence" value="80%" />);
    expect(html).not.toContain("<a");
    expect(html).toContain("detail-tile__value");
    expect(html).toContain("80%");
    expect(html).toContain("Confidence");
  });
});
