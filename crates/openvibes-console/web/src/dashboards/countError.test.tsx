import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { CountError } from "./CountError";

describe("a count that failed to load", () => {
  it("says the role lacks access on 403 and shows the error otherwise", () => {
    expect(renderToStaticMarkup(<CountError error={{ status: 403, message: "x" }} />)).toContain("Not available with your role");
    const html = renderToStaticMarkup(<CountError error={{ status: 503, message: "History is down" }} />);
    expect(html).toContain("History is down");
    expect(html).toContain("tile-empty");
  });
});
