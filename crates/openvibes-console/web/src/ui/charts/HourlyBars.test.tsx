import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { HourlyBars, barHeights } from "./HourlyBars";

describe("HourlyBars", () => {
  it("scales bars to the largest hour, with a minimum for non-zero", () => {
    expect(barHeights([0, 5, 10], 40)).toEqual([0, 20, 40]);
    expect(barHeights([0, 0], 40)).toEqual([0, 0]);
    expect(barHeights([1, 1000], 40)[0]).toBeGreaterThanOrEqual(1);
  });

  it("draws one titled bar per hour and a hidden table of the values", () => {
    const values = Array.from({ length: 24 }, (_, i) => i);
    const html = renderToStaticMarkup(<HourlyBars values={values} label="Starts per hour" />);
    expect(html.match(/<rect/g)).toHaveLength(24);
    expect(html).toContain("<title>");
    // The table carries the values for screen readers; the picture is hidden from them.
    expect(html).toContain('<svg aria-hidden="true"');
    expect(html).not.toContain('role="img"');
    expect(html).toContain("<caption>Starts per hour</caption>");
    expect(html).toContain("sr-only");
    expect(html.match(/<tr/g)).toHaveLength(25);
  });

  it("counts days too: today last, one bar each", () => {
    const html = renderToStaticMarkup(<HourlyBars values={[1, 2, 3]} label="Failing hosts per day" unit="day" />);
    expect(html.match(/<rect/g)).toHaveLength(3);
    expect(html).toContain("<title>today: 3</title>");
    expect(html).toContain("<title>2 days ago: 1</title>");
    expect(html).toContain('<th scope="col">Day</th>');
  });
});
