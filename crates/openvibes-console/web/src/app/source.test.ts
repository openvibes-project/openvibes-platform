import { describe, expect, it } from "vitest";

import { chooseSource } from "./source";

describe("data source", () => {
  const installed = { DEV: false, VITE_DEMO: undefined };
  const preview = { DEV: false, VITE_DEMO: "true" };
  const dev = { DEV: true, VITE_DEMO: undefined };

  it("an installed console is always live, whatever the URL or storage says", () => {
    expect(chooseSource("?demo=1", "demo", installed)).toEqual({ demo: false, demoAllowed: false, remember: null });
    expect(chooseSource("", null, installed).demo).toBe(false);
  });

  it("the preview defaults to the demo and can switch to live", () => {
    expect(chooseSource("", null, preview)).toMatchObject({ demo: true, demoAllowed: true });
    expect(chooseSource("?live=1", null, preview)).toEqual({ demo: false, demoAllowed: true, remember: "live" });
  });

  it("development defaults to the demo and remembers an explicit choice", () => {
    expect(chooseSource("", null, dev).demo).toBe(true);
    expect(chooseSource("", "live", dev).demo).toBe(false);
    expect(chooseSource("?demo=1", "live", dev)).toEqual({ demo: true, demoAllowed: true, remember: "demo" });
  });
});
