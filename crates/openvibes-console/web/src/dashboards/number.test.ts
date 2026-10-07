import { describe, expect, it } from "vitest";
import { delta, partText, permitted } from "./metrics";

describe("number tile", () => {
  it("describes the change over the period", () => {
    expect(delta([{ day: "2026-10-01", value: 3 }, { day: "2026-10-07", value: 1 }])).toBe("−2");
    expect(delta([{ day: "2026-10-01", value: 1 }, { day: "2026-10-07", value: 2 }])).toBe("+1");
    expect(delta([{ day: "2026-10-01", value: 1 }, { day: "2026-10-07", value: 1 }])).toBe("no change");
    expect(delta([{ day: "2026-10-07", value: 1 }])).toBeNull();
    expect(delta([{ day: "a", value: 1 }, { day: "b", value: 1500 }])).toBe("+1,499");
  });
  it("needs every permission of a cross-kind count", () => {
    const can = (p: string) => p !== "alarms.read";
    expect(permitted("all.open.critical", can)).toBe(false);
    expect(permitted("vulns.exploited", can)).toBe(true);
  });
  it("formats part counts with separators", () => {
    expect(partText("alarm", 1200)).toBe(`${(1200).toLocaleString()} alarms`);
  });
});
