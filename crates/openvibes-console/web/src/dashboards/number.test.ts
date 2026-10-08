import { describe, expect, it } from "vitest";
import { delta, deltaSince, partText, permitted } from "./metrics";

describe("number tile", () => {
  it("describes the change over the period", () => {
    expect(delta([{ day: "2026-10-01", value: 3 }, { day: "2026-10-07", value: 1 }])).toBe("−2");
    expect(delta([{ day: "2026-10-01", value: 1 }, { day: "2026-10-07", value: 2 }])).toBe("+1");
    expect(delta([{ day: "2026-10-01", value: 1 }, { day: "2026-10-07", value: 1 }])).toBe("no change");
    expect(delta([{ day: "2026-10-07", value: 1 }])).toBeNull();
    expect(delta([{ day: "a", value: 1 }, { day: "b", value: 1500 }])).toBe("+1,499");
  });
  it("says so when the history is shorter than the period", () => {
    const now = Date.parse("2026-10-07T12:00:00Z");
    const pts = (d: string) => [{ day: d }, { day: "2026-10-07" }];
    expect(deltaSince(pts("2026-09-25"), 30, now)).toBe("vs 12 d ago");
    expect(deltaSince(pts("2026-09-08"), 30, now)).toBeNull();
    expect(deltaSince([{ day: "2026-10-07" }], 30, now)).toBeNull();
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
