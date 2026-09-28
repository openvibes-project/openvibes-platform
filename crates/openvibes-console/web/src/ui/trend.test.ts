import { describe, expect, it } from "vitest";

import { dailyHosts } from "./trend";

describe("dailyHosts", () => {
  it("counts distinct hosts per UTC day, oldest first, with empty days as zero", () => {
    const now = Date.parse("2026-09-28T12:00:00Z");
    const entries = [
      { agent_id: "a", observed_day: "2026-09-28" },
      { agent_id: "a", observed_day: "2026-09-28" },
      { agent_id: "b", observed_day: "2026-09-28" },
      { agent_id: "a", observed_day: "2026-09-26" },
    ];
    expect(dailyHosts(entries, 3, now)).toEqual([
      { day: "2026-09-26", hosts: 1 },
      { day: "2026-09-27", hosts: 0 },
      { day: "2026-09-28", hosts: 2 },
    ]);
  });
});
