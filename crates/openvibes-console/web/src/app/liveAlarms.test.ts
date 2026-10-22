import { describe, expect, it } from "vitest";

import type { AlarmPage } from "../api/types";
import { ALARMS_PREFIX, LIST_MS, LIST_PREFIX, LIVE_PREFIXES, compareNewest, listRefresh } from "./liveAlarms";

const alarm = (id: string, first_seen: string, last_seen = first_seen, count = 1) => ({ id, first_seen, last_seen, count });
const page = (...items: ReturnType<typeof alarm>[]) => ({ items }) as unknown as AlarmPage;
const T = (s: number) => `2026-10-02T10:00:${String(s).padStart(2, "0")}.000Z`;

describe("live alarms", () => {
  it("treats the first answer as the baseline", () => {
    expect(compareNewest(undefined, page(alarm("a", T(1))))).toMatchObject({ changed: false, fresh: false });
    expect(compareNewest(undefined, page())).toMatchObject({ changed: false, fresh: false });
  });

  it("a newly appeared alarm is fresh", () => {
    const { seen } = compareNewest(undefined, page(alarm("a", T(1))));
    expect(compareNewest(seen, page(alarm("b", T(5))))).toMatchObject({ changed: true, fresh: true });
  });

  it("an older alarm repeating moves to the top but is not fresh", () => {
    const { seen } = compareNewest(undefined, page(alarm("b", T(5))));
    expect(compareNewest(seen, page(alarm("a", T(1), T(9), 2)))).toMatchObject({ changed: true, fresh: false });
  });

  it("the newest going away refreshes but is not fresh", () => {
    const { seen } = compareNewest(undefined, page(alarm("b", T(5))));
    expect(compareNewest(seen, page(alarm("a", T(1))))).toMatchObject({ changed: true, fresh: false });
    expect(compareNewest(seen, page())).toMatchObject({ changed: true, fresh: false });
  });

  it("the first alarm after none is fresh, once", () => {
    const { seen } = compareNewest(undefined, page());
    const next = compareNewest(seen, page(alarm("a", T(1))));
    expect(next).toMatchObject({ changed: true, fresh: true });
    expect(compareNewest(next.seen, page(alarm("a", T(1), T(3), 2)))).toMatchObject({ changed: true, fresh: false });
  });

  it("compares times, not text: a fraction of a second later is fresh", () => {
    const { seen } = compareNewest(undefined, page(alarm("a", "2026-10-02T10:00:00Z")));
    expect(compareNewest(seen, page(alarm("b", "2026-10-02T10:00:00.5Z")))).toMatchObject({ fresh: true });
  });

  it("a change refreshes the alarm reads at once, but not the Alarms list", () => {
    const live = (path: string) => LIVE_PREFIXES.some((prefix) => path.startsWith(prefix));
    for (const path of ["/api/v1/alarms?state=active", "/api/v1/alarms/9000/summary", "/api/v1/alarm-suppressions?state=pending"]) expect(live(path)).toBe(true);
    expect(live("/api/v1/alarm-list?limit=50")).toBe(false);
    expect("/api/v1/alarm-list?limit=50".startsWith(LIST_PREFIX)).toBe(true);
    // Triage (BulkBar) still refreshes every alarm read, the list included.
    expect("/api/v1/alarm-list?limit=50".startsWith(ALARMS_PREFIX)).toBe(true);
  });

  it("refreshes the Alarms list at most every 30 s, and catches up on a change it held back", () => {
    expect(LIST_MS).toBe(30_000);
    let clock = { due: false, at: 0 };
    let step = listRefresh(clock, 5_000, true);
    expect(step.refresh).toBe(false);
    clock = step.clock;
    step = listRefresh(clock, 25_000, false);
    expect(step.refresh).toBe(false);
    clock = step.clock;
    step = listRefresh(clock, 30_000, false);
    expect(step.refresh).toBe(true);
    clock = step.clock;
    expect(listRefresh(clock, 35_000, true).refresh).toBe(false);
    expect(listRefresh(clock, 90_000, false).refresh).toBe(false);
    expect(listRefresh(clock, 60_000, true).refresh).toBe(true);
  });
});
