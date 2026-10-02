import { describe, expect, it } from "vitest";

import type { AlarmPage } from "../api/types";
import { compareNewest } from "./liveAlarms";

const page = (id: string, count = 1, last_seen = "2026-10-02T10:00:00Z"): AlarmPage =>
  ({ items: [{ id, count, last_seen }] }) as unknown as AlarmPage;
const empty = { items: [] } as unknown as AlarmPage;

describe("live alarms", () => {
  it("treats the first answer as the baseline", () => {
    expect(compareNewest(undefined, page("a"))).toMatchObject({ changed: false, fresh: false });
    expect(compareNewest(undefined, empty)).toMatchObject({ seen: null, changed: false });
  });

  it("a new alarm is fresh; a repeat of the newest only refreshes", () => {
    const base = compareNewest(undefined, page("a")).seen;
    expect(compareNewest(base, page("b"))).toMatchObject({ changed: true, fresh: true });
    expect(compareNewest(base, page("a", 2, "2026-10-02T10:00:05Z"))).toMatchObject({ changed: true, fresh: false });
    expect(compareNewest(base, page("a"))).toMatchObject({ changed: false, fresh: false });
  });

  it("the first alarm after none is fresh", () => {
    expect(compareNewest(null, page("a"))).toMatchObject({ changed: true, fresh: true });
  });
});
