import { describe, expect, it, vi } from "vitest";

import { parseEvents } from "./livePresence";

describe("parseEvents", () => {
  it("fires for presence events and ignores comments", () => {
    const onEvent = vi.fn();
    const rest = parseEvents("retry: 3000\n: connected\n\nevent: presence\ndata: changed\n\n: keep-alive\n\n", onEvent);
    expect(onEvent).toHaveBeenCalledTimes(1);
    expect(rest).toBe("");
  });
  it("keeps an unfinished event for the next chunk", () => {
    const onEvent = vi.fn();
    const rest = parseEvents("event: presence\ndata: ch", onEvent);
    expect(onEvent).not.toHaveBeenCalled();
    parseEvents(`${rest}anged\n\n`, onEvent);
    expect(onEvent).toHaveBeenCalledTimes(1);
  });
});
