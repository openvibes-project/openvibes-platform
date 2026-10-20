import { describe, expect, it, vi } from "vitest";

import { PRESENCE_PREFIXES, parseEvents } from "./livePresence";

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

describe("PRESENCE_PREFIXES", () => {
  it("refetch the agent views, the Hosts list and the host summaries", () => {
    for (const path of ["/api/v1/agents?limit=100", "/api/v1/agents/agent-1", "/api/v1/hosts?status=online&limit=50", "/api/v1/hosts/agent-1/summary"]) {
      expect(PRESENCE_PREFIXES.some((p) => path.startsWith(p)), path).toBe(true);
    }
    expect(PRESENCE_PREFIXES.some((p) => "/api/v1/host-groups".startsWith(p))).toBe(false);
  });
});
