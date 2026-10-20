import { describe, expect, it, vi } from "vitest";

import { ApiError, configureDemo, invalidate, load, loadAllPages, prime, request, subscribe } from "./client";

describe("client", () => {
  it("serves demo requests and raises problem details as ApiError", async () => {
    configureDemo("viewer");
    const summary = await request<{ total: number }>("GET", "/api/v1/agents/summary");
    expect(summary.total).toBeGreaterThan(0);
    await expect(request("GET", "/api/v1/audit-events")).rejects.toMatchObject({ status: 403, code: "forbidden" });
    await expect(request("GET", "/api/v1/audit-events")).rejects.toBeInstanceOf(ApiError);
  });

  it("caches loads and tells subscribers when a prefix is invalidated", async () => {
    configureDemo("admin");
    const first = await load("/api/v1/agents/summary");
    expect(await load("/api/v1/agents/summary")).toBe(first);
    let told = 0;
    const stop = subscribe(() => { told += 1; });
    invalidate("/api/v1/agents");
    expect(told).toBe(1);
    expect(await load("/api/v1/agents/summary")).not.toBe(first);
    stop();
  });

  it("serves a primed value without asking the server, and tells subscribers", async () => {
    configureDemo("admin");
    let told = 0;
    const stop = subscribe(() => { told += 1; });
    prime("/api/v1/no-such-endpoint", { saved: true });
    expect(told).toBe(1);
    expect(await load("/api/v1/no-such-endpoint")).toEqual({ saved: true });
    stop();
  });

  it("follows array pages by after= past 2000 rows, up to max", async () => {
    configureDemo(undefined);
    const fetch = vi.fn(async (url: string) => {
      const after = Number(new URL(url, "http://x").searchParams.get("after") ?? -1);
      const rows = Array.from({ length: after + 100 < 2500 ? 100 : 2499 - after }, (_, i) => ({ agent_id: String(after + 1 + i) }));
      return new Response(JSON.stringify(rows), { status: 200 });
    });
    vi.stubGlobal("fetch", fetch);
    try {
      expect((await loadAllPages<{ agent_id: string }>("/api/v1/host-groups/big/hosts", 10000, "agent_id")).length).toBe(2500);
      expect((await loadAllPages<{ agent_id: string }>("/api/v1/host-groups/big2/hosts", 300, "agent_id")).length).toBe(300);
    } finally {
      vi.unstubAllGlobals();
    }
  });
});
