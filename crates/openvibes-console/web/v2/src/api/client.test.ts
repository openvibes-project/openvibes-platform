import { describe, expect, it } from "vitest";

import { ApiError, configureDemo, invalidate, load, request, subscribe } from "./client";

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
});
