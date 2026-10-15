import { describe, expect, it } from "vitest";

import { createDemoServer } from "../server";

async function json(response: Response) {
  return response.json() as Promise<Record<string, unknown>>;
}

describe("demo metrics history", () => {
  const history = async (query: string) =>
    createDemoServer({ persona: "admin" }).handle("GET", `/api/v1/metrics/history?${query}`);

  it("returns at most `days` points ending today, deterministically", async () => {
    const body = await json(await history("metric=alarms.active&days=30"));
    const points = body.points as { day: string; value: number }[];
    expect(points).toHaveLength(30);
    expect(points.at(-1)?.day).toBe(new Date().toISOString().slice(0, 10));
    expect(points.every((p) => Number.isInteger(p.value) && p.value >= 0)).toBe(true);
    expect(((await json(await history("metric=alarms.active&days=30"))).points)).toEqual(points);
    expect(((await json(await history("metric=alarms.active&days=7"))).points as unknown[]).length).toBe(7);
  });

  it("takes only the real API's day counts, 30 by default", async () => {
    for (const days of ["5", "abc", "0"]) {
      const response = await history(`metric=alarms.active&days=${days}`);
      expect(response.status).toBe(422);
      expect(((await json(response)).field_errors as { code: string }[])[0]?.code).toBe("invalid_days");
    }
    expect(((await json(await history("metric=alarms.active"))).points as unknown[]).length).toBe(30);
  });

  it("rejects an unknown metric like the real API, before days and permission", async () => {
    const response = await history("metric=nope&days=5");
    expect(response.status).toBe(422);
    const body = await json(response);
    expect(body).toMatchObject({ code: "invalid_metric_query", title: "The metric query is invalid", field_errors: [{ field: "metric", code: "unknown_metric", message: "Unknown metric" }] });
    expect(((await json(await history("metric=alarms.active&days=5"))).field_errors as { code: string }[])[0]?.code).toBe("invalid_days");
  });

  it("ends on the same count the summaries show", async () => {
    const server = createDemoServer({ persona: "admin" });
    const last = async (metric: string) => ((await json(await server.handle("GET", `/api/v1/metrics/history?metric=${metric}&days=7`))).points as { value: number }[]).at(-1)?.value;
    const agents = await json(await server.handle("GET", "/api/v1/agents/summary"));
    const findings = await json(await server.handle("GET", "/api/v1/compliance/summary"));
    const vulns = await json(await server.handle("GET", "/api/v1/vulnerabilities/summary"));
    expect(await last("agents.stale")).toBe(agents.stale);
    expect(await last("compliance.open.critical")).toBe(findings.critical);
    expect(await last("vulns.exploited")).toBe(vulns.exploited);
  });

  it("refuses unknown metrics", async () => {
    expect((await history("metric=nope")).status).toBe(422);
  });
});

describe("demo top hosts", () => {
  const top = (query = "") => createDemoServer({ persona: "admin" }).handle("GET", `/api/v1/metrics/top-hosts${query}`);

  it("ranks hosts across kinds, serious first, at most `limit`", async () => {
    const items = (await json(await top("?limit=5"))).items as { serious: number; open: number }[];
    expect(items.length).toBeGreaterThan(0);
    expect(items.length).toBeLessThanOrEqual(5);
    for (const [i, a] of items.entries()) {
      const b = items[i + 1];
      if (b) expect(a.serious > b.serious || (a.serious === b.serious && a.open >= b.open)).toBe(true);
    }
  });

  it("refuses a bad limit like the real API", async () => {
    const response = await top("?limit=11");
    expect(response.status).toBe(422);
    expect(await json(response)).toMatchObject({ code: "invalid_metric_query", field_errors: [{ field: "limit", code: "invalid_limit" }] });
  });
});
