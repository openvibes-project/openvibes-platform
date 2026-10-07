// The server serves the SPA only for routes in web/frontend-contract.json;
// every view in the registry (and sign-in, the old /findings page, and a
// dashboard by id) must be one.
import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

const read = (path: string) => readFileSync(new URL(path, import.meta.url), "utf8");

describe("frontend contract", () => {
  it("serves exactly the registry's views, sign-in, /findings and dashboards by id", () => {
    const contract = JSON.parse(read("../../frontend-contract.json")) as { browserRoutes: string[] };
    const viewPaths = [...read("./registry.tsx").matchAll(/\{ path: "(\/[^"]*)"/g)].map((match) => match[1]);
    expect(viewPaths.length).toBeGreaterThan(5);
    expect(new Set(contract.browserRoutes)).toEqual(new Set([...viewPaths, "/login", "/findings", "/dashboards/{dashboard_id}"]));
    expect(contract.browserRoutes[0]).toBe("/");
  });

  it("lists every public asset the page references", () => {
    const contract = JSON.parse(read("../../frontend-contract.json")) as { publicAssets: { route: string }[] };
    const html = read("../../index.html");
    const referenced = [...html.matchAll(/%BASE_URL%([^"]+)"/g)].map((match) => `/${match[1]}`);
    for (const route of referenced) expect(contract.publicAssets.map((asset) => asset.route)).toContain(route);
  });
});
