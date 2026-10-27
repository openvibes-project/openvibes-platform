import { describe, expect, it } from "vitest";

import { createDemoServer } from "../server";

async function json(response: Response) {
  return response.json() as Promise<Record<string, unknown>>;
}

describe("demo dashboards", () => {
  const layout = { schema: 1, widgets: [{ id: "w1", type: "number", x: 0, y: 0, w: 3, h: 2, config: { metric: "agents.active" } }] };

  it("runs the dashboard lifecycle with ETags and If-Match like the API", async () => {
    const server = createDemoServer({ persona: "admin" });
    const created = await server.handle("POST", "/api/v1/dashboards", { name: " Morning ", layout });
    expect(created.status).toBe(201);
    expect(created.headers.get("etag")).toBe('"1"');
    const dashboard = await json(created);
    expect(dashboard).toMatchObject({ name: "Morning", mine: true, version: 1 });
    const uri = `/api/v1/dashboards/${String(dashboard.dashboard_id)}`;
    expect((await server.handle("PUT", uri, { name: "x", layout })).status).toBe(428);
    expect((await server.handle("PUT", uri, { name: "x", layout }, { "if-match": '"1"' })).status).toBe(200);
    expect((await server.handle("PUT", uri, { name: "y", layout }, { "if-match": '"1"' })).status).toBe(412);
    expect((await server.handle("DELETE", uri)).status).toBe(204);
    expect((await server.handle("GET", uri)).status).toBe(404);
    expect((await server.handle("GET", "/api/v1/dashboards/not-a-uuid")).status).toBe(404);
  });

  it("refuses invalid layouts with the server's field paths", async () => {
    const server = createDemoServer({ persona: "admin" });
    const bad = await server.handle("POST", "/api/v1/dashboards", { name: "X", layout: { schema: 1, widgets: [{ id: "w1", type: "pie-chart", x: 0, y: 0, w: 3, h: 2, config: {} }] } });
    expect(bad.status).toBe(422);
    expect(((await json(bad)).field_errors as { field: string }[])[0]?.field).toBe("layout.widgets[0].type");
    expect((await server.handle("POST", "/api/v1/dashboards", { name: "", layout })).status).toBe(422);
    expect((await server.handle("POST", "/api/v1/dashboards", { name: "X" })).status).toBe(400);
  });

  it("a viewer never sees an unshared dashboard, and sharing needs the permission", async () => {
    const admin = createDemoServer({ persona: "admin" });
    const viewer = createDemoServer({ persona: "viewer" });
    const own = (await json(await viewer.handle("GET", "/api/v1/dashboards"))).items as { name: string; mine: boolean }[];
    expect(own.some((d) => d.name === "My morning check")).toBe(false);
    const mine = await json(await viewer.handle("POST", "/api/v1/dashboards", { name: "Viewer's", layout }));
    expect((await viewer.handle("PUT", `/api/v1/dashboards/${String(mine.dashboard_id)}/sharing`, { visibility: "roles", role_ids: ["viewer"] })).status).toBe(403);
    expect((await admin.handle("PUT", "/api/v1/dashboards/d-admin-morning/sharing", { visibility: "roles", role_ids: ["no_such"] })).status).toBe(422);
  });

  it("shows the seeded team dashboard to analysts read-only and lets them make it home", async () => {
    const analyst = createDemoServer({ persona: "analyst" });
    const items = (await json(await analyst.handle("GET", "/api/v1/dashboards"))).items as { dashboard_id: string; name: string; mine: boolean }[];
    const team = items.find((d) => d.name === "Analyst triage");
    expect(team?.mine).toBe(false);
    expect((await analyst.handle("PUT", `/api/v1/dashboards/${team?.dashboard_id ?? ""}`, { name: "x", layout }, { "if-match": '"1"' })).status).toBe(403);
    expect((await analyst.handle("PUT", "/api/v1/me/home", { dashboard_id: team?.dashboard_id })).status).toBe(200);
    expect((await json(await analyst.handle("GET", "/api/v1/me/home"))).dashboard_id).toBe(team?.dashboard_id);
    expect((await analyst.handle("PUT", "/api/v1/me/home", { dashboard_id: "d-admin-morning" })).status).toBe(404);
  });

  it("names the roles a dashboard is shared with, as the API does", async () => {
    const analyst = createDemoServer({ persona: "analyst" });
    const items = (await json(await analyst.handle("GET", "/api/v1/dashboards"))).items as { name: string; visibility: string; roles: { name: string }[] }[];
    const team = items.find((d) => d.name === "Analyst triage");
    expect([team?.visibility, team?.roles.map((r) => r.name)]).toEqual(["roles", ["Analyst"]]);
    const own = await json(await createDemoServer({ persona: "admin" }).handle("POST", "/api/v1/dashboards", { name: "Mine", layout }));
    expect([own.visibility, own.roles]).toEqual(["private", []]);
  });

  it("shares with roles the owner holds, with everyone, and back to private", async () => {
    const admin = createDemoServer({ persona: "admin" });
    const uri = "/api/v1/dashboards/d-admin-morning/sharing";
    expect((await admin.handle("PUT", uri, { visibility: "world" })).status).toBe(400);
    expect((await admin.handle("PUT", uri, { visibility: "roles", role_ids: [] })).status).toBe(422);
    const everyone = await json(await admin.handle("PUT", uri, { visibility: "everyone", role_ids: ["viewer"] }));
    expect([everyone.visibility, everyone.roles]).toEqual(["everyone", []]);
    const viewer = await json(await admin.handle("PUT", uri, { visibility: "private" }));
    expect(viewer.version).toBe(3);
    // Sharing with everyone needs dashboards.publish, which a plain sharer lacks.
    const lead = createDemoServer({ persona: "team_lead" });
    const made = await json(await lead.handle("POST", "/api/v1/dashboards", { name: "Lead's", layout }));
    expect((await lead.handle("PUT", `/api/v1/dashboards/${String(made.dashboard_id)}/sharing`, { visibility: "everyone" })).status).toBe(403);
  });

  it("checks a save in the server's order: If-Match, then the body, then ownership and version", async () => {
    const server = createDemoServer({ persona: "admin" });
    const created = await json(await server.handle("POST", "/api/v1/dashboards", { name: "Order", layout }));
    const uri = `/api/v1/dashboards/${String(created.dashboard_id)}`;
    expect((await server.handle("PUT", uri, { name: "", layout }, { "if-match": '"9"' })).status).toBe(422);
    expect((await server.handle("PUT", uri, { name: "" })).status).toBe(428);
    expect((await server.handle("PUT", "/api/v1/dashboards/d-ola-triage", { name: "", layout }, { "if-match": '"1"' })).status).toBe(422);
  });

  it("limits an owner to 100 dashboards", async () => {
    const server = createDemoServer({ persona: "viewer" });
    for (let index = 0; index < 100; index += 1) await server.handle("POST", "/api/v1/dashboards", { name: `D${index}`, layout });
    expect((await server.handle("POST", "/api/v1/dashboards", { name: "One more", layout })).status).toBe(422);
  });
});
