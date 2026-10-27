// The demo's saved views and list columns answer like the real ones
// (src/lists/saved_views.rs): codes, caps, per-person storage.
import { afterEach, describe, expect, it, vi } from "vitest";

import type { ListColumns, SavedView, SavedViewList } from "../../api/types";
import { createDemoServer } from "../server";

type Server = ReturnType<typeof createDemoServer>;
const call = async <T = Record<string, unknown>>(server: Server, method: string, path: string, body?: unknown) => {
  const response = await server.handle(method, path, body);
  const text = await response.text();
  return { status: response.status, body: (text === "" ? {} : JSON.parse(text)) as T };
};
const admin = () => createDemoServer({ persona: "admin" });
const save = (server: Server, name: string, query = "status=online", page = "hosts") =>
  call<SavedView>(server, "POST", "/api/v1/saved-views", { page, name, query });
const list = async (server: Server) => (await call<SavedViewList>(server, "GET", "/api/v1/saved-views?page=hosts")).body.items;

/** A Map-backed localStorage, so the demo's browser persistence runs. */
function stubStorage(initial: Record<string, string> = {}) {
  const store = new Map(Object.entries(initial));
  vi.stubGlobal("localStorage", {
    getItem: (k: string) => store.get(k) ?? null, setItem: (k: string, v: string) => { store.set(k, v); },
    removeItem: (k: string) => { store.delete(k); },
  });
  return store;
}

afterEach(() => vi.unstubAllGlobals());

describe("demo saved views", () => {
  it("saves, lists by name regardless of case, and deletes", async () => {
    const server = admin();
    expect(await list(server)).toEqual([]);
    const created = await save(server, "  linux  ", "os=linux");
    expect(created.status).toBe(201);
    expect(created.body).toMatchObject({ page: "hosts", name: "linux", query: "os=linux" });
    expect(typeof created.body.id).toBe("string");
    await save(server, "Critical", "problems=critical");
    await save(server, "Éclair");
    await save(server, "zed");
    // The server's lower(name) order: code units, no locale (É after z).
    expect((await list(server)).map((v) => v.name)).toEqual(["Critical", "linux", "zed", "Éclair"]);
    expect((await call(server, "DELETE", `/api/v1/saved-views/${created.body.id}`)).status).toBe(204);
    expect(await call(server, "DELETE", `/api/v1/saved-views/${created.body.id}`)).toMatchObject({ status: 404, body: { code: "saved_view_not_found" } });
    expect((await list(server)).map((v) => v.name)).toEqual(["Critical", "zed", "Éclair"]);
  });

  it("refuses a taken name (any case), bad fields, unknown pages and a 51st view", async () => {
    const server = admin();
    await save(server, "Online");
    expect(await save(server, "ONLINE")).toMatchObject({ status: 409, body: { code: "view_name_taken", title: "You already have a view with that name" } });
    expect(await save(server, "x".repeat(61))).toMatchObject({ status: 422, body: { code: "invalid_saved_view", field_errors: [{ field: "name" }] } });
    expect(await save(server, "   ")).toMatchObject({ status: 422, body: { field_errors: [{ field: "name" }] } });
    expect(await save(server, "Long", "q=".padEnd(1001, "a"))).toMatchObject({ status: 422, body: { field_errors: [{ field: "query" }] } });
    expect(await save(server, "Ctl", "q=a\u0007")).toMatchObject({ status: 422, body: { field_errors: [{ field: "query" }] } });
    expect(await save(server, "Nonsense", "", "nonsense")).toMatchObject({ status: 404, body: { code: "list_page_not_found" } });
    expect((await call(server, "GET", "/api/v1/saved-views?page=nope")).status).toBe(404);
    expect((await call(server, "POST", "/api/v1/saved-views", { page: "hosts", name: 3, query: "" })).status).toBe(400);
    for (let i = 1; i < 50; i += 1) expect((await save(server, `View ${i}`)).status).toBe(201);
    expect(await save(server, "One too many")).toMatchObject({ status: 409, body: { code: "too_many_views", title: "You can keep at most 50 views on this page" } });
    // Full is checked before the name, as the store does.
    expect(await save(server, "Online")).toMatchObject({ status: 409, body: { code: "too_many_views" } });
  });

  it("keeps each person's views in their own storage and drops what does not fit on load", async () => {
    const store = stubStorage();
    await save(admin(), "Mine");
    expect((await list(admin())).map((v) => v.name)).toEqual(["Mine"]);
    expect(await list(createDemoServer({ persona: "analyst" }))).toEqual([]);
    const key = [...store.keys()].find((k) => k.startsWith("openvibes.v2.demo.lists.")) ?? "";
    const good = { id: "v-1", page: "hosts", name: "Good", query: "status=online", created_at: "2026-10-20T10:00:00Z" };
    store.set(key, JSON.stringify({
      views: [good, { ...good, id: "v-2", name: "GOOD" }, { ...good, id: "v-3", page: "ports" }, { ...good, id: "v-4", name: "" }, "junk"],
      hidden: { hosts: ["os", "host", "os", "nope"], ports: ["x"] },
    }));
    const server = admin();
    expect((await list(server)).map((v) => v.id)).toEqual(["v-1"]);
    expect((await call<ListColumns>(server, "GET", "/api/v1/list-columns/hosts")).body).toEqual({ hidden: ["os"] });
    store.set(key, "{not json");
    expect(await list(admin())).toEqual([]);
  });
});

describe("demo list columns", () => {
  it("keeps the alarms page's columns, Host hideable there and Severity never", async () => {
    const server = admin();
    expect(await call(server, "PUT", "/api/v1/list-columns/alarms", { hidden: ["host", "case"] })).toMatchObject({ status: 200, body: { hidden: ["host", "case"] } });
    expect((await call(server, "PUT", "/api/v1/list-columns/alarms", { hidden: ["severity"] })).status).toBe(422);
  });

  it("keeps the cases page's views and columns, Case and Title never hidden (step 5d)", async () => {
    const server = admin();
    expect((await save(server, "Mine", "assignee=me", "cases")).status).toBe(201);
    expect(await call(server, "PUT", "/api/v1/list-columns/cases", { hidden: ["hosts", "updated"] })).toMatchObject({ status: 200, body: { hidden: ["hosts", "updated"] } });
    for (const locked of ["case", "title"]) expect((await call(server, "PUT", "/api/v1/list-columns/cases", { hidden: [locked] })).status).toBe(422);
  });

  it("remembers hidden columns, never Host, nothing unknown or repeated", async () => {
    const server = admin();
    expect((await call(server, "GET", "/api/v1/list-columns/hosts")).body).toEqual({ hidden: [] });
    expect(await call(server, "PUT", "/api/v1/list-columns/hosts", { hidden: ["labels", "agent"] })).toMatchObject({ status: 200, body: { hidden: ["labels", "agent"] } });
    expect((await call(server, "GET", "/api/v1/list-columns/hosts")).body).toEqual({ hidden: ["labels", "agent"] });
    expect(await call(server, "PUT", "/api/v1/list-columns/hosts", { hidden: ["host"] }))
      .toMatchObject({ status: 422, body: { code: "invalid_columns", title: "The Host column can't be hidden", field_errors: [{ field: "hidden" }] } });
    expect(await call(server, "PUT", "/api/v1/list-columns/hosts", { hidden: ["os", "os"] })).toMatchObject({ status: 422, body: { title: "Unknown or repeated column" } });
    expect(await call(server, "PUT", "/api/v1/list-columns/hosts", { hidden: ["cpu"] })).toMatchObject({ status: 422 });
    expect((await call(server, "PUT", "/api/v1/list-columns/hosts", { hidden: "os" })).status).toBe(400);
    expect((await call(server, "GET", "/api/v1/list-columns/nonsense")).body).toMatchObject({ code: "list_page_not_found" });
  });
});
