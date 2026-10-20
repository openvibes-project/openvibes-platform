// Saved views and hidden columns through the API (the in-browser demo, see
// test-setup.ts), and the one-time import of the old browser-only views.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ApiError, apiMessage, configureDemo, request } from "../../api/client";
import type { SavedViewList } from "../../api/types";
import { deleteView, importBrowserViews, saveView, setHiddenColumns } from "./savedViews";

function stubStorage(initial: Record<string, string> = {}) {
  const store = new Map(Object.entries(initial));
  vi.stubGlobal("localStorage", {
    getItem: (k: string) => store.get(k) ?? null, setItem: (k: string, v: string) => { store.set(k, v); },
    removeItem: (k: string) => { store.delete(k); },
  });
  return store;
}
const views = async () => (await request<SavedViewList>("GET", "/api/v1/saved-views?page=hosts")).items;
const LEGACY = "openvibes.v2.views./agents";
const toOnline = (query: string) => query.replace("status=active", "status=online");

beforeEach(() => configureDemo("admin"));
afterEach(() => { vi.unstubAllGlobals(); configureDemo(undefined); });

describe("saved views", () => {
  it("posts {page, name, query} and deletes by id", async () => {
    const posted: unknown[] = [];
    configureDemo(undefined);
    vi.stubGlobal("fetch", vi.fn((url: string, init: RequestInit) => {
      posted.push({ url, method: init.method, body: JSON.parse(String(init.body)) });
      return Promise.resolve(new Response(JSON.stringify({ id: "v1", page: "hosts", name: "Online", query: "status=online", created_at: "" }), { status: 201 }));
    }));
    await saveView("hosts", "Online", "status=online");
    expect(posted).toEqual([{ url: "/api/v1/saved-views", method: "POST", body: { page: "hosts", name: "Online", query: "status=online" } }]);
  });

  it("refuses a second view of the same name with the server's words", async () => {
    await saveView("hosts", "Online", "status=online");
    const error = await saveView("hosts", "online", "status=offline").catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ApiError);
    expect(apiMessage(error, "")).toBe("You already have a view with that name");
    const [view] = await views();
    await deleteView("hosts", view?.id ?? "");
    expect(await views()).toEqual([]);
  });

  it("saves hidden columns", async () => {
    expect(await setHiddenColumns("hosts", ["labels"])).toEqual({ hidden: ["labels"] });
    expect(await request("GET", "/api/v1/list-columns/hosts")).toEqual({ hidden: ["labels"] });
    expect(apiMessage(await setHiddenColumns("hosts", ["host"]).catch((e: unknown) => e), "")).toBe("The Host column can't be hidden");
  });
});

describe("importBrowserViews", () => {
  it("imports the old views once, mapped, then removes the key", async () => {
    const store = stubStorage({ [LEGACY]: JSON.stringify([{ name: "Active", query: "status=active" }, { name: "Bad" }, { name: "Linux", query: "os=linux" }]) });
    await importBrowserViews("hosts", LEGACY, toOnline);
    expect((await views()).map((v) => [v.name, v.query])).toEqual([["Active", "status=online"], ["Linux", "os=linux"]]);
    expect(store.has(LEGACY)).toBe(false);
    await importBrowserViews("hosts", LEGACY, toOnline);
    expect(await views()).toHaveLength(2);
  });

  it("skips views the server refuses (a taken name) and still removes the key", async () => {
    await saveView("hosts", "Active", "status=offline");
    const store = stubStorage({ [LEGACY]: JSON.stringify([{ name: "active", query: "status=active" }]) });
    await importBrowserViews("hosts", LEGACY, toOnline);
    expect((await views()).map((v) => v.query)).toEqual(["status=offline"]);
    expect(store.has(LEGACY)).toBe(false);
  });

  it("keeps the key when the console cannot be reached, to try again next time", async () => {
    configureDemo(undefined);
    vi.stubGlobal("fetch", vi.fn(() => Promise.reject(new Error("offline"))));
    const store = stubStorage({ [LEGACY]: JSON.stringify([{ name: "Active", query: "status=active" }]) });
    await importBrowserViews("hosts", LEGACY, toOnline);
    expect(store.has(LEGACY)).toBe(true);
  });

  it("does nothing without storage or old views", async () => {
    await importBrowserViews("hosts", LEGACY, toOnline);
    stubStorage({ [LEGACY]: "not json" });
    await importBrowserViews("hosts", LEGACY, toOnline);
    expect(await views()).toEqual([]);
  });
});
