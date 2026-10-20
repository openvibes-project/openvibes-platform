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
  it("imports the old views once, mapped and normalised, then removes the key", async () => {
    const store = stubStorage({ [LEGACY]: JSON.stringify([{ name: "Active", query: "status=active&os=linux" }, { name: "Bad" }, { name: "Linux", query: "os=linux" }]) });
    await importBrowserViews("hosts", LEGACY, toOnline);
    // Stored sorted (viewQuery), so the FilterBar shows it as the active view.
    expect((await views()).map((v) => [v.name, v.query])).toEqual([["Active", "os=linux&status=online"], ["Linux", "os=linux"]]);
    expect(store.has(LEGACY)).toBe(false);
    await importBrowserViews("hosts", LEGACY, toOnline);
    expect(await views()).toHaveLength(2);
  });

  it("renames a clash with a different view, skips an exact duplicate, and shortens long names", async () => {
    await saveView("hosts", "Active", "status=offline");
    await saveView("hosts", "Linux", "os=linux");
    const long = `${"é".repeat(59)}xyz`;
    const store = stubStorage({ [LEGACY]: JSON.stringify([
      { name: "active", query: "status=active" }, { name: "LINUX", query: "os=linux" }, { name: long, query: "q=a" }, { name: "  ", query: "q=b" },
    ]) });
    await importBrowserViews("hosts", LEGACY, toOnline);
    const byName = new Map((await views()).map((v) => [v.name, v.query]));
    expect(byName.get("Active")).toBe("status=offline");
    expect(byName.get("active (imported)")).toBe("status=online");
    expect(byName.get("Linux")).toBe("os=linux");
    expect(byName.get(`${"é".repeat(59)}x`)).toBe("q=a");
    expect(byName.get("Imported view")).toBe("q=b");
    expect(byName.size).toBe(5);
    expect(store.has(LEGACY)).toBe(false);
    // A second run (say the key came back) finds every view already there.
    store.set(LEGACY, JSON.stringify([{ name: "active", query: "status=active" }]));
    await importBrowserViews("hosts", LEGACY, toOnline);
    expect(await views()).toHaveLength(5);
    expect(store.has(LEGACY)).toBe(false);
  });

  it("keeps the key while a view could not be saved (too many, invalid), for the next visit", async () => {
    for (let i = 0; i < 50; i += 1) await saveView("hosts", `View ${i}`, "");
    const store = stubStorage({ [LEGACY]: JSON.stringify([{ name: "Active", query: "status=active" }]) });
    await importBrowserViews("hosts", LEGACY, toOnline);
    expect(store.has(LEGACY)).toBe(true);
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
