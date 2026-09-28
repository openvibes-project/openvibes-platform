import { beforeEach, describe, expect, it } from "vitest";

// A per-tab store like the browser's, for draft recovery.
const store = new Map<string, string>();
Object.assign(globalThis, { sessionStorage: {
  getItem: (key: string) => store.get(key) ?? null,
  setItem: (key: string, value: string) => { store.set(key, value); },
  removeItem: (key: string) => { store.delete(key); },
} });

import { configureDemo, request } from "../api/client";
import type { Dashboard } from "../api/types";
import { BUILTIN_LAYOUT } from "./builtin";
import { editor, editorState } from "./editor";
import { validateLayout } from "./layout";

const layout = { schema: 1 as const, widgets: [{ id: "w1", type: "number" as const, x: 0, y: 0, w: 3, h: 2, config: { metric: "agents.active" } }] };

describe("editor", () => {
  beforeEach(() => { configureDemo("admin"); editor.cancel(); });

  it("the built-in Overview is a valid layout", () => {
    expect(validateLayout(BUILTIN_LAYOUT)).toEqual([]);
  });

  it("refuses to edit what you do not own", async () => {
    configureDemo("analyst");
    const items = (await request<{ items: Dashboard[] }>("GET", "/api/v1/dashboards")).items;
    const shared = items.find((d) => !d.mine);
    expect(shared).toBeDefined();
    expect(editor.begin(shared as Dashboard)).toBe(false);
    expect(editorState().draft).toBeNull();
  });

  it("adds, configures and saves with the version", async () => {
    const created = await request<Dashboard>("POST", "/api/v1/dashboards", { name: "Mine", layout });
    expect(editor.begin(created)).toBe(true);
    const id = editor.add("note");
    editor.configure(id, { text: ["hello"] });
    const saved = await editor.save();
    expect(saved?.version).toBe(2);
    expect(saved?.layout.widgets).toHaveLength(2);
    expect(editorState().dirty).toBe(false);
  });

  it("flags a conflict on 412 and keeps the draft, then saves a copy", async () => {
    const created = await request<Dashboard>("POST", "/api/v1/dashboards", { name: "Shared tab", layout });
    editor.begin(created);
    editor.rename("From tab one");
    await request("PUT", `/api/v1/dashboards/${created.dashboard_id}`, { name: "From tab two", layout }, { "if-match": '"1"' });
    expect(await editor.save()).toBeUndefined();
    expect(editorState()).toMatchObject({ conflict: true, name: "From tab one", dirty: true });
    const copy = await editor.saveAsCopy();
    expect(copy).toMatchObject({ name: "From tab one", mine: true, version: 1 });
  });

  it("shows server problems and keeps the draft", async () => {
    const created = await request<Dashboard>("POST", "/api/v1/dashboards", { name: "Valid", layout });
    editor.begin(created);
    editor.rename("   ");
    expect(await editor.save()).toBeUndefined();
    expect(editorState().problems.map((p) => p.field)).toEqual(["name"]);
    expect(editorState().draft).not.toBeNull();
  });

  it("removing a tile can be undone", async () => {
    const created = await request<Dashboard>("POST", "/api/v1/dashboards", { name: "Undo", layout });
    editor.begin(created);
    editor.remove("w1");
    expect(editorState().draft?.widgets).toHaveLength(0);
    expect(editorState().removed?.id).toBe("w1");
    editor.undo();
    expect(editorState().draft?.widgets.map((w) => w.id)).toEqual(["w1"]);
    expect(editorState().removed).toBeNull();
  });

  it("keeps an unsaved draft across a lost session and offers it back", async () => {
    const created = await request<Dashboard>("POST", "/api/v1/dashboards", { name: "Long edit", layout });
    editor.begin(created);
    editor.rename("Half done");
    editor.suspend();
    expect(editorState().draft).toBeNull();
    expect(editor.recoverable(created.dashboard_id)?.name).toBe("Half done");
    editor.recover(created);
    expect(editorState()).toMatchObject({ name: "Half done", dirty: true });
    editor.cancel();
    expect(editor.recoverable(created.dashboard_id)).toBeNull();
  });

  it("a saved dashboard leaves no draft behind", async () => {
    const created = await request<Dashboard>("POST", "/api/v1/dashboards", { name: "Saved", layout });
    editor.begin(created);
    editor.rename("Saved again");
    await editor.save();
    expect(editor.recoverable(created.dashboard_id)).toBeNull();
  });
});
