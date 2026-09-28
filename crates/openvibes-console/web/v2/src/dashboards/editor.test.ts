import { beforeEach, describe, expect, it } from "vitest";

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
});
