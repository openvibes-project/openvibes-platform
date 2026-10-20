// The FilterBar. Vitest runs in node with no DOM library (see ui/controls.test.tsx):
// the bar is checked as markup from react-dom/server against real URLs, its
// actions as the pure helpers it calls. Click and key flows: the Hosts e2e.
import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// nav.ts reads the location when loaded; replaceState moves it like a browser.
vi.hoisted(() => {
  const location = { pathname: "/hosts", search: "" };
  const move = (_: unknown, __: string, url: string) => { const u = new URL(url, "http://x"); location.pathname = u.pathname; location.search = u.search; };
  Object.assign(globalThis, { window: { location, history: { replaceState: move, pushState: move }, addEventListener() {}, removeEventListener() {} } });
});

import type { SavedView } from "../../api/types";
import { nav } from "../../app/nav";
import { ColumnList } from "./ColumnsMenu";
import { FilterBarBody, SavedViewChip, SaveViewForm } from "./FilterBar";
import { type ListFilter, applyViewChanges, chosenFilters, clearAllChanges, debounce, hasFilters, valueOptions, viewQuery } from "./filters";
import { columnSaver, toggleHidden } from "./savedViews";

const status: ListFilter = { param: "status", label: "Status", values: [{ value: "online", label: "Online", count: 9 }, { value: "offline", label: "Offline", count: 1234 }] };
const os: ListFilter = { param: "os", label: "OS", values: [{ value: "linux", label: "Linux", count: 8 }] };
const columns = [{ key: "host", label: "Host" }, { key: "os", label: "OS" }, { key: "labels", label: "Labels" }];
const online: SavedView = { id: "v1", page: "hosts", name: "Online", query: "status=online", created_at: "2026-10-20T10:00:00Z" };
const noop = () => {};

const url = (query: string) => {
  nav.setParams(Object.fromEntries([...nav.location.params.keys()].map((k) => [k, null])));
  nav.setParams(Object.fromEntries(new URLSearchParams(query)));
};
const render = (views: SavedView[] = []) => renderToStaticMarkup(
  <FilterBarBody page="hosts" label="Search hosts" filters={[status, os]} columns={columns} params={nav.location.params} views={views} hidden={["labels"]} />,
);

beforeEach(() => url(""));
afterEach(() => vi.useRealTimers());

describe("FilterBar", () => {
  it("renders a chip per filter that opens its values with counts", () => {
    const html = render();
    expect(html).toMatch(/aria-haspopup="listbox" aria-expanded="false"[^>]*aria-label="Status"/);
    expect(html).toContain('aria-label="OS"');
    expect(valueOptions(status)).toEqual([{ value: "online", label: "Online", hint: "9" }, { value: "offline", label: "Offline", hint: "1,234" }]);
    expect(html).toContain('placeholder="Search…"');
    expect(html).toContain("Search hosts");
  });

  it("shows a chosen value as a chip with ×, which clears it", () => {
    url("status=online");
    expect(nav.location.params.get("status")).toBe("online");
    expect(chosenFilters([status, os], nav.location.params)).toEqual([{ param: "status", text: "Status: Online" }]);
    const html = render();
    expect(html).toContain("Status: Online");
    expect(html).toContain('aria-label="Remove filter Status: Online"');
    expect(html).not.toContain('aria-label="Status"');
    // A value the list no longer offers still shows, by its raw value.
    expect(chosenFilters([status], new URLSearchParams("status=gone"))).toEqual([{ param: "status", text: "Status: gone" }]);
  });

  it("Clear all clears every filter but keeps the sort", () => {
    url("q=web&status=online&os=linux&sort=name&dir=desc");
    nav.setParams(clearAllChanges(nav.location.params));
    expect(nav.location.params.toString()).toBe("sort=name&dir=desc");
    expect(render()).not.toContain("Clear all");
  });

  it("offers Clear all and Save view only with filters set, and not for a view already saved", () => {
    expect(render()).not.toContain("Save view");
    url("sort=name");
    expect(render()).not.toContain("Save view");
    url("status=online&q=web");
    expect(render()).toContain("Save view");
    expect(render()).toContain("Clear all");
    expect(viewQuery(nav.location.params)).toBe("q=web&status=online");
    url("status=online");
    const html = render([online]);
    expect(html).not.toContain("Save view");
    expect(html).toMatch(/aria-pressed="true"[^>]*>Online</);
  });

  it("names a new view in a form whose refusal is announced and tied to the field", () => {
    const html = renderToStaticMarkup(<SaveViewForm error="You already have a view with that name" onSave={noop} onCancel={noop} />);
    expect(html).toContain('aria-label="View name"');
    expect(html).toMatch(/aria-invalid="true" aria-describedby="([^"]+)"[\s\S]*id="\1" role="alert"[^>]*>You already have a view with that name/);
    expect(renderToStaticMarkup(<SaveViewForm onSave={noop} onCancel={noop} />)).not.toContain('role="alert"');
  });

  it("lists saved views; applying one replaces the filters; deleting asks first", () => {
    const html = render([online]);
    expect(html).toContain(">Online</button>");
    expect(html).toContain('aria-label="Delete saved view Online"');
    expect(applyViewChanges(new URLSearchParams("q=web&os=linux&sort=name"), "status=online", [status, os]))
      .toEqual({ q: null, os: null, sort: null, status: "online" });
    // Only the page's filters, q and the order come from a view: a dropped filter is not set.
    expect(applyViewChanges(new URLSearchParams(""), "old=1&q=db&dir=desc&os=linux", [status, os]))
      .toEqual({ q: "db", dir: "desc", os: "linux" });
    expect(html).toMatch(/role="group" aria-label="Saved views" tabindex="-1"/);
    const asking = renderToStaticMarkup(<SavedViewChip view={online} active={false} confirming onApply={noop} onAsk={noop} onDelete={noop} onCancel={noop} />);
    expect(asking).toContain("Delete the view “Online”?");
    expect(asking).toContain(">Delete</button>");
    expect(asking).toContain(">Cancel</button>");
  });

  it("has a Columns menu with Host always shown, saving each change", () => {
    expect(render()).toMatch(/aria-expanded="false"[^>]*>.*Columns/);
    const html = renderToStaticMarkup(<ColumnList columns={columns} hidden={["labels"]} onToggle={noop} />);
    expect(html).toMatch(/<input(?=[^>]*checked="")(?=[^>]*disabled="")[^>]*>[^<]*<span>Host<\/span>/);
    expect(html).toMatch(/<input[^>]*checked=""[^>]*>[^<]*<span>OS<\/span>/);
    expect(html).not.toMatch(/<input[^>]*checked=""[^>]*>[^<]*<span>Labels<\/span>/);
    // Until the person's columns load, nothing can be toggled (a toggle then would wipe them).
    const loading = renderToStaticMarkup(<ColumnList columns={columns} hidden={undefined} onToggle={noop} />);
    expect(loading.match(/disabled=""/g)).toHaveLength(3);
    expect(toggleHidden(["labels"], "os")).toEqual(["labels", "os"]);
    expect(toggleHidden(["labels", "os"], "labels")).toEqual(["os"]);
  });

  it("treats the page offset as neither a filter nor part of a view, and Clear all resets it", () => {
    const params = new URLSearchParams("status=online&offset=50&sort=host");
    expect(viewQuery(params)).toBe("sort=host&status=online");
    expect(hasFilters(new URLSearchParams("offset=50&sort=host"))).toBe(false);
    expect(clearAllChanges(params)).toEqual({ status: null, offset: null });
  });

  it("sends the search to the URL 250 ms after the last key, or at once on flush", () => {
    vi.useFakeTimers();
    const sent: string[] = [];
    const search = debounce((q: string) => sent.push(q), 250);
    search.set("w");
    vi.advanceTimersByTime(200);
    search.set("we");
    vi.advanceTimersByTime(249);
    expect(sent).toEqual([]);
    vi.advanceTimersByTime(1);
    expect(sent).toEqual(["we"]);
    search.set("web");
    search.flush();
    search.flush();
    expect(sent).toEqual(["we", "web"]);
    search.set("x");
    search.cancel();
    vi.advanceTimersByTime(500);
    expect(sent).toEqual(["we", "web"]);
  });

  it("saves quick column toggles in order, each with the full set", async () => {
    const puts: string[][] = [];
    let release: () => void = noop;
    const shown: (string[] | undefined)[] = [];
    const save = columnSaver("hosts", (p) => shown.push(p), noop, (_, hidden) => {
      puts.push(hidden);
      return new Promise<void>((resolve) => { release = resolve; });
    });
    save(["labels"], "os");
    save(["labels"], "agent"); // the server's copy has not caught up yet
    await Promise.resolve();
    expect(puts).toEqual([["labels", "os"]]);
    release();
    await new Promise((r) => setTimeout(r, 0));
    expect(puts).toEqual([["labels", "os"], ["labels", "os", "agent"]]);
    release();
    await new Promise((r) => setTimeout(r, 0));
    expect(shown).toEqual([["labels", "os"], ["labels", "os", "agent"], undefined]);
  });

  it("keeps queued toggles when an earlier save fails, reverting only once the queue drains", async () => {
    const puts: string[][] = [];
    const errors: unknown[] = [];
    const replies: { resolve: () => void; reject: (e: unknown) => void }[] = [];
    const shown: (string[] | undefined)[] = [];
    const save = columnSaver("hosts", (p) => shown.push(p), (e) => errors.push(e), (_, hidden) => {
      puts.push(hidden);
      return new Promise<void>((resolve, reject) => { replies.push({ resolve, reject }); });
    });
    const tick = () => new Promise((r) => setTimeout(r, 0));
    save(["labels"], "os");
    save(["labels"], "agent");
    await tick();
    replies[0]?.reject(new Error("offline"));
    await tick();
    expect(errors).toHaveLength(1);
    // A toggle made now builds on the queued ones, not on the server's copy.
    save(["labels"], "groups");
    expect(shown.at(-1)).toEqual(["labels", "os", "agent", "groups"]);
    replies[1]?.resolve();
    await tick();
    replies[2]?.resolve();
    await tick();
    expect(puts).toEqual([["labels", "os"], ["labels", "os", "agent"], ["labels", "os", "agent", "groups"]]);
    expect(shown.at(-1)).toBeUndefined();
    expect(shown.filter((p) => p === undefined)).toHaveLength(1);
  });
});
