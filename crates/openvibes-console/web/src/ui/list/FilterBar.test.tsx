// The FilterBar. Vitest runs in node with no DOM library (see ui/controls.test.tsx):
// the bar is checked as markup from react-dom/server against real URLs, its
// actions as the pure helpers it calls. Click and key flows: the Hosts e2e.
import { renderToStaticMarkup } from "react-dom/server";
import { beforeEach, describe, expect, it, vi } from "vitest";

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
import { type ListFilter, applyViewChanges, chosenFilters, clearAllChanges, valueOptions, viewQuery } from "./filters";
import { toggleHidden } from "./savedViews";

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
    expect(applyViewChanges(new URLSearchParams("q=web&os=linux&sort=name"), "status=online"))
      .toEqual({ q: null, os: null, sort: null, status: "online" });
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
    expect(toggleHidden(["labels"], "os")).toEqual(["labels", "os"]);
    expect(toggleHidden(["labels", "os"], "labels")).toEqual(["os"]);
  });
});
