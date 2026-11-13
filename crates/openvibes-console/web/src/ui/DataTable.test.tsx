// DataTable's selection bar, as markup (no DOM library in vitest; see
// ui/controls.test.tsx). Keys and clicks: the demo e2e.
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

// nav.ts reads the location when loaded.
vi.hoisted(() => {
  Object.assign(globalThis, { window: { location: { pathname: "/alarms", search: "" }, history: { replaceState() {} }, addEventListener() {}, removeEventListener() {} } });
});

import { DataTable, SortHeader, sortBy, sortQuery } from "./DataTable";
import { severityRank } from "./format";

const rows = Array.from({ length: 200 }, (_, i) => ({ id: String(i) }));
const render = (shown: typeof rows, serverPaged = false) => renderToStaticMarkup(
  <DataTable label="Rows" rows={shown} rowKey={(r) => r.id} onOpen={() => undefined} serverPaged={serverPaged}
    columns={[{ key: "id", header: "Id", render: (r) => r.id }]}
    selection={{ selected: new Set(shown.slice(0, 150).map((r) => r.id)), onChange: () => undefined }} />,
).replace(/<!-- -->/g, "");

describe("DataTable selection", () => {
  it("offers every row the filter matches when the rows are all loaded", () => {
    expect(render(rows)).toContain("Select all 200 matching this filter");
  });

  it("on a server-paged list, promises only the page", () => {
    const html = render(rows.slice(0, 50), true);
    expect(html).toContain("All 50 on this page are selected.");
    expect(html).not.toContain("matching this filter");
  });
});

describe("sorting outside DataTable (#577)", () => {
  const rows = [{ n: "b", s: "low" }, { n: "a", s: "critical" }, { n: "c", s: null }];
  const by = { name: (r: (typeof rows)[number]) => r.n, severity: (r: (typeof rows)[number]) => severityRank(r.s) };

  it("sorts by the chosen key, and keeps the order it came in when none is chosen", () => {
    expect(sortBy(rows, by, { key: "name", direction: "desc" }).map((r) => r.n)).toEqual(["c", "b", "a"]);
    expect(sortBy(rows, by, { key: undefined, direction: "asc" })).toBe(rows);
    expect(sortBy(rows, by, { key: "gone", direction: "asc" })).toBe(rows);
  });

  it("puts Critical first when Severity sorts descending, an unknown severity last", () => {
    expect(sortBy(rows, by, { key: "severity", direction: "desc" }).map((r) => r.s)).toEqual(["critical", "low", null]);
  });

  it("sends a chosen sort to the server, and nothing for its default", () => {
    expect(sortQuery({ key: "date", direction: "desc" })).toBe("&sort=date&dir=desc");
    expect(sortQuery({ key: undefined, direction: "asc" })).toBe("");
  });

  it("marks the sorted header for screen readers", () => {
    const head = (key: string) => renderToStaticMarkup(<table><thead><tr><SortHeader sort={{ key, direction: "asc" }} column="host">Host</SortHeader></tr></thead></table>);
    expect(head("host")).toContain('aria-sort="ascending"');
    expect(head("state")).not.toContain("aria-sort");
  });
});
