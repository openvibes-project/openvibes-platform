// DataTable's selection bar, as markup (no DOM library in vitest; see
// ui/controls.test.tsx). Keys and clicks: the demo e2e.
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

// nav.ts reads the location when loaded.
vi.hoisted(() => {
  Object.assign(globalThis, { window: { location: { pathname: "/alarms", search: "" }, history: { replaceState() {} }, addEventListener() {}, removeEventListener() {} } });
});

import { DataTable } from "./DataTable";

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
