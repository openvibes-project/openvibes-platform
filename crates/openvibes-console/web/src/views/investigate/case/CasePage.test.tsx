// A case's page (approved screen 32), as markup: no DOM library in vitest
// (see ui/controls.test.tsx); the actions are covered by e2e/demo/case-page.spec.ts.
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

// nav.ts reads the location when loaded.
vi.hoisted(() => {
  Object.assign(globalThis, { window: { location: { pathname: "/", search: "" }, history: { replaceState() {} }, addEventListener() {}, removeEventListener() {} } });
});

import type { CaseDetail, CaseItem, CasePageSummary } from "../../../api/types";
import { withSession } from "../../../test-session";
import { peopleCount, problemLinks } from "./CaseCards";
import { CaseView, closeBlocker, exportRows, openFor } from "./CasePage";

const sam = { user_id: "u-sam", username: "sam", display_name: "Sam Analyst" };
const ALL = { edit: true, assign: true, close: true, reopen: false, note: true, outcome: true, ask: false, export: true };
const at = "2026-10-25T08:40:00Z";
const page = (over: Partial<CasePageSummary> = {}): CasePageSummary => ({
  header: { case_id: "c-104", number: 104, title: "Shells started by nginx on web-01", status: "investigating", severity: "high", opened_by: sam, assignee: sam, created_at: at, version: 3 },
  tiles: { items: 3, need_outcome: 2, hosts: 1, open_for_seconds: 3600 + 120, ready: false },
  details: { title: "Shells started by nginx on web-01", severity: "high", status: "investigating", opened_by: sam, created_at: at, updated_at: at },
  hosts: [{ agent_id: "a-1", hostname: "web-01", os: { distribution: "Fedora 44" }, problems: { alarms: 3, critical_vulns: 1, failing_checks: 0, compliance_stale: false } }],
  people: { names: [sam], total: 4, complete: true },
  can: ALL,
  ...over,
});
const item = (over: Partial<CaseItem> = {}): CaseItem => ({
  item_id: "i-1", kind: "alarm", ref: "9001", agent_id: "a-1", hostname: "web-01", title: "A web server started a shell", severity: "high",
  active: true, evidence_gone: false, added_at: at, added_by: sam, outcome: null, ...over,
});
const detail = (items: CaseItem[] = [item(), item({ item_id: "i-2", ref: "9002", title: "A shell downloaded a program" }), item({ item_id: "i-3", kind: "vulnerability", ref: "a-1/CVE-1", title: "curl", outcome: "false_positive", outcome_note: "not reachable" })]): CaseDetail => ({
  case_id: "c-104", number: 104, title: "Shells started by nginx on web-01", status: "investigating", severity: "high", opened_by: sam, assignee: sam,
  created_at: at, updated_at: at, version: 3, item_count: items.length, pending_item_count: 2, items,
  events: [
    { event_id: 1, at, actor: sam, kind: "created", detail: {} as never },
    { event_id: 2, at, actor: sam, kind: "note", body: "One command is the health check.", detail: {} as never },
  ],
} as CaseDetail);
const render = (p = page(), d = detail()) => renderToStaticMarkup(withSession(<CaseView page={p} detail={d} />)).replace(/<!-- -->/g, "");
const text = (html: string) => html.replace(/<[^>]+>/g, "");

describe("case page", () => {
  it("names the case, its severity, status, opener, assignee and reach in the header", () => {
    const t = text(render());
    expect(t).toContain("C-104 Shells started by nginx on web-01");
    expect(t).toContain("High");
    expect(t).toContain("Investigating");
    expect(t).toContain("assigned to Sam Analyst · 3 items on 1 host · updated");
  });

  it("offers Edit, Assign, Close case… and ⋯, and never Ask about this (ruling 14)", () => {
    const html = render();
    expect(html).toContain("Edit");
    expect(html).toContain(">Assign<");
    expect(html).toContain("Close case…");
    expect(html).toContain('aria-label="More actions"');
    expect(html).not.toContain("Ask about this");
    const none = render(page({ can: { ...ALL, edit: false, assign: false, close: false } }));
    for (const gone of ["Edit<", ">Assign<", "Close case…"]) expect(none).not.toContain(gone);
  });

  it("counts the tiles down to Ready to close", () => {
    expect(render()).toContain('aria-label="Need an outcome: 2, 2 items still need an outcome"');
    expect(render()).toContain('aria-label="Items: 3"');
    expect(render(page({ tiles: { ...page().tiles, need_outcome: 0, ready: true } }), detail([]))).toContain("Ready to close");
    expect(text(render())).toContain("1 h");
  });

  it("says what blocks closing, never naming a hidden item", () => {
    expect(closeBlocker(page(), detail())).toBe("2 items still need an outcome");
    expect(closeBlocker(page({ tiles: { ...page().tiles, need_outcome: 1 } }), detail([item()]))).toBe("1 item still needs an outcome");
    // Fixed with the evidence back blocks too.
    expect(closeBlocker(page({ tiles: { ...page().tiles, need_outcome: 0 } }), detail([item({ outcome: "resolved" })]))).toBe("1 item still needs an outcome");
    expect(closeBlocker(page({ tiles: { ...page().tiles, need_outcome: 0, ready: false } }), detail([]))).toBe("An item you can't see still needs an outcome");
    expect(closeBlocker(page({ tiles: { ...page().tiles, need_outcome: 0, ready: true } }), detail([]))).toBeNull();
  });

  it("lists each host's open problems as links to the filtered lists", () => {
    const links = page().hosts.flatMap(problemLinks);
    expect(links.map((l) => [l.label, l.view, l.params])).toEqual([
      ["3 open alarms", "/alarms", { host: "a-1" }], ["1 critical", "/vulnerabilities", { host: "a-1", severity: "critical" }],
    ]);
    const html = render();
    expect(html).toContain('href="/hosts/a-1"');
    expect(html).toContain('href="/alarms?host=a-1"');
    expect(html).toContain("Fedora 44");
  });

  it('says who can see it: "N", or "at least N" when the count is partial, names only with access.read', () => {
    expect(peopleCount({ total: 4, complete: true })).toBe("4 people");
    expect(peopleCount({ total: 1, complete: false })).toBe("at least 1 person");
    expect(render()).toContain("Sam Analyst <span class=\"subtle\">(sam)</span>");
    expect(render()).toContain("and 3 more");
    expect(render(page({ people: { names: null, total: 4, complete: false } }))).not.toContain("(sam)");
  });

  it("shows every item with its outcome control, and a note box above the timeline, newest first", () => {
    const html = render();
    expect(html).toContain('aria-label="Outcome for A web server started a shell"');
    expect(html).toContain("Remove A web server started a shell");
    expect(html).toContain("Add item");
    expect(html.indexOf('aria-label="Note"')).toBeLessThan(html.indexOf("Timeline, newest first"));
    const t = text(html);
    expect(t.indexOf("added a note")).toBeLessThan(t.indexOf("opened the case"));
    // A closed case: no outcome control, no Add item.
    const closed = render(page({ can: { ...ALL, outcome: false } }));
    expect(closed).not.toContain("Outcome for");
    expect(closed).not.toContain("Add item");
  });

  it("shows how an old closed case ended, and its closing note", () => {
    const t = text(render(page({ details: { ...page().details, status: "closed", resolution: "mitigated", resolution_note: "Patched.", closed_at: at } })));
    expect(t).toContain("How it endedMitigated");
    expect(t).toContain("Closing notePatched.");
  });

  it("exports the items and the timeline", () => {
    const rows = exportRows(detail());
    expect(rows[0]).toEqual(["case", "section", "at", "who", "kind", "what", "host", "severity", "outcome", "note"]);
    expect(rows[3]).toEqual(["C-104", "item", at, "Sam Analyst", "Vulnerability", "curl", "web-01", "high", "False positive", "not reachable"]);
    expect(rows[5]).toEqual(["C-104", "timeline", at, "Sam Analyst", "note", "added a note", "", "", "", "One command is the health check."]);
  });

  it("says how long it has been open", () => {
    expect(openFor(30)).toBe("under a minute");
    expect(openFor(125)).toBe("2 min");
    expect(openFor(3 * 86_400 + 5)).toBe("3 days");
  });
});
