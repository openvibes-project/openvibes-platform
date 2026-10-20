// Alarm suppressions (approved screen 14) as markup: By status, one card per
// status, and each row's facts and actions by its flags.
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

// nav.ts reads the location when loaded.
vi.hoisted(() => {
  Object.assign(globalThis, { window: { location: { pathname: "/", search: "" }, history: { replaceState() {} }, addEventListener() {}, removeEventListener() {} } });
});

import type { AlarmSuppression, AuditEvent } from "../../api/types";
import { SessionContext } from "../../app/session";
import { AlarmSuppressionsBody } from "./AlarmSuppressions";
import { bodyOf } from "../../panels/alarms/SuppressForm";
import { RejectForm, again } from "./SuppressionRow";

const hoursAgo = (h: number) => new Date(Date.now() - h * 3_600_000).toISOString();
const row = (id: string, more: Partial<AlarmSuppression> = {}): AlarmSuppression => ({
  id, rule_set_id: "rs", rule_id: "shell-from-web", what: "program", exe: "/usr/bin/sh", where: { kind: "host", hostname: "web-01" },
  for_days: 7, status: "active", reason: "health check", requested_by: "Alice", requested_at: hoursAgo(2), alarm_id: null,
  would_close: null, would_close_capped: false, can_decide: false, can_withdraw: false, can_remove: false, ...more,
});
const items: AlarmSuppression[] = [
  row("1", { status: "waiting", would_close: 12, can_decide: true, alarm_id: "9001" }),
  row("2", { status: "waiting", would_close: 10000, would_close_capped: true, can_withdraw: true, what: "command", where: { kind: "group", group_name: "Web" }, for_days: null }),
  row("3", { can_remove: true, where: { kind: "all" }, for_days: 30 }),
  row("4"),
  row("5", { status: "expired" }),
  row("6", { status: "rejected", decided_by: "Lee", decision_reason: "too broad", alarm_id: "9002" }),
];
const recent: AuditEvent[] = [
  { id: "a1", at: hoursAgo(1), actor: "lee", action: "alarm.suppression.rejected", result: "success", target: "alarm_suppression", target_id: "6" },
];
const html = (can: (p: string) => boolean = () => true, audit: AuditEvent[] | "loading" | "failed" | null = recent) => renderToStaticMarkup(
  <SessionContext.Provider value={{ session: undefined, demo: false, can, canEverywhere: can }}>
    <AlarmSuppressionsBody items={items} recent={audit ?? undefined} />
  </SessionContext.Provider>,
);
const cardOf = (out: string, title: string) => out.slice(out.indexOf(`>${title}</h2>`)).split('class="card person-card"')[0] ?? "";
const rowOf = (out: string, id: string) => out.slice(out.indexOf(`data-id="${id}"`)).split("data-id=")[1] ?? "";

describe("AlarmSuppressions", () => {
  it("has the header and summary", () => {
    const out = html();
    expect(out).toContain("Alarm suppressions");
    expect(out).toContain("Alarms that are closed as they arrive, and requests waiting for approval.");
  });
  it("counts By status, each linking to its card, then Recent changes", () => {
    const out = html();
    expect(out).toMatch(/href="#suppressions-waiting"[^>]*>Waiting<\/a><span[^>]*>2</);
    expect(out).toMatch(/href="#suppressions-active"[^>]*>Active<\/a><span[^>]*>3</);
    expect(out).toMatch(/href="#suppressions-rejected"[^>]*>Rejected<\/a><span[^>]*>1</);
    expect(out.indexOf("By status")).toBeLessThan(out.indexOf("Recent changes"));
    expect(out).toContain("Rejected a suppression #6");
    expect(out).not.toContain("#alarm_suppression");
  });
  it("says what an empty, loading or failed Recent changes means", () => {
    expect(html(undefined, [])).toContain("No suppression changes in the last 30 days.");
    expect(html(undefined, "loading")).toContain("Loading recent changes…");
    expect(html(undefined, "failed")).toContain("Recent changes could not be loaded");
  });
  it("hides Recent changes without audit access", () => {
    expect(html((p) => p !== "audit.read", null)).not.toContain("Recent changes");
  });
  it("has one card per status, in order", () => {
    const out = html();
    const at = ["Waiting", "Active", "Rejected"].map((t) => out.indexOf(`id="suppressions-${t.toLowerCase()}"`));
    expect(at.every((i) => i > 0)).toBe(true);
    expect([...at].sort((a, b) => a - b)).toEqual(at);
  });
  it("shows the command, the chips, the reason, who asked and when", () => {
    const one = rowOf(html(), "1");
    expect(one).toContain("/usr/bin/sh");
    expect(one).toContain("What: Program");
    expect(one).toContain("Where: web-01");
    expect(one).toContain("For: 7 days");
    expect(one).toContain("“health check”");
    expect(one).toMatch(/asked by Alice · 2 (h|hr)/);
    expect(rowOf(html(), "2")).toContain("What: Exact command");
    expect(rowOf(html(), "2")).toContain("Where: Web");
    expect(rowOf(html(), "2")).toContain("For: Until removed");
    expect(rowOf(html(), "3")).toContain("Where: All hosts");
  });
  it("says what a waiting request would have closed, at least N when capped", () => {
    expect(rowOf(html(), "1")).toContain("Would have closed 12 alarms in the last 7 days");
    expect(rowOf(html(), "2")).toContain("Would have closed at least 10,000 alarms in the last 7 days");
    expect(rowOf(html(), "3")).not.toContain("Would have closed");
  });
  it("shows the status badge, with the reason when rejected", () => {
    const out = html();
    expect(rowOf(out, "1")).toContain(">Waiting<");
    expect(rowOf(out, "3")).toContain(">Active<");
    expect(rowOf(out, "5")).toContain(">Expired<");
    expect(rowOf(out, "6")).toContain(">Rejected<");
    expect(rowOf(out, "6")).toContain("Rejected by Lee: “too broad”");
  });
  it("links Open alarm when the row has one", () => {
    expect(rowOf(html(), "1")).toContain("Open alarm");
    expect(rowOf(html(), "3")).not.toContain("Open alarm");
  });
  it("offers the actions its flags allow", () => {
    const out = html();
    expect(rowOf(out, "1")).toContain(">Approve</button>");
    expect(rowOf(out, "1")).toContain(">Reject…</button>");
    expect(rowOf(out, "1")).not.toContain("Withdraw");
    expect(rowOf(out, "2")).toContain(">Withdraw</button>");
    expect(rowOf(out, "2")).not.toContain("Approve");
    expect(rowOf(out, "3")).toContain(">Remove…</button>");
    expect(rowOf(out, "4")).not.toContain("<button");
    expect(rowOf(out, "6")).toContain(">Ask again…</button>");
    expect(rowOf(html((p) => p !== "alarms.suppress"), "6")).not.toContain("Ask again");
  });
  it("names the row in each action's label, keeping the visible text", () => {
    const out = html();
    expect(rowOf(out, "1")).toContain('aria-label="Approve /usr/bin/sh"');
    expect(rowOf(out, "1")).toContain('aria-label="Reject… /usr/bin/sh"');
    expect(rowOf(out, "2")).toContain('aria-label="Withdraw /usr/bin/sh"');
    expect(rowOf(out, "3")).toContain('aria-label="Remove… /usr/bin/sh"');
    expect(rowOf(out, "6")).toContain('aria-label="Ask again… /usr/bin/sh"');
  });
  it("puts waiting rows in Waiting and expired ones in Active", () => {
    const out = html();
    expect(cardOf(out, "Waiting")).toContain('data-id="2"');
    expect(cardOf(out, "Active")).toContain('data-id="5"');
    expect(cardOf(out, "Rejected")).toContain('data-id="6"');
  });
});

describe("RejectForm", () => {
  it("keeps Reject disabled until a reason is given", () => {
    const form = (reason: string) => renderToStaticMarkup(<RejectForm id="1" initial={reason} onDone={() => undefined} onCancel={() => undefined} />);
    expect(form("")).toMatch(/<button[^>]*type="submit"[^>]*disabled=""[^>]*>Reject<\/button>/);
    expect(form("   ")).toMatch(/<button[^>]*type="submit"[^>]*disabled=""[^>]*>Reject<\/button>/);
    expect(form("too broad")).not.toMatch(/type="submit"[^>]*disabled/);
    expect(form("")).toContain("Reason (required)");
  });
});

describe("Ask again…", () => {
  const defaults = { what: "program", where: "host", forDays: 7, reason: "" } as const;
  it("prefills the alarm, what, where, for and reason of the rejected row", () => {
    const rejected = row("7", { status: "rejected", what: "command", where: { kind: "group", group_id: "g-web", group_name: "Web" }, for_days: 30, reason: "nightly job", alarm_id: "9003" });
    expect(again(rejected)).toEqual({ what: "command", where: "group:g-web", forDays: 30, reason: "nightly job" });
    expect(bodyOf(rejected.alarm_id ?? "", { ...defaults, ...again(rejected) }))
      .toEqual({ alarm_id: "9003", what: "command", where: { kind: "group", group_id: "g-web" }, for_days: 30, reason: "nightly job" });
    expect(again(row("8", { where: { kind: "all" }, for_days: null }))).toMatchObject({ what: "program", where: "all", forDays: null });
    expect(again(row("9"))).toMatchObject({ where: "host", forDays: 7 });
  });
  it("keeps a deleted group as a group, so the form can say it is gone", () => {
    expect(again(row("10", { where: { kind: "group", group_name: null } })).where).toBe("group:");
  });
});
