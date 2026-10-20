// An alarm's page (approved screen 30), as markup: no DOM library in vitest
// (see ui/controls.test.tsx); the actions are covered by e2e/demo/alarm-page.spec.ts.
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

// nav.ts reads the location when loaded.
vi.hoisted(() => {
  Object.assign(globalThis, { window: { location: { pathname: "/", search: "" }, history: { replaceState() {} }, addEventListener() {}, removeEventListener() {} } });
});

import type { AlarmSummaryPage, AlarmSuppression, Session } from "../../../api/types";
import { SessionContext } from "../../../app/session";
import { date } from "../../../ui/format";
import { WaitingRequest } from "./AlarmCards";
import { AlarmView, exportRows, moreActions } from "./AlarmPage";

const now = Date.now();
const iso = (ms: number) => new Date(ms).toISOString();
const ALL = { triage: true, assign: true, suppress: true, add_to_case: true, ask: true, export: true };
const command = (id: number, args: string[], count: number, over: Partial<AlarmSummaryPage["commands"][number]> = {}) =>
  ({ id, args, count, first_seen: iso(now - 3_600_000), last_seen: iso(now - 60_000), state: "open", suppressed_by: null, case: null, ...over });
const fixture = (over: Partial<AlarmSummaryPage> = {}): AlarmSummaryPage => ({
  alarm: {
    id: 9000, message: "A web server started a shell", severity: "high", state: "open", suppressed: false, count: 3,
    first_seen: iso(now - 7_200_000), last_seen: iso(now - 60_000), rule_id: "web-server-spawns-shell", rule_set_id: "baseline",
    program: "/usr/bin/sh", parent_program: "/usr/sbin/nginx", techniques: ["T1505.003"],
    host: { id: "agent-00001", name: "web-01", distribution: "Debian 12", os_family: "linux" },
    assignee: null, case: null, confidence: 80, rule_set_version: 4, rule_version: 1, received_at: iso(now - 58_000),
    process: { pid: 48211, exe: "/usr/bin/sh", args: ["sh", "-c", "id; uname -a"], uid: 33, euid: 33, truncated: false, cwd: "/var/www/html" } as unknown as AlarmSummaryPage["alarm"]["process"],
    ancestors: [{ pid: 1102, exe: "/usr/sbin/nginx", args: ["nginx: worker process"], uid: 33, euid: 33, truncated: false }] as unknown as AlarmSummaryPage["alarm"]["ancestors"],
    triage: { state: "open", assigned_to: null, note: null, accepted_until: null, version: 1, updated_at: null, updated_by: null },
  },
  tiles: { starts: 16, different_commands: 3, first_seen: iso(now - 7_200_000), confidence: 80 },
  rule: { title: "Web server spawns a shell", message: "A web server started a shell", explain: "A web server ran a shell.\nThat is rare.", check: "Look at the command.", techniques: ["T1505.003"] },
  commands: [command(9008, ["sh", "-c", "/usr/local/bin/healthcheck"], 12), command(9000, ["sh", "-c", "id; uname -a"], 3), command(9009, ["sh", "-c", "cat /etc/passwd"], 1)],
  hourly: Array.from({ length: 24 }, (_, i) => (i === 23 ? 4 : 0)),
  related: {
    host_alarms: { total: 1, items: [{ id: 9001, rule_id: "shell-from-database", message: "A database server started a shell", severity: "critical", last_seen: iso(now) }] },
    host_vulnerabilities: { total: 2, items: [{ advisory: "DSA-5501-1", severity: "critical", kev: false, exploited: true, title: "openssl" }] },
    same_rule_elsewhere: { hosts: 2, open: 3 },
  },
  can: ALL,
  ...over,
});
const session = { principal: { id: "u-me", username: "me", display_name: "Me" }, capabilities: [] } as unknown as Session;
// Without alarms.suppressions.read the page need not wait to know of a waiting request.
const render = (page: AlarmSummaryPage, can = true) => renderToStaticMarkup(
  <SessionContext.Provider value={{ session, demo: false, can: (p) => can && p !== "alarms.suppressions.read", canEverywhere: () => can }}>
    <AlarmView page={page} />
  </SessionContext.Provider>,
).replace(/<!-- -->/g, "");
const text = (html: string) => html.replace(/<[^>]+>/g, "");

describe("alarm page", () => {
  it("has the four tiles; different commands leads to the Commands card", () => {
    const html = render(fixture());
    expect(html).toMatch(/<a [^>]*href="#commands"[^>]*aria-label="Different commands: 3"/);
    expect(html).toContain('id="commands"');
    expect(html).toMatch(/aria-label="Starts matched: 16"/);
    expect(text(html)).toContain("First seen (any command)");
    // This alarm's own first start, in Details.
    expect(text(html)).toContain(`First seen${date(fixture().alarm.first_seen)}`);
    expect(text(html)).toContain("80%Confidence");
  });

  it("says what happened and what to check from the rule, newlines kept, as text", () => {
    const html = render(fixture({ rule: { ...fixture().rule, explain: "<b>x</b>\nline two" } }));
    expect(html).toContain("&lt;b&gt;x&lt;/b&gt;\nline two");
    expect(html).toMatch(/class="pre-line"/);
    expect(text(html)).toContain("Look at the command.");
  });

  it("falls back to the rule's title and message until the rule has text", () => {
    const t = text(render(fixture({ rule: { title: "Web server spawns a shell", message: "nginx ran sh", explain: null, check: null, techniques: [] } })));
    expect(t).toContain("Web server spawns a shell");
    expect(t).toContain("nginx ran sh");
    expect(t).not.toContain("What to check");
  });

  it("offers Suppress this command… on the usual command only, and highlights a command seen once with Add to case", () => {
    const html = render(fixture());
    expect(html.match(/Suppress this command…/g)).toHaveLength(1);
    const rows = html.split("<tr").slice(2);
    expect(rows[0]).toContain("/usr/local/bin/healthcheck");
    expect(rows[0]).toContain("Suppress this command…");
    expect(rows[2]).toContain("cmd-once");
    expect(rows[2]).toContain("Seen once");
    expect(rows[2]).toContain('aria-label="Add sh -c cat /etc/passwd to a case"');
    expect(rows[1]).toContain("This alarm");
  });

  it("shows the header actions only as allowed", () => {
    const all = text(render(fixture()));
    for (const action of ["Set state", "Suppress…", "Ask about this"]) expect(all).toContain(action);
    const none = render(fixture({ can: { triage: false, assign: false, suppress: false, add_to_case: false, ask: false, export: false } }), false);
    for (const action of ["Set state", "Suppress…", "Suppress this command…", "Ask about this", "Add to case"]) expect(text(none)).not.toContain(action);
    expect(none).toContain('aria-label="More actions"');
  });

  it("follows the summary's can, not the session: everything allowed by the session, nothing on this host", () => {
    const none = { triage: false, assign: false, suppress: false, add_to_case: false, ask: false, export: false };
    const t = text(render(fixture({ can: none })));
    for (const action of ["Set state", "Suppress…", "Suppress this command…", "Ask about this", "Add to case", "Reopen"]) expect(t).not.toContain(action);
    expect(moreActions(none).map((m) => m.label)).toEqual(["Copy link"]);
    expect(moreActions({ ...none, export: true }).map((m) => m.label)).toEqual(["Export", "Copy link"]);
  });

  it("names the suppression that closed it, and offers no Suppress…", () => {
    const page = fixture({ alarm: { ...fixture().alarm, suppressed: true }, commands: [command(9000, ["sh"], 3, { suppressed_by: 900, state: "false_positive" })] });
    const t = text(render(page));
    expect(t).toContain("By suppression #900");
    expect(t).not.toContain("Suppress…");
    expect(t).not.toContain("Suppress this command…");
  });

  it("draws the last 24 hours and the Related card", () => {
    const html = render(fixture());
    expect(html.match(/<rect /g)).toHaveLength(24);
    expect(text(html)).toContain("A database server started a shell");
    expect(text(html)).toContain("DSA-5501-1");
    expect(html).toMatch(/href="\/alarms\?q=web-server-spawns-shell"/);
    expect(text(html)).toContain("3 open on 2 other hosts");
  });

  it("exports this alarm and its siblings", () => {
    const rows = exportRows(fixture());
    expect(rows[0]).toEqual(["alarm_id", "host", "rule_set", "rule", "program", "parent", "command", "count", "first_seen", "last_seen", "state", "suppressed_by", "case"]);
    expect(rows.slice(1).map((r) => r[0])).toEqual([9008, 9000, 9009]);
    expect(rows[3]?.[6]).toBe("sh -c cat /etc/passwd");
  });
});

const waiting = (canWithdraw: boolean) => ({ id: "4", status: "waiting", can_withdraw: canWithdraw }) as AlarmSuppression;

describe("WaitingRequest", () => {
  it("says the request waits and offers Withdraw to the requester", () => {
    const out = renderToStaticMarkup(<WaitingRequest request={waiting(true)} />);
    expect(out).toContain("Suppression requested, waiting for approval… these alarms keep arriving");
    expect(out).toMatch(/<button[^>]*>.*Withdraw request<\/button>/);
  });
  it("offers no Withdraw to someone else", () => {
    expect(renderToStaticMarkup(<WaitingRequest request={waiting(false)} />)).not.toContain("Withdraw request");
  });
});
