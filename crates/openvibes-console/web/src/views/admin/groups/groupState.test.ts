// The group editor's pure parts: the draft reducer, the PATCH body (only
// what changed), the preview sentence and the list's wording.
import { describe, expect, it } from "vitest";

import type { HostGroup, HostGroupPreview } from "../../../api/types";
import { ApiError } from "../../../api/client";
import {
  type Draft, blankDraft, isDirty, rebase, valueLabel, createBody, fromGroup, hostsLabel, membershipText, patchBody, previewBody, previewSentence, reduce, refusal,
} from "./groupState";

const group = (over: Partial<HostGroup> = {}): HostGroup => ({
  asset_group_id: "g-win", name: "WindowsServers", kind: "rule", description: "Windows servers the Windows team runs.",
  conditions: [{ field: "os_family", values: ["windows"] }, { field: "hostname", negate: true, values: ["*test*"] }],
  membership: "Hosts where OS family is Windows and hostname does not match *test*", picked: 0, hosts: 4, online: 3,
  open_alarms: 3, critical: 4, roles: [{ role_id: "r-win", name: "Windows lead" }], people: 2, upgraded_from_tags: false, version: 5, ...over,
});
const run = (start: Draft, ...actions: Parameters<typeof reduce>[1][]) => actions.reduce(reduce, start);
const preview = (over: Partial<HostGroupPreview> = {}): HostGroupPreview => ({
  joins: [], joins_total: 0, leaves: [], leaves_total: 0, gains: [], loses: [], people_total: 0, overrides_removed: 0, ...over,
});
const host = (agent_id: string, hostname: string) => ({ agent_id, hostname });
const person = (display_name: string) => ({ user_id: display_name, username: display_name, display_name });

describe("group draft", () => {
  it("adds, edits and removes conditions", () => {
    const base = fromGroup(group(), []);
    const added = run(base, { type: "add" });
    expect(added.conditions).toHaveLength(3);
    expect(added.conditions[2]).toEqual({ field: "os_family", negate: false, values: [] });
    const edited = run(added, { type: "field", index: 2, field: "ip" }, { type: "values", index: 2, values: ["10.0.0.0/16"] }, { type: "negate", index: 2, negate: true });
    expect(edited.conditions[2]).toEqual({ field: "ip", negate: true, values: ["10.0.0.0/16"] });
    // A new field starts with no values: "windows" is no IP range.
    expect(run(base, { type: "field", index: 0, field: "ip" }).conditions[0]).toEqual({ field: "ip", negate: false, values: [] });
    const removed = run(edited, { type: "remove", index: 0 });
    expect(removed.conditions.map((c) => c.field)).toEqual(["hostname", "ip"]);
    // Rows keep their keys, and a new row never reuses one.
    expect(removed.keys).toEqual([1, 2]);
    expect(run(removed, { type: "add" }).keys).toEqual([1, 2, 3]);
  });

  it("picks and unpicks hosts once each", () => {
    const d = run(blankDraft("manual"), { type: "pick", host: host("a1", "web-01") }, { type: "pick", host: host("a1", "web-01") }, { type: "pick", host: host("a2", "db-02") });
    expect(d.picked.map((h) => h.agent_id)).toEqual(["a1", "a2"]);
    expect(run(d, { type: "unpick", agent_id: "a1" }).picked.map((h) => h.agent_id)).toEqual(["a2"]);
  });

  it("an automatic group edits as a rule; Turn into a rule starts a new rule draft", () => {
    expect(fromGroup(group({ kind: "automatic" }), []).kind).toBe("rule");
    const manual = fromGroup(group({ kind: "manual", conditions: [] }), [host("a1", "web-01")]);
    const rule = reduce(manual, { type: "toRule" });
    expect(rule.kind).toBe("rule");
    expect(rule.conditions).toEqual([{ field: "os_family", negate: false, values: [] }]);
  });
});

describe("save bodies", () => {
  const g = group();
  const base = fromGroup(g, []);

  it("a rename sends the name only", () => {
    expect(patchBody(run(base, { type: "name", name: " Windows " }), base, g.version)).toEqual({ name: "Windows", version: 5 });
  });

  it("a rule change sends the conditions only", () => {
    const body = patchBody(run(base, { type: "remove", index: 1 }), base, g.version);
    expect(body).toEqual({ conditions: [{ field: "os_family", negate: false, values: ["windows"] }], version: 5 });
  });

  it("a manual change sends the picked ids", () => {
    const m = fromGroup(group({ kind: "manual", conditions: [] }), [host("a1", "web-01"), host("a2", "db-02")]);
    expect(patchBody(run(m, { type: "unpick", agent_id: "a1" }), m, 2)).toEqual({ agent_ids: ["a2"], version: 2 });
    expect(patchBody(m, m, 2)).toEqual({ version: 2 });
  });

  it("a new group sends its kind and membership; the preview sends membership only", () => {
    const d = run(blankDraft("rule"), { type: "name", name: "Lab" }, { type: "values", index: 0, values: ["linux"] });
    expect(createBody(d)).toEqual({ name: "Lab", description: "", kind: "rule", conditions: [{ field: "os_family", negate: false, values: ["linux"] }] });
    expect(previewBody(d)).toEqual({ conditions: [{ field: "os_family", negate: false, values: ["linux"] }] });
    // Nothing to preview until every condition has a value.
    expect(previewBody(blankDraft("rule"))).toBeUndefined();
    expect(previewBody(run(blankDraft("manual"), { type: "pick", host: host("a1", "web-01") }))).toEqual({ agent_ids: ["a1"] });
  });

  it("a stale save reloads and says so", () => {
    expect(refusal(new ApiError(409, "stale_group", "stale"), "x")).toEqual({ message: "Someone else changed this group. It has been reloaded.", reload: true });
    expect(refusal(new ApiError(409, "group_name_taken", "Another group has this name"), "x")).toEqual({ message: "Another group has this name", reload: false });
  });
});

describe("a stale save", () => {
  const started = fromGroup(group({ kind: "manual", conditions: [] }), [host("a1", "web-01"), host("a2", "db-02")]);

  it("keeps the user's change and takes the rest from the reload", () => {
    const mine = run(started, { type: "unpick", agent_id: "a2" }, { type: "description", description: "Mine" });
    // Meanwhile someone renamed it and added a3.
    const reloaded = { ...started, name: "Pilot", picked: [...started.picked, host("a3", "mx-03")] };
    const next = rebase(mine, started, reloaded);
    expect(next.name).toBe("Pilot");
    expect(next.description).toBe("Mine");
    expect(next.picked.map((h) => h.agent_id)).toEqual(["a1", "a3"]);
    expect(patchBody(next, reloaded, 6)).toEqual({ description: "Mine", agent_ids: ["a1", "a3"], version: 6 });
  });

  it("a rename alone does not touch the reloaded rule", () => {
    const rule = fromGroup(group(), []);
    const mine = run(rule, { type: "name", name: "Win" });
    const reloaded = run(rule, { type: "remove", index: 1 });
    const next = rebase(mine, rule, reloaded);
    expect(next.conditions).toEqual(reloaded.conditions);
    expect(patchBody(next, reloaded, 6)).toEqual({ name: "Win", version: 6 });
    expect(isDirty(mine, rule)).toBe(true);
    expect(isDirty(rule, rule)).toBe(false);
  });
});

describe("preview sentence", () => {
  it("names joins and who gains", () => {
    expect(previewSentence(preview({ joins: [host("a", "web-01"), host("b", "db-02")], joins_total: 2, gains: [person("Wendy Ward")], people_total: 1 })))
      .toBe("If you save: +2 (web-01, db-02). Wendy Ward gains access to them.");
  });

  it("names leaves and who loses", () => {
    expect(previewSentence(preview({ leaves: [host("a", "win-test-01")], leaves_total: 1, loses: [person("Wendy Ward"), person("Tom Tanaka")], people_total: 2 })))
      .toBe("If you save: −1 (win-test-01). Wendy Ward, Tom Tanaka lose access to them.");
  });

  it("both ways, more than listed, and nobody", () => {
    expect(previewSentence(preview({ joins: [host("a", "web-01")], joins_total: 3, leaves: [host("b", "db-02")], leaves_total: 1, gains: [person("Wendy Ward")], loses: [person("Wendy Ward")], people_total: 1 })))
      .toBe("If you save: +3 (web-01 and 2 more), −1 (db-02). Wendy Ward gains and loses access accordingly.");
    expect(previewSentence(preview({ leaves: [{ agent_id: "agent.x" }], leaves_total: 1 }))).toBe("If you save: −1 (agent.x).");
    expect(previewSentence(preview())).toBe("");
  });

  it("a delete says If you delete", () => {
    expect(previewSentence(preview({ leaves: [host("a", "db-02")], leaves_total: 1 }), "delete")).toBe("If you delete: −1 (db-02).");
  });
});

describe("values", () => {
  it("read as the server names them", () => {
    expect(valueLabel("os_family", "windows")).toBe("Windows");
    expect(valueLabel("distribution", "debian 12")).toBe("Debian 12");
    expect(valueLabel("distribution", "production 1")).toBe("production 1");
    expect(valueLabel("hostname", "web-*")).toBe("web-*");
  });
});

describe("list wording", () => {
  it("counts read as what you can see when you do not see every host", () => {
    expect(hostsLabel(0, true)).toBe("0 hosts");
    expect(hostsLabel(0, false)).toBe("No hosts you can see");
    expect(hostsLabel(1, false)).toBe("1 host you can see");
    expect(hostsLabel(3, false)).toBe("3 hosts you can see");
    const manual = group({ kind: "manual", membership: "0 hosts picked by hand" });
    expect(membershipText(manual, true)).toBe("0 hosts picked by hand");
    expect(membershipText(manual, false)).toBe("Hosts picked by hand");
    expect(membershipText(group(), false)).toBe(group().membership);
  });
});
