// The demo's membership evaluator against the store's membership cases
// (crates/platform-store/tests/host_groups_membership.rs), which pin the SQL
// function console_host_in_group of migration 53.
import { describe, expect, it } from "vitest";

import { type Condition, type HostFacts, type StoredGroup, distribution, inGroup, invalidRule, membershipSentence } from "./hostGroups";

let next = 0;
const host = (os: [string, string] | null, hostname: string | null, address: string | null, status = "active"): HostFacts =>
  ({ id: `agent-${++next}`, status, os_id: os?.[0] ?? null, os_version: os?.[1] ?? null, hostname, last_address: address });
const c = (field: string, negate: boolean, values: string[]): Condition => ({ field, negate, values });
const rule = (...conditions: Condition[]): StoredGroup => ({
  asset_group_id: "g", name: "G", kind: "rule", description: "", conditions, picked: [],
  upgraded_from_tags: false, changed_at: null, changed_by: null, version: 1,
});
const manual = (picked: string[]): StoredGroup => ({ ...rule(), kind: "manual", picked });
const members = (hosts: HostFacts[], group: StoredGroup) => hosts.filter((h) => inGroup(h, group)).map((h) => h.id);

describe("host group membership (console_host_in_group)", () => {
  it("matches os family and distribution on reported facts", () => {
    const deb = host(["debian", "12"], null, null);
    const fed = host(["fedora", "44"], null, null);
    const bare = host(null, "bare", null);
    const all = [deb, fed, bare];
    expect(members(all, rule(c("os_family", false, ["linux"])))).toEqual([deb.id, fed.id]);
    expect(members(all, rule(c("distribution", false, ["debian 12"])))).toEqual([deb.id]);
  });

  it("collapses rocky and alma to the major release", () => {
    expect(distribution(host(["rocky", "9.4"], null, null))).toBe("rocky 9");
    expect(distribution(host(["almalinux", "9.5"], null, null))).toBe("almalinux 9");
    expect(distribution(host(["Ubuntu", "24.04"], null, null))).toBe("ubuntu 24.04");
    expect(distribution(host(["debian", null as unknown as string], null, null))).toBeNull();
  });

  it("reads hostname patterns literally except *, ignoring case", () => {
    const web = host(null, "WEB-01", null);
    const webDash = host(null, "web-01", null);
    const percent = host(null, "a%b", null);
    const axb = host(null, "axb", null);
    const win = host(null, "win-test-01", null);
    const all = [web, webDash, percent, axb, win];
    expect(members(all, rule(c("hostname", false, ["web-*"])))).toEqual([web.id, webDash.id]);
    expect(members(all, rule(c("hostname", false, ["web_01"])))).toEqual([]);
    expect(members(all, rule(c("hostname", false, ["a%b"])))).toEqual([percent.id]);
    expect(members(all, rule(c("hostname", false, ["*test*"])))).toEqual([win.id]);
  });

  it("treats a backslash as literal", () => {
    const literal = host(null, "a\\b", null);
    const all = [literal, host(null, "ab", null), host(null, "a\\\\b", null)];
    expect(members(all, rule(c("hostname", false, ["a\\b"])))).toEqual([literal.id]);
  });

  it("takes CIDRs and single addresses, v4 and v6", () => {
    const lan = host(null, null, "10.0.1.10");
    const lab = host(null, null, "10.9.0.44");
    const six = host(null, null, "2001:db8::5");
    const all = [lan, lab, six];
    expect(members(all, rule(c("ip", false, ["10.0.0.0/16"])))).toEqual([lan.id]);
    expect(members(all, rule(c("ip", false, ["10.9.0.44"])))).toEqual([lab.id]);
    expect(members(all, rule(c("ip", false, ["2001:db8::/32"])))).toEqual([six.id]);
    expect(members(all, rule(c("ip", false, ["2001:db8::5"])))).toEqual([six.id]);
    expect(members(all, rule(c("ip", false, ["0.0.0.0/0"])))).toEqual([lan.id, lab.id]);
  });

  it("excludes with negated conditions", () => {
    const web = host(null, "web-01", null);
    expect(members([web, host(null, "win-test-01", null)], rule(c("hostname", true, ["*test*"])))).toEqual([web.id]);
  });

  it("never matches an unknown fact, negated or not", () => {
    const blank = [host(null, null, null)];
    for (const cond of [c("hostname", false, ["*"]), c("hostname", true, ["*test*"]), c("ip", true, ["10.0.0.0/8"]),
      c("os_family", true, ["windows"]), c("distribution", true, ["debian 12"])]) {
      expect(members(blank, rule(cond)), JSON.stringify(cond)).toEqual([]);
    }
  });

  it("holds when any value matches and every condition holds", () => {
    const deb = host(["debian", "12"], "web-01", null);
    const fed = host(["fedora", "44"], "db-01", null);
    const all = [deb, fed, host(["ubuntu", "24.04"], "web-02", null)];
    const either = c("distribution", false, ["debian 12", "fedora 44"]);
    expect(members(all, rule(either))).toEqual([deb.id, fed.id]);
    expect(members(all, rule(either, c("hostname", false, ["web-*"])))).toEqual([deb.id]);
  });

  it("holds no one with a rule of no conditions", () => {
    expect(members([host(["debian", "12"], "web-01", null)], rule())).toEqual([]);
  });

  it("holds exactly the picked hosts in a manual group", () => {
    const a = host(["debian", "12"], null, null);
    expect(members([a, host(["debian", "12"], null, null)], manual([a.id]))).toEqual([a.id]);
  });

  it("puts revoked and imported hosts in no group; stale ones are active in the store", () => {
    const revoked = host(["debian", "12"], "web-01", null, "revoked");
    const imported = host(["debian", "12"], "web-02", null, "imported");
    const stale = host(["debian", "12"], "web-03", null, "stale");
    const all = [revoked, imported, stale];
    expect(members(all, rule(c("os_family", false, ["linux"])))).toEqual([stale.id]);
    expect(members(all, manual([revoked.id, imported.id]))).toEqual([]);
  });
});

describe("rule checks (group_checks.rs, host_group_writes.rs)", () => {
  it("names the bad part", () => {
    expect(invalidRule([])).toBe("conditions");
    expect(invalidRule(Array.from({ length: 17 }, () => c("os_family", false, ["linux"])))).toBe("conditions");
    expect(invalidRule([c("os_family", false, ["Linux"])])).toBe("os_family");
    expect(invalidRule([c("ip", false, ["10.0.0.0/8", "not-an-address"])])).toBe("ip");
    expect(invalidRule([c("ip", false, ["10.0.0.0/33"])])).toBe("ip");
    expect(invalidRule([c("ip", false, ["2001:db8::/129"])])).toBe("ip");
    expect(invalidRule([c("distribution", false, ["Debian 12"])])).toBe("distribution");
    expect(invalidRule([c("distribution", false, ["debian"])])).toBe("distribution");
    expect(invalidRule([c("hostname", false, [])])).toBe("hostname");
    expect(invalidRule([c("hostname", false, ["x".repeat(256)])])).toBe("hostname");
    expect(invalidRule([c("tag", false, ["x"])])).toBe("tag");
    expect(invalidRule([c("hostname", false, ["*web*"]), c("ip", false, ["10.0.0.0/16", "2001:db8::1"])])).toBeUndefined();
  });

  it("words the membership like group_words.rs", () => {
    expect(membershipSentence("rule", [c("os_family", false, ["windows"]), c("hostname", true, ["*test*"])], 0))
      .toBe("Hosts where OS family is Windows and hostname does not match *test*");
    expect(membershipSentence("automatic", [c("distribution", true, ["debian 12", "fedora 44", "x 1"]), c("ip", true, ["10.0.0.0/8"])], 0))
      .toBe("Hosts where distribution is not Debian 12, Fedora 44 or x 1 and IP address is not in 10.0.0.0/8");
    expect(membershipSentence("manual", [], 1)).toBe("1 host picked by hand");
    expect(membershipSentence("manual", [], 3)).toBe("3 hosts picked by hand");
  });
});
