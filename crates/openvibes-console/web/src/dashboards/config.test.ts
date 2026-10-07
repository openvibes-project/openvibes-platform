import { describe, expect, it } from "vitest";

import { int, list, noteLines, noteParts, parseListConfig, str, toInt } from "./config";

describe("widget configs", () => {
  it("reads configs defensively", () => {
    expect(str({ metric: 5 }, "metric", "agents.active", ["agents.active"])).toBe("agents.active");
    expect(str({ metric: "nope" }, "metric", "agents.active", ["agents.active", "agents.stale"])).toBe("agents.active");
    expect(int({ limit: "8" }, "limit", 5, 1, 20)).toBe(5);
    expect(int({ limit: 99 }, "limit", 5, 1, 20)).toBe(20);
    expect(list({ include: ["stale", "evil"] }, "include", ["exploited", "compliance", "stale"])).toEqual(["stale"]);
    expect(list({ include: "stale" }, "include", ["stale"])).toEqual([]);
  });

  it("noteParts links only whole https words and never interprets markup", () => {
    expect(noteParts("See https://wiki.example.test/a now")).toEqual([{ text: "See " }, { href: "https://wiki.example.test/a" }, { text: " now" }]);
    expect(noteParts("javascript:alert(1) <b>bold</b>")).toEqual([{ text: "javascript:alert(1) <b>bold</b>" }]);
    expect(noteParts("http://plain.example.test")).toEqual([{ text: "http://plain.example.test" }]);
  });

  it("parseListConfig accepts only known views and keeps the query", () => {
    expect(parseListConfig({ view: "/compliance", query: "severity=critical", limit: 3 })).toMatchObject({ view: "/compliance", limit: 3 });
    expect(parseListConfig({ view: "/compliance", query: "severity=critical", limit: 3 })?.params.get("severity")).toBe("critical");
    expect(parseListConfig({ view: "/etc/passwd" })).toBeUndefined();
    expect(parseListConfig({ view: "/agents", query: "%%%" })?.params.toString()).toBe("");
  });
});

describe("settings input", () => {
  it("number fields keep whole numbers within bounds", () => {
    expect(toInt("1.5", 1, 20, 8)).toBe(2);
    expect(toInt("", 1, 20, 8)).toBe(8);
    expect(toInt("abc", 1, 20, 8)).toBe(8);
    expect(toInt("99", 1, 20, 8)).toBe(20);
    expect(toInt("0", 1, 20, 8)).toBe(1);
  });

  it("note lines are cut by character, never inside an emoji", () => {
    const line = `${"a".repeat(255)}😀tail`;
    const [cut] = noteLines(line);
    expect([...(cut ?? "")].length).toBe(256);
    expect(cut?.endsWith("😀")).toBe(true);
    expect(JSON.parse(JSON.stringify(cut))).toBe(cut);
    expect(noteLines(Array(20).fill("x").join("\n"))).toHaveLength(16);
  });
});
