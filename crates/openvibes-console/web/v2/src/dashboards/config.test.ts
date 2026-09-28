import { describe, expect, it } from "vitest";

import { int, list, noteParts, parseListConfig, str } from "./config";

describe("widget configs", () => {
  it("reads configs defensively", () => {
    expect(str({ metric: 5 }, "metric", "agents.active", ["agents.active"])).toBe("agents.active");
    expect(str({ metric: "nope" }, "metric", "agents.active", ["agents.active", "agents.stale"])).toBe("agents.active");
    expect(int({ limit: "8" }, "limit", 5, 1, 20)).toBe(5);
    expect(int({ limit: 99 }, "limit", 5, 1, 20)).toBe(20);
    expect(list({ include: ["stale", "evil"] }, "include", ["exploited", "findings", "stale"])).toEqual(["stale"]);
    expect(list({ include: "stale" }, "include", ["stale"])).toEqual([]);
  });

  it("noteParts links only whole https words and never interprets markup", () => {
    expect(noteParts("See https://wiki.example.test/a now")).toEqual([{ text: "See " }, { href: "https://wiki.example.test/a" }, { text: " now" }]);
    expect(noteParts("javascript:alert(1) <b>bold</b>")).toEqual([{ text: "javascript:alert(1) <b>bold</b>" }]);
    expect(noteParts("http://plain.example.test")).toEqual([{ text: "http://plain.example.test" }]);
  });

  it("parseListConfig accepts only known views and keeps the query", () => {
    expect(parseListConfig({ view: "/findings", query: "severity=critical", limit: 3 })).toMatchObject({ view: "/findings", limit: 3 });
    expect(parseListConfig({ view: "/findings", query: "severity=critical", limit: 3 })?.params.get("severity")).toBe("critical");
    expect(parseListConfig({ view: "/etc/passwd" })).toBeUndefined();
    expect(parseListConfig({ view: "/agents", query: "%%%" })?.params.toString()).toBe("");
  });
});
