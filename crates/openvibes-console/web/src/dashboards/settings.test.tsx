// Markup checks (vitest runs in node, no DOM library); clicks and keys are in e2e/demo/dashboards.spec.ts.
import type { ComponentType } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

import type { Widget, WidgetType } from "./layout";
import { METRIC_GROUPS } from "./metrics";

// The tiles import the router, which reads window at load; a bare location is enough for markup.
vi.stubGlobal("window", { location: { pathname: "/", search: "" }, addEventListener: () => {}, removeEventListener: () => {} });
const { AttentionSettings, BreakdownSettings, GraphSettings, ListSettings, NumberSettings, ruleGroups, ruleUnknownLabel, TopHostsSettings } = await import("./settings");

const noop = () => {};
const html = (Settings: ComponentType<{ widget: Widget; onChange: () => void }>, type: WidgetType, config: Widget["config"]) =>
  renderToStaticMarkup(<Settings widget={{ id: `${type}-1`, type, x: 0, y: 0, w: 4, h: 3, config }} onChange={noop} />);
// Selected states of the radios in a markup string, in order: "label:true|false".
const radios = (markup: string, group: string) => {
  const part = markup.slice(markup.indexOf(`aria-label="${group}"`));
  const end = part.indexOf("</div>");
  return [...part.slice(0, end).matchAll(/aria-checked="(true|false)"[^>]*>([^<]*)</g)].map((m) => `${m[2]}:${m[1]}`);
};

describe("METRIC_GROUPS", () => {
  it("groups the catalogue by kind", () => {
    expect(METRIC_GROUPS.map((g) => g.group)).toEqual(["All kinds", "Alarms", "Vulnerabilities", "Compliance", "Hosts"]);
    expect(METRIC_GROUPS.flatMap((g) => g.options).length).toBe(21);
    expect(METRIC_GROUPS[0]?.options[0]?.label).toBe("Critical (all kinds)");
  });
});

describe("Graph editor", () => {
  const three = { metrics: ["alarms.active", "all.open.high", "vulns.exploited"] };
  it("one row per count with its series colour, combobox and remove button", () => {
    const m = html(GraphSettings, "graph", three);
    expect(m.match(/role="combobox"/g)).toHaveLength(3);
    for (const n of [1, 2, 3]) {
      expect(m).toContain(`var(--series-${n})`);
      expect(m).toContain(`aria-label="Remove count ${n}"`);
    }
    expect(m).toContain("Add a count");
  });
  it("hides Add a count at four and Remove with a single count", () => {
    expect(html(GraphSettings, "graph", { metrics: ["alarms.active", "all.open.high", "vulns.exploited", "agents.stale"] })).not.toContain("Add a count");
    expect(html(GraphSettings, "graph", {})).not.toContain("Remove count");
  });
  it("Period and Line are radiogroups; a stored odd period is an extra", () => {
    const m = html(GraphSettings, "graph", { days: 14 });
    expect(m).toContain('role="radiogroup" aria-label="Line"');
    expect(radios(m, "Period")).toEqual(["7 d:false", "30 d:false", "90 d:false", "1 y:false", "14 d:true"]);
  });
});

describe("Number editor", () => {
  it("Trend is a radiogroup and a stored 14 stays as an extra", () => {
    expect(radios(html(NumberSettings, "number", { trend: 30 }), "Trend")).toEqual(["Off:false", "7 d:false", "30 d:true", "90 d:false"]);
    expect(radios(html(NumberSettings, "number", { trend: 14 }), "Trend").at(-1)).toBe("14 d:true");
  });
});

describe("Attention editor", () => {
  it("one switch per kind; Show at most keeps a stored 12", () => {
    const m = html(AttentionSettings, "attention", { limit: 12 });
    expect(m.match(/role="switch"/g)).toHaveLength(5);
    expect(radios(m, "Show at most")).toEqual(["5:false", "8:false", "10:false", "15:false", "12:true"]);
  });
  it("an include list switches the others off; the last one on cannot be turned off", () => {
    const m = html(AttentionSettings, "attention", { include: ["alarms", "bogus"] });
    expect(m.match(/role="switch" aria-checked="true"/g)).toHaveLength(1);
    expect(m.match(/<button[^>]*role="switch"[^>]*disabled/g)).toHaveLength(1);
    expect(html(AttentionSettings, "attention", { include: ["bogus"] }).match(/role="switch" aria-checked="true"/g)).toHaveLength(5);
  });
});

describe("List editor", () => {
  it("shows the list by its name and stored filters as removable chips", () => {
    const m = html(ListSettings, "list", { view: "/compliance", query: "severity=critical&bad=1" });
    expect(m).toContain("Compliance findings");
    expect(m).toContain("Severity: Critical");
    expect(m).toContain("bad=1");
    expect(m).toContain('aria-label="Remove filter Severity: Critical"');
    expect(m).toContain('aria-label="Remove filter bad=1"');
    expect(m).toContain('aria-label="Add filter"');
  });
  it("still offers a used choice filter, and plain chips for an unknown list", () => {
    expect(html(ListSettings, "list", { view: "/agents", query: "status=stale" })).toContain('aria-label="Add filter"');
    expect(html(ListSettings, "list", { view: "/gone", query: "" })).not.toContain('aria-label="Add filter"');
    const m = html(ListSettings, "list", { view: "/gone", query: "severity=low" });
    expect(m).toContain("severity=low");
    expect(m).toContain("/gone");
  });
});

describe("Trend rule", () => {
  it("groups rules by set under their latest message, and names a missing stored rule", () => {
    const groups = ruleGroups([
      { rule_set_id: "b", rule_id: "r2", latest_message: "Second" }, { rule_set_id: "a", rule_id: "r1", latest_message: "First" },
      { rule_set_id: "a", rule_id: "r3", latest_message: null },
    ]);
    expect(groups.map((g) => [g.group, g.options.map((o) => o.value)])).toEqual([["a", ["a/r1", "a/r3"]], ["b", ["b/r2"]]]);
    expect(groups[0]?.options.map((o) => o.label)).toEqual(["First · r1", "r3"]);
    expect(ruleUnknownLabel("a/x", false, true)).toBe("a/x (not found)");
    expect(ruleUnknownLabel("a/x", true, false)).toBe("a/x (could not load)");
    expect(ruleUnknownLabel("a/x", false, false)).toBe("a/x");
  });
});

describe("Top hosts and Breakdown", () => {
  it("are radiogroups", () => {
    const m = html(TopHostsSettings, "top-hosts", {});
    expect(radios(m, "Count")).toEqual(["All kinds:true", "Vulnerabilities only:false"]);
    expect(radios(m, "Hosts")).toEqual(["3:false", "6:true", "10:false"]);
    expect(radios(html(BreakdownSettings, "breakdown", { source: "agents" }), "Break down")).toEqual(["Alarms:false", "Vulnerabilities:false", "Compliance:false", "Hosts:true"]);
  });
});
