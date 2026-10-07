import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { METRICS } from "./metrics";
import { upgradeLayout } from "./legacy";

// The server's CATALOGUE is the source of truth: read it as text so drift fails the build.
const source = readFileSync(new URL("../../../src/metrics.rs", import.meta.url), "utf8");
const PERMISSION = { AL: "alarms.read", VU: "vulnerabilities.read", CO: "compliance.read", AG: "agents.read" } as const;
const server = [...source.matchAll(/m!\(\s*"([^"]+)",\s*"[^"]*",\s*&\[([A-Z, ]+)\]/g)].map(([, id, perms]) => [
  id, (perms ?? "").split(",").map((p) => p.trim()).filter(Boolean).map((p) => PERMISSION[p as keyof typeof PERMISSION]),
] as const);

describe("catalogue", () => {
  it("matches the server catalogue ids and permissions", () => {
    expect(server).toHaveLength(21);
    expect(Object.keys(METRICS).sort()).toEqual(server.map(([id]) => id).sort());
    for (const [id, permissions] of server) expect([id, METRICS[id as keyof typeof METRICS].permissions]).toEqual([id, permissions]);
  });
  it("cross-kind counts need all three read permissions and link each part", () => {
    expect(METRICS["all.open.high"].permissions).toEqual(["alarms.read", "vulnerabilities.read", "compliance.read"]);
    expect(METRICS["all.open.high"].parts).toEqual([["alarm", "alarms.active.high"], ["vulnerability", "vulns.open.high"], ["compliance", "compliance.open.high"]]);
    expect(METRICS["vulns.open.high"].view).toEqual(["/vulnerabilities", { severity: "important" }]);
    expect(METRICS["vulns.open.medium"].view).toEqual(["/vulnerabilities", { severity: "moderate" }]);
  });
  it("every part is itself a catalogue entry", () => {
    for (const m of Object.values(METRICS)) for (const [, id] of "parts" in m ? m.parts : []) expect(METRICS).toHaveProperty(id);
  });
  it("keeps every id older dashboards used, including through the findings rename", () => {
    const old = ["alarms.active", "agents.active", "agents.stale", "agents.revoked", "compliance.open.critical", "compliance.open.high", "compliance.open.medium", "compliance.open.low", "vulns.exploited", "vulns.reboot_hosts", "vulns.no_fix"];
    const widgets = [...old, ...old.filter((id) => id.startsWith("compliance.")).map((id) => id.replace("compliance.", "findings."))]
      .map((metric, i) => ({ id: `w${i}`, type: "number", x: 0, y: 0, w: 3, h: 2, config: { metric } }));
    for (const w of upgradeLayout({ schema: 1, widgets } as never).widgets) expect(METRICS).toHaveProperty(String(w.config.metric));
  });
});
