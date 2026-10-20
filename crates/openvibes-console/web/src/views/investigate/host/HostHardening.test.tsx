import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import type { Agent } from "../../../api/types";
import { HardeningLine, NotAssigned, hostAssignmentsPath } from "./HostHardening";

const text = (html: string) => html.replace(/<[^>]+>/g, "").replaceAll("&#x27;", "'");

describe("the host's Hardening line", () => {
  it("names the deciding group (screen 6)", () => {
    const html = renderToStaticMarkup(<dl><HardeningLine parts={[{ name: "L1", on: false, group: "Production", note: null }, { name: "L2", on: false, group: null, note: null }]} facts="ok" okAt={null} /></dl>);
    expect(text(html)).toBe("HardeningL1 off (Production) · L2 off");
  });
  it("says a set waits until published, or is pending (screen 7)", () => {
    const html = renderToStaticMarkup(<dl><HardeningLine parts={[{ name: "L1", on: true, group: null, note: "pending" }, { name: "L2", on: true, group: "Lab", note: "waits until published" }]} facts={null} okAt={null} /></dl>);
    expect(text(html)).toBe("HardeningL1 on · pending · L2 on (Lab) · waits until published");
  });
  it("warns when the root-facts helper's facts are unavailable, for how long (screen 8)", () => {
    const threeDaysAgo = new Date(Date.now() - 3 * 86_400_000 - 3_600_000).toISOString();
    const html = renderToStaticMarkup(<dl><HardeningLine parts={[{ name: "L1", on: true, group: null, note: null }]} facts="not_found" okAt={threeDaysAgo} /></dl>);
    expect(html).toContain('<span class="badge badge--warn badge--plain">Hardening facts unavailable</span>');
    expect(text(html)).toContain("The agent's root-facts helper has not reported for 3 days (openvibes-agent-facts.timer), so checks that read root-only files show as unavailable, not failed.");
    expect(html).toContain('style="grid-column:1 / -1"');
    const never = renderToStaticMarkup(<dl><HardeningLine parts={[]} facts="not_found" okAt={null} /></dl>);
    expect(text(never)).toContain("has not reported since enrollment (");
    const ok = renderToStaticMarkup(<dl><HardeningLine parts={[]} facts="ok" okAt={threeDaysAgo} /></dl>);
    expect(ok).not.toContain("Hardening facts unavailable");
  });
  it("a set the host reports not assigned: the badge and the group (screen 6)", () => {
    expect(renderToStaticMarkup(<NotAssigned text="off for Production" />)).toBe('<span class="badge badge--plain" title="Switched off for Production">Not assigned</span><span class="subtle nowrap">off for Production</span>');
    expect(renderToStaticMarkup(<NotAssigned text="off by default" />)).toBe('<span class="badge badge--plain" title="Switched off by default">Not assigned</span><span class="subtle nowrap">off by default</span>');
    expect(renderToStaticMarkup(<NotAssigned text={null} />)).toBe('<span class="badge badge--plain">Not assigned</span>');
  });
});

describe("which hosts have a Hardening line", () => {
  const host = (status: string, os_id: string | null) => ({ id: "agent.1", status, os_id }) as unknown as Agent;
  it("only active Linux hosts: not imported, revoked or without os-release", () => {
    expect(hostAssignmentsPath(host("active", "fedora"))).toBe("/api/v1/agents/agent.1/rule-set-assignments");
    for (const status of ["imported", "revoked"]) expect(hostAssignmentsPath(host(status, "fedora"))).toBeNull();
    expect(hostAssignmentsPath(host("active", null))).toBeNull();
  });
});
