// The Compliance list and a check's page on the real console (roles step 5c):
// a team lead reaching only comp-P-* (console-e2e-server.sh, one rule set
// e2e-comp-P per browser P) sees only those hosts' checks, the list's counts
// agree with its rows, a healthy host running the set passes, and setting one
// host's state on a check's page moves the list row's hosts bar. The browsers
// share one server, so every name carries the project's.
import { type Page, expect, test } from "@playwright/test";

import templates from "../../src/api/templates.json" with { type: "json" };
import { api, firstSignIn, signIn } from "./helpers";

type Count = { value: string; count: number };
type Row = { rule_set_id: string; rule_id: string; title: string; failing: number; passing: number; open: number; mitigated: number };
type List = {
  total: number; items: Row[];
  summary: { failing_checks: number; hosts: number; critical: number; rule_sets: Count[] };
  counts: { severity: Count[]; rule_set: Count[] };
};

const BROWSER: Record<string, number> = { chromium: 1, firefox: 2, webkit: 3 };
const rows = (page: Page) => page.getByRole("table", { name: "Compliance" }).locator("tbody tr");
const card = (page: Page, title: RegExp) => page.locator(".person-card").filter({ has: page.getByRole("heading", { name: title }) });
const hosts = (page: Page) => card(page, /^Hosts/).getByRole("table", { name: "Hosts", exact: true }).locator("tbody > tr");
const segments = (page: Page) => page.getByRole("radiogroup", { name: "Hosts by state" });
const countOf = (counts: Count[], value: string) => counts.find((c) => c.value === value)?.count ?? 0;
const A = "harden.ssh.e2e_a";
const B = "harden.ssh.e2e_b";

test("a team lead's Compliance holds only their hosts' checks, passing is inferred, and one host's state on a check's page moves the row", async ({ page, browser }, info) => {
  const p = info.project.name;
  expect(BROWSER[p]).toBeDefined();
  const set = `e2e-comp-${p}`;
  const tag = `${p}-${Date.now().toString(36)}`;
  await signIn(page, "alex");
  // The journey mitigates comp-P-1; reopening first and last keeps a retry
  // (CI's retries: 1) or a second run on the same server starting from the seed.
  const reopen = async () => {
    const r = await api(page, "POST", "/api/v1/compliance/bulk", { action: "state", state: "open", items: [{ rule_set_id: set, rule_id: A }] });
    expect(r.status).toBe(200);
  };
  await reopen();
  const created = await api(page, "POST", "/api/v1/host-groups", {
    name: `compliance ${tag}`, kind: "rule", conditions: [{ field: "hostname", negate: false, values: [`comp-${p}-*`] }],
  });
  expect(created.status).toBe(201);
  const group = (created.json as { asset_group_id: string }).asset_group_id;
  const permissions = templates.find((t) => t.name === "Team lead")?.permissions ?? [];
  const role = await api(page, "POST", "/api/v1/roles", { name: `Compliance lead ${tag}`, permissions, reach: { kind: "groups", asset_group_ids: [group] } });
  expect(role.status).toBe(201);
  const user = await api(page, "POST", "/api/v1/users", {
    username: `comp-lead-${tag}`, display_name: "Compliance lead", role_ids: [(role.json as { role_id: string }).role_id],
  });
  expect(user.status).toBe(201);
  const lead = await firstSignIn(browser, `comp-lead-${tag}`, (user.json as { one_time_password: string }).one_time_password);
  try {
    // 1. Only comp-P-*'s checks; other-comp-P-1's e2e_c and the other browsers' sets stay out.
    const all = (await api(lead, "GET", "/api/v1/compliance-list?state=all&limit=100")).json as List;
    expect(all.items.map((r) => `${r.rule_set_id}/${r.rule_id}`).sort()).toEqual([`${set}/${A}`, `${set}/${B}`]);
    const a = all.items.find((r) => r.rule_id === A);
    const b = all.items.find((r) => r.rule_id === B);
    // Failing on comp-P-1 and 2 (other-comp-P-1 is out of reach); comp-P-3 passes both.
    expect([a?.failing, a?.passing, a?.open, a?.title]).toEqual([2, 1, 2, A]);
    expect([b?.failing, b?.passing, b?.open]).toEqual([1, 2, 1]);
    // The counts agree with the rows.
    expect(all.total).toBe(2);
    expect(all.summary).toMatchObject({ failing_checks: 2, hosts: 2, critical: 0, rule_sets: [{ value: set, count: 2 }] });
    expect(countOf(all.counts.severity, "high")).toBe(1);
    expect(countOf(all.counts.severity, "medium")).toBe(1);
    expect(countOf(all.counts.severity, "low")).toBe(0);
    expect(countOf(all.counts.rule_set, set)).toBe(2);
    const passing = (await api(lead, "GET", "/api/v1/compliance-list?state=passing&limit=100")).json as List;
    expect(passing.items.map((r) => r.rule_id).sort()).toEqual([A, B]);
    expect((await api(lead, "GET", `/api/v1/compliance/checks/${set}/harden.ssh.e2e_c/summary`)).status).toBe(404);

    await lead.goto("/compliance");
    await expect(rows(lead)).toHaveCount(2);
    await expect(lead.locator(".summary-line")).toContainText("2 checks failing on 2 hosts");
    const row = (rule: string) => rows(lead).filter({ has: lead.locator(`a[href="/compliance/${set}/${rule}"]`) });
    await expect(row(A).getByRole("progressbar")).toHaveAccessibleName("Hosts: 2 open · 1 pass");
    await expect(row(A)).toContainText("2 of 3");
    await expect(row(B).getByRole("progressbar")).toHaveAccessibleName("Hosts: 1 open · 2 pass");

    // 2. The check's page, opened from its row; its segments.
    await row(A).locator(`a[href="/compliance/${set}/${A}"]`).click();
    await expect(lead).toHaveURL(new RegExp(`/compliance/${set}/${A.replace(/\./g, "\\.")}$`));
    await expect(lead.getByRole("heading", { level: 1 })).toHaveText(A);
    await expect(hosts(lead)).toHaveCount(3);
    await expect(hosts(lead).filter({ hasText: `other-comp-${p}-1` })).toHaveCount(0);
    await segments(lead).getByRole("radio", { name: /^Passing/ }).click();
    await expect(lead).toHaveURL(/[?&]segment=passing/);
    await expect(hosts(lead)).toHaveCount(1);
    await expect(hosts(lead)).toContainText(`comp-${p}-3`);
    await expect(hosts(lead)).toContainText("Passing");
    await segments(lead).getByRole("radio", { name: /^Failing/ }).click();
    await expect(hosts(lead)).toHaveCount(2);

    // 3. Mitigate comp-P-1 alone.
    await hosts(lead).filter({ hasText: `comp-${p}-1` }).getByRole("checkbox").check();
    const bar = lead.getByRole("region", { name: "Bulk actions" });
    await expect(bar).toContainText("1 selected");
    await bar.getByRole("button", { name: /^Set state/ }).click();
    await lead.getByRole("menuitem", { name: /^Mitigate/ }).click();
    const dialog = lead.getByRole("dialog", { name: "Mitigate" });
    await dialog.getByRole("textbox").fill("PermitRootLogin no");
    await dialog.getByRole("button", { name: "Mitigate 1 host" }).click();
    await expect(lead.locator(".toast").last()).toContainText("1 changed");
    await expect(hosts(lead).filter({ hasText: `comp-${p}-1` })).toContainText("Mitigated");

    // 4. The list row follows; the other check does not move.
    await lead.goto("/compliance");
    await expect(row(A).getByRole("progressbar")).toHaveAccessibleName("Hosts: 1 open · 1 mitigated · 1 pass");
    await expect(row(B).getByRole("progressbar")).toHaveAccessibleName("Hosts: 1 open · 2 pass");
  } finally {
    await lead.context().close();
    await reopen();
  }
});
