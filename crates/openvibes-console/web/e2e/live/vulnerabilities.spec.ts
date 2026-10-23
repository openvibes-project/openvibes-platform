// The Vulnerabilities list and a CVE's page on the real console (roles step
// 5b): a team lead reaching only vuln-P-* (console-e2e-server.sh, one set per
// browser P) sees only those hosts' CVEs, the list's counts agree with its
// rows, and setting one host's state on a CVE's page moves the list row's
// "n open of m", and its sibling CVE's (one advisory covers both). The
// browsers share one server, so every name carries the project's.
import { type Page, expect, test } from "@playwright/test";

import templates from "../../src/api/templates.json" with { type: "json" };
import { api, firstSignIn, signIn } from "./helpers";

type Count = { value: string; count: number };
type Row = { key: string; open: number; total: number; advisories: string[]; also_covers: string[] };
type List = {
  total: number; items: Row[];
  summary: { open_rows: number; hosts: number };
  counts: { severity: Count[]; state: Count[]; package: Count[] };
};

const BROWSER: Record<string, number> = { chromium: 1, firefox: 2, webkit: 3 };
const rows = (page: Page) => page.getByRole("table", { name: "Vulnerabilities" }).locator("tbody tr");
const card = (page: Page, title: RegExp) => page.locator(".person-card").filter({ has: page.getByRole("heading", { name: title }) });
const hosts = (page: Page) => card(page, /^Hosts/).locator("tbody tr");
const segments = (page: Page) => page.getByRole("radiogroup", { name: "Hosts by state" });
const countOf = (counts: Count[], value: string) => counts.find((c) => c.value === value)?.count ?? 0;

test("a team lead's Vulnerabilities hold only their hosts' CVEs, and one host's state on a CVE's page moves the row's open count", async ({ page, browser }, info) => {
  const p = info.project.name;
  const n = BROWSER[p];
  expect(n).toBeDefined();
  const cve = (c: number) => `CVE-2099-${n}00${c}`;
  const tag = `${p}-${Date.now().toString(36)}`;
  await signIn(page, "alex");
  const created = await api(page, "POST", "/api/v1/host-groups", {
    name: `vulns ${tag}`, kind: "rule", conditions: [{ field: "hostname", negate: false, values: [`vuln-${p}-*`] }],
  });
  expect(created.status).toBe(201);
  const group = (created.json as { asset_group_id: string }).asset_group_id;
  const permissions = templates.find((t) => t.name === "Team lead")?.permissions ?? [];
  const role = await api(page, "POST", "/api/v1/roles", { name: `Vulns lead ${tag}`, permissions, reach: { kind: "groups", asset_group_ids: [group] } });
  expect(role.status).toBe(201);
  const user = await api(page, "POST", "/api/v1/users", {
    username: `vulns-lead-${tag}`, display_name: "Vulns lead", role_ids: [(role.json as { role_id: string }).role_id],
  });
  expect(user.status).toBe(201);
  const lead = await firstSignIn(browser, `vulns-lead-${tag}`, (user.json as { one_time_password: string }).one_time_password);
  try {
    // 1. Only vuln-P-1/2's CVEs; out-P-1's own CVE and the other browsers' stay out.
    const list = (await api(lead, "GET", "/api/v1/vulnerability-list?state=all&limit=100")).json as List;
    expect(list.items.map((r) => r.key).sort()).toEqual([cve(1), cve(2), cve(4)]);
    expect(list.total).toBe(3);
    const first = list.items.find((r) => r.key === cve(1));
    expect([first?.open, first?.total]).toEqual([2, 2]);
    expect(first?.advisories).toEqual([`DSA-E2E-${p}-1`]);
    expect(first?.also_covers).toEqual([cve(2)]);
    // The counts agree with the rows.
    expect(list.summary).toMatchObject({ open_rows: 3, hosts: 2 });
    expect(countOf(list.counts.severity, "important")).toBe(2);
    expect(countOf(list.counts.severity, "low")).toBe(1);
    expect(countOf(list.counts.severity, "critical")).toBe(0);
    expect(countOf(list.counts.state, "open")).toBe(3);
    expect(countOf(list.counts.package, "openssl")).toBe(2);
    expect(countOf(list.counts.package, "secretpkg")).toBe(0);
    expect((await api(lead, "GET", `/api/v1/vulnerabilities/${cve(3)}/summary`)).status).toBe(404);

    await lead.goto("/vulnerabilities");
    await expect(rows(lead)).toHaveCount(3);
    await expect(lead.locator(".view-header__count")).toHaveText("3");
    await expect(lead.locator(".summary-line")).toContainText("3 open on 2 hosts");
    const row = (c: number) => rows(lead).filter({ hasText: cve(c) });
    await expect(row(1).getByRole("progressbar")).toHaveAccessibleName("2 open of 2 hosts");
    await expect(rows(lead).filter({ hasText: cve(3) })).toHaveCount(0);

    // 2. The CVE's page, opened from its row; its segments.
    await row(1).locator(`a[href="/vulnerabilities/${cve(1)}"]`).click();
    await expect(lead).toHaveURL(new RegExp(`/vulnerabilities/${cve(1)}$`));
    await expect(hosts(lead)).toHaveCount(2);
    await expect(hosts(lead).filter({ hasText: `out-${p}-1` })).toHaveCount(0);
    await segments(lead).getByRole("radio", { name: /^Mitigated/ }).click();
    await expect(lead).toHaveURL(/[?&]segment=mitigated/);
    await expect(card(lead, /^Hosts/)).not.toContainText(`vuln-${p}-1`);
    await segments(lead).getByRole("radio", { name: /^Open/ }).click();
    await expect(hosts(lead)).toHaveCount(2);

    // 3. Mitigate vuln-P-1 alone.
    await hosts(lead).filter({ hasText: `vuln-${p}-1` }).getByRole("checkbox").check();
    const bar = lead.getByRole("region", { name: "Bulk actions" });
    await expect(bar).toContainText("1 selected");
    await bar.getByRole("button", { name: /^Set state/ }).click();
    await lead.getByRole("menuitem", { name: /^Mitigate/ }).click();
    const dialog = lead.getByRole("dialog", { name: "Mitigate" });
    await dialog.getByRole("textbox").fill("blocked at the firewall");
    await dialog.getByRole("button", { name: /^Mitigate 1 host/ }).click();
    await expect(lead.locator(".toast").last()).toContainText("1 changed");
    await expect(hosts(lead)).toHaveCount(1);
    await segments(lead).getByRole("radio", { name: /^Mitigated/ }).click();
    await expect(hosts(lead)).toHaveCount(1);
    await expect(hosts(lead)).toContainText(`vuln-${p}-1`);

    // 4. The list row follows, and so does its sibling CVE.
    await lead.goto("/vulnerabilities");
    await expect(row(1).getByRole("progressbar")).toHaveAccessibleName("1 open of 2 hosts");
    await expect(row(2).getByRole("progressbar")).toHaveAccessibleName("1 open of 2 hosts");
    await expect(row(4).getByRole("progressbar")).toHaveAccessibleName("1 open of 1 hosts");
  } finally {
    await lead.context().close();
  }
});
