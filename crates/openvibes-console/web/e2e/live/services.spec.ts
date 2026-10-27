// The Services list and a service's page on the real console (roles step
// 5f): a team lead sees only units on their hosts, the counts agree with the
// rows, a unit started a day ago shows in This week and in the page's Recent
// changes, and the lead opens the page, switches segments and adds the unit
// to a case. console-e2e-server.sh seeds one set per browser n:
// sshd.service on port-P-1, port-P-2 and portout-P-1, postgresql.service and
// buildN.service on port-P-1 only (the lead's reach), far.service on
// portout-P-1 (outside it). The browsers share one server, so every name
// carries the project's.
import { type Page, expect, test } from "@playwright/test";

import templates from "../../src/api/templates.json" with { type: "json" };
import { api, firstSignIn, signIn } from "./helpers";

type Count = { value: string; count: number };
type Row = { unit: string; hosts: number; root_hosts: number; exposed_hosts: number; week_added: number; look: string[]; package: string | null };
type List = { total: number; items: Row[]; counts: { runs_as: Count[]; changes: Count[]; group: Count[] }; summary: { reporting_hosts: number } };

const N = { chromium: 1, firefox: 2, webkit: 3 } as const;
const rows = (page: Page) => page.getByRole("table", { name: "Services", exact: true }).locator("tbody tr");
const hostRows = (page: Page) => page.getByRole("table", { name: "Hosts", exact: true }).locator("tbody tr");
const list = async (page: Page, query = "") => (await api(page, "GET", `/api/v1/service-list?limit=100${query}`)).json as List;
const countOf = (counts: Count[], value: string) => counts.find((c) => c.value === value)?.count ?? 0;

test("a team lead's Services list and service page stay inside their team; an Administrator sees the rest", async ({ page, browser }, info) => {
  const n = N[info.project.name as keyof typeof N];
  const tag = `${info.project.name}-${Date.now().toString(36)}`;
  const build = `build${n}.service`;
  await signIn(page, "alex");
  const created = await api(page, "POST", "/api/v1/host-groups", {
    name: `services ${tag}`, kind: "rule", conditions: [{ field: "hostname", negate: false, values: [`port-${info.project.name}-*`] }],
  });
  expect(created.status).toBe(201);
  const group = (created.json as { asset_group_id: string }).asset_group_id;
  const permissions = templates.find((t) => t.name === "Team lead")?.permissions ?? [];
  expect(permissions).not.toContain("hosts.export");
  const role = await api(page, "POST", "/api/v1/roles", { name: `Services lead ${tag}`, permissions, reach: { kind: "groups", asset_group_ids: [group] } });
  expect(role.status).toBe(201);
  const user = await api(page, "POST", "/api/v1/users", {
    username: `services-lead-${tag}`, display_name: "Services lead", role_ids: [(role.json as { role_id: string }).role_id],
  });
  expect(user.status).toBe(201);
  const lead = await firstSignIn(browser, `services-lead-${tag}`, (user.json as { one_time_password: string }).one_time_password);
  try {
    // 1. Only units on the team's hosts, and the counts agree with the rows.
    await lead.goto("/services");
    await expect(rows(lead).first()).toBeVisible();
    const mine = await list(lead);
    expect(mine.items.map((r) => r.unit)).toEqual([build, "postgresql.service", "sshd.service"]);
    await expect(lead.locator(".view-header__count")).toHaveText("3");
    await expect(rows(lead)).toHaveCount(3);
    const ssh = mine.items.find((r) => r.unit === "sshd.service");
    expect([ssh?.hosts, ssh?.root_hosts, ssh?.exposed_hosts]).toEqual([2, 2, 1]);
    expect(mine.summary.reporting_hosts).toBe(2);
    expect(countOf(mine.counts.group, group)).toBe(3);
    expect(countOf(mine.counts.runs_as, "root")).toBe(2);
    // The Needs a look and This week cells agree with the API.
    expect(mine.items.find((r) => r.unit === "postgresql.service")?.look).toEqual(["database_exposed"]);
    const fresh = mine.items.find((r) => r.unit === build);
    expect([fresh?.week_added, fresh?.look, fresh?.package]).toEqual([1, ["root_unpackaged", "new_unusual"], null]);
    await expect(rows(lead).filter({ hasText: "postgresql.service" })).toContainText("Database reachable from the network");
    await expect(rows(lead).filter({ hasText: build })).toContainText("+1 host");
    await expect(rows(lead).filter({ hasText: build })).toContainText("Not a usual service");

    // 2. A filter narrows both the rows and the counts; a reload keeps it.
    await lead.goto("/services?changes=new");
    await expect(rows(lead)).toHaveCount(1);
    await expect(rows(lead).first()).toContainText(build);
    await lead.reload();
    await expect(lead.getByRole("group", { name: "Filters" })).toContainText("Changes: New this week");
    await expect(rows(lead)).toHaveCount(1);

    // 3. The page: this team's hosts only, segments, and no Export without hosts.export.
    await lead.goto("/services");
    await rows(lead).filter({ hasText: "sshd.service" }).getByRole("link", { name: "sshd.service" }).click();
    await expect(lead).toHaveURL(/\/services\/sshd\.service$/);
    await expect(lead.getByRole("heading", { level: 1 })).toContainText("sshd.service");
    await expect(hostRows(lead)).toHaveCount(2);
    await lead.getByRole("radiogroup", { name: "Hosts by exposure and user" }).getByRole("radio", { name: /^Exposed/ }).click();
    await expect(hostRows(lead)).toHaveCount(1);
    await expect(hostRows(lead).first()).toContainText(`port-${info.project.name}-1`);
    await lead.getByRole("button", { name: "More actions" }).click();
    await expect(lead.getByRole("menuitem", { name: /^Export/ })).toHaveCount(0);
    await lead.keyboard.press("Escape");

    // 4. A unit started a day ago shows in Recent changes; one outside the reach is not there.
    await lead.goto(`/services/${build}`);
    await expect(lead.locator(".person-card").filter({ has: lead.getByRole("heading", { name: "Recent changes" }) })).toContainText(`port-${info.project.name}-1.example.test started running it`);
    await lead.goto("/services/far.service");
    await expect(lead.getByText("No such service")).toBeVisible();
    expect((await api(lead, "GET", "/api/v1/services/far.service/summary")).status).toBe(404);

    // 5. Add the unit to a case: it is in the case, and the case lists it.
    await lead.goto("/services/sshd.service");
    await expect(hostRows(lead).first()).toBeVisible();
    await lead.getByRole("button", { name: "Add to case" }).click();
    const menu = lead.getByRole("dialog", { name: /Add service to a case/ });
    await menu.getByRole("button", { name: "New case…" }).click();
    await menu.getByLabel("Title").fill(`sshd review ${tag}`);
    await menu.getByRole("button", { name: "Open case" }).click();
    await expect(lead.locator(".toast")).toContainText(/Opened C-\d+/);
    await menu.getByRole("link", { name: new RegExp(`sshd review ${tag}`) }).click();
    await expect(lead.locator(".person-card").filter({ has: lead.getByRole("heading", { name: /^Items/ }) }).locator("tr.case-row")).toContainText("sshd.service");

    // 6. An old link opens the page.
    await lead.goto(`/hosts?open=${encodeURIComponent("unit:sshd.service")}`);
    await expect(lead).toHaveURL(/\/services\/sshd\.service$/);
  } finally {
    await lead.context().close();
  }

  // 7. The Administrator sees the outside host's unit too, and may export.
  const all = await list(page);
  expect(all.items.map((r) => r.unit)).toContain("far.service");
  await page.goto("/services/sshd.service");
  await page.getByRole("button", { name: "More actions" }).click();
  await expect(page.getByRole("menuitem", { name: /^Export/ })).toBeVisible();
});
