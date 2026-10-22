// The Alarms list and an alarm's page on the real console (roles step 5a):
// a team lead reaching only page-1 (console-e2e-server.sh: its alarm
// `--nightly` ×1 with two siblings, `--weekly` ×5 and `--monthly` ×2, all
// started this hour) sees only those three alarms, the list's counts agree
// with its rows, and an alarm's page shows its commands and timeline. The
// browsers share one server, so every name carries the project's.
import { type Page, expect, test } from "@playwright/test";

import templates from "../../src/api/templates.json" with { type: "json" };
import { api, firstSignIn, signIn } from "./helpers";

type Count = { value: string; count: number };
type Row = { id: number; count: number; host: { name: string | null } };
type List = { total: number; items: Row[]; summary: { open: number }; counts: { severity: Count[]; state: Count[] } };

const rows = (page: Page) => page.getByRole("table", { name: "Alarms" }).locator("tbody tr");
const card = (page: Page, title: RegExp) => page.locator(".person-card").filter({ has: page.getByRole("heading", { name: title }) });
const countOf = (counts: Count[], value: string) => counts.find((c) => c.value === value)?.count ?? 0;

test("a team lead's Alarms list holds only their host's alarms, and an alarm's page shows its commands and timeline", async ({ page, browser }, info) => {
  const tag = `${info.project.name}-${Date.now().toString(36)}`;
  await signIn(page, "alex");
  const created = await api(page, "POST", "/api/v1/host-groups", {
    name: `alarms page ${tag}`, kind: "rule", conditions: [{ field: "hostname", negate: false, values: ["page-*"] }],
  });
  expect(created.status).toBe(201);
  const group = (created.json as { asset_group_id: string }).asset_group_id;
  const permissions = templates.find((t) => t.name === "Team lead")?.permissions ?? [];
  const role = await api(page, "POST", "/api/v1/roles", { name: `Alarms lead ${tag}`, permissions, reach: { kind: "groups", asset_group_ids: [group] } });
  expect(role.status).toBe(201);
  const user = await api(page, "POST", "/api/v1/users", {
    username: `alarms-lead-${tag}`, display_name: "Alarms lead", role_ids: [(role.json as { role_id: string }).role_id],
  });
  expect(user.status).toBe(201);
  const lead = await firstSignIn(browser, `alarms-lead-${tag}`, (user.json as { one_time_password: string }).one_time_password);
  try {
    // 1. Only page-1's alarms, and the counts agree with the rows.
    const list = (await api(lead, "GET", "/api/v1/alarm-list?limit=100")).json as List;
    expect(list.total).toBe(3);
    expect(list.items.map((a) => a.host.name)).toEqual(Array(3).fill("page-1.example.test"));
    expect(list.summary.open).toBe(3);
    expect(countOf(list.counts.severity, "low")).toBe(3);
    expect(countOf(list.counts.state, "open")).toBe(3);
    await lead.goto("/alarms");
    await expect(rows(lead)).toHaveCount(3);
    await expect(lead.locator(".view-header__count")).toHaveText("3");
    await expect(lead.locator(".summary-line")).toContainText("3 open");
    await expect(rows(lead).filter({ hasText: /Team alarm on (linux|windows|lin-sup)/ })).toHaveCount(0);

    // 2. The nightly alarm's page, opened from its row.
    const nightly = list.items.find((a) => a.count === 1);
    expect(nightly).toBeDefined();
    await rows(lead).locator(`a[href="/alarms/${nightly?.id}"]`).click();
    await expect(lead).toHaveURL(new RegExp(`/alarms/${nightly?.id}$`));
    await expect(lead.getByRole("heading", { level: 1 })).toHaveText("Team alarm on page-1");
    await expect(lead.getByRole("link", { name: /^Starts matched: 8$/ })).toBeVisible();
    await expect(lead.getByRole("link", { name: /^Different commands: 3$/ })).toBeVisible();

    // 3. Commands seen: the usual one first, the alarm's own seen once.
    const commands = card(lead, /^Commands seen/).locator("tbody tr");
    await expect(commands).toHaveCount(3);
    await expect(commands.nth(0)).toContainText("--weekly");
    await expect(commands.nth(0)).toContainText("Usual");
    await expect(commands.nth(1)).toContainText("--monthly");
    await expect(commands.nth(2)).toContainText("--nightly");
    await expect(commands.nth(2)).toHaveClass(/cmd-once/);

    // 4. The last 24 hours: 24 bars, the 8 starts in the table's last two
    // hours (the seeding may straddle the turn of the hour).
    const timeline = card(lead, /^Last 24 hours$/);
    await expect(timeline.locator("svg rect")).toHaveCount(24);
    await expect(timeline.locator("table tbody tr")).toHaveCount(24);
    await expect(timeline.locator("table tbody tr").last()).toContainText("this hour");
    const hourly = await timeline.locator("table tbody tr td").allTextContents();
    expect(hourly.slice(-2).reduce((sum, v) => sum + Number(v.replace(/\D/g, "")), 0)).toBe(8);
  } finally {
    await lead.context().close();
  }
});
