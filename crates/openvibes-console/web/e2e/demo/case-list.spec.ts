import { expect, test } from "@playwright/test";

import { expectChips, expectNoAxeViolations, hideColumnAcrossReload, listParts, pointerOffRail, saveClearRestore } from "./list-helpers";

// The Cases list on the demo (approved screen 31): the demo answers
// GET /api/v1/case-list like cases/list_page.rs, over src/demo/caseSeed.ts.
// The seed's cases that are not closed: four open, four investigating; the
// empty one and the software-only one are ready to close.
const { table, rows, filters, choose } = listParts("Cases");

pointerOffRail();

test("filters by Contains and Updated, and a reload keeps both", async ({ page }) => {
  await page.goto("/cases");
  await expect(rows(page)).toHaveCount(8);
  await choose(page, "Contains", /^Alarms/);
  await expectChips(filters(page), ["Contains: Alarms"]);
  await choose(page, "Updated", /^This week/);
  await expectChips(filters(page), ["Updated: This week"]);
  await expect(page).toHaveURL(/[?&]contains=alarms/);
  await expect(page).toHaveURL(/[?&]updated=week/);
  // The cron case has an alarm but has been quiet for over a week.
  const check = async () => {
    await expect(rows(page)).toHaveCount(3);
    await expect(rows(page).filter({ hasText: "Odd cron entry" })).toHaveCount(0);
    for (const text of await rows(page).allTextContents()) expect(text).toMatch(/\d+ alarms?/);
  };
  await check();
  await page.reload();
  await expectChips(filters(page), ["Contains: Alarms", "Updated: This week"]);
  await check();
});

test("a saved view comes back after Clear all", async ({ page }) => {
  await page.goto("/cases?status=all&contains=findings");
  await expect(rows(page)).toHaveCount(4);
  await saveClearRestore(page, "Findings, any status", /\/cases$/);
  await expectChips(filters(page), ["Status: All statuses", "Contains: Compliance findings"]);
  await expect(rows(page)).toHaveCount(4);
});

test("a hidden column stays hidden after a reload; Case and Title can't be hidden", async ({ page }) => {
  await page.goto("/cases");
  await hideColumnAcrossReload(page, table, rows, "Hosts", ["Case", "Title"]);
});

test("the summary counts what is ready to close, and the rows say which", async ({ page }) => {
  await page.goto("/cases");
  await expect(page.locator(".summary-line")).toHaveText("4 open · 4 investigating · 5 unassigned · 2 ready to close · closed cases hidden");
  await expect(rows(page).filter({ hasText: "Review the new Windows baseline" })).toContainText("Ready to close");
  await expect(rows(page).filter({ hasText: "Which hosts still run the old openssl?" })).toContainText("Ready to close");
  const shells = rows(page).filter({ hasText: "Web servers starting shells" });
  await expect(shells).not.toContainText("Ready to close");
  await expect(shells.getByRole("progressbar", { name: "0 of 2 with an outcome" })).toBeVisible();
  await expect(shells).toContainText("0/2 with an outcome");
});

test("the title is a real link to the case's page, which links back", async ({ page }) => {
  await page.goto("/cases?q=C-104");
  // The link names the case for screen readers too ("C-104 Web servers…").
  const link = rows(page).getByRole("link", { name: /^C-104 Web servers starting shells/ });
  await expect(link).toHaveAttribute("href", /^\/cases\/[0-9a-f-]+$/);
  await link.click();
  await expect(page).toHaveURL(/\/cases\/[0-9a-f-]+$/);
  await expect(page.getByRole("heading", { level: 1 })).toContainText("C-104");
  await page.getByRole("link", { name: "Cases", exact: true }).first().click();
  await expect(page).toHaveURL(/\/cases$/);
  await expect(rows(page)).toHaveCount(8);
});

test("New case is a link to /cases/new, and the new case opens on its page", async ({ page }) => {
  await page.goto("/cases");
  const add = page.getByRole("link", { name: "New case" });
  await expect(add).toHaveAttribute("href", "/cases/new");
  await add.click();
  await page.getByLabel("Title").fill("Looked at by hand");
  await page.getByRole("button", { name: "Open case" }).click();
  await expect(page.locator(".toast")).toContainText("Opened C-111");
  await expect(page).toHaveURL(/\/cases\/[0-9a-f-]+$/);
  await expect(page.getByRole("heading", { level: 1 })).toContainText("C-111");
});

test("old_case_urls_keep_their_meaning: old filters and views saved in this browser come over", async ({ page }) => {
  await page.evaluate(() => {
    localStorage.setItem("openvibes.v2.views./cases", JSON.stringify([{ name: "Old unassigned", query: "assignee=none&status=all&sort=title" }]));
  });
  await page.goto("/cases?assignee=none&severity=critical");
  await expect(page).toHaveURL(/\/cases\?assignee=unassigned&severity=critical$/);
  await expectChips(filters(page), ["Assignee: Unassigned", "Severity: Critical"]);
  await page.goto("/cases");
  await page.getByRole("group", { name: "Saved views" }).getByRole("button", { name: "Old unassigned", exact: true }).click();
  await expectChips(filters(page), ["Status: All statuses", "Assignee: Unassigned"]);
  await expect(page).not.toHaveURL(/sort=/);
  expect(await page.evaluate(() => localStorage.getItem("openvibes.v2.views./cases"))).toBeNull();
});

test("axe finds nothing on the list, filtered or not", async ({ page }) => {
  await page.goto("/cases");
  await expect(rows(page).first()).toBeVisible();
  await expectNoAxeViolations(page);
  await page.goto("/cases?status=all&contains=alarms");
  await expect(rows(page).first()).toBeVisible();
  await expectNoAxeViolations(page);
});
