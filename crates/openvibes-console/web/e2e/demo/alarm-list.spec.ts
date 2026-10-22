import AxeBuilder from "@axe-core/playwright";
import { type Page, expect, test } from "@playwright/test";

// The Alarms list on the demo (approved screen 29): the demo answers
// GET /api/v1/alarm-list like alarms/list.rs. The demo keeps its data in
// memory, so a test that changes alarms never reloads after the change.
const table = (page: Page) => page.getByRole("table", { name: "Alarms" });
const rows = (page: Page) => table(page).locator("tbody tr");
const filters = (page: Page) => page.getByRole("group", { name: "Filters" });
const choose = async (page: Page, filter: string, option: RegExp) => {
  await filters(page).getByRole("combobox", { name: filter }).click();
  await page.getByRole("option", { name: option }).click();
};

// The pointer off the rail, which opens while hovered and covers the first columns.
test.beforeEach(async ({ page }) => {
  await page.goto("/");
  await page.mouse.move(900, 500);
});

test("filters by Severity and Technique, and a reload keeps both", async ({ page }) => {
  await page.goto("/alarms");
  await expect(rows(page).first()).toBeVisible();
  await expect(page.locator(".summary-line")).toContainText(/\d+ open · \d+ critical or high · \d+ on hosts with alarms off/);
  await choose(page, "Severity", /^High/);
  await expect(filters(page)).toContainText("Severity: High");
  await choose(page, "Technique", /^T1505\.003/);
  await expect(filters(page)).toContainText("Technique: T1505.003");
  await expect(page).toHaveURL(/[?&]severity=high/);
  await expect(page).toHaveURL(/[?&]technique=T1505\.003/);
  const check = async () => {
    await expect(rows(page).first()).toBeVisible();
    for (const text of await rows(page).allTextContents()) {
      expect(text).toContain("A web server started a shell");
      expect(text).toContain("T1505.003");
    }
  };
  await check();
  await page.reload();
  await expect(filters(page)).toContainText("Severity: High");
  await expect(filters(page)).toContainText("Technique: T1505.003");
  await check();
});

test("a saved view comes back after Clear all", async ({ page }) => {
  await page.goto("/alarms?state=all&suppressed=shown");
  await expect(rows(page).filter({ hasText: "False positive" }).first()).toBeVisible();
  await page.getByRole("button", { name: "Save view" }).click();
  await page.getByRole("textbox", { name: "View name" }).fill("Everything");
  await page.keyboard.press("Enter");
  await expect(page.locator(".toast").last()).toContainText("View “Everything” saved");
  await page.getByRole("button", { name: "Clear all" }).click();
  await expect(page).toHaveURL(/\/alarms$/);
  await expect(rows(page).filter({ hasText: "False positive" })).toHaveCount(0);
  await page.getByRole("group", { name: "Saved views" }).getByRole("button", { name: "Everything", exact: true }).click();
  await expect(filters(page)).toContainText("State: All states");
  await expect(filters(page)).toContainText("Suppressed: Shown");
});

test("a hidden column stays hidden after a reload; Severity can't be hidden", async ({ page }) => {
  await page.goto("/alarms");
  await expect(table(page).getByRole("columnheader", { name: "Case" })).toBeVisible();
  await page.getByRole("button", { name: "Columns" }).click();
  await expect(page.getByRole("checkbox", { name: "Severity" })).toBeDisabled();
  await page.getByRole("checkbox", { name: "Case" }).uncheck();
  await expect(table(page).getByRole("columnheader", { name: "Case" })).toHaveCount(0);
  await page.reload();
  await expect(rows(page).first()).toBeVisible();
  await expect(table(page).getByRole("columnheader", { name: "Case" })).toHaveCount(0);
});

test("rows have no Suppress…; the bulk bar suppresses the selection, promising only this page", async ({ page }) => {
  await page.goto("/alarms");
  await expect(rows(page).first()).toBeVisible();
  await expect(table(page).getByRole("button", { name: /Suppress/ })).toHaveCount(0);
  await table(page).getByRole("checkbox", { name: "Select the rows on screen" }).check();
  await expect(page.locator(".select-all-bar")).toHaveText(/^All \d+ on this page are selected\.$/);
  await table(page).getByRole("checkbox", { name: "Select the rows on screen" }).uncheck();

  const row = rows(page).filter({ hasText: "A shell downloaded a program and ran it" }).first();
  await row.getByRole("checkbox", { name: "Select row" }).check();
  const bar = page.getByRole("region", { name: "Bulk actions" });
  await expect(bar).toContainText("1 selected");
  await bar.getByRole("button", { name: /^Set state/ }).click();
  await page.getByRole("menuitem", { name: /^Suppress…/ }).click();
  const dialog = page.getByRole("dialog", { name: "Suppress" });
  await dialog.getByRole("textbox", { name: "Why (required)" }).fill("admin's install script");
  await dialog.getByRole("button", { name: "Quiet 1 alarm" }).click();
  await expect(page.locator(".toast").last()).toContainText("1 changed");
  // Closed, it leaves the default (open) list, and the list refreshed without a reload.
  await expect(bar).toHaveCount(0);
  await choose(page, "State", /^False positive/);
  await choose(page, "Suppressed", /^Shown/);
  await expect(rows(page).filter({ hasText: "A shell downloaded a program and ran it" }).first()).toBeVisible();
});

test("the message is a real link to the alarm's page, which shows the alarm full width", async ({ page }) => {
  await page.goto("/alarms");
  const link = rows(page).filter({ hasText: "A database server started a shell" }).getByRole("link", { name: "A database server started a shell" });
  const href = await link.getAttribute("href");
  expect(href).toMatch(/^\/alarms\/\d+$/);
  await link.click();
  await expect(page).toHaveURL(new RegExp(`${href ?? ""}$`));
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("A database server started a shell");
  await expect(page.locator(".inspector")).toHaveCount(0);
  await page.locator(".person-page__crumb").getByRole("link", { name: "Alarms" }).click();
  await expect(page).toHaveURL(/\/alarms$/);
});

test("axe finds nothing on the list, filtered or not", async ({ page }) => {
  await page.goto("/alarms");
  await expect(rows(page).first()).toBeVisible();
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
  await page.goto("/alarms?state=all&suppressed=shown&severity=high");
  await expect(rows(page).first()).toBeVisible();
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
});

test("a re-sort empties the selection, and First seen sorts on the server", async ({ page }) => {
  await page.goto("/alarms");
  await rows(page).first().getByRole("checkbox", { name: "Select row" }).check();
  const bar = page.getByRole("region", { name: "Bulk actions" });
  await expect(bar).toContainText("1 selected");
  await table(page).getByRole("button", { name: "First seen" }).click();
  await expect(page).toHaveURL(/[?&]sort=first/);
  await expect(bar).toHaveCount(0);
  await expect(table(page).getByRole("checkbox", { name: "Select row", checked: true })).toHaveCount(0);
});

test("an old link and a view saved in this browser by the old list come over", async ({ page }) => {
  await page.evaluate(() => localStorage.setItem("openvibes.v2.views./alarms",
    JSON.stringify([{ name: "Old everything", query: "state=all&suppressed=true&sort=last&dir=asc" }])));
  await page.goto("/alarms?suppressed=true");
  await expect(page).toHaveURL(/[?&]suppressed=shown/);
  await expect(filters(page)).toContainText("Suppressed: Shown");
  await page.getByRole("group", { name: "Saved views" }).getByRole("button", { name: "Old everything", exact: true }).click();
  await expect(page).toHaveURL(/[?&]sort=seen/);
  await expect(filters(page)).toContainText("State: All states");
  expect(await page.evaluate(() => localStorage.getItem("openvibes.v2.views./alarms"))).toBeNull();
});
