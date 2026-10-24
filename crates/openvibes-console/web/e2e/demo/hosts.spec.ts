import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";
import type { Page } from "@playwright/test";

// The Hosts list on the demo (approved screen 16): the demo answers
// GET /api/v1/hosts like the real one (hosts/list.rs).
const rows = (page: Page) => page.getByRole("table", { name: "Hosts", exact: true }).locator("tbody tr");
const filters = (page: Page) => page.getByRole("group", { name: "Filters" });
const summary = (page: Page) => page.locator(".summary-line");
const optionText = async (page: Page, filter: string, option: RegExp) => {
  await filters(page).getByRole("combobox", { name: filter }).click();
  const text = await page.getByRole("option", { name: option }).textContent();
  await page.keyboard.press("Escape");
  return text;
};
const choose = async (page: Page, filter: string, option: RegExp) => {
  await filters(page).getByRole("combobox", { name: filter }).click();
  await page.getByRole("option", { name: option }).click();
};

test("filters by OS, then group: the counts follow, the URL holds both, and a reload keeps them", async ({ page }) => {
  await page.goto("/hosts");
  await expect(rows(page)).toHaveCount(50);
  const online = await optionText(page, "Status", /^Online/);
  const line = await summary(page).textContent();
  await choose(page, "OS", /^Linux/);
  await expect(filters(page)).toContainText("OS: Linux");
  await choose(page, "Group", /^Lab/);
  await expect(filters(page)).toContainText("Group: Lab");
  await expect(page).toHaveURL(/[?&]os=linux/);
  await expect(page).toHaveURL(/[?&]group=grp-lab/);
  await expect(summary(page)).not.toHaveText(line ?? "");
  expect(await optionText(page, "Status", /^Online/)).not.toBe(online);
  for (const host of await rows(page).locator("td:first-child").allTextContents()) expect(host).toContain(".lab.");
  await page.reload();
  await expect(filters(page)).toContainText("OS: Linux");
  await expect(filters(page)).toContainText("Group: Lab");
  for (const host of await rows(page).locator("td:first-child").allTextContents()) expect(host).toContain(".lab.");
});

test("a saved view comes back after Clear all", async ({ page }) => {
  await page.goto("/hosts?status=offline");
  await page.getByRole("button", { name: "Save view" }).click();
  await page.getByRole("textbox", { name: "View name" }).fill("Offline hosts");
  await page.keyboard.press("Enter");
  await expect(page.locator(".toast").last()).toContainText("View “Offline hosts” saved");
  await page.getByRole("button", { name: "Clear all" }).click();
  await expect(page).toHaveURL(/\/hosts$/);
  await expect(rows(page)).toHaveCount(50);
  await page.getByRole("group", { name: "Saved views" }).getByRole("button", { name: "Offline hosts", exact: true }).click();
  await expect(page).toHaveURL(/[?&]status=offline/);
  await expect(filters(page)).toContainText("Status: Offline");
});

test("a hidden column stays hidden after a reload", async ({ page }) => {
  await page.goto("/hosts");
  const table = page.getByRole("table", { name: "Hosts", exact: true });
  await expect(table.getByRole("columnheader", { name: "Labels" })).toBeVisible();
  await page.getByRole("button", { name: "Columns" }).click();
  await page.getByRole("checkbox", { name: "Labels" }).uncheck();
  await expect(table.getByRole("columnheader", { name: "Labels" })).toHaveCount(0);
  await page.reload();
  await expect(table.getByRole("columnheader", { name: "Groups" })).toBeVisible();
  await expect(table.getByRole("columnheader", { name: "Labels" })).toHaveCount(0);
});

test("pages to the second page and back", async ({ page }) => {
  await page.goto("/hosts");
  const first = await rows(page).first().textContent();
  const pager = page.getByRole("navigation", { name: "Pages" });
  await expect(pager).toContainText("1–50 of 186");
  await pager.getByRole("button", { name: "Next", exact: true }).click();
  await expect(pager).toContainText("51–100 of 186");
  await expect(page).toHaveURL(/[?&]offset=50/);
  await expect(rows(page).first()).not.toHaveText(first ?? "");
  // A filter starts again at the first page.
  await choose(page, "Status", /^Online/);
  await expect(page).not.toHaveURL(/offset=/);
  await expect(pager).toContainText(/^1–50 of/);
});

test("a filter is chosen from the keyboard, focus landing on its ×; Escape closes a menu", async ({ page }) => {
  await page.goto("/hosts");
  await expect(rows(page)).toHaveCount(50);
  const status = filters(page).getByRole("combobox", { name: "Status" });
  await status.focus();
  await page.keyboard.press("Enter");
  await expect(page.getByRole("listbox", { name: "Status" })).toBeVisible();
  await page.keyboard.press("ArrowDown");
  await page.keyboard.press("Enter");
  await expect(page).toHaveURL(/[?&]status=offline/);
  await expect(filters(page).getByRole("button", { name: "Remove filter Status: Offline" })).toBeFocused();
  const os = filters(page).getByRole("combobox", { name: "OS" });
  await os.focus();
  await page.keyboard.press("Enter");
  await expect(page.getByRole("listbox", { name: "OS" })).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(page.getByRole("listbox", { name: "OS" })).toHaveCount(0);
  await expect(os).toBeFocused();
  // × removes it again, from the keyboard too.
  await filters(page).getByRole("button", { name: "Remove filter Status: Offline" }).press("Enter");
  await expect(page).not.toHaveURL(/status=/);
});

test("a search typed just before leaving is not written onto the next page", async ({ page }) => {
  await page.goto("/alarms");
  await page.getByRole("link", { name: "Hosts", exact: true }).click();
  await expect(rows(page)).toHaveCount(50);
  await page.getByRole("searchbox", { name: "Search hosts" }).fill("web");
  await page.goBack();
  await expect(page).toHaveURL(/\/alarms$/);
  await page.waitForTimeout(400);
  await expect(page).toHaveURL(/\/alarms$/);
});

test("clicking a host opens its page, and old links land on the Hosts list or page", async ({ page }) => {
  await page.goto("/hosts?q=web-");
  await rows(page).first().locator("td").nth(1).click();
  await expect(page).toHaveURL(/\/hosts\/agent-\d{5}$/);
  await expect(page.getByRole("heading", { level: 1 })).toContainText("web-");
  await page.goto("/agents?status=stale&q=web");
  await expect(page).toHaveURL(/\/hosts\?status=offline&q=web$/);
  await expect(filters(page)).toContainText("Status: Offline");
  await page.goto("/agents?agent=agent-00005");
  await expect(page).toHaveURL(/\/hosts\/agent-00005$/);
  await expect(page.locator(".detail-page__facts")).toContainText("agent-00005");
});

test("the Hosts list passes axe, filtered and not", async ({ page }) => {
  await page.goto("/hosts");
  await expect(rows(page)).toHaveCount(50);
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
  await choose(page, "OS", /^Linux/);
  await page.getByRole("button", { name: "Columns" }).click();
  await expect(filters(page)).toContainText("OS: Linux");
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
});
