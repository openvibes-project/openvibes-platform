import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

// Cases on the demo: the list, a case with its notes and outcomes, closing,
// and "Add to case" from an alarm. The demo keeps cases in memory (and in
// localStorage, fresh for each test), so each test starts from the seed.
test.beforeEach(async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { level: 1 })).toContainText("Alex");
});

test("the list opens a case in the inspector, where a note joins the timeline", async ({ page }) => {
  await page.getByRole("link", { name: "Cases", exact: true }).click();
  await expect(page.getByRole("heading", { level: 1, name: /Cases/ })).toBeVisible();
  const rows = page.getByRole("table", { name: "Cases" }).locator("tbody tr");
  await expect(rows).toHaveCount(3);
  await expect(rows.filter({ hasText: "C-101" })).toHaveCount(0);
  await rows.filter({ hasText: "C-103" }).locator("td").nth(1).click();
  const inspector = page.locator(".inspector");
  await expect(inspector.locator(".panel-header__kind")).toContainText("C-103");
  await expect(inspector.getByRole("list", { name: "Items" }).locator("li")).toHaveCount(3);
  await inspector.getByRole("textbox", { name: "Note" }).fill("Disabled password logins in the staging copy of sshd_config.");
  await inspector.getByRole("button", { name: "Add note" }).click();
  await expect(inspector.getByRole("list", { name: /Timeline/ }).locator("li").first()).toContainText("Disabled password logins");
  await expect(page.locator(".toast")).toContainText("Note added");
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
  // The item opens its own panel on top.
  await inspector.getByRole("list", { name: "Items" }).getByRole("link", { name: "A database server started a shell" }).click();
  await expect(page.locator(".panel-header__kind")).toContainText("Alarm");
});

test("a case closes only once every alarm has an outcome", async ({ page }) => {
  await page.goto("/cases");
  await page.getByRole("table", { name: "Cases" }).locator("tbody tr").filter({ hasText: "C-104" }).locator("td").nth(1).click();
  const inspector = page.locator(".inspector");
  await inspector.getByRole("button", { name: "Close case…" }).click();
  const closing = inspector.getByRole("group", { name: "Close this case" });
  await expect(closing).toContainText("2 items still need an outcome");
  await expect(closing.getByRole("button", { name: "Close case" })).toBeDisabled();
  // "Resolved" is not offered while the alarm is still happening.
  const items = inspector.getByRole("list", { name: "Items" }).locator("li");
  await expect(items.first().locator("option", { hasText: "Resolved" })).toBeDisabled();
  for (let index = 0; index < 2; index += 1) {
    const item = items.nth(index);
    await item.getByRole("combobox", { name: /^Outcome for/ }).selectOption("false_positive");
    await item.getByRole("textbox", { name: /^Note for/ }).fill("Our health check script.");
    await item.getByRole("button", { name: "Save outcome" }).click();
    await expect(item.getByRole("button", { name: "Save outcome" })).toBeDisabled();
  }
  await expect(inspector.locator(".panel-header")).not.toContainText("unresolved");
  await closing.getByLabel("Resolution").selectOption("false_positive");
  await closing.getByLabel("Note").fill("Both are the same health check.");
  await closing.getByRole("button", { name: "Close case" }).click();
  await expect(inspector.locator(".panel-header")).toContainText("Closed · false positive");
  await expect(inspector.getByRole("button", { name: "Reopen" })).toBeVisible();
  // Closed cases leave the default list.
  await page.keyboard.press("Escape");
  await expect(page.getByRole("table", { name: "Cases" }).locator("tbody tr")).toHaveCount(2);
  await page.getByRole("button", { name: "Include closed" }).click();
  await expect(page.getByRole("table", { name: "Cases" }).locator("tbody tr")).toHaveCount(4);
});

test("Add to case from an alarm opens a case, and then points at it", async ({ page }) => {
  await page.goto("/alarms?open=alarm%3A9002");
  const inspector = page.locator(".inspector");
  await inspector.getByRole("button", { name: "Add to case" }).click();
  const menu = page.getByRole("dialog", { name: /Add alarm to a case/ });
  await expect(menu.getByRole("button", { name: /C-103/ })).toBeVisible();
  await menu.getByRole("button", { name: "New case…" }).click();
  await menu.getByLabel("Title").fill("Download and run from a shell");
  await menu.getByRole("button", { name: "Open case" }).click();
  await expect(page.locator(".toast")).toContainText("Opened C-105");
  // The alarm is now in one open case: the menu says which and offers no other.
  await expect(menu).toContainText("Already in an open case");
  await expect(menu.getByRole("button", { name: "New case…" })).toHaveCount(0);
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
  await menu.getByRole("link", { name: /C-105/ }).click();
  await expect(page.locator(".panel-header__kind")).toContainText("C-105");
  await expect(page.locator(".inspector").getByRole("list", { name: "Items" })).toContainText("A shell downloaded a program and ran it");
  // A second case cannot take the same alarm; the refusal names the first.
  await page.getByRole("link", { name: "Cases", exact: true }).click();
  await page.getByRole("button", { name: "New case" }).click();
  await page.getByLabel("Title").fill("Another try");
  await page.getByRole("button", { name: "Open case" }).click();
  await expect(page.locator(".panel-header__kind")).toContainText("C-106");
  await page.locator(".inspector").getByRole("button", { name: "Add item" }).click();
  await page.getByLabel("Id").fill("9002");
  await page.getByRole("combobox", { name: "Kind" }).selectOption("alarm");
  await page.getByRole("button", { name: "Add", exact: true }).click();
  await expect(page.getByRole("alert")).toContainText("already in another open case: C-105");
});

test("a viewer has no Cases, and an analyst manages them", async ({ page }) => {
  await page.getByRole("button", { name: "Account" }).click();
  await page.getByRole("menuitemradio", { name: "viewer" }).click();
  await expect(page.getByRole("link", { name: "Cases", exact: true })).toHaveCount(0);
  await page.getByRole("button", { name: "Account" }).click();
  await page.getByRole("menuitemradio", { name: "analyst" }).click();
  await page.getByRole("link", { name: "Cases", exact: true }).click();
  await expect(page.getByRole("button", { name: "New case" })).toBeVisible();
});
