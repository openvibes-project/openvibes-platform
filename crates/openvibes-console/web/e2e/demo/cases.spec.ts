import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

// Cases on the demo: the list, a case's page, closing, and "Add to case"
// from an alarm. A row opens /cases/{id} (screen 32; its actions:
// case-page.spec.ts); the list itself: case-list.spec.ts. The demo keeps cases in memory (and in
// localStorage, fresh for each test), so each test starts from the seed.
test.beforeEach(async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { level: 1 })).toContainText("Alex");
});

test("the list opens a case on its page, whose items open their own pages", async ({ page }) => {
  await page.getByRole("link", { name: "Cases", exact: true }).click();
  await expect(page.getByRole("heading", { level: 1, name: /Cases/ })).toBeVisible();
  const rows = page.getByRole("table", { name: "Cases" }).locator("tbody tr");
  // The seed's cases that are not closed (src/demo/caseSeed.ts).
  await expect(rows).toHaveCount(8);
  await expect(rows.filter({ hasText: "C-101" })).toHaveCount(0);
  await rows.filter({ hasText: "C-103" }).locator("td").nth(1).click();
  await expect(page).toHaveURL(/\/cases\/[0-9a-f-]+$/);
  await expect(page.getByRole("heading", { level: 1 })).toContainText("C-103");
  const items = page.getByRole("list", { name: "Items" });
  await expect(items.locator("li")).toHaveCount(3);
  // The item opens the alarm's page (screen 30), and no panel opens.
  await items.getByRole("link", { name: "A database server started a shell" }).click();
  await expect(page).toHaveURL(/\/alarms\/\d+$/);
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("A database server started a shell");
  await expect(page.locator(".inspector")).toHaveCount(0);
});

test("a closed case leaves the default list, and All statuses shows it", async ({ page }) => {
  await page.goto("/cases");
  await page.getByRole("table", { name: "Cases" }).locator("tbody tr").filter({ hasText: "C-109" }).locator("td").nth(1).click();
  // An empty case is ready to close.
  await page.locator(".person-page__actions").getByRole("button", { name: "Close case…" }).click();
  const closing = page.getByRole("dialog", { name: "Close C-109" });
  await closing.getByLabel("Closing note").fill("Reviewed; nothing to do.");
  await closing.getByRole("button", { name: "Close case" }).click();
  await expect(page.locator(".person-page__head")).toContainText("Closed");
  await page.getByRole("link", { name: "Cases", exact: true }).first().click();
  await expect(page.getByRole("table", { name: "Cases" }).locator("tbody tr")).toHaveCount(7);
  await page.getByRole("group", { name: "Filters" }).getByRole("combobox", { name: "Status" }).click();
  await page.getByRole("option", { name: /^All statuses/ }).click();
  const rows = page.getByRole("table", { name: "Cases" }).locator("tbody tr");
  await expect(rows).toHaveCount(10);
  // A case closed before step 5d still says how it ended.
  await expect(rows.filter({ hasText: "C-101" })).toContainText("Closed · mitigated");
});

test("Add to case from an alarm opens a case, and then points at it", async ({ page }) => {
  // An old panel link: it opens the alarm's page.
  await page.goto("/alarms?open=alarm%3A9002");
  await expect(page).toHaveURL(/\/alarms\/9002$/);
  // Once the evidence and history have loaded: the menu closes when its anchor moves.
  await expect(page.locator(".detection-verdict")).toBeVisible();
  await expect(page.getByText("No triage changes yet")).toBeVisible();
  const add = page.locator(".person-card").filter({ has: page.getByRole("heading", { name: "Details" }) }).getByRole("button", { name: "Add to case" });
  // Scrolled there first: a scroll right after the click would close the menu.
  await add.scrollIntoViewIfNeeded();
  await page.evaluate(() => new Promise((done) => requestAnimationFrame(() => requestAnimationFrame(done))));
  await add.click();
  const menu = page.getByRole("dialog", { name: /Add alarm to a case/ });
  await expect(menu.getByRole("button", { name: /C-103/ })).toBeVisible();
  await menu.getByRole("button", { name: "New case…" }).click();
  await menu.getByLabel("Title").fill("Download and run from a shell");
  await menu.getByRole("button", { name: "Open case" }).click();
  await expect(page.locator(".toast")).toContainText("Opened C-111");
  // The alarm is now in one open case: the menu says which and offers no other.
  await expect(menu).toContainText("Already in an open case");
  await expect(menu.getByRole("button", { name: "New case…" })).toHaveCount(0);
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
  await menu.getByRole("link", { name: /C-111/ }).click();
  await expect(page.getByRole("heading", { level: 1 })).toContainText("C-111");
  await expect(page.getByRole("list", { name: "Items" })).toContainText("A shell downloaded a program and ran it");
  // A second case cannot take the same alarm; the refusal names the first.
  await page.getByRole("link", { name: "Cases", exact: true }).first().click();
  await page.getByRole("link", { name: "New case" }).click();
  await page.getByLabel("Title").fill("Another try");
  await page.getByRole("button", { name: "Open case" }).click();
  await expect(page.getByRole("heading", { level: 1 })).toContainText("C-112");
  await page.getByRole("button", { name: "Add item" }).click();
  await page.getByLabel("Id").fill("9002");
  await page.getByRole("combobox", { name: "Kind" }).click();
  await page.getByRole("option", { name: "Alarm", exact: true }).click();
  await page.getByRole("button", { name: "Add", exact: true }).click();
  await expect(page.getByRole("alert")).toContainText("already in another open case: C-111");
});

test("an operator has no Cases, and an analyst manages them", async ({ page }) => {
  // The Operator template holds no cases permission; Viewer reads them.
  await page.getByRole("button", { name: "Account" }).click();
  await page.getByRole("menuitemradio", { name: "operator", exact: true }).click();
  await expect(page.getByRole("link", { name: "Cases", exact: true })).toHaveCount(0);
  await page.getByRole("button", { name: "Account" }).click();
  await page.getByRole("menuitemradio", { name: "analyst" }).click();
  await page.getByRole("link", { name: "Cases", exact: true }).click();
  await expect(page.getByRole("link", { name: "New case" })).toBeVisible();
});
