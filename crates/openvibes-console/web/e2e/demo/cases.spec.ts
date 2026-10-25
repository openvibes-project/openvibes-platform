import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

// Cases on the demo: the list, a case with its notes and outcomes, closing,
// and "Add to case" from an alarm. A row opens /cases/{id}, which shows the
// case panel's content as a page until screen 32 lands (step 5d task 7); the
// list itself: case-list.spec.ts. The demo keeps cases in memory (and in
// localStorage, fresh for each test), so each test starts from the seed.
test.beforeEach(async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { level: 1 })).toContainText("Alex");
});

test("the list opens a case on its page, where a note joins the timeline", async ({ page }) => {
  await page.getByRole("link", { name: "Cases", exact: true }).click();
  await expect(page.getByRole("heading", { level: 1, name: /Cases/ })).toBeVisible();
  const rows = page.getByRole("table", { name: "Cases" }).locator("tbody tr");
  // The seed's cases that are not closed (src/demo/caseSeed.ts).
  await expect(rows).toHaveCount(8);
  await expect(rows.filter({ hasText: "C-101" })).toHaveCount(0);
  await rows.filter({ hasText: "C-103" }).locator("td").nth(1).click();
  await expect(page).toHaveURL(/\/cases\/[0-9a-f-]+$/);
  const inspector = page.locator(".view");
  await expect(inspector.locator(".panel-header__kind")).toContainText("C-103");
  await expect(inspector.getByRole("list", { name: "Items" }).locator("li")).toHaveCount(3);
  await inspector.getByRole("textbox", { name: "Note" }).fill("Disabled password logins in the staging copy of sshd_config.");
  await inspector.getByRole("button", { name: "Add note" }).click();
  await expect(inspector.getByRole("list", { name: /Timeline/ }).locator("li").first()).toContainText("Disabled password logins");
  await expect(page.locator(".toast")).toContainText("Note added");
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
  // The item opens the alarm's page (screen 30), and the panels close.
  await inspector.getByRole("list", { name: "Items" }).getByRole("link", { name: "A database server started a shell" }).click();
  await expect(page).toHaveURL(/\/alarms\/\d+$/);
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("A database server started a shell");
  await expect(page.locator(".inspector")).toHaveCount(0);
});

test("a case closes only once every alarm has an outcome", async ({ page }) => {
  await page.goto("/cases");
  await page.getByRole("table", { name: "Cases" }).locator("tbody tr").filter({ hasText: "C-104" }).locator("td").nth(1).click();
  const inspector = page.locator(".view");
  await inspector.getByRole("button", { name: "Close case…" }).click();
  const closing = inspector.getByRole("group", { name: "Close this case" });
  await expect(closing).toContainText("2 items still need an outcome");
  await expect(closing.getByRole("button", { name: "Close case" })).toBeDisabled();
  // "Fixed" is not offered while the alarm is still happening.
  const items = inspector.getByRole("list", { name: "Items" }).locator("li");
  await items.first().getByRole("combobox", { name: /^Outcome for/ }).click();
  await expect(page.getByRole("option", { name: /^Fixed/ })).toHaveAttribute("aria-disabled", "true");
  await expect(page.getByRole("option", { name: /^Fixed/ })).toContainText("Only when the evidence is gone");
  await page.keyboard.press("Escape");
  for (let index = 0; index < 2; index += 1) {
    const item = items.nth(index);
    await item.getByRole("combobox", { name: /^Outcome for/ }).click();
    await page.getByRole("option", { name: "False positive" }).click();
    await item.getByRole("textbox", { name: /^Note for/ }).fill("Our health check script.");
    // The demo has no network; the outcome PUT body is unchanged by construction (CasePanel is untouched there).
    await item.getByRole("button", { name: "Save outcome" }).click();
    await expect(item.getByRole("button", { name: "Save outcome" })).toBeDisabled();
  }
  await expect(inspector.locator(".panel-header")).not.toContainText("unresolved");
  // Closing asks for a closing note only; the items say how it ended.
  await closing.getByLabel("Closing note").fill("Both are the same health check.");
  await closing.getByRole("button", { name: "Close case" }).click();
  await expect(inspector.locator(".panel-header")).toContainText("Closed");
  await expect(inspector.getByText("Both are the same health check.").first()).toBeVisible();
  await expect(inspector.getByRole("button", { name: "Reopen" })).toBeVisible();
  // Closed cases leave the default list.
  await inspector.getByRole("link", { name: "Cases", exact: true }).click();
  await expect(page.getByRole("table", { name: "Cases" }).locator("tbody tr")).toHaveCount(7);
  await page.getByRole("group", { name: "Filters" }).getByRole("combobox", { name: "Status" }).click();
  await page.getByRole("option", { name: /^All statuses/ }).click();
  await expect(page.getByRole("table", { name: "Cases" }).locator("tbody tr")).toHaveCount(10);
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
  await expect(page.locator(".panel-header__kind")).toContainText("C-111");
  await expect(page.locator(".inspector").getByRole("list", { name: "Items" })).toContainText("A shell downloaded a program and ran it");
  // A second case cannot take the same alarm; the refusal names the first.
  await page.getByRole("link", { name: "Cases", exact: true }).click();
  // The C-111 panel stays open beside the list (switching views keeps panels); the form is the page's.
  await page.getByRole("link", { name: "New case" }).click();
  await page.locator(".view").getByLabel("Title").fill("Another try");
  await page.locator(".view").getByRole("button", { name: "Open case" }).click();
  await expect(page.locator(".panel-header__kind")).toContainText("C-112");
  await page.locator(".view").getByRole("button", { name: "Add item" }).click();
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
