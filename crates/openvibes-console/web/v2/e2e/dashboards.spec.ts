import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

test.beforeEach(async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { level: 1 })).toContainText("Alex");
  await page.mouse.move(900, 500);
});

test("home falls back to the built-in", async ({ page }) => {
  await expect(page.locator(".tile")).toHaveCount(9);
  await expect(page.getByRole("button", { name: "Duplicate to edit" })).toBeVisible();
});

test("a new dashboard gets a widget, is saved, and survives a reload", async ({ page }) => {
  await page.getByRole("button", { name: "Dashboards" }).click();
  await page.getByRole("menuitem", { name: "New dashboard" }).click();
  await page.getByRole("button", { name: /^Number/ }).click();
  await page.getByLabel("Count", { exact: true }).selectOption("agents.stale");
  await page.getByLabel("Dashboard name").fill("Stale watch");
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Stale watch");
  const url = page.url();
  await page.reload();
  await expect(page).toHaveURL(url);
  await expect(page.locator(".tile", { hasText: "Stale hosts" })).toBeVisible();
});

test("the built-in is duplicated to edit, a tile moves by keyboard, and it becomes home", async ({ page }) => {
  await page.getByRole("button", { name: "Duplicate to edit" }).click();
  await expect(page.getByLabel("Dashboard name")).toHaveValue("Copy of Overview");
  const tile = page.locator(".tile").first();
  const before = await tile.evaluate((el) => (el as HTMLElement).style.top);
  await tile.focus();
  await page.keyboard.press("ArrowDown");
  await expect.poll(async () => tile.evaluate((el) => (el as HTMLElement).style.top)).not.toBe(before);
  await page.getByRole("button", { name: "Save" }).click();
  await page.getByRole("button", { name: "Set as home" }).click();
  await page.goto("/");
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Copy of Overview");
});

test("asks before leaving unsaved edits", async ({ page }) => {
  await page.getByRole("button", { name: "Duplicate to edit" }).click();
  await page.getByLabel("Dashboard name").fill("Changed");
  let asked = false;
  page.once("dialog", (dialog) => { asked = true; void dialog.dismiss(); });
  await page.getByRole("link", { name: "Findings" }).click();
  expect(asked).toBe(true);
  await expect(page.getByLabel("Dashboard name")).toHaveValue("Changed");
});

test("an analyst sees the team dashboard read-only", async ({ page }) => {
  await page.getByRole("button", { name: "Account" }).click();
  await page.getByRole("menuitemradio", { name: "analyst" }).click();
  await page.getByRole("button", { name: "Dashboards" }).click();
  await page.getByRole("menuitemradio", { name: "Analyst triage" }).click();
  await expect(page.getByText("Shared by")).toBeVisible();
  await expect(page.getByRole("button", { name: "Edit", exact: true })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Duplicate to edit" })).toBeVisible();
});

test("an admin shares a dashboard with a role", async ({ page }) => {
  await page.getByRole("button", { name: "Dashboards" }).click();
  await page.getByRole("menuitemradio", { name: "My morning check" }).click();
  await page.getByRole("button", { name: "Dashboard menu" }).click();
  await page.getByRole("menuitemradio", { name: "analyst" }).click();
  await expect(page.locator("#main").getByText("Shared with analyst")).toBeVisible();
});

for (const scheme of ["light", "dark"] as const) {
  test(`no accessibility violations on a dashboard, viewing and editing (${scheme})`, async ({ page }) => {
    await page.emulateMedia({ colorScheme: scheme });
    await page.goto("/dashboards/d-admin-morning");
    await expect(page.locator(".tile").first()).toBeVisible();
    await page.waitForTimeout(400);
    expect((await new AxeBuilder({ page }).analyze()).violations.map((v) => v.id)).toEqual([]);
    await page.getByRole("button", { name: "Edit", exact: true }).click();
    await page.getByRole("button", { name: "Add widget" }).click();
    await page.waitForTimeout(300);
    expect((await new AxeBuilder({ page }).analyze()).violations.map((v) => v.id)).toEqual([]);
  });
}

test("New dashboard while editing keeps the draft when you choose to stay", async ({ page }) => {
  await page.getByRole("button", { name: "Duplicate to edit" }).click();
  await page.getByLabel("Dashboard name").fill("Changed");
  const url = page.url();
  page.once("dialog", (dialog) => void dialog.dismiss());
  await page.getByRole("button", { name: "Dashboards" }).click();
  await page.getByRole("menuitem", { name: "New dashboard" }).click();
  await expect(page.getByLabel("Dashboard name")).toHaveValue("Changed");
  expect(page.url()).toBe(url);
  await page.getByRole("button", { name: "Dashboards" }).click();
  await expect(page.getByRole("menuitemradio", { name: "Untitled dashboard" })).toHaveCount(0);
});

test("Back with unsaved edits asks first", async ({ page }) => {
  await page.getByRole("link", { name: "Findings" }).click();
  await page.getByRole("link", { name: "Dashboards" }).click();
  await page.getByRole("button", { name: "Duplicate to edit" }).click();
  await page.getByLabel("Dashboard name").fill("Changed");
  let asked = false;
  page.once("dialog", (dialog) => { asked = true; void dialog.dismiss(); });
  await page.goBack();
  await expect.poll(() => asked).toBe(true);
  await expect(page.getByLabel("Dashboard name")).toHaveValue("Changed");
});

test("a dashboard with a widget type this console does not know still renders", async ({ page }) => {
  await page.evaluate(() => {
    const layout = { schema: 1, widgets: [
      { id: "future", type: "future-widget", x: 0, y: 0, w: 4, h: 2, config: {} },
      { id: "stale", type: "number", x: 4, y: 0, w: 3, h: 2, config: { metric: "agents.stale" } },
    ] };
    const now = new Date().toISOString();
    localStorage.setItem("openvibes.v2.demo.dashboards", JSON.stringify({ rows: [
      { dashboard_id: "d-future", owner: "u-admin", name: "From a newer console", shared_role_id: null, layout, version: 1, created_at: now, updated_at: now },
    ], homes: [["u-admin", "d-future"]] }));
  });
  await page.goto("/");
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("From a newer console");
  await expect(page.locator(".tile", { hasText: "Unsupported widget" })).toBeVisible();
  await expect(page.locator(".tile", { hasText: "Stale hosts" })).toBeVisible();
  await expect(page.getByRole("link", { name: "Findings" })).toBeVisible();
});
