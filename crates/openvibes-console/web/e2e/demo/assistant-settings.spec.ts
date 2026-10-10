import { expect, test } from "@playwright/test";

test.beforeEach(async ({ page }) => { await page.goto("/assistant-settings"); });

test("level 1 is confirmed with its risk text, and level 2 needs level 1 and a URL", async ({ page }) => {
  const level1 = page.getByRole("switch", { name: "Look up security references" });
  const level2 = page.getByRole("switch", { name: "Search the web" });
  await expect(level1).not.toBeChecked();
  await expect(level2).toBeDisabled();
  await level1.click();
  const dialog = page.getByRole("dialog");
  await expect(dialog).toContainText("api.osv.dev");
  await expect(dialog).toContainText("No host data leaves your network");
  await dialog.getByRole("button", { name: "Turn on" }).click();
  await expect(level1).toBeChecked();
  await expect(level2).toBeEnabled();
  await level2.click();
  await expect(page.getByRole("dialog")).toContainText("SearXNG URL");
  await expect(page.getByRole("dialog").getByRole("button", { name: "Turn on" })).toBeDisabled();
});

test("a viewer does not see the page", async ({ page }) => {
  await page.getByRole("button", { name: "Account" }).click();
  await page.getByRole("menuitemradio", { name: "viewer" }).click();
  await expect(page.getByRole("link", { name: "Assistant" })).toHaveCount(0);
});

test("an unsaved domains edit survives a switch toggle and is saved with it", async ({ page }) => {
  const box = page.getByLabel("Internal domains (one per line)");
  await box.fill("Corp.Example\nintranet");
  await page.getByRole("switch", { name: "Look up security references" }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Turn on" }).click();
  await expect(page.getByRole("switch", { name: "Look up security references" })).toBeChecked();
  await expect(box).toHaveValue("corp.example\nintranet");
  await expect(page.getByRole("button", { name: "Save domains" })).toBeDisabled();
});

test("Test connection appears at level 2 and reports the result", async ({ page }) => {
  await page.getByRole("switch", { name: "Look up security references" }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Turn on" }).click();
  await page.getByRole("switch", { name: "Search the web" }).click();
  const dialog = page.getByRole("dialog");
  await dialog.getByLabel("SearXNG URL").fill("https://searx.corp.example");
  await dialog.getByRole("button", { name: "Turn on" }).click();
  await page.getByRole("button", { name: "Test connection" }).click();
  await expect(page.getByRole("status").filter({ hasText: "5 results" })).toBeVisible();
});
