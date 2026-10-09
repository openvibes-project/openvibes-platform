import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

test("a finding explains one host and opens its original rule", async ({ page }) => {
  await page.goto("/compliance");
  const row = page.locator(".view tbody tr").filter({ hasText: "Redis (tcp 6379)" });
  await row.locator("td").nth(1).click();
  const panel = page.locator(".inspector");
  await panel.getByRole("button", { name: "View evidence", exact: true }).first().click();
  await expect(panel.getByText("Complete list of 2 values", { exact: false })).toBeVisible();
  await expect(panel.locator(".detection-verdict")).toContainText("Matched 1 of 1 condition");
  await panel.getByRole("button", { name: "Show rule" }).click();
  await expect(panel.locator(".detection-code code").first()).toHaveText("'6379' in facts['port.tcp.exposed']");
  await expect(panel.locator(".detection-steps")).toBeVisible();
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
});

test("an alarm opens the historical rule and evidence at a narrow width", async ({ page }) => {
  await page.goto("/alarms");
  const row = page.locator(".view tbody tr").filter({ hasText: "A database server started a shell" });
  await row.locator("td").nth(1).click();
  const panel = page.locator(".inspector");
  await panel.getByRole("button", { name: "Show rule" }).click();
  await expect(panel.locator(".detection-code code").first()).toContainText('/usr/bin/postgres');
  await expect(panel.locator(".detection-inputs")).toContainText('/usr/bin/bash');
  await page.setViewportSize({ width: 390, height: 844 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBeTruthy();
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
});

test("the host Select filters, picks a host and its evidence opens", async ({ page }) => {
  await page.goto("/compliance");
  await page.locator(".view tbody tr").filter({ hasText: "SSH (tcp 22)" }).locator("td").nth(1).click();
  const panel = page.locator(".inspector");
  await panel.getByRole("combobox", { name: "Host", exact: true }).click();
  await panel.getByRole("textbox", { name: "Filter Host" }).fill("db-01");
  await expect(panel.getByRole("option")).toHaveCount(1);
  expect((await new AxeBuilder({ page }).include(".inspector").analyze()).violations).toEqual([]);
  await panel.getByRole("option").click();
  await expect(panel.getByRole("combobox", { name: "Host", exact: true })).toContainText("db-01");
  await expect(panel.getByText("Why it triggered")).toBeVisible();
});

test("the host Select opens by keyboard, never clipped at 390 px", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/compliance");
  await page.locator(".view tbody tr").filter({ hasText: "SSH (tcp 22)" }).locator("td").nth(1).click();
  const host = page.locator(".inspector").getByRole("combobox", { name: "Host", exact: true });
  await host.focus();
  await page.keyboard.press("ArrowDown");
  const popup = page.locator(".sel__popup");
  await expect(host).toHaveAttribute("aria-expanded", "true");
  const box = await popup.boundingBox();
  expect(box?.x ?? -1).toBeGreaterThanOrEqual(0);
  expect((box?.x ?? 999) + (box?.width ?? 999)).toBeLessThanOrEqual(390);
  await page.keyboard.press("Escape");
  await expect(popup).toHaveCount(0);
  await expect(host).toBeFocused();
  await page.keyboard.press("ArrowDown");
  await page.keyboard.press("Enter");
  await expect(popup).toHaveCount(0);
  await expect(host).not.toContainText("Choose a host");
});
