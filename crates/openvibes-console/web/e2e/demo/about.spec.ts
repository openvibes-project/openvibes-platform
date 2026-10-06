import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

test("About shows the versions and a newer release", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { level: 1 })).toContainText("Alex");
  await page.getByRole("link", { name: "About", exact: true }).click();
  await expect(page.getByRole("heading", { level: 1, name: "About" })).toBeVisible();
  await expect(page.locator(".view")).toContainText("0.4.2");
  await expect(page.locator(".view")).toContainText("v33");
  await expect(page.locator(".view")).toContainText("16.4");
  await expect(page.locator(".view")).toContainText("42 active, 39 reporting now");
  await expect(page.locator(".view")).toContainText("fedora-44-x86_64");
  await expect(page.getByText("Last check failed")).toBeVisible();
  await expect(page.getByText("Update available")).toBeVisible();
  await expect(page.getByRole("link", { name: "Release notes" })).toHaveAttribute("href", /releases\/tag\/v0\.4\.3$/);
  const results = await new AxeBuilder({ page }).analyze();
  expect(results.violations).toEqual([]);
});
