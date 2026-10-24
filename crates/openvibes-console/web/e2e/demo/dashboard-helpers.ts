// Helpers shared by dashboards.spec.ts and dashboard-editors.spec.ts.
import { type Page, expect } from "@playwright/test";

// Duplicate lives in the dashboard menu only (#252: no "Duplicate to edit" button).
export async function duplicate(page: Page) {
  await page.getByRole("button", { name: "Dashboard menu" }).click();
  await page.getByRole("menuitem", { name: "Duplicate" }).click();
}

export async function openHome(page: Page) {
  await page.goto("/");
  await expect(page.getByRole("heading", { level: 1 })).toContainText("Alex");
  await page.mouse.move(900, 500);
}

export async function newWidget(page: Page, name: RegExp) {
  await page.getByRole("button", { name: "Dashboards" }).click();
  await page.getByRole("menuitem", { name: "New dashboard" }).click();
  await page.getByRole("button", { name }).click();
  return page.locator(".inspector");
}
