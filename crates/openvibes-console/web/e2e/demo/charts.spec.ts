import { type Locator, expect, test } from "@playwright/test";

async function boxOf(locator: Locator) {
  const box = await locator.boundingBox();
  if (!box) throw new Error("not visible");
  return box;
}

test("graph hover shows the edge days and stays inside its tile", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { level: 1 })).toContainText("Alex");
  await page.getByRole("button", { name: "Dashboards" }).click();
  await page.getByRole("menuitem", { name: "New dashboard" }).click();
  await page.getByRole("button", { name: /^Graph/ }).click();
  await page.getByLabel("Period").selectOption("365");
  const chart = page.getByRole("img", { name: /Active alarms/ });
  await expect(chart).toBeVisible();
  const box = await boxOf(chart);
  await page.mouse.move(box.x + 1, box.y + box.height / 2);
  await expect(page.locator(".linechart__tip")).toContainText(/\d/);
  await expect(page.locator(".linechart__tip")).not.toContainText("Today");
  await page.mouse.move(box.x + box.width - 1, box.y + box.height / 2);
  await expect(page.locator(".linechart__tip")).toContainText("Today");
  const tip = await boxOf(page.locator(".linechart__tip"));
  const tile = await boxOf(chart.locator("xpath=ancestor::*[contains(@class,'tile')][1]"));
  expect(tip.x + tip.width).toBeLessThanOrEqual(tile.x + tile.width);
  expect(tip.x).toBeGreaterThanOrEqual(tile.x);
});
