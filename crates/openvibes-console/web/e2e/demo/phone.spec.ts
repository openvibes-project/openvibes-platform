import { type Locator, expect, test } from "@playwright/test";

// Board #55: the console on a 390px phone.
test.use({ viewport: { width: 390, height: 844 } });

async function box(locator: Locator) {
  const found = await locator.boundingBox();
  if (!found) throw new Error("not rendered");
  return found;
}

test("every destination fits in the bottom bar, none hidden", async ({ page }) => {
  await page.goto("/");
  const items = page.locator(".rail a.rail__item"); // destinations; the pin is desktop-only
  await expect(items).toHaveCount(9);
  // The two that sat past the bar's edge before, found by their names.
  for (const name of ["Service accounts", "Audit log"]) {
    await expect(page.locator(".rail").getByRole("link", { name })).toBeInViewport({ ratio: 1 });
  }
  for (const item of await items.all()) {
    const { x, width } = await box(item);
    expect(x).toBeGreaterThanOrEqual(0);
    expect(x + width).toBeLessThanOrEqual(390);
  }
});

test("number tiles sit two to a row", async ({ page }) => {
  await page.goto("/");
  const tiles = page.locator(".tile[data-type=number]");
  await expect(tiles.first()).toBeVisible();
  const [a, b] = [await box(tiles.nth(0)), await box(tiles.nth(1))];
  expect(Math.abs(a.y - b.y)).toBeLessThan(2);
  expect(a.height).toBeLessThan(120);
});

test("an agent's host name wraps instead of being cut", async ({ page }) => {
  await page.goto("/agents");
  const host = page.locator("tbody tr").first().locator(".cell-two > span").first();
  await expect(host).toBeVisible();
  expect(await host.evaluate((e) => e.scrollWidth <= e.clientWidth)).toBe(true);
  // A name of ordinary length stays on one line.
  expect((await box(host)).height).toBeLessThan(24);
});
