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

test("the greeting sits above its buttons, not squeezed beside them", async ({ page }) => {
  await page.goto("/");
  const heading = page.getByRole("heading", { level: 1 });
  const buttons = page.getByRole("button", { name: "Dashboards" });
  const [h, b] = [await box(heading), await box(buttons)];
  expect(b.y).toBeGreaterThanOrEqual(h.y + h.height - 1);
  // One or two lines, not three.
  expect(h.height).toBeLessThan(70);
});

test("tile titles are not cut off", async ({ page }) => {
  await page.goto("/");
  const titles = page.locator(".tile__title");
  await expect(titles.first()).toBeVisible();
  for (const title of await titles.all()) {
    const cut = await title.evaluate((e) => e.scrollWidth > e.clientWidth);
    expect(cut, await title.textContent() ?? "").toBe(false);
  }
});

test("a phone offers no way into editing, which it cannot do", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("button", { name: "Dashboards" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Duplicate to edit" })).toBeHidden();
});
