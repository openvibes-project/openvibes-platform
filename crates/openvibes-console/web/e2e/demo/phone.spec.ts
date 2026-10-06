import AxeBuilder from "@axe-core/playwright";
import { type Locator, expect, test } from "@playwright/test";

// Board #55: the console on a 390px phone.
test.use({ viewport: { width: 390, height: 844 } });

async function box(locator: Locator) {
  const found = await locator.boundingBox();
  if (!found) throw new Error("not rendered");
  return found;
}

test("the bottom bar is labeled; the rest sit under More (board #85)", async ({ page }) => {
  await page.goto("/");
  const bar = page.locator(".rail");
  // The Investigate views and More, each with a visible label, all on screen.
  for (const [name, label] of [["Dashboards", "Home"], ["Compliance", "Compliance"], ["Alarms", "Alarms"], ["Vulnerabilities", "Vulns"], ["Hosts", "Hosts"], ["More", "More"]] as const) {
    const item = bar.getByRole(name === "More" ? "button" : "link", { name, exact: true });
    await expect(item).toBeInViewport({ ratio: 1 });
    await expect(item).toContainText(label);
  }
  await expect(bar.getByRole("link", { name: "Audit log" })).toBeHidden();
  await bar.getByRole("button", { name: "More" }).click();
  const menu = bar.getByRole("menu");
  for (const name of ["Software", "Enrollment", "Rule sets", "Access", "Service accounts", "Audit log"]) {
    await expect(menu.getByRole("menuitem", { name })).toBeInViewport({ ratio: 1 });
  }
  await menu.getByRole("menuitem", { name: "Audit log" }).click();
  await expect(page).toHaveURL(/\/audit/);
  await expect(menu).toBeHidden();
  await expect(bar.getByRole("button", { name: "More" })).toHaveAttribute("aria-current", "page");
});

test("at 320px every bar label fits its slot", async ({ page }) => {
  await page.setViewportSize({ width: 320, height: 640 });
  await page.goto("/");
  for (const label of await page.locator(".rail .rail__short").all()) {
    if (!(await label.isVisible())) continue;
    expect(await label.evaluate((el) => el.scrollWidth <= el.clientWidth)).toBe(true);
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
  // Someone looking for it is told why.
  await page.getByRole("button", { name: "Dashboard menu" }).click();
  // A menu item, so screen readers moving through the menu announce it.
  const note = page.getByRole("menuitem", { name: "Editing needs a wider screen" });
  await expect(note).toBeVisible();
  await expect(note).toHaveAttribute("aria-disabled", "true");
  const axe = await new AxeBuilder({ page }).include(".menu__pop").analyze();
  expect(axe.violations).toEqual([]);
});
