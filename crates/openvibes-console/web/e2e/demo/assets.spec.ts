import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

// Assets v1 on the demo: the fleet Software view and a host's software.
test.beforeEach(async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { level: 1 })).toContainText("Alex");
});

test("software lists packages across hosts and opens the hosts that run one", async ({ page }) => {
  await page.getByRole("link", { name: "Software", exact: true }).click();
  const bash = page.locator(".view tbody tr").filter({ hasText: /^bash/ }).first();
  await expect(bash).toBeVisible();
  await page.getByPlaceholder("Filter by package name…").fill("nginx");
  const nginx = page.locator(".view tbody tr").filter({ hasText: "nginx" }).first();
  await nginx.locator("td").first().click();
  const inspector = page.locator(".inspector");
  await expect(inspector.locator(".panel-header__kind")).toContainText("Software");
  await expect(inspector.getByRole("heading", { name: "Versions in use" }).or(inspector.getByText("Versions in use"))).toBeVisible();
  await inspector.locator(".list a").first().click();
  await expect(inspector.locator(".panel-header__kind")).toContainText("Host");
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
});

test("a host page shows its installed software, filterable", async ({ page }) => {
  await page.getByRole("link", { name: "Hosts", exact: true }).click();
  await page.locator(".view tbody tr").first().locator("td").nth(1).click();
  const inspector = page.locator(".inspector");
  await expect(inspector.locator(".panel-header__kind")).toContainText("Host");
  await inspector.getByRole("tab", { name: "Software" }).click();
  const list = inspector.getByRole("list", { name: "Installed software" });
  await expect(list.locator("li").filter({ hasText: "openssl" })).toBeVisible();
  await inspector.getByRole("textbox", { name: "Filter installed software" }).fill("sudo");
  await expect(list.locator("li")).toHaveCount(1);
});
