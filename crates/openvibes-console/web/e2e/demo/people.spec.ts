import AxeBuilder from "@axe-core/playwright";
import { expect, type Page, test } from "@playwright/test";

// Settings › People on the demo: a person's page, giving and removing a role,
// and your own page. The last-Administrator refusal is covered by
// people_http.rs and PersonPage.test.tsx.
test.beforeEach(async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { level: 1 })).toContainText("Alex");
});

/** "Night shift": the Analyst template on WindowsServers (roles.spec.ts makes it step by step). */
async function nightShift(page: Page) {
  await page.goto("/settings/roles/new");
  await page.getByRole("textbox", { name: "Name" }).fill("Night shift");
  await page.getByRole("combobox", { name: "Start from" }).click();
  await page.getByRole("option", { name: /^Analyst template/ }).click();
  await page.getByRole("searchbox", { name: "Search host groups" }).click();
  await page.getByRole("group", { name: "Host groups" }).getByRole("button", { name: "WindowsServers" }).click();
  await page.keyboard.press("Escape");
  await page.getByRole("button", { name: "Create role" }).click();
  await expect(page.locator(".toast")).toContainText("Role created");
}

test("an administrator gives a person a role on one group and takes it away", async ({ page }) => {
  await nightShift(page);
  // In-page navigation: a reload would start the demo afresh, without the new role.
  await page.getByRole("tab", { name: "People" }).click();
  await page.getByRole("table", { name: "People" }).locator("tbody tr").filter({ hasText: "Vic Viewer" }).locator("td").first().click();
  await expect(page.getByRole("heading", { level: 1, name: "Vic Viewer" })).toBeVisible();
  await expect(page.locator(".person-page__activity li").first()).toContainText("Revoked a host");
  await page.getByRole("button", { name: "Add role" }).click();
  await page.getByRole("group", { name: "Roles to add" }).getByRole("button", { name: /^Night shift/ }).click();
  await expect(page.locator(".toast").last()).toContainText("Role added");
  const scoped = page.locator(".person-access").filter({ hasText: "Only on WindowsServers" });
  await expect(scoped).toContainText("Triage alarms · from Night shift");
  // View alarms is held on all hosts through Viewer, so it is not repeated under the group.
  await expect(scoped).not.toContainText("View alarms");
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
  await page.locator(".person-role").filter({ hasText: "Night shift" }).getByRole("button", { name: "Remove" }).click();
  await expect(page.locator(".toast").last()).toContainText("Role removed");
  await expect(page.locator(".person-access").filter({ hasText: "Only on WindowsServers" })).toHaveCount(0);
});

test("on your own page Disable and Remove are not offered", async ({ page }) => {
  await page.goto("/settings?tab=people");
  await page.getByRole("table", { name: "People" }).locator("tbody tr").filter({ hasText: "Alex Admin" }).locator("td").first().click();
  await expect(page.getByRole("heading", { level: 1, name: "Alex Admin" })).toBeVisible();
  await expect(page.locator(".person-role").filter({ hasText: "Administrator" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Remove" })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Add role" })).toHaveCount(0);
  await expect(page.getByText("Nobody can change their own roles.")).toBeVisible();
  await expect(page.getByText("Disable user…")).toHaveCount(0);
});
