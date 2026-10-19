import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

// Settings › Roles on the demo: a custom role from a template, on one host
// group. The demo server answers like the real one (share check, needs).
test.beforeEach(async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { level: 1 })).toContainText("Alex");
});

test("an administrator creates a role from the Analyst template on one host group", async ({ page }) => {
  await page.goto("/settings?tab=roles");
  const list = page.getByRole("table", { name: "Roles" }).locator("tbody tr");
  await expect(list.filter({ hasText: "Windows lead" })).toContainText("WindowsServers");
  await page.getByRole("button", { name: "New role" }).click();
  await expect(page.getByRole("heading", { level: 1, name: "New role" })).toBeVisible();
  await page.getByRole("textbox", { name: "Name" }).fill("Night shift");
  await page.getByRole("combobox", { name: "Start from" }).click();
  await page.getByRole("option", { name: /^Analyst template/ }).click();
  const matrix = page.getByRole("table", { name: "Permissions" });
  await expect(matrix.getByRole("button", { name: "Triage alarms", exact: true })).toHaveAttribute("aria-pressed", "true");
  // Analyst already has what Assign cases needs; publishing dashboards needs sharing them.
  await matrix.getByRole("button", { name: "Assign cases", exact: true }).click();
  await expect(matrix.getByRole("button", { name: "Assign cases", exact: true })).toHaveAttribute("aria-pressed", "true");
  await matrix.getByRole("button", { name: /^Publish dashboards to everyone/ }).click();
  await expect(page.locator(".role-page__notice")).toContainText("Also turned on: Share dashboards with your roles");
  await page.getByRole("searchbox", { name: "Search host groups" }).click();
  await page.getByRole("group", { name: "Host groups" }).getByRole("button", { name: "WindowsServers" }).click();
  // The list closes on a pick, so Create role is clickable straight away.
  await expect(page.getByRole("group", { name: "Host groups" })).toHaveCount(0);
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
  await page.getByRole("button", { name: "Create role" }).click();
  await expect(page.locator(".toast")).toContainText("Role created");
  const created = list.filter({ hasText: "Night shift" });
  await expect(created).toContainText("WindowsServers");
  // Columns: Role, Hosts, Permissions, People.
  await expect(created.locator("td").nth(2)).toHaveText("17");
});

test("a role name is taken whatever its case", async ({ page }) => {
  await page.goto("/settings/roles/new");
  await page.getByRole("textbox", { name: "Name" }).fill("windows LEAD");
  await page.getByRole("button", { name: "Create role" }).click();
  await expect(page.getByText("Another role has this name")).toBeVisible();
});
