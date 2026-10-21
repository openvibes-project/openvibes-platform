import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";
import type { Page } from "@playwright/test";

// Settings › Host groups on the demo (approved screens 9, 10, 10b, 10c, 17):
// the demo server answers like the real one (hosts/groups.rs, labels.rs).
const groups = (page: Page) => page.getByRole("table", { name: "Host groups" }).locator("tbody tr");
const openGroup = async (page: Page, name: string) => {
  await page.goto("/settings?tab=host-groups");
  await groups(page).filter({ hasText: name }).first().click();
  await expect(page.getByRole("heading", { level: 1, name })).toBeVisible();
};
const condition = async (page: Page, n: number, field: string, value: string) => {
  await page.getByRole("combobox", { name: `Field of condition ${n}` }).click();
  await page.getByRole("option", { name: field, exact: true }).click();
  const values = page.getByRole("textbox", { name: `Values of condition ${n}` });
  await values.fill(value);
  await values.press("Enter");
};

test("an administrator creates a rule group after seeing who joins", async ({ page }) => {
  await page.goto("/settings?tab=host-groups");
  await page.getByRole("button", { name: "New group" }).click();
  await expect(page.getByRole("heading", { level: 1, name: "New group" })).toBeVisible();
  await page.getByRole("textbox", { name: "Name" }).fill("Web at HQ");
  await condition(page, 1, "Hostname", "*web*");
  await page.getByRole("button", { name: "+ Add condition" }).click();
  await condition(page, 2, "IP address", "10.0.0.0/16");
  await expect(page.getByRole("status").filter({ hasText: "If you save" })).toContainText(/\+\d+ \(web-/);
  await page.getByRole("button", { name: "Create group" }).click();
  await expect(page.getByRole("heading", { level: 1, name: "Web at HQ" })).toBeVisible();
  await expect(page.getByRole("table").filter({ hasText: "Matches the rule" })).toContainText(/web-\d+\.prod/);
  await page.getByRole("link", { name: "Host groups" }).click();
  await expect(groups(page).filter({ hasText: "Web at HQ" })).toContainText("Hosts where hostname matches *web* and IP address is in 10.0.0.0/16");
});

test("an edited automatic group becomes a rule group", async ({ page }) => {
  await openGroup(page, "Debian 12");
  const head = page.locator(".person-page__head");
  await expect(head).toContainText("Automatic");
  await page.getByRole("button", { name: "Edit", exact: true }).click();
  await page.getByRole("textbox", { name: "Description" }).fill("Our Debian 12 hosts.");
  await page.getByRole("button", { name: "Save changes" }).click();
  await expect(page.locator(".toast")).toContainText("Saved");
  await expect(head).toContainText("Rule");
  await expect(head).not.toContainText("Automatic");
});

test("a group no role uses is deleted", async ({ page }) => {
  await openGroup(page, "Lab");
  await page.getByRole("button", { name: "More actions" }).click();
  await page.getByRole("menuitem", { name: "Delete group…" }).click();
  const dialog = page.getByRole("dialog", { name: "Delete group" });
  await expect(dialog.getByRole("status")).toContainText(/If you delete: −\d+/);
  await dialog.getByRole("button", { name: "Delete group", exact: true }).click();
  await expect(page.locator(".toast")).toContainText("Group deleted");
  await expect(groups(page).first()).toBeVisible();
  await expect(groups(page).filter({ hasText: /^Lab/ })).toHaveCount(0);
});

test("a group a role uses is refused, naming the role", async ({ page }) => {
  await openGroup(page, "WindowsServers");
  await page.getByRole("button", { name: "More actions" }).click();
  await page.getByRole("menuitem", { name: "Delete group…" }).click();
  const dialog = page.getByRole("dialog", { name: "Delete group" });
  await dialog.getByRole("button", { name: "Delete group", exact: true }).click();
  await expect(dialog.getByRole("alert")).toHaveText("Roles still use this group: Windows lead.");
});

test("a host's labels are added and removed", async ({ page }) => {
  await page.goto("/hosts/agent-00003");
  const card = page.locator(".person-card").filter({ has: page.getByRole("heading", { name: "Groups and labels" }) });
  await expect(card.getByLabel("Groups")).toContainText("Production");
  await card.getByRole("textbox", { name: "Add a label" }).fill("rack-c4");
  await card.getByRole("textbox", { name: "Add a label" }).press("Enter");
  await expect(card.getByLabel("Labels")).toContainText("rack-c4");
  await card.getByRole("button", { name: "Remove label rack-c4" }).click();
  await expect(card.getByLabel("Labels")).not.toContainText("rack-c4");
});

test("the group list and a group page pass axe", async ({ page }) => {
  await page.goto("/settings?tab=host-groups");
  await expect(groups(page).first()).toBeVisible();
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
  await openGroup(page, "Production");
  await expect(page.getByText("Picked by hand").first()).toBeVisible();
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
});
