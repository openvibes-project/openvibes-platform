import AxeBuilder from "@axe-core/playwright";
import { type Page, expect, test } from "@playwright/test";

// A host's page (approved screen 17) on the demo: the demo answers
// GET /api/v1/hosts/{id}/summary like hosts/summary.rs. agent-00005 is
// vpn-01.office.example.test, Debian 12, online, with no open alarms.
const NAME = "vpn-01.office.example.test";
const heading = (page: Page) => page.getByRole("heading", { level: 1 });
const tiles = (page: Page) => page.locator(".detail-tiles");

test.beforeEach(async ({ page }) => {
  await page.goto("/");
  await expect(heading(page)).toContainText("Alex");
});

test("old_panel_links_open_the_page: an old host link lands on the page, and Back skips the dead URL", async ({ page }) => {
  await page.goto("/alarms");
  await expect(heading(page)).toHaveText("Alarms");
  await page.goto("/agents?open=agent%3Aagent-00005");
  await expect(page).toHaveURL(/\/hosts\/agent-00005$/);
  await expect(heading(page)).toContainText(NAME);
  await page.goBack();
  await expect(page).toHaveURL(/\/alarms$/);
  // An old host panel on another view is the page too, with no panels (a whole page).
  await page.goto("/compliance?open=agent%3Aagent-00005");
  await expect(page).toHaveURL(/\/hosts\/agent-00005$/);
  await page.goBack();
  await expect(page).toHaveURL(/\/alarms$/);
});

test("the header reads the host's facts and the tiles lead to the filtered lists; the host chip removes the filter", async ({ page }) => {
  await page.goto("/hosts/agent-00005");
  await expect(page.locator(".detail-page__facts")).toContainText("agent-00005 · Debian 12 · 192.168.20.5 · 0.4.2 ·");
  await expect(page.locator(".detail-page__facts")).toContainText("· enrolled ");
  await tiles(page).getByRole("link", { name: /^Vulnerabilities: \d+$/ }).click();
  await expect(page).toHaveURL(/\/vulnerabilities\?host=agent-00005$/);
  await expect(page.getByText(`Host: ${NAME}`)).toBeVisible();
  await page.goBack();
  await tiles(page).getByRole("link", { name: /^Open alarms: \d+$/ }).click();
  await expect(page).toHaveURL(/\/alarms\?host=agent-00005$/);
  await page.getByRole("button", { name: `Remove filter Host: ${NAME}` }).click();
  await expect(page).toHaveURL(/\/alarms$/);
  await expect(page.getByText(`Host: ${NAME}`)).toHaveCount(0);
  await page.goto("/hosts/agent-00005");
  await tiles(page).getByRole("link", { name: /^Compliance failing: \d+$/ }).click();
  // The host's failing checks (baseline ssh, plus the seeded hardening ones).
  await expect(page).toHaveURL(/\/compliance\?host=agent-00005$/);
  await expect(page.locator(".view tbody tr")).toHaveCount(3);
  await page.getByRole("button", { name: `Remove filter Host: ${NAME}` }).click();
  await expect(page).toHaveURL(/\/compliance$/);
});

test("a label is added and removed", async ({ page }) => {
  await page.goto("/hosts/agent-00005");
  const card = page.locator(".person-card").filter({ has: page.getByRole("heading", { name: "Groups and labels" }) });
  await expect(card.getByLabel("Groups")).toContainText("Pilot hosts");
  await card.getByRole("textbox", { name: "Add a label" }).fill("rack-c4");
  await card.getByRole("textbox", { name: "Add a label" }).press("Enter");
  await expect(card.getByLabel("Labels")).toContainText("rack-c4");
  await card.getByRole("button", { name: "Remove label rack-c4" }).click();
  await expect(card.getByLabel("Labels")).not.toContainText("rack-c4");
});

test("Revoke under ⋯ asks for a reason", async ({ page }) => {
  await page.goto("/hosts/agent-00005");
  await page.getByRole("button", { name: "More actions" }).click();
  await page.getByRole("menuitem", { name: /^Revoke…/ }).click();
  const dialog = page.getByRole("dialog", { name: `Revoke ${NAME}` });
  await expect(dialog.getByRole("button", { name: "Revoke", exact: true })).toBeDisabled();
  await dialog.getByRole("textbox", { name: "Reason (kept in the audit log)" }).fill("Decommissioned");
  await dialog.getByRole("button", { name: "Revoke", exact: true }).click();
  await expect(page.locator(".toast").last()).toContainText(`${NAME} revoked`);
  await expect(page.locator(".person-page__head")).toContainText("Revoked");
  // A revoked host takes no more labels and cannot be revoked again.
  await expect(page.getByRole("button", { name: "More actions" })).toHaveCount(0);
  await expect(page.getByRole("textbox", { name: "Add a label" })).toHaveCount(0);
});

test("a person without alarms.read sees no alarms tile or card", async ({ page }) => {
  await page.getByRole("button", { name: "Account" }).click();
  await page.getByRole("menuitemradio", { name: "rule author" }).click();
  await page.goto("/hosts/agent-00005");
  await expect(heading(page)).toContainText(NAME);
  await expect(tiles(page).getByRole("link", { name: /^Software: \d+$/ })).toBeVisible();
  await expect(tiles(page).getByRole("link", { name: /^Open alarms/ })).toHaveCount(0);
  await expect(page.getByRole("heading", { name: /^Open alarms/ })).toHaveCount(0);
  await expect(page.getByRole("heading", { name: /^Vulnerabilities/ })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "More actions" })).toHaveCount(0);
});

test("the software sub-page filters, and the ports and services pages are one click away", async ({ page }) => {
  await page.goto("/hosts/agent-00005");
  await tiles(page).getByRole("link", { name: /^Software: \d+$/ }).click();
  await expect(page).toHaveURL(/\/hosts\/agent-00005\/software$/);
  const list = page.getByRole("list", { name: "Installed software" });
  await expect(list.locator("li").filter({ hasText: "openssl" })).toBeVisible();
  await page.getByRole("textbox", { name: "Filter installed software" }).fill("sudo");
  await expect(list.locator("li")).toHaveCount(1);
  await page.getByRole("navigation", { name: "This host's lists" }).getByRole("link", { name: "Open ports" }).click();
  await expect(page.getByRole("table", { name: "Open ports" }).locator("tr").filter({ hasText: "22/tcp" })).toContainText("sshd.service");
  await page.getByRole("link", { name: NAME }).click();
  await expect(page).toHaveURL(/\/hosts\/agent-00005$/);
});

for (const scheme of ["light", "dark"] as const) {
  test(`the page and a sub-page pass axe (${scheme})`, async ({ page }) => {
    await page.emulateMedia({ colorScheme: scheme });
    for (const path of ["/hosts/agent-00005", "/hosts/agent-00005/services"]) {
      await page.goto(path);
      await expect(heading(page)).toContainText(path.endsWith("services") ? "Services" : NAME);
      await page.mouse.move(900, 500);
      await page.waitForTimeout(400);
      const result = await new AxeBuilder({ page }).analyze();
      expect(result.violations.flatMap((v) => v.nodes.map((n) => `${v.id}: ${n.target.join(" ")} ${n.any[0]?.message ?? ""}`))).toEqual([]);
    }
  });
}

test("a host silent for a day shows no failing count and no link to an empty list (roles 5c)", async ({ page }) => {
  // db-13 last reported days ago in the demo: the Compliance list's window (a day) holds nothing of it.
  await page.goto("/hosts/agent-00170");
  const tile = tiles(page).getByRole("group", { name: "Compliance failing: No report in the last day" });
  await expect(tile).toBeVisible();
  await expect(tiles(page).getByRole("link", { name: /^Compliance failing/ })).toHaveCount(0);
});
