import AxeBuilder from "@axe-core/playwright";
import { type Page, expect, test } from "@playwright/test";

// Rule-set assignment on the demo: the approved screens
// (docs/specs/rule-set-assignment-ui/approved.md), by mouse and by keyboard.
test.beforeEach(async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { level: 1 })).toContainText("Alex");
});

const row = (page: Page, id: string) =>
  page.getByRole("table", { name: "Rule sets" }).locator("tbody tr").filter({ has: page.getByText(id, { exact: true }) });

test("the list says where each set runs, and L2 is not published", async ({ page }) => {
  await page.goto("/settings?tab=rule-sets");
  await expect(row(page, "baseline")).toContainText("All hosts");
  await expect(row(page, "baseline-alarms")).toContainText("Linux");
  await expect(row(page, "hardening-linux-l1")).toContainText("Linux · 1 group off");
  await expect(row(page, "hardening-linux-l2")).toContainText("Off");
  await expect(row(page, "hardening-linux-l2")).toContainText("Not published");
  await expect(row(page, "site")).toContainText("Hosts that trust its key");
});

test("L2 is switched on for Lab from the panel, by keyboard too", async ({ page }) => {
  await page.goto("/settings?tab=rule-sets&open=rule-set%3Ahardening-linux-l2");
  const inspector = page.locator(".inspector");
  await expect(inspector.getByText("Not available yet.")).toBeVisible();
  await expect(inspector.getByText("No group differs from the default.")).toBeVisible();
  await expect(inspector.getByText("Published versions")).toHaveCount(0);
  const addGroup = inspector.getByRole("button", { name: "+ Add group" });
  await addGroup.click();
  await expect(inspector.getByRole("combobox", { name: "Group" })).toBeFocused();
  // Esc cancels the row, keeps the panel open, and gives focus back.
  await page.keyboard.press("Escape");
  await expect(addGroup).toBeFocused();
  await expect(inspector.locator(".panel-header__title")).toHaveText("hardening-linux-l2");
  await page.keyboard.press("Enter");
  await inspector.getByRole("combobox", { name: "Group" }).click();
  await page.getByRole("option", { name: "Lab" }).click();
  await expect(inspector.getByRole("radio", { name: "On" })).toHaveAttribute("aria-checked", "true");
  expect((await new AxeBuilder({ page }).include(".inspector").analyze()).violations).toEqual([]);
  await inspector.getByRole("button", { name: "Add", exact: true }).click();
  await expect(page.locator(".toast").last()).toContainText("hardening-linux-l2 is now on for Lab");
  const lab = inspector.getByRole("table", { name: "Group overrides" }).locator("tbody tr").filter({ hasText: "Lab" });
  await expect(lab).toContainText("env=lab");
  const labSwitch = lab.getByRole("switch", { name: "Runs for Lab" });
  await expect(labSwitch).toHaveAttribute("aria-checked", "true");
  await expect(row(page, "hardening-linux-l2")).toContainText("Off · 1 group on");
  // The host follows: a Lab host waits until L2 is published.
  await page.goto("/agents?open=agent%3Aagent-00004");
  await page.getByRole("tab", { name: "Details" }).click();
  await expect(page.locator(".inspector dt", { hasText: "Hardening" }).locator("xpath=following-sibling::dd[1]")).toHaveText("L1 on · L2 on (Lab) · waits until published");
  // Space on the focused switch turns it off again.
  await page.goto("/settings?tab=rule-sets&open=rule-set%3Ahardening-linux-l2");
  await labSwitch.focus();
  await page.keyboard.press("Space");
  await expect(page.locator(".toast").last()).toContainText("hardening-linux-l2 is now off for Lab");
  await expect(labSwitch).toHaveAttribute("aria-checked", "false");
  await page.getByRole("link", { name: "Audit log" }).click();
  await expect(page.getByText("rules.assignment.change").first()).toBeVisible();
});

test("hosts: a group switched L1 off, one host pending, one without root facts", async ({ page }) => {
  await page.goto("/agents?open=agent%3Aagent-00003");
  await page.getByRole("tab", { name: "Details" }).click();
  const hardening = page.locator(".inspector dt", { hasText: "Hardening" }).locator("xpath=following-sibling::dd[1]");
  await expect(hardening).toHaveText("L1 off (Production) · L2 off");
  const l1 = page.getByRole("list", { name: "Rule sets on this host" }).locator("li").filter({ hasText: "hardening-linux-l1" });
  await expect(l1).toContainText("Not assigned");
  await expect(l1).toContainText("off for Production");
  await page.goto("/agents?open=agent%3Aagent-00040");
  await page.getByRole("tab", { name: "Details" }).click();
  await expect(hardening).toHaveText("L1 on · pending · L2 off");
  await page.goto("/agents?open=agent%3Aagent-00017");
  await page.getByRole("tab", { name: "Details" }).click();
  await expect(page.locator(".inspector").getByText("Hardening facts unavailable")).toBeVisible();
  await expect(page.locator(".inspector")).toContainText("has not reported for 3 days (openvibes-agent-facts.timer)");
  await page.goto("/agents?open=agent%3Aagent-00034");
  await page.getByRole("tab", { name: "Details" }).click();
  await expect(page.locator(".inspector")).toContainText("has not reported since enrollment (openvibes-agent-facts.timer)");
});

test("a viewer reads the rule list without its switches, an operator reads the rule list and changes switches", async ({ page }) => {
  // The Viewer template holds rules.read and rules.coverage.read, not rules.assignment.read.
  await page.getByRole("button", { name: "Account" }).click();
  await page.getByRole("menuitemradio", { name: "viewer" }).click();
  await expect(page.getByRole("link", { name: "Coverage" })).toBeVisible();
  await page.goto("/settings?tab=rule-sets&open=rule-set%3Ahardening-linux-l1");
  await expect(row(page, "hardening-linux-l1")).toBeVisible();
  await expect(page.getByRole("table", { name: "Rule sets" }).getByRole("columnheader", { name: "Runs on" })).toHaveCount(0);
  await expect(page.locator(".inspector").getByText("Published versions")).toBeVisible();
  await expect(page.locator(".inspector").getByRole("switch", { name: "On for Linux hosts by default" })).toHaveCount(0);
  await page.getByRole("button", { name: "Account" }).click();
  await page.getByRole("menuitemradio", { name: "operator", exact: true }).click();
  await expect(page.getByRole("link", { name: "Coverage" })).toBeVisible();
  await page.goto("/settings?tab=rule-sets&open=rule-set%3Ahardening-linux-l1");
  // rules.publish holders read the list, history and versions like an admin (user, 2026-10-15).
  await expect(row(page, "baseline")).toBeVisible();
  await expect(row(page, "hardening-linux-l1")).toContainText("openvibes-1");
  await expect(page.locator(".inspector").getByText("Published versions")).toBeVisible();
  const byDefault = page.locator(".inspector").getByRole("switch", { name: "On for Linux hosts by default" });
  await expect(byDefault).toBeEnabled();
  await byDefault.click();
  await expect(page.locator(".toast").last()).toContainText("hardening-linux-l1 is now off by default");
  await page.getByRole("button", { name: "Account" }).click();
  await page.getByRole("menuitemradio", { name: "admin" }).click();
});
