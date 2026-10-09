import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

// Writing the site's own rules on the demo: check as you type, save a draft,
// see its version rise, delete it.
test.beforeEach(async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { level: 1 })).toContainText("Alex");
});

test("a compliance rule is checked as you type, saved, changed and deleted", async ({ page }) => {
  await page.getByRole("link", { name: "Site rules" }).click();
  await expect(page.getByText("Rules saved here are drafts")).toBeVisible();
  await page.getByRole("button", { name: "New rule" }).first().click();
  const inspector = page.locator(".inspector");
  await inspector.getByLabel("Rule id").fill("port.redis.exposed");
  await inspector.getByLabel("Title").fill("Redis is exposed");
  await inspector.getByLabel("Expression").fill("'6379' in facts['port.tcp.exposed'] && (");
  await expect(inspector.getByRole("alert")).toContainText("not a valid expression");
  await expect(inspector.getByRole("button", { name: "Save draft" })).toBeDisabled();
  await inspector.getByLabel("Expression").fill("'6379' in facts['port.tcp.exposed']");
  await inspector.getByLabel("Compliance finding message").fill("Redis listens beyond loopback.");
  await expect(inspector.getByText("Hosts would accept this rule.")).toBeVisible();
  await inspector.getByRole("button", { name: "Save draft" }).click();
  const row = page.locator(".view tbody tr").filter({ hasText: "port.redis.exposed" });
  await expect(row).toContainText("1");

  await inspector.getByLabel("Confidence (0 to 100)").fill("70");
  await inspector.getByRole("button", { name: "Save draft" }).click();
  await expect(row.locator("td").nth(2)).toHaveText("2");
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);

  await inspector.getByRole("button", { name: "Delete", exact: true }).click();
  await inspector.getByRole("button", { name: "Confirm" }).click();
  await expect(row).toHaveCount(0);
});

test("an alarm rule needs a program", async ({ page }) => {
  await page.goto("/site-rules");
  await page.getByRole("button", { name: "New rule" }).nth(1).click();
  const inspector = page.locator(".inspector");
  await inspector.getByLabel("Rule id").fill("alarm.nginx.shell");
  await inspector.getByLabel("Title").fill("Nginx started a shell");
  await inspector.getByLabel("Expression").fill("event['process.name'] == 'sh'");
  await inspector.getByLabel("Alarm message").fill("A web server started a shell.");
  await expect(inspector.getByRole("alert")).toContainText("name one to 8");
  await inspector.getByLabel(/^Programs/).fill("nginx");
  await expect(inspector.getByText("Hosts would accept this rule.")).toBeVisible();
});

test("publishing a set asks for the password and shows what changes", async ({ page }) => {
  await page.goto("/site-rules");
  await page.getByRole("button", { name: "New rule" }).first().click();
  const inspector = page.locator(".inspector");
  await inspector.getByLabel("Rule id").fill("port.redis.exposed");
  await inspector.getByLabel("Title").fill("Redis is exposed");
  await inspector.getByLabel("Expression").fill("'6379' in facts['port.tcp.exposed']");
  await inspector.getByLabel("Compliance finding message").fill("Redis listens beyond loopback.");
  await inspector.getByRole("button", { name: "Save draft" }).click();
  const section = page.locator(".view-section").filter({ hasText: "Publish compliance rules" });
  await expect(section).toContainText("Added: port.redis.exposed");
  await expect(section.getByRole("button", { name: "Publish" })).toBeDisabled();
  await section.getByLabel("Your password, to sign").fill("correct horse");
  await section.getByRole("button", { name: "Publish" }).click();
  await expect(section).toContainText("Version 1 is published");
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
});

test("a rule is tested against a host", async ({ page }) => {
  await page.goto("/site-rules");
  await page.getByRole("button", { name: "New rule" }).first().click();
  const inspector = page.locator(".inspector");
  await inspector.getByLabel("Rule id").fill("port.https.exposed");
  await inspector.getByLabel("Title").fill("HTTPS is exposed");
  await inspector.getByLabel("Expression").fill("'443' in facts['port.tcp.exposed']");
  await inspector.getByLabel("Compliance finding message").fill("HTTPS listens beyond loopback.");
  await expect(inspector.getByText("Hosts would accept this rule.")).toBeVisible();
  await inspector.getByRole("button", { name: "Save draft" }).click();
  await expect(inspector.getByRole("button", { name: "Test", exact: true })).toBeDisabled();
  await inspector.getByRole("combobox", { name: "Host" }).click();
  await page.getByRole("option").nth(1).click();
  await inspector.getByRole("button", { name: "Test", exact: true }).click();
  await expect(inspector.getByRole("status")).toContainText("Matches: the rule would raise a compliance finding");
  await inspector.getByLabel("Expression").fill("'sshd' in facts['process.names']");
  await inspector.getByRole("button", { name: "Test", exact: true }).click();
  await expect(inspector.getByRole("status")).toContainText("Unavailable here");
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
});

test("the fleet view lists hosts without the site rule sets and the lines to paste", async ({ page }) => {
  await page.goto("/site-rules");
  const hosts = page.locator(".view-section").filter({ hasText: "Not in agent.toml" }).last();
  await expect(hosts.getByRole("heading", { name: "Hosts" })).toBeVisible();
  await expect(hosts).toContainText("not set up");
  await expect(hosts.getByText('id = "site-alarms"')).toBeVisible();
  await expect(hosts.getByRole("button", { name: "Copy the agent.toml lines" })).toBeVisible();
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
});
