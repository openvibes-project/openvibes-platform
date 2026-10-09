import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

test.beforeEach(async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { level: 1 })).toContainText("Alex");
  await page.mouse.move(900, 500);
});

test("overview lists what needs attention and opens it beside the page", async ({ page }) => {
  const first = page.locator(".attention__row").first();
  await expect(first).toBeVisible();
  await first.click();
  await expect(page.locator(".inspector")).toBeVisible();
  await expect(page).toHaveURL(/open=/);
  await page.goBack();
  await expect(page.locator(".inspector")).toHaveCount(0);
});

test("a finding opens in the inspector, links stack, and Esc goes back", async ({ page }) => {
  await page.getByRole("link", { name: "Compliance", exact: true }).click();
  await page.locator(".view tbody tr").first().locator("td").nth(1).click();
  await expect(page.locator(".panel-header__kind")).toContainText("Compliance finding");
  await page.locator(".inspector tbody a").first().click();
  await expect(page.locator(".panel-header__kind")).toContainText("Host");
  await expect(page.locator(".crumbs__item")).toHaveCount(2);
  await page.keyboard.press("Escape");
  await expect(page.locator(".panel-header__kind")).toContainText("Compliance finding");
});

test("a finding's hosts show their assignee and accepted-risk expiry", async ({ page }) => {
  await page.goto("/compliance?open=finding%3Abaseline%2Fport.ssh.exposed");
  const hosts = page.locator(".inspector tbody tr");
  await expect(hosts.filter({ hasText: "cache-04.prod.example.test" })).toContainText("analyst");
  await expect(hosts.filter({ hasText: "backup-02.lab.example.test" })).toContainText(/until /);
});

test("a host whose match ended shows when it was fixed", async ({ page }) => {
  await page.goto("/compliance?open=finding%3Abaseline%2Fport.smb.exposed");
  await expect(page.locator(".inspector tbody tr").filter({ hasText: "files-03.office.example.test" })).toContainText(/fixed /);
});

test("the palette finds a host and opens it", async ({ page }) => {
  await page.keyboard.press("Control+k");
  await page.getByRole("combobox", { name: "Search" }).fill("web-01");
  await page.keyboard.press("Enter");
  await expect(page.locator(".panel-header__kind")).toContainText("Host");
  await expect(page.locator(".panel-header__title")).toContainText("web-01");
});

test("a panel pops out into a window and docks back", async ({ page }) => {
  await page.goto("/compliance");
  await page.locator(".view tbody tr").first().locator("td").nth(1).click();
  await page.getByRole("button", { name: "Open in a window" }).click();
  await expect(page.locator(".window")).toBeVisible();
  await expect(page.locator(".inspector")).toHaveCount(0);
  await page.getByRole("button", { name: "Back into the details pane" }).click();
  await expect(page.locator(".window")).toHaveCount(0);
  await expect(page.locator(".inspector")).toBeVisible();
});

test("the assistant answers with citations that open objects", async ({ page }) => {
  await page.keyboard.press("Control+j");
  await page.getByRole("button", { name: "Which hosts are stale?" }).click();
  const cite = page.locator(".cite").first();
  await expect(cite).toBeVisible();
  await cite.click();
  await expect(page.locator(".panel-header__kind")).toContainText("Host");
  await expect(page.locator(".assistant")).toBeVisible();
});

test("a viewer does not see administration", async ({ page }) => {
  await page.getByRole("button", { name: "Account" }).click();
  await page.getByRole("menuitemradio", { name: "viewer" }).click();
  await expect(page.getByRole("link", { name: "Audit log" })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Assistant" })).toHaveCount(0);
  await page.getByRole("button", { name: "Account" }).click();
  await page.getByRole("menuitemradio", { name: "admin" }).click();
});

for (const scheme of ["light", "dark"] as const) for (const path of ["/", "/compliance?open=finding%3Abaseline%2Fport.ssh.exposed", "/vulnerabilities?open=advisory%3AFEDORA-2026-3a214d1f", "/agents?open=agent%3Aagent-00005", "/audit"]) {
  test(`no accessibility violations on ${path} (${scheme})`, async ({ page }) => {
    await page.emulateMedia({ colorScheme: scheme });
    await page.goto(path);
    await page.mouse.move(900, 500);
    await expect(page.locator(".view")).toBeVisible();
    await page.waitForTimeout(400);
    const result = await new AxeBuilder({ page }).analyze();
    expect(result.violations.flatMap((v) => v.nodes.map((n) => `${v.id}: ${n.target.join(" ")} ${n.any[0]?.message ?? ""}`))).toEqual([]);
  });
}

test("a service account is created and issues a token shown once", async ({ page }) => {
  await page.goto("/service-accounts");
  await page.getByRole("button", { name: "New account" }).click();
  await page.getByLabel("Name").fill("Backup job");
  await page.getByRole("button", { name: "Create account" }).click();
  await expect(page.locator(".panel-header__title")).toContainText("Backup job");
  await page.getByLabel("Token label").fill("nightly");
  await page.getByRole("button", { name: "Issue" }).click();
  await expect(page.locator(".secret")).toContainText("ovst_demo_");
});

test("revoking a service token asks first (board #85)", async ({ page }) => {
  await page.goto("/service-accounts");
  await page.getByRole("button", { name: "New account" }).click();
  await page.getByLabel("Name").fill("Report job");
  await page.getByRole("button", { name: "Create account" }).click();
  await page.getByLabel("Token label").fill("weekly");
  await page.getByRole("button", { name: "Issue" }).click();
  const row = page.locator(".inspector tbody tr").filter({ hasText: "weekly" });
  await row.getByRole("button", { name: "Revoke" }).click();
  await expect(row).toContainText("Revoke weekly? Whatever uses it stops working at once.");
  await expect(row).toContainText("Active");
  await row.getByRole("button", { name: "Confirm" }).click();
  await expect(row).toContainText("Revoked");
});

test("audit retention changes from its panel", async ({ page }) => {
  await page.goto("/audit");
  await page.getByRole("button", { name: /Kept 365 days/ }).click();
  await page.getByLabel("Keep audit events for (days)").fill("400");
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("button", { name: /Kept 400 days/ })).toBeVisible();
});

test("an asset group is created from the access view", async ({ page }) => {
  await page.goto("/access");
  await page.getByRole("button", { name: "New group" }).click();
  await page.getByLabel("Name").fill("Web servers");
  await page.getByLabel("Selectors (one key=value per line)").fill("role=web");
  await page.getByRole("button", { name: "Create group" }).click();
  await expect(page.locator(".panel-header__title")).toContainText("Web servers");
  await expect(page.locator(".group-card", { hasText: "Web servers" })).toBeVisible();
});

test("a finding set to Investigating stays in the default Findings list (board #83)", async ({ page }) => {
  await page.goto("/compliance?open=finding%3Abaseline%2Fport.docker_api.exposed");
  const inspector = page.locator(".inspector");
  await inspector.getByRole("group", { name: "Show hosts by triage state" }).getByRole("button", { name: /^Open/ }).click();
  await inspector.getByRole("checkbox", { name: "Select all hosts" }).check();
  await inspector.getByRole("combobox", { name: "New triage state" }).click();
  await page.getByRole("option", { name: "Investigating" }).click();
  await inspector.getByRole("button", { name: "Apply" }).click();
  await expect(inspector.getByRole("group", { name: "Show hosts by triage state" }).getByRole("button", { name: /^Open/ })).toHaveCount(0);
  // Not page.goto: the demo keeps its data in memory and a reload resets it.
  await page.keyboard.press("Escape");
  await page.getByRole("link", { name: "Compliance", exact: true }).click();
  await expect(page.locator(".view tbody tr").filter({ hasText: "The unencrypted Docker API" })).toBeVisible();
});

test("an administrator creates a user and sees the one-time password once (board #85)", async ({ page }) => {
  await page.goto("/access");
  await page.getByRole("button", { name: "New user" }).click();
  await page.getByLabel("Username").fill("jdoe");
  await page.getByLabel("Display name").fill("Jane Doe");
  await page.getByRole("button", { name: "Create user" }).click();
  await expect(page.locator(".secret")).toContainText("demo1-pass2-word3-onlyx");
  await expect(page.getByText("It is shown only once")).toBeVisible();
  await page.getByRole("button", { name: "Done" }).click();
  await expect(page.locator(".view tbody tr").filter({ hasText: "jdoe" })).toBeVisible();
});

test("the Overview shows active alarms and lists them under Needs attention", async ({ page }) => {
  const tile = page.locator(".tile").filter({ hasText: "Active alarms" });
  await expect(tile).toBeVisible();
  await expect(page.locator(".attention__row").filter({ hasText: "Alarm ·" }).first()).toBeVisible();
  await tile.locator("button").click();
  await expect(page).toHaveURL(/\/alarms/);
});

// User, 2026-10-02: opening the rail made the page jump for a moment. The
// unpinned rail opens over the page, so the page's left edge must not move
// at any frame while it opens or closes.
const pageLeft = (page: import("@playwright/test").Page, ms: number) =>
  page.evaluate(
    (ms) =>
      new Promise<number[]>((done) => {
        const seen: number[] = [];
        const end = performance.now() + ms;
        const tick = () => {
          seen.push(document.querySelector(".app__main")?.getBoundingClientRect().left ?? Number.NaN);
          if (performance.now() < end) requestAnimationFrame(tick);
          else done(seen);
        };
        requestAnimationFrame(tick);
      }),
    ms,
  );

test("opening the rail over the page never moves the page", async ({ page }) => {
  const start = (await pageLeft(page, 0))[0] ?? Number.NaN;
  const opening = pageLeft(page, 700);
  await page.mouse.move(20, 300);
  const opened = await opening;
  expect(await page.locator(".rail").evaluate((rail) => rail.getBoundingClientRect().width)).toBeGreaterThan(200);
  const closing = pageLeft(page, 700);
  await page.mouse.move(900, 500);
  for (const left of [...opened, ...(await closing)]) expect(Math.abs(left - start)).toBeLessThan(0.5);
});

test("the menu shows counts beside Alarms, Compliance and Vulnerabilities (#117)", async ({ page }) => {
  for (const name of ["Alarms", "Compliance", "Vulnerabilities"]) {
    const item = page.locator(".rail .rail__item").filter({ hasText: name }).first();
    await expect(item.locator(".rail__count")).toHaveText(/^(\d{1,2}|99\+)$/);
  }
  await expect(page.locator(".rail .rail__item").filter({ hasText: "Alarms" }).first().locator(".rail__count--bad")).toBeVisible();
  await expect(page.locator(".rail .rail__item").filter({ hasText: "Software" }).first().locator(".rail__count")).toHaveCount(0);
});

test("Enrollment offers the install package and a CLI install command to copy (install walkthrough)", async ({ page }) => {
  await page.goto("/enrollment");
  const add = page.getByRole("region", { name: "Add a host" });
  await expect(add).toBeVisible();
  await expect(add.getByRole("button", { name: /Install package/ })).toBeVisible();
  const copy = add.getByRole("button", { name: "Copy CLI install" });
  await expect(copy).toBeEnabled();
  // The command is copied, not shown: the long line no longer fills the page.
  await expect(add.locator("pre")).toHaveCount(0);
  await expect(add).not.toContainText("curl -fsSL");
  await copy.click();
  await expect(page.getByText("Install command copied")).toBeVisible();
  await expect(add).toContainText("anyone with it can enroll a host");
});
