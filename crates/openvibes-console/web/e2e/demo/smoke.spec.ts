import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

test.beforeEach(async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { level: 1 })).toContainText("Alex");
  await page.mouse.move(900, 500);
});

test("overview lists what needs attention and each row opens its page", async ({ page }) => {
  // Every kind it lists is a page now (hosts, alarms, vulnerabilities, checks): no row opens a panel.
  await expect(page.locator(".attention__row").first()).toBeVisible();
  await expect(page.locator('.attention__row[href*="open="]')).toHaveCount(0);
  // A check (approved screen 28): its row goes to its page; Back returns.
  await page.locator('.attention__row[href^="/compliance/"]').first().click();
  await expect(page).toHaveURL(/\/compliance\/[^/?]+\/[^/?]+$/);
  await expect(page.locator(".detail-page h1")).toBeVisible();
  await page.goBack();
  // An alarm is a whole page (approved screen 30): its row goes there; Back returns.
  await page.locator('.attention__row[href^="/alarms/"]').first().click();
  await expect(page).toHaveURL(/\/alarms\/\d+$/);
  await expect(page.locator(".detail-page h1")).toBeVisible();
  await page.goBack();
  await expect(page.locator(".attention__row").first()).toBeVisible();
});

test("a check's page links its hosts, and Back returns to it", async ({ page }) => {
  await page.goto("/compliance/baseline/port.ssh.exposed");
  // A host is a whole page (approved screen 17): its link opens it; Back returns.
  await page.getByRole("table", { name: "Hosts", exact: true }).locator("tbody a").first().click();
  await expect(page).toHaveURL(/\/hosts\/agent-\d{5}$/);
  await expect(page.locator(".detail-page h1")).toBeVisible();
  await page.goBack();
  await expect(page).toHaveURL(/\/compliance\/baseline\/port\.ssh\.exposed$/);
});

test("a check's hosts show their assignee and accepted-risk expiry", async ({ page }) => {
  await page.goto("/compliance/baseline/port.ssh.exposed?segment=failing");
  const hosts = page.getByRole("table", { name: "Hosts", exact: true }).locator("tbody tr");
  await expect(hosts.filter({ hasText: "cache-04.prod.example.test" })).toContainText("Sam Analyst");
  await expect(hosts.filter({ hasText: "backup-02.lab.example.test" })).toContainText(/until /);
});

test("a host whose match ended passes again in the check's History", async ({ page }) => {
  // demo/checkSeed.ts: host 1's harden.kernel.aslr finding ended two days ago.
  await page.goto("/compliance/hardening-linux-l1/harden.kernel.aslr");
  await expect(page.locator(".person-card").filter({ has: page.getByRole("heading", { name: "History" }) })).toContainText(/\S+ passes again/);
});

test("the palette finds a host and opens it", async ({ page }) => {
  await page.keyboard.press("Control+k");
  await page.getByRole("combobox", { name: "Search" }).fill("web-01");
  await page.keyboard.press("Enter");
  await expect(page).toHaveURL(/\/hosts\/agent-\d{5}$/);
  await expect(page.getByRole("heading", { level: 1 })).toContainText("web-01");
});

test("a panel pops out into a window and docks back", async ({ page }) => {
  await page.goto("/ports?open=port%3Atcp%3A22");
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
  await expect(page).toHaveURL(/\/hosts\/agent-\d{5}$/);
  await expect(page.locator(".detail-page h1")).toBeVisible();
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

for (const scheme of ["light", "dark"] as const) for (const path of ["/", "/compliance/baseline/port.ssh.exposed", "/vulnerabilities/CVE-2026-10523", "/hosts", "/hosts/agent-00005", "/audit"]) {
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
  await page.goto("/settings?tab=service-accounts");
  // Roles are shown by name, never by id.
  await expect(page.getByRole("row", { name: /CI rule publisher/ })).toContainText("Operator (Prod)");
  await page.getByRole("button", { name: "New account" }).click();
  await page.getByLabel("Name").fill("Backup job");
  await expect(page.getByRole("button", { name: "Create account" })).toBeDisabled();
  await page.getByRole("combobox", { name: "Role" }).click();
  await page.getByRole("option", { name: "Viewer" }).click();
  await page.getByRole("button", { name: "Create account" }).click();
  await expect(page.locator(".panel-header__title")).toContainText("Backup job");
  await page.getByLabel("Token label").fill("nightly");
  await page.getByRole("button", { name: "Issue" }).click();
  await expect(page.locator(".secret")).toContainText("ovst_demo_");
});

test("revoking a service token asks first (board #85)", async ({ page }) => {
  await page.goto("/settings?tab=service-accounts");
  await page.getByRole("button", { name: "New account" }).click();
  await page.getByLabel("Name").fill("Report job");
  await expect(page.getByRole("button", { name: "Create account" })).toBeDisabled();
  await page.getByRole("combobox", { name: "Role" }).click();
  await page.getByRole("option", { name: "Viewer" }).click();
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

test("a host group is created from the Host groups tab", async ({ page }) => {
  await page.goto("/settings?tab=host-groups");
  await page.getByRole("button", { name: "New group" }).click();
  await page.getByRole("textbox", { name: "Name" }).fill("Web servers");
  await page.getByRole("combobox", { name: "Field of condition 1" }).click();
  await page.getByRole("option", { name: "Hostname", exact: true }).click();
  await page.getByRole("textbox", { name: "Values of condition 1" }).fill("web-*");
  await page.getByRole("textbox", { name: "Values of condition 1" }).press("Enter");
  await page.getByRole("button", { name: "Create group" }).click();
  await expect(page.getByRole("heading", { level: 1, name: "Web servers" })).toBeVisible();
  await expect(page.getByText("Hosts where hostname matches web-*")).toBeVisible();
});

test("a check mitigated on every open host leaves the default Compliance list (board #83)", async ({ page }) => {
  await page.goto("/compliance/baseline/port.docker_api.exposed");
  const actions = page.locator(".person-page__actions");
  // The header acts on every open failing host in one step; a close needs a note.
  await actions.getByRole("button", { name: /^Set state/ }).click();
  await page.getByRole("menuitem", { name: /^Mitigate/ }).click();
  const dialog = page.getByRole("dialog", { name: "Mitigate" });
  await dialog.getByRole("textbox", { name: "Why (required)" }).fill("firewalled at the edge");
  await dialog.getByRole("button", { name: /^Mitigate/ }).click();
  await expect(page.locator(".toast")).toContainText("changed");
  await expect(actions.getByRole("button", { name: /^Set state/ })).toHaveCount(0);
  // Not page.goto: the demo keeps its data in memory and a reload resets it.
  await page.locator(".person-page__crumb").getByRole("link", { name: "Compliance", exact: true }).click();
  await expect(page.locator(".view tbody tr").filter({ hasText: "port.docker_api.exposed" })).toHaveCount(0);
});

test("an administrator creates a user and sees the one-time password once (board #85)", async ({ page }) => {
  await page.goto("/settings?tab=people");
  await page.getByRole("button", { name: "New person" }).click();
  await page.getByLabel("Username").fill("jdoe");
  await page.getByLabel("Display name").fill("Jane Doe");
  await expect(page.getByRole("button", { name: "Create person" })).toBeDisabled();
  await page.getByRole("combobox", { name: "Role" }).click();
  await page.getByRole("option", { name: "Viewer" }).click();
  await page.getByRole("button", { name: "Create person" }).click();
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
  await page.goto("/settings?tab=enrollment");
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

// #257: a long context label is cut short; the send button stays in the dock.
test("a long assistant context keeps the send button in view", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto("/compliance/baseline/port.ssh.exposed");
  await page.getByRole("button", { name: "Ask about this" }).click();
  const dock = page.locator(".assistant");
  await expect(dock.locator(".context-chip")).toBeVisible();
  await page.evaluate(() => {
    const label = document.querySelector(".context-chip .truncate");
    if (label) label.textContent = `About ${"python3-docs-3.14.8-1.fc44 python3.14-3.14.8-1.fc44 ".repeat(3)}`;
  });
  const [box, send] = [await dock.boundingBox(), await dock.locator(".icon-button--send").boundingBox()];
  expect(send && box && send.x + send.width).toBeLessThanOrEqual((box?.x ?? 0) + (box?.width ?? 0));
  const form = await dock.locator(".assistant__form").boundingBox();
  expect(form?.width).toBeLessThanOrEqual((box?.width ?? 0) + 1);
});
