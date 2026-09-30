// The shipped console against a real server: production CSP, no third-party
// requests, sign-in, every view, triage, dashboards shared between two people,
// and accessibility in both themes.
import AxeBuilder from "@axe-core/playwright";
import { type Page, expect, test } from "@playwright/test";

const PASSWORD = "e2e-console-Passw0rd!";
const origin = "https://127.0.0.1:18490";

declare global {
  interface Window { cspViolations?: string[] }
}

async function watch(page: Page) {
  const thirdParty: string[] = [];
  page.on("request", (request) => { if (!request.url().startsWith(origin) && !request.url().startsWith("data:")) thirdParty.push(request.url()); });
  await page.addInitScript(() => {
    window.cspViolations = [];
    document.addEventListener("securitypolicyviolation", (event) => window.cspViolations?.push(`${event.violatedDirective} ${event.blockedURI}`));
  });
  return {
    csp: () => page.evaluate(() => window.cspViolations ?? []),
    thirdParty,
  };
}

async function signIn(page: Page, username: string) {
  await page.goto("/");
  await page.getByLabel("Username").fill(username);
  await page.getByLabel("Password").fill(PASSWORD);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.locator(".view")).toBeVisible();
  await page.mouse.move(900, 600);
}

test("sign-in, every view, and no CSP violations or third-party requests", async ({ page }) => {
  const checks = await watch(page);
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
  await expect(page.getByText("Explore the demo")).toHaveCount(0);
  await expect(page.getByText("Demo data")).toHaveCount(0);
  await signIn(page, "alex");
  await expect(page.getByRole("heading", { level: 1 })).toContainText("Alex");
  for (const view of ["/findings", "/vulnerabilities", "/agents", "/enrollment", "/rule-sets", "/access", "/service-accounts", "/audit"]) {
    await page.goto(view);
    await expect(page.locator(".view")).toBeVisible();
    await expect(page.locator(".error-box")).toHaveCount(0);
  }
  expect(await checks.csp()).toEqual([]);
  expect(checks.thirdParty).toEqual([]);
});

test("/login shows home once signed in, and /assistant is gone", async ({ page }) => {
  await signIn(page, "alex");
  await page.goto("/login");
  await expect(page).toHaveURL(`${origin}/`);
  const response = await page.request.get("/assistant");
  expect(response.status()).toBe(404);
});

test("an empty service accounts view explains the next step", async ({ page }) => {
  await signIn(page, "alex");
  await page.goto("/service-accounts");
  await expect(page.getByText("No service accounts")).toBeVisible();
  await expect(page.getByText("Create one for integrations that need API access.")).toBeVisible();
});

test("Most exposed hosts says scanning is not set up before any feed imported", async ({ page }) => {
  // This platform never imported a vulnerability feed: "no vulnerable host"
  // would claim a scan that never ran (board #47).
  await signIn(page, "alex");
  const tile = page.locator(".tile", { hasText: "Most exposed hosts" });
  await expect(tile.getByText("Vulnerability scanning is not set up")).toBeVisible();
  await expect(tile.getByText("No host has an open vulnerability")).toHaveCount(0);
});

test("vulnerability number tiles show no zero before any feed imported", async ({ page }) => {
  // A 0 would claim nothing was found; nothing was looked for (board #47).
  await signIn(page, "alex");
  for (const title of ["Exploited", "Hosts needing a reboot"]) {
    const tile = page.locator(".tile", { hasText: title });
    await expect(tile.locator(".stat__value")).toHaveText("—");
    const note = tile.getByText("Not set up");
    await expect(note).toBeVisible();
    // Inside the tile, not cut off by its fixed height.
    const bottom = async (l: typeof tile) => { const b = await l.boundingBox(); if (!b) throw new Error("not rendered"); return b.y + b.height; };
    expect(await bottom(note)).toBeLessThanOrEqual(await bottom(tile));
  }
});

test("an Access filter with no matches explains the empty list", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.emulateMedia({ colorScheme: "light" });
  await signIn(page, "alex");
  await page.goto("/access?q=no-such-person");
  await expect(page.getByText("Nothing matches these filters")).toBeVisible();
  await expect(page.getByText("Clear a filter to see more.")).toBeVisible();
});

test("an Audit filter with no matches explains the empty list", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.emulateMedia({ colorScheme: "dark" });
  await signIn(page, "alex");
  await page.goto("/audit?q=no-such-action");
  await expect(page.getByText("Nothing matches these filters")).toBeVisible();
  await expect(page.getByText("Clear a filter to see more.")).toBeVisible();
});

test("imported findings are triaged in bulk from the panel", async ({ page }, info) => {
  await signIn(page, "alex");
  await page.goto("/findings");
  await page.locator(".view tbody tr").first().locator("td").nth(1).click();
  await expect(page.locator(".panel-header__kind")).toContainText("Finding");
  // Hosts that can all move to investigating: the open ones, else those already there.
  await page.getByRole("group", { name: "Show hosts by triage state" }).getByRole("button", { name: /^(Open|Investigating) \d/ }).first().click();
  await page.getByRole("checkbox", { name: "Select all hosts" }).check();
  await page.getByLabel("New triage state").selectOption("investigating");
  await page.getByLabel("Triage note").fill(`e2e ${info.project.name}`);
  await page.locator(".bulk-bar button[type=submit]").click();
  await expect(page.locator(".toast")).toContainText("set to investigating");
});

test("one host's risk is accepted until a date with an assignee, and the form shows it again", async ({ page }) => {
  await signIn(page, "alex");
  await page.goto("/findings");
  await page.locator(".view tbody tr").first().locator("td").nth(1).click();
  await expect(page.locator(".panel-header__kind")).toContainText("Finding");
  await page.getByRole("group", { name: "Show hosts by triage state" }).getByRole("button", { name: /^(Open|Investigating) \d/ }).first().click();
  const label = await page.locator(".inspector tbody input[type=checkbox]").first().getAttribute("aria-label");
  await page.getByRole("group", { name: "Show hosts by triage state" }).getByRole("button", { name: /^All \d/ }).click();
  const host = page.getByRole("checkbox", { name: label ?? "", exact: true });
  await host.check();
  // The workflow: an open host is investigated before its risk is accepted.
  await expect(page.getByLabel("New triage state")).toBeEnabled();
  if (await page.getByLabel("New triage state").inputValue() === "open") {
    await expect(page.getByLabel("New triage state").locator("option")).toHaveText(["Open", "Investigating"]);
    await page.getByLabel("New triage state").selectOption("investigating");
    await page.locator(".bulk-bar button[type=submit]").click();
    await expect(page.locator(".toast").last()).toContainText("set to investigating");
    await host.check();
    await expect(page.getByLabel("New triage state")).toHaveValue("investigating");
  }
  await page.getByLabel("New triage state").selectOption("accepted_risk");
  await page.getByLabel("Accepted until").fill("2099-06-30");
  await page.getByLabel("Assignee").fill("nobody");
  await page.getByLabel("Triage note").fill("vendor fix due");
  await page.locator(".bulk-bar button[type=submit]").click();
  await expect(page.locator(".toast").last()).toContainText("Assignee must be an enabled analyst or admin");
  await page.getByLabel("Assignee").fill("sam");
  await page.locator(".bulk-bar button[type=submit]").click();
  await expect(page.locator(".toast").last()).toContainText("set to accepted risk");
  await host.check();
  await expect(page.getByLabel("New triage state")).toHaveValue("accepted_risk");
  await expect(page.getByLabel("Assignee")).toHaveValue("sam");
  await expect(page.getByLabel("Accepted until")).toHaveValue("2099-06-30");
});

test("a dashboard is created, saved, shared and seen read-only by an analyst", async ({ page, browser }, info) => {
  const name = `Team board ${info.project.name}`;
  const checks = await watch(page);
  await signIn(page, "alex");
  await page.getByRole("button", { name: "Dashboards" }).click();
  await page.getByRole("menuitem", { name: "New dashboard" }).click();
  await page.getByRole("button", { name: /^Number/ }).click();
  await page.getByLabel("Count", { exact: true }).selectOption("findings.open.critical");
  await page.getByLabel("Dashboard name").fill(name);
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText(name);
  await page.getByRole("button", { name: "Dashboard menu" }).click();
  await page.getByRole("menuitemradio", { name: "analyst" }).click();
  await expect(page.locator("#main").getByText("Shared with analyst")).toBeVisible();
  const url = page.url();
  await page.reload();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText(name);
  expect(await checks.csp()).toEqual([]);

  const sam = await browser.newPage();
  await signIn(sam, "sam");
  await sam.goto(url);
  await expect(sam.getByRole("heading", { level: 1 })).toHaveText(name);
  await expect(sam.getByText("Shared by Alex Admin")).toBeVisible();
  await expect(sam.getByRole("button", { name: "Edit", exact: true })).toHaveCount(0);
  await sam.close();
});

for (const scheme of ["light", "dark"] as const) {
  test(`no accessibility violations when signed in (${scheme})`, async ({ page }) => {
    await page.emulateMedia({ colorScheme: scheme });
    await signIn(page, "alex");
    for (const path of ["/", "/findings", "/audit"]) {
      await page.goto(path);
      await expect(page.locator(".view")).toBeVisible();
      await page.waitForTimeout(500);
      const result = await new AxeBuilder({ page }).analyze();
      expect(result.violations.flatMap((v) => v.nodes.map((n) => `${path} ${v.id}: ${n.target.join(" ")}`))).toEqual([]);
    }
  });
}
