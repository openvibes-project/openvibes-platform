import AxeBuilder from "@axe-core/playwright";
import { expect, type Page, test } from "@playwright/test";

declare global {
  interface Window {
    openvibesCspViolations?: string[];
  }
}

/**
 * Records every CSP violation, report-only included, from the page's own
 * `securitypolicyviolation` events. Console text differs between browsers
 * (Firefox writes "Content-Security-Policy"), so it is not scraped.
 */
async function recordCspViolations(page: Page): Promise<() => Promise<string[]>> {
  await page.addInitScript(() => {
    window.openvibesCspViolations = [];
    document.addEventListener("securitypolicyviolation", (event) => {
      window.openvibesCspViolations?.push(`${event.effectiveDirective} ${event.blockedURI}`);
    });
  });
  return () => page.evaluate(() => window.openvibesCspViolations ?? []);
}

async function selectDemoOption(page: Page, label: string, value: string): Promise<void> {
  await Promise.all([
    page.waitForNavigation(),
    page.getByLabel(label).selectOption(value),
  ]);
}

async function mockAuthenticatedSession(page: Page): Promise<void> {
  await page.route("**/api/v1/session", (route) => route.fulfill({
    status: 200,
    contentType: "application/json",
    body: JSON.stringify({
      principal: { id: "test-user", display_name: "Test Operator" },
      authentication_method: "local_password",
      authentication_level: "single_factor",
      capabilities: [
        { permission: "agents.read", scope: { kind: "global" } },
        { permission: "findings.read", scope: { kind: "global" } },
      ],
      csrf_token: "c".repeat(43),
      idle_expires_at: "2026-09-24T23:59:00Z",
      absolute_expires_at: "2026-09-25T07:29:00Z",
    }),
  }));
}

const targetCsp = [
  "default-src 'none'",
  "script-src 'self'",
  "script-src-attr 'none'",
  "style-src 'self'",
  "style-src-attr 'none'",
  "img-src 'self'",
  "connect-src 'self'",
  "form-action 'self'",
  "base-uri 'none'",
  "object-src 'none'",
  "frame-ancestors 'none'",
  "manifest-src 'self'",
];

test("serves the accessible shell with the target security boundary", async ({ page }) => {
  const cspViolations = await recordCspViolations(page);
  const thirdPartyRequests: string[] = [];
  page.on("request", (request) => {
    const url = new URL(request.url());
    if ((url.protocol === "http:" || url.protocol === "https:") && url.origin !== "http://127.0.0.1:18490") {
      thirdPartyRequests.push(url.origin);
    }
  });
  await mockAuthenticatedSession(page);

  const response = await page.goto("/");
  expect(response?.status()).toBe(200);
  const headers = response?.headers() ?? {};
  const csp = headers["content-security-policy"] ?? "";
  for (const directive of targetCsp) {
    expect(csp).toContain(directive);
  }
  expect(csp).not.toContain("'unsafe-inline'");
  expect(csp).not.toContain("'unsafe-eval'");
  expect(headers["x-content-type-options"]).toBe("nosniff");
  expect(headers["referrer-policy"]).toBe("no-referrer");

  await expect(page.getByRole("heading", { level: 1, name: "Overview" })).toBeVisible();
  await expect(page.getByRole("navigation", { name: "Console" })).toBeVisible();
  await expect(page.getByLabel("Theme")).toHaveValue("system");
  const brandImages = page.getByRole("link", { name: "OpenVIBES Console home" }).locator("img");
  expect(await brandImages.count()).toBe(2);
  for (let index = 0; index < (await brandImages.count()); index += 1) {
    await expect(brandImages.nth(index)).toHaveJSProperty("complete", true);
    expect(
      await brandImages.nth(index).evaluate((image) => (image as HTMLImageElement).naturalWidth),
    ).toBeGreaterThan(0);
  }

  const accessibility = await new AxeBuilder({ page }).analyze();
  expect(accessibility.violations).toEqual([]);
  expect(await cspViolations()).toEqual([]);
  expect(thirdPartyRequests).toEqual([]);
});

test("serves the local sign-in page and obtains one-use pre-auth state", async ({ page }) => {
  await page.route("**/auth/v1/preauth", (route) => route.fulfill({
    status: 200,
    contentType: "application/json",
    body: JSON.stringify({ csrf_token: "p".repeat(43), expires_at: "2026-09-24T23:59:00Z" }),
  }));

  const response = await page.goto("/login");
  expect(response?.status()).toBe(200);
  await expect(page.getByRole("heading", { level: 1, name: "Sign in" })).toBeVisible();
  await expect(page.getByLabel("Username")).toBeEnabled();
  await expect(page.getByLabel("Password")).toBeEnabled();
  await expect(page.getByRole("button", { name: "Sign in" })).toBeEnabled();
  const accessibility = await new AxeBuilder({ page }).analyze();
  expect(accessibility.violations).toEqual([]);
});

test("gates the workspace when there is no authenticated session", async ({ page }) => {
  await page.route("**/api/v1/session", (route) => route.fulfill({
    status: 401,
    contentType: "application/problem+json",
    body: JSON.stringify({
      type: "about:blank",
      title: "Authentication required",
      status: 401,
      code: "authentication_required",
      request_id: "test-request",
    }),
  }));

  await page.goto("/");
  await expect(page.getByRole("heading", { level: 1, name: "Your session" })).toBeVisible();
  await expect(page.getByRole("link", { name: "Sign in" })).toHaveAttribute("href", "/login");
});

test("completes the browser login, session check, and sign-out journey", async ({ page }) => {
  const preauthToken = "p".repeat(43);
  const sessionToken = "s".repeat(43);
  await page.route("**/auth/v1/preauth", (route) => route.fulfill({
    status: 200,
    contentType: "application/json",
    body: JSON.stringify({ csrf_token: preauthToken, expires_at: "2026-09-24T23:59:00Z" }),
  }));
  await page.route("**/auth/v1/login", async (route) => {
    expect(route.request().headers()["x-csrf-token"]).toBe(preauthToken);
    expect(JSON.parse(route.request().postData() ?? "{}")).toEqual({
      username: "alice",
      password: "violet-satellite-mountain-otter-2026",
    });
    await route.fulfill({ status: 200, contentType: "application/json", body: "{}" });
  });
  await page.route("**/api/v1/session", (route) => route.fulfill({
    status: 200,
    contentType: "application/json",
    body: JSON.stringify({
      principal: { id: "test-user", display_name: "Test Operator" },
      authentication_method: "local_password",
      authentication_level: "single_factor",
      capabilities: [
        { permission: "agents.read", scope: { kind: "global" } },
        { permission: "findings.read", scope: { kind: "global" } },
      ],
      csrf_token: sessionToken,
      idle_expires_at: "2026-09-24T23:59:00Z",
      absolute_expires_at: "2026-09-25T07:29:00Z",
    }),
  }));
  await page.route("**/api/v1/agents/summary", (route) => {
    expect(route.request().headers()).not.toHaveProperty("x-openvibes-dev-persona");
    return route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ total: 12, active: 10, stale: 2, revoked: 0 }),
    });
  });
  await page.route("**/api/v1/findings/summary", (route) => {
    expect(route.request().headers()).not.toHaveProperty("x-openvibes-dev-persona");
    return route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ total: 4, impacted_agents: 3, critical: 1, high: 2, medium: 1, low: 0 }),
    });
  });
  await page.route("**/auth/v1/logout", async (route) => {
    expect(route.request().headers()["x-csrf-token"]).toBe(sessionToken);
    await route.fulfill({ status: 204 });
  });

  await page.goto("/login");
  await page.getByLabel("Username").fill("alice");
  await page.getByLabel("Password").fill("violet-satellite-mountain-otter-2026");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page).toHaveURL("/");
  await expect(page.getByRole("heading", { level: 1, name: "Overview" })).toBeVisible();
  await expect(page.getByText("Enrolled")).toBeVisible();
  await expect(page.getByText("12", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Sign out" }).click();
  await expect(page).toHaveURL("/login");
  await expect(page.getByRole("heading", { level: 1, name: "Sign in" })).toBeVisible();
});

test("applies and persists an explicit theme before application startup", async ({ page }) => {
  await mockAuthenticatedSession(page);
  await page.addInitScript(() => {
    if (localStorage.getItem("openvibes.theme") === null) {
      localStorage.setItem("openvibes.theme", "dark");
    }
  });
  await page.goto("/findings", { waitUntil: "domcontentloaded" });

  await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
  await expect(page.locator('meta[name="theme-color"]')).toHaveAttribute("content", "#11171d");
  await expect(page.getByLabel("Theme")).toHaveValue("dark");

  await page.getByLabel("Theme").selectOption("light");
  await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
  await page.reload();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
  await expect(page.locator('meta[name="theme-color"]')).toHaveAttribute("content", "#f5f4f0");
});

test("keeps reserved route families out of SPA fallback", async ({ request }) => {
  const api = await request.get("/api/v1/not-a-route");
  expect(api.status()).toBe(404);
  expect(api.headers()["content-type"]).toContain("application/problem+json");
  expect((await api.json()).code).toBe("api_not_found");

  const auth = await request.get("/auth/not-a-route");
  expect(auth.status()).toBe(404);
  expect((await auth.json()).code).toBe("auth_not_found");

  const asset = await request.get("/assets/not-a-route.js");
  expect(asset.status()).toBe(404);
  expect(await asset.text()).toBe("");

  const health = await request.get("/health");
  expect(health.status()).toBe(404);
});

test("supports keyboard entry and the compact-navigation control", async ({ page }) => {
  await mockAuthenticatedSession(page);
  await page.goto("/");
  await expect(page.getByRole("heading", { level: 1, name: "Overview" })).toBeVisible();
  await page.keyboard.press("Tab");
  await expect(page.getByRole("link", { name: "Skip to main content" })).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(page.locator("#main-content")).toBeFocused();

  const collapse = page.getByRole("button", { name: "Collapse primary navigation" });
  await collapse.click();
  await expect(page.getByRole("button", { name: "Expand primary navigation" })).toHaveAttribute(
    "aria-pressed",
    "true",
  );
  await expect(page.getByRole("link", { name: "OpenVIBES Console home" }).locator("img")).toHaveAttribute(
    "src",
    "/brand/openvibes-mark.svg",
  );
});

test("keeps native menu, dialog, and combobox primitives keyboard accessible", async ({ page }) => {
  const cspViolations = await recordCspViolations(page);

  await mockAuthenticatedSession(page);
  await page.goto("/");
  await expect(page.getByRole("combobox", { name: "Theme" })).toBeVisible();

  const help = page.getByRole("button", { name: "Help" });
  await help.click();
  const menu = page.getByRole("menu", { name: "Help" });
  await expect(menu).toBeVisible();

  const about = page.getByRole("menuitem", { name: "About this console" });
  const findings = page.getByRole("menuitem", { name: "Open findings" });
  await expect(about).toBeFocused();
  await page.keyboard.press("ArrowDown");
  await expect(findings).toBeFocused();
  await page.keyboard.press("Home");
  await expect(about).toBeFocused();
  await about.click();

  const dialog = page.getByRole("dialog", { name: "About this console" });
  await expect(dialog).toBeVisible();
  await expect(page.getByRole("button", { name: "Close about this console dialog" })).toBeFocused();
  expect((await new AxeBuilder({ page }).include("dialog").analyze()).violations).toEqual([]);

  await page.keyboard.press("Escape");
  await expect(dialog).toBeHidden();
  await expect(help).toBeFocused();
  expect(await cspViolations()).toEqual([]);
});

test("keeps the 50,000-agent scenario bounded to one page", async ({ page }) => {
  await page.goto("/?seeded=1");
  await selectDemoOption(page, "Data scenario", "large");
  await page.goto("/agents");

  await expect(page.getByRole("heading", { name: "50 agents on this page" })).toBeVisible();
  await expect(page.locator("tbody tr")).toHaveCount(50);
  await expect(page.getByRole("link", { name: "Next page" })).toBeVisible();

  await page.goto("/agents?agent=agent-00011");
  await expect(page.getByRole("heading", { level: 2, name: "agent-00011" })).toBeVisible();
  await expect(page.getByText("Hostname not reported")).toBeVisible();
  await expect(page.getByText("0.4.0")).toBeVisible();
  await expect(page.getByText("findings, heartbeat")).toBeVisible();
  await expect(page.locator(".certificate-list li")).toHaveCount(1);
});

test("hides an out-of-scope agent and shows empty and unavailable states", async ({ page }) => {
  await page.goto("/?seeded=1");
  await selectDemoOption(page, "Persona", "scoped_operator");
  await page.goto("/agents?agent=agent-00001");
  await expect(page.getByRole("heading", { name: "Data unavailable" })).toBeVisible();
  await expect(page.getByText("host-00001.example.test")).toHaveCount(0);

  await page.goto("/agents");
  await selectDemoOption(page, "Data scenario", "empty");
  await expect(page.getByText("No agents match these filters.")).toBeVisible();

  await page.goto("/findings");
  await selectDemoOption(page, "Data scenario", "partial_failure");
  await expect(page.getByRole("heading", { name: "Data unavailable" })).toBeVisible();
});

test("shows stale, removed-permission, and expired-session states", async ({ page }) => {
  await page.goto("/?seeded=1");
  await selectDemoOption(page, "Data scenario", "stale");
  await page.goto("/agents");
  await expect(page.locator("tbody tr")).toHaveCount(50);
  await expect(page.getByText("stale", { exact: true })).toHaveCount(50);
  await page.goto("/agents?agent=agent-00199");
  await expect(page.getByText("No heartbeat recorded")).toBeVisible();

  await page.goto("/agents");
  await selectDemoOption(page, "Data scenario", "permission_removed");
  await expect(page.getByRole("heading", { name: "You do not have access to this page" })).toBeVisible();

  await page.goto("/findings");
  await selectDemoOption(page, "Data scenario", "expired_session");
  await expect(page.getByRole("heading", { name: "Session expired" })).toBeVisible();
});

test("shows latest finding provenance and evidence", async ({ page }) => {
  await page.goto("/?seeded=1");
  await page.goto("/findings?finding=agent-00041%2F~unknown%2FOV-0120");

  await expect(page.getByRole("heading", { level: 2, name: "OV-0120 · rule set unknown (earlier agent)" })).toBeVisible();
  await expect(page.getByText("Imported · unauthenticated", { exact: true })).toBeVisible();
  await expect(page.getByText("82%", { exact: true })).toBeVisible();
  await expect(page.getByText("scan-00120", { exact: true })).toBeVisible();
  await expect(page.getByText("synthetic.observation=0120", { exact: true })).toBeVisible();
});
