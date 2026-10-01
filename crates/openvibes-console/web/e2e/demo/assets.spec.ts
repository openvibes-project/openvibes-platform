import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

// Assets v1 on the demo: the fleet Software view and a host's software.

// The inspector fades in; axe must measure colours after that, or text
// mid-fade fails contrast (Firefox measured 4.37:1 for a 4.6:1 badge).
async function settled(page: import("@playwright/test").Page) {
  await page.waitForFunction(() => document.getAnimations().every((a) => a.playState !== "running"));
}
test.beforeEach(async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { level: 1 })).toContainText("Alex");
});

test("software lists packages across hosts and opens the hosts that run one", async ({ page }) => {
  await page.getByRole("link", { name: "Software", exact: true }).click();
  const bash = page.locator(".view tbody tr").filter({ hasText: /^bash/ }).first();
  await expect(bash).toBeVisible();
  await page.getByPlaceholder("Filter by package name…").fill("nginx");
  const nginx = page.locator(".view tbody tr").filter({ hasText: "nginx" }).first();
  await nginx.locator("td").first().click();
  const inspector = page.locator(".inspector");
  await expect(inspector.locator(".panel-header__kind")).toContainText("Software");
  await expect(inspector.getByRole("heading", { name: "Versions in use" }).or(inspector.getByText("Versions in use"))).toBeVisible();
  await inspector.locator(".list a").first().click();
  await expect(inspector.locator(".panel-header__kind")).toContainText("Host");
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
});

test("a host page shows its installed software, filterable", async ({ page }) => {
  await page.getByRole("link", { name: "Hosts", exact: true }).click();
  await page.locator(".view tbody tr").first().locator("td").nth(1).click();
  const inspector = page.locator(".inspector");
  await expect(inspector.locator(".panel-header__kind")).toContainText("Host");
  await inspector.getByRole("tab", { name: "Software" }).click();
  const list = inspector.getByRole("list", { name: "Installed software" });
  await expect(list.locator("li").filter({ hasText: "openssl" })).toBeVisible();
  await inspector.getByRole("textbox", { name: "Filter installed software" }).fill("sudo");
  await expect(list.locator("li")).toHaveCount(1);
});

test("a host page shows its open ports and services; the fleet lists them (Assets v2)", async ({ page }) => {
  await page.getByRole("link", { name: "Hosts", exact: true }).click();
  await page.locator(".view tbody tr").first().locator("td").nth(1).click();
  const inspector = page.locator(".inspector");
  await inspector.getByRole("tab", { name: "Ports" }).click();
  const ports = inspector.getByRole("table", { name: "Open ports" });
  await expect(ports.locator("tr").filter({ hasText: "22/tcp" })).toContainText("sshd.service");
  await inspector.getByRole("tab", { name: "Services" }).click();
  await expect(inspector.getByRole("table", { name: "Running services" }).locator("tr").filter({ hasText: "chronyd.service" })).toBeVisible();
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
  await page.keyboard.press("Escape");
  await page.goto("/ports?exposed=true");
  await expect(page.locator(".view tbody tr").filter({ hasText: "22/tcp" })).toBeVisible();
  await expect(page.locator(".view tbody tr").filter({ hasText: "53/udp" })).toHaveCount(0);
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
});

test("fleet Ports and Services rows open the hosts that have them, linking to the Host page (#102)", async ({ page }) => {
  await page.goto("/ports");
  await page.locator(".view tbody tr").filter({ hasText: "443/tcp" }).first().locator("td").first().click();
  const inspector = page.locator(".inspector");
  await expect(inspector.locator(".panel-header__kind")).toContainText("Port");
  const listening = inspector.getByRole("list", { name: "Hosts listening on this port" });
  await expect(listening.locator("li").first()).toContainText("exposed");
  await settled(page);
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
  await listening.locator("li a").first().click();
  await expect(inspector.locator(".panel-header__kind")).toContainText("Host");
  await page.keyboard.press("Escape");
  await page.goto("/services");
  await page.locator(".view tbody tr").filter({ hasText: "chronyd.service" }).first().locator("td").first().click();
  await expect(inspector.locator(".panel-header__kind")).toContainText("Service");
  await expect(inspector.getByRole("list", { name: "Hosts running this service" }).locator("li").first()).toContainText("chronyd");
  await settled(page);
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
});

test("the fleet Ports and Services views work from the keyboard: j moves, Enter opens, Escape closes", async ({ page }) => {
  for (const [path, kind] of [["/ports", "Port"], ["/services", "Service"]] as const) {
    await page.goto(path);
    await page.locator(".view table").focus();
    await page.keyboard.press("j");
    await page.keyboard.press("Enter");
    const inspector = page.locator(".inspector");
    await expect(inspector.locator(".panel-header__kind")).toContainText(kind);
    await page.keyboard.press("Escape");
    await expect(inspector).toHaveCount(0);
  }
});

test("wider than a phone every Host tab is visible: the strip wraps (reviewer, #148)", async ({ page }) => {
  await page.goto("/agents");
  await page.getByPlaceholder("Filter by host name, ID or version…").fill("web-");
  await page.locator(".view tbody tr").filter({ hasText: "web-" }).first().click();
  const tabs = page.locator(".inspector").getByRole("tab");
  await expect(tabs).toHaveCount(7);
  for (const tab of await tabs.all()) await expect(tab).toBeInViewport({ ratio: 1 });
});

test("on a phone the Host page's tab strip scrolls itself, never the page", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/agents");
  await page.getByPlaceholder("Filter by host name, ID or version…").fill("web-");
  await page.locator(".view tbody tr, .view .list li").filter({ hasText: "web-" }).first().click();
  const inspector = page.locator(".inspector");
  await inspector.getByRole("tab", { name: "Services" }).click();
  // Selecting a far tab must not scroll the panel sideways.
  const shifted = await inspector.evaluate((panel) => [...panel.querySelectorAll("*")].some((el) => el.scrollLeft > 0 && !el.classList.contains("tabs") && !el.classList.contains("table-wrap")));
  expect(shifted).toBe(false);
});

test("panels load the hosts after the first page with Show more (#104)", async ({ page }) => {
  await page.goto("/ports");
  await page.locator(".view tbody tr").filter({ hasText: "22/tcp" }).first().locator("td").first().click();
  const inspector = page.locator(".inspector");
  const rows = inspector.getByRole("list", { name: "Hosts listening on this port" }).locator("li");
  await expect(rows).toHaveCount(50);
  const more = inspector.getByRole("button", { name: "Show more hosts" });
  await more.click();
  await expect(rows).toHaveCount(100);
  await more.click();
  await more.click();
  await expect(rows).toHaveCount(183);
  await expect(more).toHaveCount(0);
  await settled(page);
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
  // The same in a package's panel; Enter on the focused button works too.
  await page.goto("/software");
  await page.locator(".view tbody tr").filter({ hasText: /^bash/ }).first().locator("td").first().click();
  const pkg = inspector.getByRole("list", { name: "Hosts that have it" }).locator("li");
  await expect(pkg).toHaveCount(50);
  await inspector.getByRole("button", { name: "Show more hosts" }).focus();
  await page.keyboard.press("Enter");
  await expect(pkg).toHaveCount(100);
});

test("a host whose lists were cut says some ports are not listed", async ({ page }) => {
  await page.getByRole("link", { name: "Hosts", exact: true }).click();
  await page.locator(".view tbody tr").filter({ hasText: "build-" }).first().locator("td").nth(1).click();
  const inspector = page.locator(".inspector");
  await inspector.getByRole("tab", { name: "Ports" }).click();
  await expect(inspector.getByText("some ports not listed")).toBeVisible();
});

test("a host whose last services report was refused says so above its old lists", async ({ page }) => {
  await page.getByRole("link", { name: "Hosts", exact: true }).click();
  await page.locator(".view tbody tr").filter({ hasText: "mail-" }).first().locator("td").nth(1).click();
  const inspector = page.locator(".inspector");
  await inspector.getByRole("tab", { name: "Ports" }).click();
  await expect(inspector.getByRole("status").filter({ hasText: "Last report refused" })).toContainText("over 512 KiB");
  await expect(inspector.getByRole("table", { name: "Open ports" })).toBeVisible();
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
});
