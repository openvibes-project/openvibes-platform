import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

// Assets v1 on the demo: a host's software, ports and services (the fleet Software list: software-list.spec.ts).

// The inspector fades in; axe must measure colours after that, or text
// mid-fade fails contrast (Firefox measured 4.37:1 for a 4.6:1 badge).
async function settled(page: import("@playwright/test").Page) {
  await page.waitForFunction(() => document.getAnimations().every((a) => a.playState !== "running"));
}
test.beforeEach(async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { level: 1 })).toContainText("Alex");
});

/** The first host of the Hosts list, opened: its page. */
async function firstHost(page: import("@playwright/test").Page, query = "") {
  await page.goto(`/hosts${query}`);
  await page.locator(".view tbody tr").first().locator("td").nth(1).click();
  await expect(page).toHaveURL(/\/hosts\/agent-\d{5}$/);
}

test("a host page shows its installed software, filterable", async ({ page }) => {
  await firstHost(page);
  await page.locator(".detail-tiles").getByRole("link", { name: /^Software: \d+$/ }).click();
  const list = page.getByRole("list", { name: "Installed software" });
  await expect(list.locator("li").filter({ hasText: "openssl" })).toBeVisible();
  await page.getByRole("textbox", { name: "Filter installed software" }).fill("sudo");
  await expect(list.locator("li")).toHaveCount(1);
});

test("a host page shows its open ports and services; the fleet lists them (Assets v2)", async ({ page }) => {
  await firstHost(page);
  await page.getByRole("link", { name: /^Show all \d+ ports$/ }).click();
  const ports = page.getByRole("table", { name: "Open ports" });
  await expect(ports.locator("tr").filter({ hasText: "22/tcp" })).toContainText("sshd.service");
  await page.getByRole("navigation", { name: "This host's lists" }).getByRole("link", { name: "Services" }).click();
  await expect(page.getByRole("table", { name: "Running services" }).locator("tr").filter({ hasText: "chronyd.service" })).toBeVisible();
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
  await page.goto("/ports?exposed=true");
  await expect(page.locator(".view tbody tr").filter({ hasText: "22/tcp" })).toBeVisible();
  await expect(page.locator(".view tbody tr").filter({ hasText: "631/tcp" })).toHaveCount(0);
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
});

test("fleet Ports rows open the port's page and Services rows open the hosts that run them, linking to the Host page (#102)", async ({ page }) => {
  await page.goto("/ports");
  await page.locator(".view tbody tr").filter({ hasText: "443/tcp" }).first().locator("td").first().click();
  await expect(page).toHaveURL(/\/ports\/443\/tcp$/);
  const listening = page.getByRole("table", { name: "Hosts", exact: true });
  await expect(listening.locator("tbody tr").first()).toContainText("exposed");
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
  await listening.locator("tbody tr a").first().click();
  await expect(page).toHaveURL(/\/hosts\/agent-\d{5}$/);
  await expect(page.locator(".detail-page h1")).toBeVisible();
  await page.goto("/services");
  await page.locator(".view tbody tr").filter({ hasText: "chronyd.service" }).first().locator("td").first().click();
  await expect(page).toHaveURL(/\/services\/chronyd\.service$/);
  await expect(page.getByRole("table", { name: "Hosts", exact: true }).locator("tbody tr").first()).toContainText("chrony");
  await settled(page);
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
});

test("the fleet Ports and Services views work from the keyboard: j moves, Enter opens (a port page, a service page)", async ({ page }) => {
  await page.goto("/ports");
  await page.locator(".view table").focus();
  await page.keyboard.press("j");
  await page.keyboard.press("Enter");
  await expect(page).toHaveURL(/\/ports\/\d+\/(tcp|udp)$/);
  await page.goto("/services");
  await page.locator(".view table").focus();
  await page.keyboard.press("j");
  await page.keyboard.press("Enter");
  await expect(page).toHaveURL(/\/services\/[^/]+$/);
});

test("on a phone the host page and its lists never scroll the page sideways", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  for (const path of ["/hosts/agent-00005", "/hosts/agent-00005/ports", "/hosts/agent-00005/services"]) {
    await page.goto(path);
    await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  }
});

test("a port's page pages its hosts (#104)", async ({ page }) => {
  await page.goto("/ports/22/tcp");
  const rows = page.getByRole("table", { name: "Hosts", exact: true }).locator("tbody tr");
  await expect(rows).toHaveCount(50);
  await expect(page.getByText("1–50 of 177")).toBeVisible();
  await page.getByRole("button", { name: "Next" }).click();
  await expect(page).toHaveURL(/offset=50/);
  await expect(page.getByText("51–100 of 177")).toBeVisible();
  await page.getByRole("button", { name: "Next" }).click();
  await page.getByRole("button", { name: "Next" }).click();
  await expect(rows).toHaveCount(27);
  await expect(page.getByRole("button", { name: "Next" })).toBeDisabled();
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
});

test("a host whose lists were cut says some ports are not listed", async ({ page }) => {
  await firstHost(page, "?q=build-");
  await page.getByRole("link", { name: /^Show all \d+ ports$/ }).click();
  await expect(page.getByText("some ports not listed")).toBeVisible();
});

test("a host whose last services report was refused says so above its old lists", async ({ page }) => {
  await firstHost(page, "?q=mail-");
  await page.getByRole("link", { name: /^Show all \d+ ports$/ }).click();
  await expect(page.getByRole("status").filter({ hasText: "Last report refused" })).toContainText("over 512 KiB");
  await expect(page.getByRole("table", { name: "Open ports" })).toBeVisible();
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
});

test("the host page's tiles and cards follow the left menu's order (#118)", async ({ page }) => {
  const menu = (await page.locator(".rail .rail__label").allTextContents()).map((t) => t.trim());
  expect(menu.filter((m) => ["Alarms", "Compliance", "Vulnerabilities", "Software"].includes(m))).toEqual(["Alarms", "Compliance", "Vulnerabilities", "Software"]);
  await firstHost(page);
  const tiles = (await page.locator(".detail-tile__label").allTextContents()).map((t) => t.trim());
  expect(tiles).toEqual(["Open alarms", "Compliance failing", "Vulnerabilities", "Software"]);
  const cards = (await page.locator(".person-page__col").nth(1).locator(".section-title").allTextContents()).map((t) => t.replace(/\s*[\d,]+$/, "").trim());
  expect(cards).toEqual(["Open alarms", "Compliance failing", "Vulnerabilities", "Software, ports and services"]);
});

test("two hosts compare to only what differs (#120)", async ({ page }) => {
  await firstHost(page, "?q=web-");
  await page.locator(".person-page__head").getByRole("button", { name: "Compare" }).click();
  const inspector = page.locator(".inspector");
  await inspector.getByRole("list", { name: "Hosts to compare with" }).getByRole("button").filter({ hasText: "db-" }).first().click();
  await expect(inspector.locator(".panel-header")).toContainText("↔");
  const ports = inspector.getByRole("table", { name: "Open ports differences" });
  await expect(ports).toContainText("443/tcp");
  await expect(ports).toContainText("5432/tcp");
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
});

test("a host exports the chosen sections to one CSV (#119)", async ({ page }) => {
  await firstHost(page);
  await page.locator(".person-page__head").getByRole("button", { name: "Export" }).click();
  const picker = page.getByRole("group", { name: "Export this host" });
  await picker.getByLabel("Compliance").uncheck();
  const [download] = await Promise.all([page.waitForEvent("download"), picker.getByRole("button", { name: "Download CSV" }).click()]);
  expect(download.suggestedFilename()).toMatch(/^openvibes-.*\.csv$/);
  const text = await (await download.createReadStream()).toArray().then((chunks) => Buffer.concat(chunks).toString());
  expect(text.split("\n")[0]).toBe('\uFEFF"section","name","detail","state","severity","extra"');
  expect(text).toContain('"ports","22/tcp"');
  expect(text).toContain('"software","bash"');
  expect(text).not.toContain('"findings",');
});
