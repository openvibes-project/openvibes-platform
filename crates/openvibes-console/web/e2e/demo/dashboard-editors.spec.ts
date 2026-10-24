// The widget editors: panels, selects, chips, button rows and focus.
import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

import { duplicate, newWidget, openHome } from "./dashboard-helpers";

test.beforeEach(async ({ page }) => openHome(page));

test("the widget panel is named for the widget, and the Graph editor's selects share one panel", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 340 });
  const panel = await newWidget(page, /^Graph/);
  await expect(panel.getByText("Edit widget · Graph")).toBeVisible();
  await expect(panel.getByText("graph-1")).toHaveCount(0);
  await panel.getByRole("button", { name: "Add a count" }).click();
  await panel.getByRole("button", { name: "Add a count" }).click();
  const [one, two] = [panel.getByRole("combobox", { name: "Count 1", exact: true }), panel.getByRole("combobox", { name: "Count 2", exact: true })];
  // Opening a second Select closes the first.
  await one.click();
  await expect(one).toHaveAttribute("aria-expanded", "true");
  await two.click();
  await expect(one).toHaveAttribute("aria-expanded", "false");
  await expect(page.locator(".sel__popup")).toHaveCount(1);
  // Group headings, the search box, and clicks on a heading or a disabled option keep focus in it.
  const popup = page.locator(".sel__popup");
  await expect(popup.getByRole("group")).toHaveCount(5);
  const search = popup.getByRole("combobox", { name: "Filter Count 2" });
  await expect(search).toBeFocused();
  await popup.locator(".sel__group").first().click();
  await expect(search).toBeFocused();
  await popup.getByRole("option", { name: "Active alarms" }).click({ force: true });
  await expect(search).toBeFocused();
  await expect(popup).toHaveCount(1);
  // Tab closes.
  await page.keyboard.press("Tab");
  await expect(popup).toHaveCount(0);
  // A typed letter opens with the search filled and an enabled row active, even when the first match is disabled.
  await two.focus();
  await page.keyboard.press("a");
  await expect(popup.getByRole("combobox", { name: "Filter Count 2" })).toHaveValue("a");
  const active = popup.locator(".sel__option--active");
  await expect(active).toHaveCount(1);
  await expect(active).not.toHaveAttribute("aria-disabled", "true");
  await page.keyboard.press("Escape");
  // The popup closes when its button scrolls out of the inspector.
  await one.click();
  await expect(popup).toHaveCount(1);
  const scroller = page.locator(".inspector__scroll");
  await scroller.evaluate((el) => { el.scrollTop = el.scrollHeight; });
  await expect(popup).toHaveCount(0);
});

test("button rows pick with a click and wrap with the arrow keys; switches toggle with Space", async ({ page }) => {
  const panel = await newWidget(page, /^Graph/);
  const period = panel.getByRole("radiogroup", { name: "Period" });
  await expect(period.getByRole("radio", { name: "30 d" })).toBeChecked();
  await period.getByRole("radio", { name: "1 y" }).click();
  await expect(period.getByRole("radio", { name: "1 y" })).toBeChecked();
  await page.keyboard.press("ArrowRight");
  await expect(period.getByRole("radio", { name: "7 d" })).toBeChecked();
  await expect(period.getByRole("radio", { name: "7 d" })).toBeFocused();
  await page.keyboard.press("ArrowLeft");
  await expect(period.getByRole("radio", { name: "1 y" })).toBeChecked();

  await page.getByRole("button", { name: "Add widget" }).click();
  await page.getByRole("button", { name: /^Needs attention/ }).click();
  const attention = page.locator(".inspector");
  const exploited = attention.getByRole("switch", { name: "Exploited vulnerabilities" });
  await expect(exploited).toBeChecked();
  await exploited.click();
  await expect(exploited).not.toBeChecked();
  await exploited.focus();
  await page.keyboard.press("Space");
  await expect(exploited).toBeChecked();
  const limit = attention.getByRole("radiogroup", { name: "Show at most" });
  await limit.getByRole("radio", { name: "15" }).click();
  await expect(limit.getByRole("radio", { name: "15" })).toBeChecked();
});

test("the List editor shows filters as chips, adds and removes them, and a Trend picks a rule", async ({ page }) => {
  const panel = await newWidget(page, /^List/);
  await expect(panel.getByText("Edit widget · List")).toBeVisible();
  await expect(panel.getByRole("combobox", { name: "List" })).toContainText("Compliance findings");
  await expect(panel.getByText("Severity: Critical")).toBeVisible();
  // A flag adds directly; a choice asks for its value, and replaces one removed first.
  await panel.getByRole("combobox", { name: "Add filter" }).click();
  await expect(page.getByRole("option", { name: "Severity" })).toHaveCount(1);
  await page.getByRole("option", { name: "Include resolved" }).click();
  await expect(panel.getByText("Include resolved")).toBeVisible();
  await expect(panel.getByRole("combobox", { name: "Add filter" })).toBeFocused();
  // A used choice filter is offered again; the new value replaces the old one, and focus lands on the value Select.
  await panel.getByRole("combobox", { name: "Add filter" }).click();
  await page.getByRole("option", { name: "Severity" }).click();
  await expect(panel.getByRole("combobox", { name: "Severity value" })).toBeFocused();
  await panel.getByRole("combobox", { name: "Severity value" }).click();
  await page.getByRole("option", { name: "High" }).click();
  await expect(panel.getByText("Severity: High")).toBeVisible();
  await expect(panel.getByText("Severity: Critical")).toHaveCount(0);
  await expect(panel.getByRole("combobox", { name: "Add filter" })).toBeFocused();
  await panel.getByRole("button", { name: "Remove filter Include resolved" }).click();
  await expect(panel.getByRole("combobox", { name: "Add filter" })).toBeFocused();
  // Changing the list drops the filters it does not support.
  await panel.getByRole("combobox", { name: "List" }).click();
  await page.getByRole("option", { name: "Hosts" }).click();
  await expect(panel.getByText("Severity: High")).toHaveCount(0);
  await expect(panel.getByText("Include resolved")).toHaveCount(0);
  await panel.getByRole("radio", { name: "10" }).click();
  await expect(panel.getByRole("radio", { name: "10" })).toBeChecked();
});

test("a Select's filter narrows its options, and the open, filtered popup passes axe", async ({ page }) => {
  const panel = await newWidget(page, /^Trend/);
  await panel.getByRole("combobox", { name: "Compliance rule" }).click();
  const popup = page.locator(".sel__popup");
  const options = popup.getByRole("option");
  const before = await options.count();
  await page.getByRole("combobox", { name: "Filter Compliance rule" }).fill("ssh");
  await expect.poll(() => options.count()).toBeLessThan(before);
  expect(await options.count()).toBeGreaterThan(0);
  for (const text of await options.allTextContents()) expect(text.toLowerCase()).toContain("ssh");
  await page.getByRole("combobox", { name: "Filter Compliance rule" }).fill("no such rule anywhere");
  await expect(options).toHaveCount(0);
  await page.getByRole("combobox", { name: "Filter Compliance rule" }).fill("ssh");
  await expect(options.first()).toBeVisible();
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
});

test("the Trend editor picks a rule from a searchable list", async ({ page }) => {
  const panel = await newWidget(page, /^Trend/);
  await expect(panel.getByText("Edit widget · Trend")).toBeVisible();
  const rule = panel.getByRole("combobox", { name: "Compliance rule" });
  await expect(rule).toContainText("Choose a rule");
  await rule.click();
  await expect(page.getByRole("combobox", { name: "Filter Compliance rule" })).toBeFocused();
  await page.getByRole("option").first().click();
  await expect(rule).not.toContainText("Choose a rule");
  await expect(panel.getByRole("radiogroup", { name: "Days" }).getByRole("radio", { name: "14" })).toBeChecked();
});

test("odd stored values show as selected extras and survive a save", async ({ page }) => {
  const config = {
    number: { metric: "agents.stale", trend: 14 },
    attention: { include: ["exploited"], limit: 12 },
    graph: { metrics: ["alarms.active"], days: 14, line: "stepped" },
    list: { view: "/compliance", query: "severity=critical&bad=1", limit: 7 },
    trend: { finding: "gone/rule", days: 10 },
    hosts: { kinds: "all", limit: 4 },
  };
  const widgets = [
    { id: "number-1", type: "number", x: 0, y: 0, w: 3, h: 2, config: config.number },
    { id: "attention-1", type: "attention", x: 3, y: 0, w: 6, h: 4, config: config.attention },
    { id: "graph-1", type: "graph", x: 0, y: 4, w: 6, h: 4, config: config.graph },
    { id: "list-1", type: "list", x: 6, y: 4, w: 6, h: 4, config: config.list },
    { id: "trend-1", type: "trend", x: 0, y: 8, w: 4, h: 3, config: config.trend },
    { id: "top-hosts-1", type: "top-hosts", x: 4, y: 8, w: 4, h: 3, config: config.hosts },
  ];
  await page.evaluate((w) => {
    const now = new Date().toISOString();
    localStorage.setItem("openvibes.v2.demo.dashboards", JSON.stringify({ rows: [
      { dashboard_id: "d-odd", owner: "u-admin", name: "Odd", shared_role_id: null, layout: { schema: 1, widgets: w }, version: 1, created_at: now, updated_at: now },
    ], homes: [["u-admin", "d-odd"]] }));
  }, widgets);
  await page.goto("/");
  await page.getByRole("button", { name: "Edit", exact: true }).click();
  const inspector = page.locator(".inspector");
  await page.locator('.tile[data-type="number"]').getByRole("button", { name: /^Settings for/ }).click();
  await expect(inspector.getByRole("radiogroup", { name: "Trend" }).getByRole("radio", { name: "14 d" })).toBeChecked();
  await page.locator('.tile[data-type="attention"]').getByRole("button", { name: /^Settings for/ }).click();
  await expect(inspector.getByRole("radiogroup", { name: "Show at most" }).getByRole("radio", { name: "12" })).toBeChecked();
  await page.locator('.tile[data-type="graph"]').getByRole("button", { name: /^Settings for/ }).click();
  await expect(inspector.getByRole("radiogroup", { name: "Period" }).getByRole("radio", { name: "14 d" })).toBeChecked();
  await page.locator('.tile[data-type="list"]').getByRole("button", { name: /^Settings for/ }).click();
  await expect(inspector.getByText("bad=1")).toBeVisible();
  await expect(inspector.getByRole("radiogroup", { name: "Rows" }).getByRole("radio", { name: "7" })).toBeChecked();
  await page.locator('.tile[data-type="trend"]').getByRole("button", { name: /^Settings for/ }).click();
  await expect(inspector.getByRole("combobox", { name: "Compliance rule" })).toContainText("gone/rule (not found)");
  await expect(inspector.getByRole("radiogroup", { name: "Days" }).getByRole("radio", { name: "10" })).toBeChecked();
  await page.locator('.tile[data-type="top-hosts"]').getByRole("button", { name: /^Settings for/ }).click();
  await expect(inspector.getByRole("radiogroup", { name: "Hosts" }).getByRole("radio", { name: "4" })).toBeChecked();
  // Save with one edit elsewhere: every config comes back unchanged.
  await page.getByLabel("Dashboard name").fill("Odd 2");
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Odd 2");
  const saved = await page.evaluate(() => (JSON.parse(localStorage.getItem("openvibes.v2.demo.dashboards") ?? "{}") as { rows: { layout: { widgets: { id: string; config: unknown }[] } }[] }).rows[0]?.layout.widgets);
  expect(Object.fromEntries((saved ?? []).map((w) => [w.id, w.config]))).toEqual({
    "number-1": config.number, "attention-1": config.attention, "graph-1": config.graph, "list-1": config.list, "trend-1": config.trend, "top-hosts-1": config.hosts,
  });
});

for (const scheme of ["light", "dark"] as const) {
  test(`no accessibility violations in the widget editors (${scheme})`, async ({ page }) => {
    await page.emulateMedia({ colorScheme: scheme });
    for (const [name, label] of [[/^Graph/, "Graph"], [/^List/, "List"], [/^Needs attention/, "Needs attention"], [/^Trend/, "Trend"]] as const) {
      const panel = await newWidget(page, name);
      await expect(panel.getByText(`Edit widget · ${label}`)).toBeVisible();
      await page.waitForTimeout(250);
      expect((await new AxeBuilder({ page }).include(".inspector").analyze()).violations.map((v) => v.id), label).toEqual([]);
      await page.goto("/");
    }
  });
}

test("a Select wrapped in a label still picks an option and stays closed", async ({ page }) => {
  const panel = await newWidget(page, /^Number/);
  await panel.locator(".sel").first().evaluate((sel) => {
    const label = document.createElement("label");
    sel.parentElement?.insertBefore(label, sel);
    label.appendChild(sel);
  });
  const count = panel.getByRole("combobox", { name: "Count", exact: true });
  await count.click();
  await page.getByRole("option", { name: "Offline hosts" }).click();
  await expect(page.locator(".sel__popup")).toHaveCount(0);
  await expect(count).toContainText("Offline hosts");
});

test("Edit shows a pencil, and new widgets fill the first free spot", async ({ page }) => {
  await duplicate(page);
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("button", { name: "Edit", exact: true }).locator("[data-icon=pencil]")).toHaveCount(1);
  await page.getByRole("button", { name: "Dashboards" }).click();
  await page.getByRole("menuitem", { name: "New dashboard" }).click();
  await page.getByRole("button", { name: /^Number/ }).click();
  await page.getByRole("button", { name: "Add widget" }).click();
  await page.getByRole("button", { name: /^Number/ }).click();
  const [a, b] = [page.locator(".tile").nth(0), page.locator(".tile").nth(1)];
  const [boxA, boxB] = [await a.boundingBox(), await b.boundingBox()];
  expect(boxA?.y).toBe(boxB?.y);
  expect(boxB?.x).toBeGreaterThan(boxA?.x ?? 0);
});

test("an Overview copy's tile editor is named for its type, not its id", async ({ page }) => {
  await duplicate(page);
  await page.getByRole("button", { name: "Settings for Critical" }).click();
  await expect(page.locator(".inspector").getByText("Edit widget · Number")).toBeVisible();
});

test("the Graph editor keeps focus when a count is removed or the last one is added", async ({ page }) => {
  const panel = await newWidget(page, /^Graph/);
  await panel.getByRole("button", { name: "Add a count" }).click();
  await expect(panel.getByRole("button", { name: "Add a count" })).toBeFocused();
  await panel.getByRole("button", { name: "Add a count" }).click();
  await panel.getByRole("button", { name: "Add a count" }).click();
  await expect(panel.getByRole("combobox", { name: "Count 1", exact: true })).toBeFocused();
  await panel.getByRole("button", { name: "Remove count 4" }).click();
  await expect(panel.getByRole("button", { name: "Add a count" })).toBeFocused();
});

// #236: Delete sat in the dashboard menu as an inline Confirm, and the menu
// closed on the click that opened it, so the confirmation never showed.
test("a copied dashboard can be deleted from its menu", async ({ page }) => {
  await page.getByRole("button", { name: "Dashboard menu" }).click();
  await page.getByRole("menuitem", { name: "Duplicate" }).click();
  // A copy opens for editing; save it as it is, like a user keeping a copy.
  await expect(page.getByLabel("Dashboard name")).toHaveValue(/^Copy of /);
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText(/^Copy of /);
  const url = page.url();
  await page.getByRole("button", { name: "Dashboard menu" }).click();
  await page.getByRole("button", { name: "Delete" }).click();
  await expect(page.getByText(/^Delete "Copy of .*"\? People it is shared with lose it too\.$/)).toBeVisible();
  await page.getByRole("button", { name: "Confirm" }).click();
  await expect(page.getByText("Dashboard deleted")).toBeVisible();
  await expect(page).not.toHaveURL(url);
  await page.getByRole("button", { name: "Dashboards" }).click();
  await expect(page.getByRole("menuitemradio", { name: /^Copy of / })).toHaveCount(0);
});

// #252: "+ New dashboard" is highlighted across the whole menu, like the other items.
test("New dashboard spans the menu's width", async ({ page }) => {
  await page.getByRole("button", { name: "Dashboards" }).click();
  const item = page.getByRole("menuitem", { name: "New dashboard" });
  const builtin = page.getByRole("menuitemradio", { name: "Overview" });
  const [a, b] = [await item.boundingBox(), await builtin.boundingBox()];
  expect(a?.width).toBeGreaterThan(0);
  expect(Math.abs((a?.width ?? 0) - (b?.width ?? 0))).toBeLessThan(1);
});

// #252: a new dashboard that is never saved is not left behind.
test("New dashboard then Cancel leaves no dashboard behind", async ({ page }) => {
  await page.getByRole("button", { name: "Dashboards" }).click();
  await page.getByRole("menuitem", { name: "New dashboard" }).click();
  await expect(page.getByLabel("Dashboard name")).toHaveValue("Untitled dashboard");
  await page.locator(".dashboard-header").getByRole("button", { name: "Cancel" }).click();
  await expect(page.getByLabel("Dashboard name")).toHaveCount(0);
  await page.getByRole("button", { name: "Dashboards" }).click();
  await expect(page.getByRole("menuitemradio", { name: "Untitled dashboard" })).toHaveCount(0);
});
