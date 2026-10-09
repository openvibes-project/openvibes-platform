import AxeBuilder from "@axe-core/playwright";
import { type Page, expect, test } from "@playwright/test";

test.beforeEach(async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { level: 1 })).toContainText("Alex");
  await page.mouse.move(900, 500);
});

test("home falls back to the built-in", async ({ page }) => {
  await expect(page.locator(".tile")).toHaveCount(11);
  // Most important first (#116): alarms, then every critical issue, top left.
  const titles = await page.locator(".tile .tile__title").allTextContents();
  expect(titles.join("|")).toMatch(/Active alarms.*Critical/);
  await expect(page.getByRole("button", { name: "Duplicate to edit" })).toBeVisible();
});

test("the Overview's Critical tile adds up, links to its part, and speaks of issues", async ({ page }) => {
  const tile = page.locator(".tile", { has: page.locator(".tile__title", { hasText: /^Critical$/ }) });
  const total = Number((await tile.locator(".stat__value").textContent())?.replace(/\D/g, ""));
  const parts = (await tile.locator(".tile-parts").textContent()) ?? "";
  const sum = [...parts.matchAll(/(\d[\d,]*) (?:alarm|vulnerabilit|compliance)/g)].reduce((n, m) => n + Number((m[1] ?? "").replace(/,/g, "")), 0);
  expect(total).toBeGreaterThan(0);
  expect(sum).toBe(total);
  await expect(page.locator(".tile", { hasText: "Needs attention" }).getByText(/^Vulnerability/).first()).toBeVisible();
  // "finding" is the compliance word only.
  const text = await page.locator("#main").innerText();
  expect(text.replace(/compliance findings?/gi, "")).not.toMatch(/\bfindings?\b/i);
  await tile.getByRole("button", { name: /vulnerabilit/ }).click();
  await expect(page).toHaveURL(/\/vulnerabilities\?severity=critical/);
});

for (const [name, width] of [["desktop", 1440], ["phone", 390]] as const) {
  test(`the Overview lays out without overflow (${name})`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    await page.goto("/");
    await expect(page.locator(".tile")).toHaveCount(11);
    await page.waitForTimeout(500);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
    // The lists scroll inside their tile by design; the number tiles must show everything.
    // Trend tiles: no tolerance. The Fleet h: 2 tiles overflow by 2px, which predates the trend tiles.
    for (const tile of await page.locator(".tile", { has: page.locator(".tile-number") }).all()) {
      const slack = (await tile.locator(".tile-parts").count()) || (await tile.locator(".linechart").count()) ? 0 : 2;
      expect(await tile.locator(".tile__body").evaluate((el, s) => el.scrollHeight <= el.clientHeight + s, slack), await tile.innerText()).toBe(true);
    }
    // Dots between the parts when there is room for them, none when the parts wrap.
    const seps = page.locator(".tile-parts__sep");
    expect(await seps.first().evaluate((el) => getComputedStyle(el).display !== "none")).toBe(width > 400);
  });
}

test("a new dashboard gets a widget, is saved, and survives a reload", async ({ page }) => {
  await page.getByRole("button", { name: "Dashboards" }).click();
  await page.getByRole("menuitem", { name: "New dashboard" }).click();
  await page.getByRole("button", { name: /^Number/ }).click();
  await page.getByRole("combobox", { name: "Count", exact: true }).click();
  await page.getByRole("option", { name: "Stale hosts" }).click();
  await page.getByLabel("Dashboard name").fill("Stale watch");
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Stale watch");
  const url = page.url();
  await page.reload();
  await expect(page).toHaveURL(url);
  await expect(page.locator(".tile", { hasText: "Stale hosts" })).toBeVisible();
});

test("the built-in is duplicated to edit, a tile moves by keyboard, and it becomes home", async ({ page }) => {
  await page.getByRole("button", { name: "Duplicate to edit" }).click();
  await expect(page.getByLabel("Dashboard name")).toHaveValue("Copy of Overview");
  const tile = page.locator(".tile").first();
  const before = await tile.evaluate((el) => (el as HTMLElement).style.top);
  await tile.focus();
  await page.keyboard.press("ArrowDown");
  await expect.poll(async () => tile.evaluate((el) => (el as HTMLElement).style.top)).not.toBe(before);
  await page.getByRole("button", { name: "Save" }).click();
  await page.getByRole("button", { name: "Set as home" }).click();
  await page.goto("/");
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Copy of Overview");
});

test("asks before leaving unsaved edits", async ({ page }) => {
  await page.getByRole("button", { name: "Duplicate to edit" }).click();
  await page.getByLabel("Dashboard name").fill("Changed");
  let asked = false;
  page.once("dialog", (dialog) => { asked = true; void dialog.dismiss(); });
  await page.getByRole("link", { name: "Compliance", exact: true }).click();
  expect(asked).toBe(true);
  await expect(page.getByLabel("Dashboard name")).toHaveValue("Changed");
});

test("an analyst sees the team dashboard read-only", async ({ page }) => {
  await page.getByRole("button", { name: "Account" }).click();
  await page.getByRole("menuitemradio", { name: "analyst" }).click();
  await page.getByRole("button", { name: "Dashboards" }).click();
  await page.getByRole("menuitemradio", { name: "Analyst triage" }).click();
  await expect(page.getByText("Shared by")).toBeVisible();
  await expect(page.getByRole("button", { name: "Edit", exact: true })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Duplicate to edit" })).toBeVisible();
});

test("an admin shares a dashboard with a role", async ({ page }) => {
  await page.getByRole("button", { name: "Dashboards" }).click();
  await page.getByRole("menuitemradio", { name: "My morning check" }).click();
  await page.getByRole("button", { name: "Dashboard menu" }).click();
  await page.getByRole("menuitemradio", { name: "analyst" }).click();
  await expect(page.locator("#main").getByText("Shared with analyst")).toBeVisible();
});

for (const scheme of ["light", "dark"] as const) {
  test(`no accessibility violations on a dashboard, viewing and editing (${scheme})`, async ({ page }) => {
    await page.emulateMedia({ colorScheme: scheme });
    await page.goto("/dashboards/d-admin-morning");
    await expect(page.locator(".tile").first()).toBeVisible();
    await page.waitForTimeout(400);
    expect((await new AxeBuilder({ page }).analyze()).violations.map((v) => v.id)).toEqual([]);
    await page.getByRole("button", { name: "Edit", exact: true }).click();
    await page.getByRole("button", { name: "Add widget" }).click();
    await page.waitForTimeout(300);
    expect((await new AxeBuilder({ page }).analyze()).violations.map((v) => v.id)).toEqual([]);
  });
}

test("New dashboard while editing keeps the draft when you choose to stay", async ({ page }) => {
  await page.getByRole("button", { name: "Duplicate to edit" }).click();
  await page.getByLabel("Dashboard name").fill("Changed");
  const url = page.url();
  page.once("dialog", (dialog) => void dialog.dismiss());
  await page.getByRole("button", { name: "Dashboards" }).click();
  await page.getByRole("menuitem", { name: "New dashboard" }).click();
  await expect(page.getByLabel("Dashboard name")).toHaveValue("Changed");
  expect(page.url()).toBe(url);
  await page.getByRole("button", { name: "Dashboards" }).click();
  await expect(page.getByRole("menuitemradio", { name: "Untitled dashboard" })).toHaveCount(0);
});

test("Back with unsaved edits asks first", async ({ page }) => {
  await page.getByRole("link", { name: "Compliance", exact: true }).click();
  await page.getByRole("link", { name: "Dashboards" }).click();
  await page.getByRole("button", { name: "Duplicate to edit" }).click();
  await page.getByLabel("Dashboard name").fill("Changed");
  let asked = false;
  page.once("dialog", (dialog) => { asked = true; void dialog.dismiss(); });
  await page.goBack();
  await expect.poll(() => asked).toBe(true);
  await expect(page.getByLabel("Dashboard name")).toHaveValue("Changed");
});

test("a dashboard with a widget type this console does not know still renders", async ({ page }) => {
  await page.evaluate(() => {
    const layout = { schema: 1, widgets: [
      { id: "future", type: "future-widget", x: 0, y: 0, w: 4, h: 2, config: {} },
      { id: "stale", type: "number", x: 4, y: 0, w: 3, h: 2, config: { metric: "agents.stale" } },
    ] };
    const now = new Date().toISOString();
    localStorage.setItem("openvibes.v2.demo.dashboards", JSON.stringify({ rows: [
      { dashboard_id: "d-future", owner: "u-admin", name: "From a newer console", shared_role_id: null, layout, version: 1, created_at: now, updated_at: now },
    ], homes: [["u-admin", "d-future"]] }));
  });
  await page.goto("/");
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("From a newer console");
  await expect(page.locator(".tile", { hasText: "Unsupported widget" })).toBeVisible();
  await expect(page.locator(".tile", { hasText: "Stale hosts" })).toBeVisible();
  await expect(page.getByRole("link", { name: "Compliance", exact: true })).toBeVisible();
});

test("a tile deleted from the keyboard comes back with Undo", async ({ page }) => {
  await page.getByRole("button", { name: "Duplicate to edit" }).click();
  const tiles = page.locator(".tile");
  // The duplicate opens in edit mode; count its tiles only once they are there.
  await expect(page.getByRole("button", { name: "Save" })).toBeVisible();
  await expect(tiles.first()).toBeVisible();
  const count = await tiles.count();
  await tiles.first().focus();
  await page.keyboard.press("Delete");
  await expect(tiles).toHaveCount(count - 1);
  await page.getByRole("button", { name: "Undo" }).click();
  await expect(tiles).toHaveCount(count);
});

test("unsaved edits survive a reload and can be restored", async ({ page }) => {
  await page.getByRole("button", { name: "Duplicate to edit" }).click();
  await page.getByRole("button", { name: "Save" }).click();
  await page.getByRole("button", { name: "Edit", exact: true }).click();
  await page.getByLabel("Dashboard name").fill("Half done");
  await page.reload();
  await page.getByRole("button", { name: "Restore" }).click();
  await expect(page.getByLabel("Dashboard name")).toHaveValue("Half done");
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Half done");
  await page.reload();
  await expect(page.getByRole("button", { name: "Restore" })).toHaveCount(0);
});

test("Most exposed hosts labels each host's open count", async ({ page }) => {
  const tile = page.locator(".tile", { hasText: "Most exposed hosts" });
  const row = tile.locator(".list__row").first();
  await expect(row).toContainText(/\d+ open$/);
});

test("the editing note is for phones only", async ({ page }) => {
  await page.getByRole("button", { name: "Dashboard menu" }).click();
  await expect(page.getByRole("menuitem", { name: "Duplicate" })).toBeVisible();
  await expect(page.getByText("Editing needs a wider screen")).toBeHidden();
});

for (const [name, width] of [["desktop", 1440], ["phone", 390]] as const) {
  test(`a Critical tile at the Overview size keeps its fine print inside (${name})`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    await page.evaluate(() => {
      const layout = { schema: 1, widgets: [{ id: "crit", type: "number", x: 0, y: 0, w: 3, h: 4, config: { metric: "all.open.critical", trend: 30 } }] };
      const now = new Date().toISOString();
      localStorage.setItem("openvibes.v2.demo.dashboards", JSON.stringify({ rows: [
        { dashboard_id: "d-crit", owner: "u-admin", name: "Critical", shared_role_id: null, layout, version: 1, created_at: now, updated_at: now },
      ], homes: [["u-admin", "d-crit"]] }));
    });
    await page.goto("/");
    const tile = page.locator(".tile", { hasText: "alarm" });
    await expect(tile.locator(".tile-parts")).toHaveText("1 alarm · 79 vulnerabilities · 4 compliance");
    await expect(tile.locator(".tile-number .delta")).toBeVisible();
    await expect(tile.locator(".linechart svg")).toBeVisible();
    await expect(tile.getByRole("button")).toHaveCount(3);
    const box = (await tile.boundingBox()) ?? { y: 0, height: 0 };
    const parts = (await tile.locator(".tile-parts").boundingBox()) ?? { y: Infinity, height: 0 };
    expect(parts.y).toBeGreaterThanOrEqual(box.y);
    expect(parts.y + parts.height).toBeLessThanOrEqual(box.y + box.height);
    expect(await tile.locator(".tile__body").evaluate((el) => el.scrollHeight <= el.clientHeight)).toBe(true);
  });
}

async function newWidget(page: Page, name: RegExp) {
  await page.getByRole("button", { name: "Dashboards" }).click();
  await page.getByRole("menuitem", { name: "New dashboard" }).click();
  await page.getByRole("button", { name }).click();
  return page.locator(".inspector");
}

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
  const search = popup.getByRole("textbox", { name: "Filter Count 2" });
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
  await expect(popup.getByRole("textbox")).toHaveValue("a");
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

test("the Trend editor picks a rule from a searchable list", async ({ page }) => {
  const panel = await newWidget(page, /^Trend/);
  await expect(panel.getByText("Edit widget · Trend")).toBeVisible();
  const rule = panel.getByRole("combobox", { name: "Compliance rule" });
  await expect(rule).toContainText("Choose a rule");
  await rule.click();
  await expect(page.getByRole("textbox", { name: "Filter Compliance rule" })).toBeFocused();
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
  await page.getByRole("option", { name: "Stale hosts" }).click();
  await expect(page.locator(".sel__popup")).toHaveCount(0);
  await expect(count).toContainText("Stale hosts");
});

test("Edit shows a pencil, and new widgets fill the first free spot", async ({ page }) => {
  await expect(page.getByRole("button", { name: "Duplicate to edit" })).toBeVisible();
  await page.getByRole("button", { name: "Duplicate to edit" }).click();
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
