import { expect, test } from "@playwright/test";
import type { Page } from "@playwright/test";

// Where it runs, by keyboard and under latency: a busy control is aria-disabled,
// not disabled, so focus never drops to <body> (where the next Esc would close
// the panel); a change is sent once until the refetch lands; a failed Add keeps
// the row. The demo answers at once, so `slow` delays every response body and
// `missing` makes the next group id unknown to the store (a group deleted
// meanwhile); `slowList` delays only the assignment list (the refetch). The full flows are in rule-set-assignment.spec.ts.
type Hooks = { __slow?: boolean; __slowList?: boolean; __missing?: boolean };
test.beforeEach(async ({ page }) => {
  await page.addInitScript(() => {
    const w = window as unknown as Hooks;
    const text = Response.prototype.text;
    Response.prototype.text = async function (this: Response) {
      if (w.__slow) await new Promise((resolve) => setTimeout(resolve, 400));
      const body = await text.call(this);
      if (w.__slowList && body.includes('"asset_groups"')) await new Promise((resolve) => setTimeout(resolve, 1500));
      return body;
    };
    const encode = window.encodeURIComponent;
    window.encodeURIComponent = (value) => (w.__missing && String(value).startsWith("grp-") ? "grp-gone" : encode(value));
  });
  await page.goto("/settings?tab=rule-sets");
});
const hook = (page: Page, name: keyof Hooks) => page.evaluate((key) => { (window as unknown as Hooks)[key] = true; }, name);
const open = (page: Page, set: string) => page.locator(".view tbody tr").filter({ hasText: set }).click();

test("a keyboard toggle keeps focus on the switch", async ({ page }) => {
  await open(page, "hardening-linux-l1");
  const prod = page.getByRole("switch", { name: "Runs for Production" });
  await expect(prod).toHaveAttribute("aria-checked", "false");
  await hook(page, "__slow");
  await prod.focus();
  await page.keyboard.press("Space");
  await expect(prod).toHaveAttribute("aria-disabled", "true");
  await expect(prod).toBeFocused();
  await expect(prod).toHaveAttribute("aria-checked", "true");
  await expect(prod).toBeFocused();
});

test("a second press before the refetch lands is not sent again", async ({ page }) => {
  await open(page, "hardening-linux-l1");
  const prod = page.getByRole("switch", { name: "Runs for Production" });
  await hook(page, "__slowList");
  await prod.click();
  const done = page.getByText("hardening-linux-l1 is now on for Production");
  await done.waitFor({ timeout: 1000 });
  await prod.click({ force: true });
  await page.waitForTimeout(300); // a resend would answer at once
  expect(await done.count()).toBe(1);
  await expect(prod).not.toHaveAttribute("aria-disabled", "true");
  await expect(prod).toHaveAttribute("aria-checked", "true");
  expect(await done.count()).toBe(1);
});

test("after Add, focus is on + Add group", async ({ page }) => {
  await open(page, "hardening-linux-l2");
  await page.getByRole("button", { name: "+ Add group" }).focus();
  await page.keyboard.press("Enter");
  await expect(page.getByRole("combobox", { name: "Group" })).toBeFocused();
  await hook(page, "__slow");
  await page.getByRole("button", { name: "Add", exact: true }).focus();
  await page.keyboard.press("Enter");
  await expect(page.getByText(/hardening-linux-l2 is now on for /)).toBeVisible();
  await expect(page.getByRole("button", { name: "+ Add group" })).toBeFocused();
});

test("after ×, focus is on + Add group", async ({ page }) => {
  await open(page, "hardening-linux-l1");
  await hook(page, "__slow");
  await page.getByRole("button", { name: "Remove Production" }).focus();
  await page.keyboard.press("Enter");
  await expect(page.getByText("Production follows the default again")).toBeVisible();
  await expect(page.getByRole("button", { name: "+ Add group" })).toBeFocused();
});

test("a failed Add keeps the row, the group and the choice", async ({ page }) => {
  await open(page, "hardening-linux-l2");
  await page.getByRole("button", { name: "+ Add group" }).click();
  const group = page.getByRole("combobox", { name: "Group" });
  const chosen = await group.innerText();
  await page.getByRole("radio", { name: "Off" }).click();
  await hook(page, "__missing");
  await page.getByRole("button", { name: "Add", exact: true }).click();
  await expect(page.getByText("Asset group not found")).toBeVisible();
  await expect(group).toHaveText(chosen);
  await expect(page.getByRole("radio", { name: "Off" })).toHaveAttribute("aria-checked", "true");
  await expect(page.getByRole("button", { name: "Add", exact: true })).toBeVisible();
});
