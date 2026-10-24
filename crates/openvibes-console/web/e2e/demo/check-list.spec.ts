import { expect, test } from "@playwright/test";

import { axeListAndFiltered, expectChips, hideColumnAcrossReload, listParts, openBulkMitigate, pointerOffRail, saveClearRestore } from "./list-helpers";

// The Compliance list on the demo (approved screen 27): the demo answers
// GET /api/v1/compliance-list like compliance/list_page.rs, over the
// hand-made checks of demo/checkSeed.ts among others. The demo keeps its data
// in memory, so a test that changes triage never reloads after the change.
const { table, rows, filters, choose } = listParts("Compliance");
const ROOT = "harden.ssh.permit_root_login";

pointerOffRail();

test("filters by Area and Rule set, and a reload keeps both", async ({ page }) => {
  await page.goto("/compliance");
  await expect(rows(page).first()).toBeVisible();
  await expect(page.locator(".summary-line")).toContainText(/\d+ checks? failing on \d+ hosts? · \d+ critical · \d+ unassigned · baseline \d+/);
  await choose(page, "Area", /^SSH/);
  await expectChips(filters(page), ["Area: SSH"]);
  await choose(page, "Rule set", /^hardening-linux-l1/);
  await expectChips(filters(page), ["Rule set: hardening-linux-l1"]);
  await expect(page).toHaveURL(/[?&]area=SSH/);
  await expect(page).toHaveURL(/[?&]rule_set=hardening-linux-l1/);
  const check = async () => {
    await expect(rows(page).filter({ hasText: ROOT })).toHaveCount(1);
    for (const text of await rows(page).allTextContents()) {
      expect(text).toContain("SSH");
      expect(text).toContain("hardening-linux-l1");
    }
  };
  await check();
  await page.reload();
  await expectChips(filters(page), ["Area: SSH", "Rule set: hardening-linux-l1"]);
  await check();
});

test("a saved view comes back after Clear all", async ({ page }) => {
  await page.goto("/compliance?state=all&area=SSH");
  await expect(rows(page).first()).toBeVisible();
  await saveClearRestore(page, "SSH, any state", /\/compliance$/);
  await expectChips(filters(page), ["State: All states", "Area: SSH"]);
  for (const text of await rows(page).allTextContents()) expect(text).toContain("SSH");
});

test("a hidden column stays hidden after a reload; Severity and Check can't be hidden", async ({ page }) => {
  await page.goto("/compliance");
  await hideColumnAcrossReload(page, table, rows, "Area", ["Severity", "Check"]);
});

test("the check is a real link to its page, and the row shows screen 27's cells", async ({ page }) => {
  await page.goto(`/compliance?q=${ROOT}`);
  const row = rows(page).filter({ hasText: ROOT });
  // Open on hosts 1 and 2, then mitigated, accepted and false positive; the rest of the hardening hosts pass.
  await expect(row).toContainText(/2 open · 1 mitigated · 1 accepted · 1 false positive · \d+ pass/);
  await expect(row.getByRole("progressbar", { name: /^Hosts: 2 open/ })).toBeVisible();
  await expect(row).toContainText(/5 of \d+/);
  await expect(row).toContainText("Sam Analyst");
  const link = row.getByRole("link", { name: `SSH allows root to log in with a password (${ROOT})`, exact: true });
  await expect(link).toHaveAttribute("href", `/compliance/hardening-linux-l1/${ROOT}`);
  await link.click();
  await expect(page).toHaveURL(new RegExp(`/compliance/hardening-linux-l1/${ROOT.replace(/\./g, "\\.")}$`));
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("SSH allows root to log in with a password");
  await page.goBack();
  await expect(rows(page).filter({ hasText: ROOT })).toHaveCount(1);
});

test("bulk Set state names the open hosts and changes only open ones; there is no Reopen", async ({ page }) => {
  await page.goto(`/compliance?q=${ROOT}`);
  const dialog = await openBulkMitigate(page, rows, ROOT);
  await expect(dialog).toContainText("Changes up to 2 open hosts. Mitigated, accepted and false-positive hosts are left as they are, and passing hosts are never touched.");
  await dialog.getByRole("textbox", { name: "Why (required)" }).fill("root login off by hand");
  await dialog.getByRole("button", { name: "Mitigate 1 check" }).click();
  await expect(page.locator(".toast").last()).toContainText("2 changed");
  // No open host left: it leaves the default (open) list without a reload.
  await expect(page.getByText("No check matches these filters.")).toBeVisible();
});

test("a check no host fails changes nothing: the bar says why and offers no action", async ({ page }) => {
  await page.goto("/compliance?state=passing&q=harden.files.passwd");
  await rows(page).filter({ hasText: "harden.files.passwd" }).getByRole("checkbox", { name: "Select row" }).check();
  const bar = page.getByRole("region", { name: "Bulk actions" });
  await expect(bar).toContainText("Nothing selected can be triaged");
  await expect(bar.getByRole("button", { name: /^Set state/ })).toHaveCount(0);
  await expect(bar.getByRole("button", { name: /Add to case/ })).toHaveCount(0);
});

test("old_compliance_urls_keep_their_meaning: old filters and views saved in this browser come over", async ({ page }) => {
  await page.evaluate(() => {
    localStorage.setItem("openvibes.v2.views./compliance", JSON.stringify([{ name: "Old site", query: "state=all&set=site&sort=last&dir=desc" }]));
    localStorage.setItem("openvibes.v2.views./findings", JSON.stringify([{ name: "Older highs", query: "severity=high&window=all" }]));
  });
  await page.goto("/compliance?set=hardening-linux-l1&window=all&severity=high");
  await expect(page).toHaveURL(/\/compliance\?severity=high&rule_set=hardening-linux-l1$/);
  await expectChips(filters(page), ["Rule set: hardening-linux-l1", "Severity: High"]);
  // In place: Back leaves the list, it does not land on the old address.
  await page.goBack();
  await expect(page).not.toHaveURL(/window=all/);
  await page.goto("/compliance");
  const views = page.getByRole("group", { name: "Saved views" });
  await expect(views.getByRole("button", { name: "Older highs", exact: true })).toBeVisible();
  await views.getByRole("button", { name: "Old site", exact: true }).click();
  await expectChips(filters(page), ["Rule set: site", "State: All states"]);
  await expect(page).not.toHaveURL(/sort=/);
  expect(await page.evaluate(() => [localStorage.getItem("openvibes.v2.views./compliance"), localStorage.getItem("openvibes.v2.views./findings")])).toEqual([null, null]);
});

test("axe finds nothing on the list, filtered, selected or not", async ({ page }) => {
  await axeListAndFiltered(page, rows, "/compliance", "/compliance?state=all&rule_set=hardening-linux-l1");
});
