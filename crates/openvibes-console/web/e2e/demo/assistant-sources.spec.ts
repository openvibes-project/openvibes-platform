import { expect, test } from "@playwright/test";

test.beforeEach(async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { level: 1 })).toContainText("Alex");
});

test("a mitigation answer shows where outside information came from", async ({ page }) => {
  await page.keyboard.press("Control+j");
  const dock = page.getByRole("complementary", { name: "Assistant" });
  await dock.getByLabel("Question").fill("How do I mitigate CVE-2024-6387?");
  await dock.getByRole("button", { name: "Send" }).click();
  const source = dock.getByRole("link", { name: "Looked up CVE-2024-6387 on osv.dev" });
  await expect(source).toHaveAttribute("href", "https://osv.dev/vulnerability/CVE-2024-6387");
  await expect(source).toHaveAttribute("target", "_blank");
  await expect(source).toHaveAttribute("rel", "noopener noreferrer");
  await expect(dock.getByText("Searched the web for: CVE-2024-6387 mitigation workaround")).toBeVisible();
});

test("an answer from local data shows no sources line", async ({ page }) => {
  await page.keyboard.press("Control+j");
  const dock = page.getByRole("complementary", { name: "Assistant" });
  await dock.getByRole("button", { name: "Which hosts are stale?" }).click();
  await expect(dock.getByText("have not checked in")).toBeVisible();
  await expect(dock.getByText("Looked up")).toHaveCount(0);
});
