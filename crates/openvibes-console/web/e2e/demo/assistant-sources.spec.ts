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
  // The OSV page came back as [web:1]: the reference line carries that number.
  const source = dock.getByRole("link", { name: "[web:1] Looked up CVE-2024-6387 on osv.dev", exact: true });
  await expect(source).toHaveAttribute("href", "https://osv.dev/vulnerability/CVE-2024-6387");
  await expect(source).toHaveAttribute("target", "_blank");
  await expect(source).toHaveAttribute("rel", "noopener noreferrer nofollow");
  await expect(dock.getByText("Searched the web for: CVE-2024-6387 mitigation workaround")).toBeVisible();
  // A search result: its number as the answer cites it, its host only, the user follows it.
  const result = dock.getByRole("link", { name: "[web:2] www.openssh.com" });
  await expect(result).toHaveAttribute("href", "https://www.openssh.com/txt/release-9.8");
  await expect(result).toHaveAttribute("target", "_blank");
  await expect(result).toHaveAttribute("rel", "noopener noreferrer nofollow");
});

test("an answer from local data shows no sources line", async ({ page }) => {
  await page.keyboard.press("Control+j");
  const dock = page.getByRole("complementary", { name: "Assistant" });
  await dock.getByRole("button", { name: "Which hosts are stale?" }).click();
  await expect(dock.getByText("have not checked in")).toBeVisible();
  await expect(dock.getByText("Looked up")).toHaveCount(0);
});

test("a failed internet lookup says the answer uses local data only", async ({ page }) => {
  const dock = page.getByRole("complementary", { name: "Assistant" });
  await page.keyboard.press("Control+j");
  await dock.getByLabel("Question").fill("Any workaround for CVE-2099-0001 while the internet is down?");
  await dock.getByRole("button", { name: "Send" }).click();
  await expect(dock.getByText("Internet lookup unavailable; this answer uses local data only")).toBeVisible();
  await expect(dock.getByRole("link")).toHaveCount(0);
});

test("a blocked web search says so and is not shown as a failure", async ({ page }) => {
  const dock = page.getByRole("complementary", { name: "Assistant" });
  await page.keyboard.press("Control+j");
  await dock.getByLabel("Question").fill("Search the web for platform.lab problem");
  await dock.getByRole("button", { name: "Send" }).click();
  await expect(dock.getByText("Web search blocked: the query contained internal data")).toBeVisible();
  await expect(dock.getByText("Internet lookup unavailable")).toHaveCount(0);
  await expect(dock.getByText("Searched the web for")).toHaveCount(0);
  await expect(dock.getByRole("link")).toHaveCount(0);
});
