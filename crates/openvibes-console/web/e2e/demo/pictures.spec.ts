import { deflateSync } from "node:zlib";

import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

// Profile pictures on the demo (spec §9.2, screen 7c): choose a file, move
// and zoom the round preview, save, see it everywhere, remove it. The
// conversion itself is covered by openvibes-picture's tests and pictures_http.rs.
test.beforeEach(async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { level: 1 })).toContainText("Alex");
});

const crc = (bytes: Buffer) => {
  let c = ~0;
  for (const byte of bytes) {
    c ^= byte;
    for (let bit = 0; bit < 8; bit += 1) c = c & 1 ? (c >>> 1) ^ 0xedb88320 : c >>> 1;
  }
  return ~c >>> 0;
};
const chunk = (type: string, data: Buffer) => {
  const body = Buffer.concat([Buffer.from(type), data]);
  const out = Buffer.alloc(12 + data.length);
  out.writeUInt32BE(data.length, 0);
  body.copy(out, 4);
  out.writeUInt32BE(crc(body), 8 + data.length);
  return out;
};
/** A `width` x `height` PNG, red on the left half and blue on the right. */
function png(width: number, height: number): Buffer {
  const header = Buffer.alloc(13);
  header.writeUInt32BE(width, 0);
  header.writeUInt32BE(height, 4);
  header.set([8, 2, 0, 0, 0], 8);
  const rows = Buffer.alloc((width * 3 + 1) * height);
  for (let y = 0; y < height; y += 1) {
    for (let x = 0; x < width; x += 1) rows.set(x < width / 2 ? [200, 40, 40] : [40, 40, 200], y * (width * 3 + 1) + 1 + x * 3);
  }
  return Buffer.concat([Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]), chunk("IHDR", header), chunk("IDAT", deflateSync(rows)), chunk("IEND", Buffer.alloc(0))]);
}

test("a person sets, sees and removes their own picture", async ({ page }) => {
  const account = page.getByRole("button", { name: "Account" });
  await expect(account.locator("img")).toHaveCount(0);
  await account.click();
  await page.getByRole("menuitem", { name: "Change picture" }).click();
  const dialog = page.getByRole("dialog", { name: "Change picture" });
  await expect(dialog.getByRole("button", { name: "Save picture" })).toBeDisabled();
  await expect(dialog.getByRole("button", { name: "Remove picture" })).toHaveCount(0);

  await dialog.getByLabel("Picture file").setInputFiles({ name: "me.png", mimeType: "image/png", buffer: png(200, 100) });
  const preview = dialog.locator(".picture-crop img");
  await expect(preview).toBeVisible();
  // At first the whole short side is kept: a 100 px square of the 200 x 100 picture.
  await expect(preview).toHaveCSS("width", "480px");
  await dialog.getByLabel("Zoom").fill("2");
  await expect(preview).toHaveCSS("width", "960px");
  // Arrow keys move the picture under the circle.
  const position = dialog.getByRole("group", { name: /Picture position/ });
  await position.focus();
  const before = await preview.evaluate((img) => img.style.left);
  await page.keyboard.press("ArrowLeft");
  await expect.poll(() => preview.evaluate((img) => img.style.left)).not.toBe(before);
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);

  await dialog.getByRole("button", { name: "Save picture" }).click();
  await expect(page.locator(".toast").last()).toContainText("Picture saved");
  await expect(account.locator("img")).toBeVisible();

  // The same picture is in the People list and on their page, and can be removed there.
  // (In-page navigation: a reload would start the demo afresh, without the picture.)
  await page.getByRole("link", { name: "Settings" }).click();
  await page.mouse.move(900, 600);
  await page.getByRole("tab", { name: "People" }).click();
  const row = page.getByRole("table", { name: "People" }).locator("tbody tr").filter({ hasText: "Alex Admin" });
  await expect(row.locator("img")).toBeVisible();
  await row.locator("td").first().click();
  await expect(page.locator(".person-page__avatar img")).toBeVisible();
  await page.getByRole("button", { name: "Change picture" }).click();
  await dialog.getByRole("button", { name: "Remove picture" }).click();
  await expect(page.locator(".toast").last()).toContainText("Picture removed");
  await expect(page.locator(".person-page__avatar img")).toHaveCount(0);
  await expect(account.locator("img")).toHaveCount(0);
});
