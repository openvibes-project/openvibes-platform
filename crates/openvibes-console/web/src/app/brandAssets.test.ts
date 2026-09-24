import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const brandRoot = new URL("../../public/brand/", import.meta.url);

describe("production brand assets", () => {
  it("keeps SVG sources self-contained and PNG derivatives at their declared sizes", () => {
    for (const name of [
      "openvibes-mark.svg",
      "openvibes-wordmark-light.svg",
      "openvibes-wordmark-dark.svg",
    ]) {
      const source = readFileSync(new URL(name, brandRoot), "utf8");
      expect(source).toContain("viewBox=");
      expect(source).not.toMatch(/<(?:animate|foreignObject|image|script|text)\b/i);
      expect(source).not.toMatch(/\b(?:href|src)=/i);
      expect(source).not.toContain("<rect");
    }

    for (const [name, expectedSize] of [
      ["openvibes-favicon-32.png", 32],
      ["openvibes-mark-192.png", 192],
      ["openvibes-mark-512.png", 512],
    ] as const) {
      const png = readFileSync(new URL(name, brandRoot));
      expect(png.subarray(0, 8).toString("hex")).toBe("89504e470d0a1a0a");
      expect(png.readUInt32BE(16)).toBe(expectedSize);
      expect(png.readUInt32BE(20)).toBe(expectedSize);
      expect(png[25]).toBe(6);
    }
  });
});
