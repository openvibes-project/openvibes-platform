import { describe, expect, it } from "vitest";

import { vulnTitle } from "./format";

describe("vulnTitle", () => {
  it("puts the package before the first sentence of the summary", () => {
    expect(vulnTitle(["brotli", "libbrotli"], "A buffer overflow in the Brotli decoder allows a crash. Fixed in 1.2.1.")).toBe("brotli: A buffer overflow in the Brotli decoder allows a crash");
  });
  it("skips an opening sentence that only says what the product is", () => {
    expect(vulnTitle(["vim"], "Vim is an open source, command line text editor. Prior to version 9.2.007, a heap overflow occurs in spell checking. Fixed.")).toBe("vim: Prior to version 9.2.007, a heap overflow occurs in spell checking");
  });
  it("leaves a title that already starts with the package, and one with no package", () => {
    expect(vulnTitle(["libevent"], "libevent-2.1.13-1.fc44")).toBe("libevent-2.1.13-1.fc44");
    expect(vulnTitle([], "CVE-2026-1")).toBe("CVE-2026-1");
  });
  it("cuts a long summary at 140 characters", () => {
    const shown = vulnTitle(["vim"], "x".repeat(300));
    expect(shown).toHaveLength(5 + 140);
    expect(shown.endsWith("…")).toBe(true);
  });
});
