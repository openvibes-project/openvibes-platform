import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, describe, expect, it } from "vitest";

import { Avatar, clearDemoPictures, initialsOf, pictureSrc, setDemoPicture } from "./avatar";

afterEach(clearDemoPictures);

describe("avatar", () => {
  it("shows initials without a picture", () => {
    expect(initialsOf("Wendy Ward")).toBe("WW");
    expect(initialsOf("  ")).toBe("?");
    const html = renderToStaticMarkup(<Avatar userId="u-1" name="Wendy Ward" picture={null} />);
    expect(html).toContain(">WW<");
    expect(html).not.toContain("<img");
  });
  it("shows the picture by its version", () => {
    const html = renderToStaticMarkup(<Avatar userId="u 1" name="Wendy Ward" picture="abc" size={256} />);
    expect(html).toContain('src="/api/v1/users/u%201/picture?size=256&amp;v=abc"');
    expect(html).not.toContain("WW");
  });
  it("uses the demo's own copy when there is one", () => {
    setDemoPicture("u-1", { version: "v", url: "data:image/png;base64,AA==" });
    expect(pictureSrc("u-1", "v", 64)).toBe("data:image/png;base64,AA==");
  });
});
