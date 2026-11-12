// Set your password after a one-time sign-in (#576), as markup.
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { SetPassword } from "./SetPassword";

const render = (known?: string) => renderToStaticMarkup(<SetPassword required known={known} onDone={() => undefined} />);

describe("SetPassword", () => {
  it("does not ask again for the one-time password typed at sign-in", () => {
    const html = render("one-time-password-1");
    expect(html).not.toContain("One-time password");
    expect(html).toContain("New password again");
  });

  it("asks for it when it is not known, as after a reload", () => {
    expect(render()).toContain("One-time password");
  });
});
