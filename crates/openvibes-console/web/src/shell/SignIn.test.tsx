import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { SsoOption } from "./SignIn";

describe("SsoOption", () => {
  it("offers single sign-on only when it is on", () => {
    const on = renderToStaticMarkup(<SsoOption enabled failed={false} />);
    expect(on).toContain('href="/auth/saml/start"');
    expect(on).toContain("Sign in with single sign-on");
    expect(renderToStaticMarkup(<SsoOption enabled={false} failed={false} />)).toBe("");
  });

  it("explains a failed attempt without saying why", () => {
    const html = renderToStaticMarkup(<SsoOption enabled failed />);
    expect(html).toContain("Single sign-on did not work");
  });
});
