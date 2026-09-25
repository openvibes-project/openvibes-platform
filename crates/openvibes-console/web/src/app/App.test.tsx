import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { App } from "./App";

describe("console shell", () => {
  it("renders navigation landmarks, the skip link, and seeded warning", () => {
    const markup = renderToStaticMarkup(<App path="/findings" seeded />);

    expect(markup).toContain("Skip to main content");
    expect(markup).toContain('aria-label="Primary navigation"');
    expect(markup).toContain('aria-current="page"');
    expect(markup).toContain('aria-pressed="false"');
    expect(markup).not.toContain("aria-expanded");
    expect(markup).toContain("Seeded environment");
    expect(markup).toContain("latest observed matches");
    expect(markup).toContain('/brand/openvibes-wordmark-light.svg');
    expect(markup).toContain('/brand/openvibes-wordmark-dark.svg');
    expect(markup).not.toContain("placeholder");
  });

  it("renders a bounded fallback for unknown browser routes", () => {
    const markup = renderToStaticMarkup(<App path="/not-a-console-route" />);

    expect(markup).toContain("Page not found");
    expect(markup).toContain("Return to Overview");
  });

  it("renders a local sign-in form on the login route", () => {
    const markup = renderToStaticMarkup(<App path="/login" />);

    expect(markup).toContain("Sign in");
    expect(markup).toContain('name="username"');
    expect(markup).toContain('name="password"');
    expect(markup).toContain('autoComplete="current-password"');
    expect(markup).toContain("disabled");
    expect(markup).not.toContain("Seeded environment");
  });

  it("renders the bounded audit search screen", () => {
    const markup = renderToStaticMarkup(<App path="/audit" seeded />);

    expect(markup).toContain("Privileged activity");
    expect(markup).toContain('name="actor"');
    expect(markup).toContain('name="action"');
    expect(markup).toContain("Apply filters");
    expect(markup).toContain("Download filtered CSV");
  });

  it("renders the access-control inventory screen", () => {
    const markup = renderToStaticMarkup(<App path="/access" seeded />);
    expect(markup).toContain("Roles and access bindings");
    expect(markup).toContain("Loading current data");
    expect(markup).not.toContain("Workspace ready for bounded console data");
  });
});
