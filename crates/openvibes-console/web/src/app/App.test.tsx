import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, describe, expect, it, vi } from "vitest";

import { App } from "./App";

function renderAsSeededPersona(path: string, persona: string) {
  vi.stubGlobal("localStorage", {
    getItem: (key: string) => key === "openvibes.dev.persona" ? persona : null,
  });
  return renderToStaticMarkup(<App path={path} seeded />);
}

describe("console shell", () => {
  afterEach(() => vi.unstubAllGlobals());

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
    const markup = renderAsSeededPersona("/audit", "admin");

    expect(markup).toContain("Privileged activity");
    expect(markup).toContain('name="actor"');
    expect(markup).toContain('name="action"');
    expect(markup).toContain("Apply filters");
    expect(markup).toContain("Download filtered CSV");
  });

  it("renders the access-control inventory screen", () => {
    const markup = renderAsSeededPersona("/access", "admin");
    expect(markup).toContain("Roles and access bindings");
    expect(markup).toContain("Loading current data");
    expect(markup).not.toContain("Workspace ready for bounded console data");
  });

  it("hides Rule sets from Viewer and denies direct navigation", () => {
    const navigation = renderAsSeededPersona("/", "viewer");
    expect(navigation).not.toContain('href="/rule-sets"');

    const restrictedPage = renderAsSeededPersona("/rule-sets", "viewer");
    expect(restrictedPage).toContain("You do not have access to this page");
    expect(restrictedPage).not.toContain('id="rules-title"');
  });

  it("shows Rule sets to Admin", () => {
    const markup = renderAsSeededPersona("/", "admin");
    expect(markup).toContain('href="/rule-sets"');
  });
});
