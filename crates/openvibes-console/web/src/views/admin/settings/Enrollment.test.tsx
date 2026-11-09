// Settings › Enrollment's "Add a host" as markup: the Windows row (#540).
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

// nav.ts reads the location when loaded.
vi.hoisted(() => {
  Object.assign(globalThis, { window: { location: { pathname: "/", search: "" }, history: { replaceState() {} }, addEventListener() {}, removeEventListener() {} } });
});

import { AGENT_RELEASES, AddHostBody } from "./Enrollment";

const linux = "curl -fsSL https://openvibes-project.github.io/install.sh | sudo sh -s -- --agent --platform p --token T --ca-sha256 AB:CD";
const windows = "msiexec /i (Get-Item .\\openvibes-agent-*-x64.msi).FullName /qn PLATFORM_URL=https://p PLATFORM_CA_SHA256=AB:CD ENROLLMENT_TOKEN=T | Out-Null";

describe("Add a host", () => {
  it("offers the Windows MSI, the CA and the install line", () => {
    const html = renderToStaticMarkup(<AddHostBody command={{ command: linux, windows }} />);
    expect(html).toContain("Windows (preview)");
    expect(html).toContain(`href="${AGENT_RELEASES}"`);
    expect(html).toMatch(/<a [^>]*href="\/api\/v1\/agent-ca"[^>]*download/);
    expect(html).toMatch(/<button[^>]*title="A one-line install to paste into PowerShell as administrator"[^>]*>/);
    expect(html).not.toMatch(/<button[^>]*disabled=""[^>]*title="A one-line install to paste into PowerShell/);
    // The secret is copied, never shown.
    expect(html).not.toContain("ENROLLMENT_TOKEN=T");
  });

  it("says why Windows is not offered when the platform's rules port is not the default", () => {
    const html = renderToStaticMarkup(<AddHostBody command={{ command: linux, windows: null }} />);
    expect(html).toContain("Not offered: this platform&#x27;s rule distribution port is not 18424");
    expect(html).not.toContain("/api/v1/agent-ca");
  });
});
