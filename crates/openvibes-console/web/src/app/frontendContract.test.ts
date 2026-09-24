import { readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { describe, expect, it } from "vitest";

import frontendContract from "../../frontend-contract.json";
import { navigationGroups, pageRoutes } from "./navigation";

const webRoot = new URL("../../", import.meta.url);
const publicRoot = new URL("../../public/", import.meta.url);

function publicFiles(directory: string): string[] {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const path = join(directory, entry.name);
    if (entry.isSymbolicLink()) {
      throw new Error(`public asset must not be a symbolic link: ${path}`);
    }
    if (entry.isDirectory()) {
      return publicFiles(path);
    }
    if (!entry.isFile() || statSync(path).size === 0) {
      throw new Error(`public asset must be a non-empty regular file: ${path}`);
    }
    return [relative(publicRoot.pathname, path).replaceAll("\\", "/")];
  });
}

describe("frontend contract", () => {
  it("keeps Rust browser routing and TypeScript navigation on the same exact route set", () => {
    const navigationRoutes = navigationGroups.flatMap((group) => group.items.map((item) => item.path));

    expect(new Set(navigationRoutes).size).toBe(navigationRoutes.length);
    expect([...navigationRoutes].sort()).toEqual([...frontendContract.browserRoutes].sort());
    expect([...pageRoutes].sort()).toEqual([...frontendContract.browserRoutes].sort());
  });

  it("lists every public source asset exactly once", () => {
    const declaredFiles = frontendContract.publicAssets.map((asset) => asset.file);
    const declaredRoutes = frontendContract.publicAssets.map((asset) => asset.route);

    expect(new Set(declaredFiles).size).toBe(declaredFiles.length);
    expect(new Set(declaredRoutes).size).toBe(declaredRoutes.length);
    expect(declaredFiles.sort()).toEqual(publicFiles(publicRoot.pathname).sort());
    expect(statSync(new URL("../../frontend-contract.json", import.meta.url)).isFile()).toBe(true);
    expect(statSync(webRoot).isDirectory()).toBe(true);
  });
});
