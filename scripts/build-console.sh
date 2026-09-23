#!/usr/bin/env bash
# Build and validate the browser application before embedding it in Rust.
set -euo pipefail

readonly required_node_version="22.23.1"
readonly script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly repository_root="$(cd -- "${script_dir}/.." && pwd -P)"
readonly web_root="${repository_root}/crates/openvibes-console/web"
readonly dist_root="${web_root}/dist"

for required_command in node npm cargo; do
    if ! command -v "${required_command}" >/dev/null 2>&1; then
        printf 'error: required command is unavailable: %s\n' "${required_command}" >&2
        exit 1
    fi
done

actual_node_version="$(node --version)"
if [[ "${actual_node_version}" != "v${required_node_version}" ]]; then
    printf 'error: Node.js v%s is required (found %s)\n' \
        "${required_node_version}" "${actual_node_version}" >&2
    exit 1
fi

if [[ ! -f "${web_root}/package-lock.json" ]]; then
    printf 'error: missing frontend lock file: %s\n' "${web_root}/package-lock.json" >&2
    exit 1
fi

cd -- "${web_root}"
npm ci --no-audit --no-fund
npm run lint
npm run typecheck
npm test
npm audit --audit-level=low
npm run build

node --input-type=module - "${web_root}" "${dist_root}" <<'NODE'
import { lstat, readFile, readdir } from "node:fs/promises";
import { isAbsolute, relative, resolve, sep } from "node:path";

const publicRoot = resolve(process.argv[2], "public");
const distRoot = resolve(process.argv[3]);
const manifestPath = resolve(distRoot, ".vite/manifest.json");

async function requireRegularFile(relativePath) {
  if (
    typeof relativePath !== "string" ||
    relativePath.length === 0 ||
    isAbsolute(relativePath)
  ) {
    throw new Error(`invalid manifest asset path: ${JSON.stringify(relativePath)}`);
  }

  const assetPath = resolve(distRoot, relativePath);
  const relativeToDist = relative(distRoot, assetPath);
  if (
    relativeToDist === "" ||
    relativeToDist === ".." ||
    relativeToDist.startsWith(`..${sep}`) ||
    isAbsolute(relativeToDist)
  ) {
    throw new Error(`manifest asset escapes dist/: ${relativePath}`);
  }

  const metadata = await lstat(assetPath);
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size === 0) {
    throw new Error(`manifest asset is not a non-empty regular file: ${relativePath}`);
  }
}

async function requireCopiedPublicFiles(directory = publicRoot) {
  let brandFileCount = 0;
  for (const directoryEntry of await readdir(directory, { withFileTypes: true })) {
    const sourcePath = resolve(directory, directoryEntry.name);
    if (directoryEntry.isSymbolicLink()) {
      throw new Error(`public asset must not be a symbolic link: ${sourcePath}`);
    }
    if (directoryEntry.isDirectory()) {
      brandFileCount += await requireCopiedPublicFiles(sourcePath);
      continue;
    }
    if (!directoryEntry.isFile()) {
      throw new Error(`public asset must be a regular file: ${sourcePath}`);
    }

    const relativePath = relative(publicRoot, sourcePath);
    await requireRegularFile(relativePath);
    if (relativePath === "brand" || relativePath.startsWith(`brand${sep}`)) {
      brandFileCount += 1;
    }
  }
  return brandFileCount;
}

const manifestMetadata = await lstat(manifestPath);
if (
  !manifestMetadata.isFile() ||
  manifestMetadata.isSymbolicLink() ||
  manifestMetadata.size === 0
) {
  throw new Error("Vite manifest is not a non-empty regular file");
}

const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
if (manifest === null || typeof manifest !== "object" || Array.isArray(manifest)) {
  throw new Error("Vite manifest is not an object");
}
const entries = Object.values(manifest);
const indexEntry = manifest["index.html"];
if (
  indexEntry === null ||
  typeof indexEntry !== "object" ||
  Array.isArray(indexEntry) ||
  indexEntry.isEntry !== true
) {
  throw new Error("Vite manifest has no index.html application entry");
}

await requireRegularFile("index.html");
await requireRegularFile("app.webmanifest");
const webManifest = JSON.parse(await readFile(resolve(distRoot, "app.webmanifest"), "utf8"));
if (webManifest === null || typeof webManifest !== "object" || Array.isArray(webManifest)) {
  throw new Error("app.webmanifest is not a JSON object");
}
if ((await requireCopiedPublicFiles()) === 0) {
  throw new Error("Vite output contains no copied brand assets");
}
for (const entry of entries) {
  if (entry === null || typeof entry !== "object" || Array.isArray(entry)) {
    throw new Error("Vite manifest contains an invalid entry");
  }
  await requireRegularFile(entry.file);
  for (const field of ["css", "assets"]) {
    const references = entry[field] ?? [];
    if (!Array.isArray(references)) {
      throw new Error(`Vite manifest field is not an array: ${field}`);
    }
    for (const reference of references) {
      await requireRegularFile(reference);
    }
  }
}
NODE

cd -- "${repository_root}"
cargo check --locked -p openvibes-console --features embedded-ui
cargo build --release --locked -p openvibes-console --features embedded-ui
