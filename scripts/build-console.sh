#!/usr/bin/env bash
# Build and validate the browser application before embedding it in Rust.
set -euo pipefail

readonly required_node_version="22.23.1"
readonly script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly repository_root="$(cd -- "${script_dir}/.." && pwd -P)"
readonly web_root="${repository_root}/crates/openvibes-console/web"
readonly dist_root="${web_root}/dist"
readonly openapi_snapshot="${repository_root}/docs/api/console-v1.openapi.json"

for required_command in node npm cargo; do
    if ! command -v "${required_command}" >/dev/null 2>&1; then
        printf 'error: required command is unavailable: %s\n' "${required_command}" >&2
        exit 1
    fi
done

"${script_dir}/build-console-brand-assets.sh"

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

cd -- "${repository_root}"
cargo run --quiet --locked -p openvibes-console --bin export_openapi -- \
    --check "${openapi_snapshot}"

cd -- "${web_root}"
npm ci --no-audit --no-fund
npm run check:api
npm run lint
npm run typecheck
npm test
npm run build

node --input-type=module - "${web_root}" "${dist_root}" <<'NODE'
import { createHash } from "node:crypto";
import { lstat, readFile, readdir, writeFile } from "node:fs/promises";
import { isAbsolute, relative, resolve, sep } from "node:path";

const webRoot = resolve(process.argv[2]);
const publicRoot = resolve(webRoot, "public");
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

async function collectFiles(root, ignoredTopDirectories = new Set(), ignoredFiles = new Set()) {
  const files = [];
  async function visit(directory) {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const path = resolve(directory, entry.name);
      const metadata = await lstat(path);
      const relativePath = relative(root, path).split(sep).join("/");
      if (metadata.isSymbolicLink()) {
        throw new Error(`frontend build input must not be a symbolic link: ${path}`);
      }
      if (metadata.isDirectory()) {
        if (!relativePath.includes("/") && ignoredTopDirectories.has(relativePath)) {
          continue;
        }
        await visit(path);
      } else if (metadata.isFile()) {
        if (!ignoredFiles.has(relativePath)) {
          files.push(relativePath);
        }
      } else {
        throw new Error(`frontend build input must be a regular file: ${path}`);
      }
    }
  }
  await visit(root);
  return files.sort();
}

async function digestFiles(root, files) {
  const digest = createHash("sha256");
  for (const relativePath of files) {
    const bytes = await readFile(resolve(root, relativePath));
    const length = Buffer.alloc(8);
    length.writeBigUInt64BE(BigInt(bytes.length));
    digest.update(relativePath, "utf8");
    digest.update(Buffer.from([0]));
    digest.update(length);
    digest.update(bytes);
  }
  return digest.digest("hex");
}

const inputFiles = await collectFiles(
  webRoot,
  new Set(["coverage", "dist", "node_modules", "playwright-report", "test-results"]),
);
const outputFiles = await collectFiles(
  distRoot,
  new Set(),
  new Set([".gitkeep", "build-stamp.json"]),
);
const buildStamp = {
  version: 1,
  algorithm: "sha256",
  inputDigest: await digestFiles(webRoot, inputFiles),
  inputFiles,
  outputDigest: await digestFiles(distRoot, outputFiles),
  outputFiles,
};
await writeFile(resolve(distRoot, "build-stamp.json"), `${JSON.stringify(buildStamp, null, 2)}\n`, {
  encoding: "utf8",
  flag: "w",
});
await writeFile(resolve(distRoot, ".gitkeep"), "\n", { flag: "w" });
NODE

cd -- "${repository_root}"
cargo check --locked -p openvibes-console --features embedded-ui
cargo build --release --locked -p openvibes-console --features embedded-ui
