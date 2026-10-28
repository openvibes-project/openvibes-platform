# Dependencies

Everything the platform depends on, in two lists: what goes into the
finished builds (the RPMs and the hosts they run on), and what is needed
only to develop, test and build them. Each list names the dependencies we
chose ourselves; the indirect ones they pull in are counted, not listed.
`Cargo.lock` and `crates/openvibes-console/web/package-lock.json` hold the
full, exact sets.

Checked against `main` on 2026-10-23. Update this page in the same change
that adds, removes or bumps a dependency, and update everything before
each release ([Before each release](#before-each-release)); the commands under
[Refreshing this page](#refreshing-this-page) print the current state.

## Before each release

Every release brings all dependencies up to date first, in a pull request
of its own that merges before the tag. Its CI and the local gate must be
green, including `cargo audit` and `npm audit`.

1. Rust crates: raise every version in the `Cargo.toml` files to the newest
   release, then `cargo update`.
2. The Rust toolchain in `rust-toolchain.toml` (and `rust-version`) to the
   newest stable.
3. Console npm packages (`npm outdated` in `crates/openvibes-console/web`),
   and the pinned Node.js version.
4. The agent revision of `openvibes-core`, `openvibes-rules` and
   `openvibes-transport`.
5. llama.cpp (`packaging/llm/llama-cpp.pin`), and a check for a newer model
   (`packaging/llm/model.pin`).
6. CI: the commit pins of the GitHub Actions, `cargo-audit`, and the
   container images.

A dependency may stay behind only with the reason written next to it on
this page. The same pull request then updates this page: versions,
counts and the date.

## 1. In the finished builds

### Rust crates compiled into the programs

The programs are `openvibes-ingest`, `-admin`, `-distribution`, `-signer`,
`-fetch`, `-vulns`, `-netlog`, `-console` and `openvibes-llm-check`. They
compile in the 49 crates below and **299 indirect crates** (348 in all), plus
10 crates used only by build scripts (proc-macro and `build.rs` helpers, not
in the programs).

| Crate | Version | Licence | Used for |
|---|---|---|---|
| aes | 0.9.3 | MIT OR Apache-2.0 | OpenSSL traditional key encryption (AES) |
| argon2 | 0.6.0 | MIT OR Apache-2.0 | Console password hashes |
| axum | 0.8.9 | MIT | Console web server and API |
| base64 | 0.23.1 | MIT OR Apache-2.0 | Encoding keys and signatures |
| cbc | 0.2.1 | MIT OR Apache-2.0 | OpenSSL traditional key encryption (CBC mode) |
| chrono | 0.4.45 | MIT OR Apache-2.0 | Dates and times everywhere |
| clap | 4.6.7 | MIT OR Apache-2.0 | Command lines of every program |
| der | 0.8.2 | Apache-2.0 OR MIT | Wrapping company keys as PKCS#8 |
| deadpool-postgres | 0.14.2 | MIT OR Apache-2.0 | PostgreSQL connection pool |
| des | 0.9.0 | MIT OR Apache-2.0 | OpenSSL traditional key encryption (3DES) |
| ed25519-dalek | 3.0.0 | BSD-3-Clause | Signing and checking rule bundles |
| flate2 | 1.1.10 | MIT OR Apache-2.0 | gzip (agent uploads, vulnerability feeds) |
| futures-util | 0.3.34 | MIT OR Apache-2.0 | Console streaming responses |
| hyper | 1.11.1 | MIT | Agent connections (HTTP over mTLS) |
| hyper-util | 0.1.20 | MIT | Agent connections (server glue) |
| libc | 0.2.189 | MIT OR Apache-2.0 | Admin TUI: terminal and process calls |
| md-5 | 0.11.0 | MIT OR Apache-2.0 | OpenSSL traditional key encryption (key derivation) |
| openvibes-core | 0.2.7 | Apache-2.0 | Our wire types, from openvibes-agent (git, pinned commit) |
| openvibes-rules | 0.2.7 | Apache-2.0 | Our rule engine, from openvibes-agent (git, pinned commit) |
| p12-keystore | 0.4.1 | MIT OR Apache-2.0 | Opening `.p12`/`.pfx` files |
| pkcs5 | 0.8.1 | Apache-2.0 OR MIT | Unlocking password-protected keys |
| quick-xml | 0.42.0 | MIT | Reading Fedora `updateinfo.xml` |
| ratatui | 0.30.2 | MIT | Admin TUI screens |
| rcgen | 0.14.10 | MIT OR Apache-2.0 | Making the platform's CA and certificates |
| gif | 0.14.2 | MIT OR Apache-2.0 | Counting the frames of an uploaded GIF (openvibes-picture) |
| image | 0.25.10 | MIT OR Apache-2.0 | Decoding uploaded profile pictures (JPEG, PNG, GIF, WebP, BMP, TIFF) and resizing them |
| image-webp | 0.2.4 | MIT OR Apache-2.0 | Reading the header of an animated WebP upload |
| ring | 0.17.14 | Apache-2.0 AND ISC | Cryptography under rustls and rcgen |
| rpassword | 7.5.4 | Apache-2.0 | Reading passwords at the terminal |
| rustls | 0.23.46 | Apache-2.0 OR ISC OR MIT | TLS for the console and agent connections |
| rustls-pki-types | 1.15.1 | MIT OR Apache-2.0 | Certificate types for the import self-check |
| rustls-webpki | 0.103.16 | ISC | Import self-check: verifying as agents do (also under rustls) |
| ruzstd | 0.9.1 | MIT | zstd in Fedora repository metadata |
| serde | 1.0.229 | MIT OR Apache-2.0 | Reading and writing data formats |
| serde_json | 1.0.151 | MIT OR Apache-2.0 | JSON |
| sha2 | 0.11.0 | MIT OR Apache-2.0 | Checksums and fingerprints |
| subtle | 2.6.1 | BSD-3-Clause | Constant-time comparison of secrets |
| time | 0.3.55 | MIT OR Apache-2.0 | Certificate validity dates (rcgen's type) |
| tokio | 1.54.1 | MIT | Async runtime of every service |
| tokio-postgres | 0.7.18 | MIT OR Apache-2.0 | PostgreSQL client |
| tokio-rustls | 0.26.5 | MIT OR Apache-2.0 | TLS on tokio sockets |
| toml | 1.1.6 | MIT OR Apache-2.0 | Reading config files |
| toml_edit | 0.25.15 | MIT OR Apache-2.0 | Changing config files, keeping comments |
| tower | 0.5.3 | MIT | Middleware for the console and agent servers |
| tracing | 0.1.44 | MIT | Logging |
| tracing-subscriber | 0.3.23 | MIT | Log output to the journal |
| unicode-normalization | 0.1.25 | MIT OR Apache-2.0 | Normalising passwords before hashing |
| ureq | 3.4.2 | MIT OR Apache-2.0 | HTTPS client (vulnerability feeds, assistant lookups) |
| webp-animation | 0.10.0 | MIT | Encoding the stored WebP pictures (builds libwebp from source; needs a C compiler to build) |
| utoipa | 5.5.0 | MIT OR Apache-2.0 | The console API's OpenAPI description |
| x509-parser | 0.18.1 | MIT OR Apache-2.0 | Reading certificates |
| zeroize | 1.9.0 | Apache-2.0 OR MIT | Wiping secrets from memory |
| zip | 9.0.3 | MIT | Reading the OSV data archive |

The Rust standard library (from the Rust toolchain, MIT OR Apache-2.0) is
compiled in as well.

### Console web interface

Built into `openvibes-console` as static files.

| Package | Version | Licence | Used for |
|---|---|---|---|
| react | 19.2.7 | MIT | The interface |
| react-dom | 19.2.7 | MIT | Drawing it in the browser |

They pull in 1 indirect package (`scheduler`, MIT).

### Third-party programs and data in the packages

| What | Version | Licence | Package | Used for |
|---|---|---|---|---|
| llama.cpp (`llama-server`) | v0.6.0, pinned by checksum in `packaging/llm/llama-cpp.pin` | MIT | openvibes-llm (CPU), openvibes-llm-vulkan (GPU) | Runs the assistant's model |
| Qwen3.5-4B, Q4_K_M GGUF | pinned in `packaging/llm/model.pin` | Apache-2.0 | openvibes-llm-model | The assistant's model (2.7 GB) |

### What the packages require from the operating system

Fedora packages the RPMs name with `Requires`:

| Package | Needed by | Why |
|---|---|---|
| systemd, shadow-utils, procps-ng | every service package | Units, the service users, stopping old processes on upgrade |
| sudo, polkit | openvibes-admin | Admin helper runs as root from the TUI |
| curl, iproute | openvibes-admin | Health checks; `ss` and `ip` for ports and addresses |
| policycoreutils | openvibes-llm | Loading its SELinux policy |

Weak dependency: openvibes-console recommends openvibes-fetch.

### Installed or used on the host by Setup

| What | Why |
|---|---|
| PostgreSQL 17 or later (`postgresql-server`, `postgresql`, `postgresql-private-libs`) | The database; Setup installs it with dnf unless it is already there |
| firewalld (`firewall-cmd`) | Opening and closing the platform's ports; if it is not running, Setup says which ports to open by hand |
| dnf, rpm | Installing and updating parts, and the optional agent |
| systemd, journalctl, logger | Running the services; logs and the admin audit lines |
| runuser, sudo | The helper's root work; the Shell page |
| openvibes-agent (optional) | The "Agent on this host" optional part |

### Online services the platform reads

| Service | Address | Used for |
|---|---|---|
| OSV | `osv-vulnerabilities.storage.googleapis.com`, `api.osv.dev` | Vulnerability records |
| NVD | `services.nvd.nist.gov` | CVE details and scores |
| EPSS | `epss.empiricalsecurity.com` | Exploit likelihood scores |
| CISA KEV | `www.cisa.gov` | Known exploited vulnerabilities |
| ENISA EUVD | `euvdservices.enisa.europa.eu` | EU vulnerability records |
| Fedora Bodhi and mirrors | `bodhi.fedoraproject.org`, `mirrors.fedoraproject.org` | Fedora updates and repository metadata |
| SearXNG (optional, the admin's own) | set by the admin | The assistant's opt-in web search (openvibes-fetch) |

## 2. For development only

Nothing below ships.

### Toolchains

| Tool | Version | Used for |
|---|---|---|
| Rust | 1.95.0 (`rust-toolchain.toml`, with clippy and rustfmt), edition 2024 | Building and checking every crate |
| Node.js and npm | 22.23.1 (release build); 22.12+ and npm 10+ for development | The console interface |
| PostgreSQL server binaries (`initdb`, `pg_ctl`, `psql`) | 17 or later | The tests' throwaway database (`scripts/test-db.sh`) |
| gcc, gcc-c++, cmake | Fedora's | Building `llama-server` |
| glslc and the Vulkan headers | Fedora's | Building the Vulkan `llama-server` |
| rpm-build, systemd-rpm-macros, rpm-sign, gnupg2, cpio, createrepo_c | Fedora's | Building, signing and checking the RPMs and repository |
| ImageMagick | Fedora's | Console brand images |
| Python 3 | standard library only | `scripts/tiny-gguf.py`, `scripts/attack-data.py` |

### Rust crates used only in tests and tools

| Crate | Version | Licence | Used for |
|---|---|---|---|
| openvibes-transport | 0.2.7 | Apache-2.0 | The agent's client side, from openvibes-agent (git, pinned commit): tests and `openvibes-load` |

Tests also use `tokio`'s `test-util` feature. The load generator
`scripts/load` (`openvibes-load`) is not packaged.

### Console npm development packages

They pull in **237 indirect packages** (250 in all).

| Package | Version | Licence | Used for |
|---|---|---|---|
| @axe-core/playwright | 4.13.0 | MPL-2.0 | Accessibility checks in browser tests |
| @eslint/js | 10.0.1 | MIT | Lint rules |
| @playwright/test | 1.63.0 | Apache-2.0 | Browser tests |
| @types/node | 22.20.4 | MIT | Types for build scripts |
| @types/react | 19.2.17 | MIT | Types |
| @types/react-dom | 19.2.3 | MIT | Types |
| eslint | 10.11.0 | MIT | Lint |
| eslint-plugin-react-hooks | 7.1.1 | MIT | Lint rules for React hooks |
| openapi-typescript | 7.13.0 | MIT | Generating the API client types |
| typescript | 5.8.3 | Apache-2.0 | Type checking |
| typescript-eslint | 8.70.1 | MIT | Lint for TypeScript |
| vite | 7.3.7 | MIT | Dev server and bundler |
| vitest | 5.0.5 | MIT | Unit tests |

### Continuous integration

| What | Version | Used for |
|---|---|---|
| GitHub runners | `ubuntu-24.04` | Every job |
| Containers | `registry.fedoraproject.org/fedora:44`, `postgres:18` | RPM builds and system tests; the tests' database |
| actions/checkout, cache, setup-node, upload-artifact, download-artifact, upload-pages-artifact, deploy-pages | pinned by commit | Workflow steps |
| Swatinem/rust-cache | pinned by commit | Rust build cache |
| taiki-e/install-action | pinned by commit | Installs cargo-audit |
| cargo-audit | 0.22.2 | Rust advisories (`cargo audit`) |
| npm audit | with npm | npm advisories |
| Playwright browsers | Chromium, Firefox | Console browser tests |
| Ubuntu packages | auditd, rpm2cpio, cpio, jq, podman | System tests |
| Fedora packages | git, systemd, postgresql-server, sqlite, jq, curl, procps-ng, util-linux, selinux-policy-targeted | System tests |
| SonarCloud | service | Code analysis |

## Refreshing this page

```sh
# Rust: direct dependencies and licences per crate
cargo tree --edges normal --depth 1 --format '{p} {l}' --target x86_64-unknown-linux-gnu
# Rust: everything compiled into the programs
cargo tree --edges normal --prefix none --target x86_64-unknown-linux-gnu --no-dedupe | sort -u
# Console
cd crates/openvibes-console/web && npm ls --depth 0 && npm ls --omit dev --all
```
