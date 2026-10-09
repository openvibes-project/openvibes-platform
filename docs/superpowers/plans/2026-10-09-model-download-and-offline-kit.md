# Model download and offline kit — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop shipping the 2.5 GB model in our packages. Online installs fetch it from Hugging Face, pinned by SHA-256. A per-Fedora offline kit on each GitHub release installs the whole platform, PostgreSQL included, air-gapped. Upgrades from 0.2.5 keep the installed model.

**Architecture:** four pieces.
1. **The pin file:** `packaging/llm/model.pin` stays the single pin and is installed with `openvibes-llm`.
2. **A bridge package:** a model-less `openvibes-llm-model` package keeps owning the model path and `model.conf` across the upgrade.
3. **A new command:** `openvibes-admin assistant model fetch` downloads with `curl` and reuses the existing verified `install`.
4. **The offline kit:** a CI job builds it in a clean Fedora container with `dnf download --resolve`, signs its checksums, and tests it in a network-less container before upload.

**Tech Stack:** Rust (`openvibes-admin`), RPM spec, POSIX sh, GitHub Actions, podman, createrepo_c, gpg.

**Spec:** `docs/superpowers/specs/2026-10-09-model-download-and-offline-kit-design.md`, approved by the user.

## Global Constraints

- **Pin values:** taken from `packaging/llm/model.pin`, never hard-coded elsewhere in code (`LLM_MODEL_FILE`, `LLM_MODEL_URL`, `LLM_MODEL_SHA256`, `LLM_MODEL_ALIAS`, `LLM_MODEL_LICENSE_URL`).
- **Downloads:** "the platform never downloads models while running". Only `openvibes-admin assistant model fetch`, Setup and `helper assistant-setup` download, and only when an admin runs them.
- **Model package names:** `-part1` and `-part2` stop being built; `openvibes-llm-model` stays (the bridge). The website excludes `*-llm-model-part*`, so do not rename.
- **Upgrade from 0.2.5:** must keep `/var/lib/openvibes-llm/models/Qwen3-4B-Q4_K_M.gguf` and `/var/lib/openvibes-llm/model.conf`.
- **Kit file name:** `openvibes-platform-<version>-offline-fedora<N>.tar`, top folder `openvibes-offline/`, entry point `openvibes-offline/install`, flags `--model FILE`, `--no-setup` and `--check`.
- **Kit key:** fingerprint `710AD8AFB7AFE6E864C0CDC4E134BAF37786DA36`, the same as the website's `install.sh`.
- **Steps:** user-visible steps are exactly spec §6, which the website copies word for word.
- **Never pass `--sleep-idle-seconds`** to llama-server.
- **Host memory:** one heavy job at a time (31 GB host with an OOM history).
- **Commits** end with `Co-Authored-By: Claude <noreply@anthropic.com>`; no push.

## Review Focus

1. **Upgrade 0.2.5 → this, with the assistant installed:** the GGUF and `model.conf` stay, the part packages leave, and the assistant still answers. Checked by `check-rpm.sh` (file ownership) in Task 1, and in the lab by the controller.
2. **`model fetch` on a host where the model is already installed:** a no-op with a clear message, never a second 2.5 GB download. Task 2.
3. **The kit on the wrong Fedora version, or tampered with:** refused before anything changes. Task 4.
4. **The kit installer on a host with no network at all:** must not hang on any repo or metadata fetch. Uses `--disablerepo='*'`, and is tested with `--network none`. Task 4.
5. **`assistant-setup` when `model.conf` exists but the GGUF does not** (the bridge package with no model yet): it fetches or tells the user, and never enables a socket for a missing file. Task 3.

---

### Task 1: Packaging — the model leaves; a bridge stays

**Files:**
- Modify: `packaging/rpm/openvibes-platform.spec` (model packages ~lines 127-160, `%install` ~225-241, `%files` ~424-445), `scripts/build-rpm.sh` (~lines 2-25), `scripts/check-rpm.sh`, `docs/components/openvibes-llm.md` (~232-262), `.github/workflows/release.yml` (only if it sets `OV_LLM_MODEL`; otherwise nothing)
- Delete: `packaging/llm/join-model.sh` (only if nothing else references it — grep)

**Interfaces:**
- Produces:
  - `/usr/share/openvibes-llm/model.pin`, installed 0644 by `openvibes-llm`;
  - the bridge `openvibes-llm-model-%{version}`, which:
    - owns `%ghost %attr(0444, root, root) %{_sharedstatedir}/openvibes-llm/models/$LLM_MODEL_FILE` and `%config(noreplace) %attr(0644, root, root) %{_sharedstatedir}/openvibes-llm/model.conf` (the same content as 0.2.5: it selects `LLM_MODEL_FILE` with `LLM_MODEL_ALIAS`);
    - declares `Obsoletes: openvibes-llm-model-part1 < %{version}-%{release}` and `Obsoletes: openvibes-llm-model-part2 < %{version}-%{release}`;
    - `Requires: openvibes-llm = %{version}-%{release}`.

- [ ] **Step 1: Write the failing checks** in `scripts/check-rpm.sh`, after the build:
  - no RPM in `target/rpm/RPMS` contains a `*.gguf`, `*.part0` or `*.part1` (`rpm -qlp`);
  - there is no `openvibes-llm-model-part*` RPM;
  - `rpm -qlp` of `openvibes-llm-model-*.rpm` lists exactly the two paths above, plus its licence file and `%dir`s;
  - `rpm -qp --obsoletes` lists both part packages;
  - `openvibes-llm` lists `/usr/share/openvibes-llm/model.pin`.
- [ ] **Step 2:** Run `bash scripts/build-rpm.sh && bash scripts/check-rpm.sh`. It fails, because today's build has parts unless `OV_LLM_MODEL=0`. Note: building with the model downloads 2.5 GB, so run Step 2 with the current default only if the model is already cached in `target/`; otherwise run it with `OV_LLM_MODEL=0` and expect the ownership and pin checks to fail.
- [ ] **Step 3: Implement.**
  - **Spec:**
    - remove `%bcond model` and both part packages;
    - the bridge package has no `%if %{with model}`;
    - `%install` writes `model.conf` from the pin as today, plus the `%ghost` list line;
    - remove `join-model` and its `%posttrans`;
    - add the bridge's `%posttrans`:
      ```sh
      [ -e %{_sharedstatedir}/openvibes-llm/models/$LLM_MODEL_FILE ] || echo "openvibes-llm-model: the assistant's model is not installed: run 'sudo openvibes-admin assistant model fetch', or install it from a file (docs: offline install)" >&2
      ```
      The file name is substituted at build time from the pin.
    - `openvibes-llm` installs `packaging/llm/model.pin` to `%{_datadir}/openvibes-llm/model.pin`.
  - **`build-rpm.sh`:** drop `fetch-llm-model.sh` and `OV_LLM_MODEL`, and update the header comment.
  - **`docs/components/openvibes-llm.md`:** describe the bridge, `model fetch`, and why the model is no longer packaged.
- [ ] **Step 4:** Run `bash scripts/build-rpm.sh && bash scripts/check-rpm.sh` (it must pass) and `bash scripts/check-names.sh`. Run the systemd e2e (`scripts/systemd-e2e.sh`) only if it is under 15 min locally; otherwise rely on CI and say so.
- [ ] **Step 5: Commit:** "Packaging: the model leaves the packages; openvibes-llm-model keeps owning the model path across upgrades".

### Task 2: `openvibes-admin assistant model fetch`

**Files:**
- Modify: `crates/openvibes-admin/src/model.rs` (`ModelCommand` ~line 25; reuse `fn install` ~line 84); the `openvibes-admin` package's `Requires: curl` in the spec
- Create: `crates/openvibes-admin/src/model_fetch.rs` (keeps `model.rs` under 500 lines)
- Test: unit tests in `model_fetch.rs`, plus `crates/openvibes-admin/tests/model_fetch.rs` if the crate's CLI tests live there

**Interfaces:**
- Produces:
  ```rust
  pub struct Pin { pub file: String, pub url: String, pub sha256: String, pub alias: String, pub license_url: String }
  pub fn read_pin(path: &Path) -> Result<Pin, String>;            // KEY=value lines; unknown keys ignored; all five required
  pub trait Downloader { fn download(&self, url: &str, dest: &Path) -> Result<(), String>; }
  pub struct Curl;                                                 // runs curl --proto =https --tlsv1.2 --fail --location --retry 3 --output DEST URL (progress to the terminal)
  pub fn fetch(pin: &Pin, downloader: &dyn Downloader, models_dir: &Path, model_config: &Path, free_bytes: impl Fn(&Path) -> u64) -> Result<String, String>;
  ```
- CLI: `ModelCommand::Fetch { #[arg(long, default_value = "/usr/share/openvibes-llm/model.pin")] pin: PathBuf, models_dir, model_config }` with the same defaults as `Install`.
- **Behaviour:**
  - If `models_dir/pin.file` exists, return `"already installed: <file> (pinned sha256 …); nothing downloaded"` without re-hashing the 2.5 GB. If `model.conf` already selects it, the command is a no-op.
  - If `free_bytes(models_dir)` is below 2.7 GB (`2_700_000_000`), fail with "need about 2.7 GB free in <dir>, have <n>".
  - Otherwise download to `models_dir/.<file>.download` (a temporary file on the same filesystem), call the existing `install(tmp, &pin.sha256, &pin.file, Some(&pin.alias), models_dir, model_config)`, and remove the temporary file on every path.
  - On a SHA mismatch the message says: "the downloaded file does not match the pinned SHA-256 (<url>); nothing was installed".
  - On a download error it names the URL and adds: "offline: download it elsewhere, then `openvibes-admin assistant model install FILE --sha256 <pin>`".

- [ ] **Step 1: Write the failing unit tests**, with a fake `Downloader` that writes given bytes:
  1. `read_pin` parses the real `packaging/llm/model.pin` (`include_str!` from the crate's relative path, or a copy under `tests/fixtures`);
  2. a missing key gives a clear error;
  3. the happy path: the fake writes bytes whose SHA-256 matches a test pin, and the file is installed and selected (reuse how `model.rs` tests `install`, with a temporary `models_dir` and `model_config`);
  4. a mismatch leaves no file in `models_dir`, no temporary file, and an unchanged `model_config`;
  5. low disk is refused before any download (the fake records whether it was called);
  6. "already installed" means no download call.
- [ ] **Step 2:** Run `cargo test -p openvibes-admin model_fetch`; it fails.
- [ ] **Step 3: Implement.**
  - `free_bytes` uses `libc::statvfs`, which is already used by #207's root-safe file handling; check `Cargo.toml`. If `libc` is not a dependency, use `fs2`-free code via `nix`, or shell out to `stat -f`.
  - Add `Requires: curl` to `openvibes-admin`.
  - Update the module docs: "the platform never downloads models itself" becomes "only when an admin runs `model fetch` (or Setup, or assistant-setup, which call it)".
- [ ] **Step 4:** Run `cargo test -p openvibes-admin`, `cargo clippy -p openvibes-admin --all-targets -- -D warnings -F unsafe-code` and `cargo fmt --check`; all pass.
- [ ] **Step 5: Commit:** "Admin: assistant model fetch downloads the pinned model from its publisher and installs it verified".

### Task 3: Setup and assistant-setup fetch the model when it is missing

**Files:**
- Modify: `crates/openvibes-admin/src/assistant_setup.rs` (~line 122 `run`), `crates/openvibes-admin/src/setup/run.rs` (~40-60, the assistant step and `done_text`), the Setup form or plan where components are chosen (`setup/plan.rs`), `docs/quick-setup.md`, `docs/components/openvibes-admin.md`
- Test: the existing Setup tests (`crates/openvibes-admin/src/setup/*` tests or `tests/setup*.rs`) and `assistant_setup` unit tests

**Interfaces:** consumes `read_pin`, `fetch` and `Curl` (Task 2).
- **`assistant-setup` (`run`):**
  - The model is considered present when `model.conf` exists **and** the selected model file exists. Read the file name from `model.conf`'s `OPENVIBES_LLM_MODEL`, using the existing `parse_env`.
  - If the file is missing and the pinned model is the one selected, call `fetch(..., &Curl, ...)` first.
  - With `--no-download`, it errors with the fetch and install commands instead.
  - It never enables the socket for a missing file (Review Focus 5).
- **Setup:**
  - When the Assistant component is chosen and the pinned model is not installed, Setup shows a confirmation, "Download the assistant's model (2.5 GB from Hugging Face)?", default **Yes**. It uses the same prompt style Setup already uses for confirmations; find it in `setup/` and reuse it.
  - Yes runs `fetch` as a Setup step with its own line in the step list ("assistant model").
  - No skips it, and the final screen says "assistant: off until you install its model (`sudo openvibes-admin assistant model fetch`)".
  - `setup --quick` gains `--model fetch|skip` (default `fetch` when assistant is in `--components`).
  - `done_text` drops "after installing a model …" when the model was fetched.

- [ ] **Step 1: Write the failing tests:**
  - `assistant_setup`: `model.conf` present and file missing, with a fake downloader (make `run` take a `&dyn Downloader`; the CLI passes `Curl`), fetches first; `--no-download` errors with both commands in the message; a present file means no download.
  - Setup: the plan with Assistant and no model includes the "assistant model" step; `--model skip` leaves it out and the final text mentions `model fetch`.
- [ ] **Step 2:** Run the tests; they fail.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run `cargo test -p openvibes-admin`, clippy and fmt. Update `docs/quick-setup.md` and `docs/components/openvibes-admin.md` with the spec §6 steps, word for word.
- [ ] **Step 5: Commit:** "Setup and assistant-setup download the pinned model when it is missing".

### Task 4: The offline kit (build, installer, CI test, release job)

**Files:**
- Create:
  - `packaging/offline/install` (POSIX sh, executable);
  - `packaging/offline/README.txt.in` (with `@VERSION@`, `@FEDORA@`, and `@MODEL_*@` from the pin);
  - `scripts/build-offline-kit.sh` (runs inside `fedora:<N>`; args: `RPM_DIR OUT_DIR FEDORA`);
  - `scripts/offline-kit-e2e.sh` (podman: one network-less container installs from the kit);
- Modify:
  - `.github/workflows/release.yml`: a new job `offline-kit`, after `release` builds and signs, matrix `fedora: [44]`, which builds the kit, runs the e2e, signs `SHA256SUMS` with the same key `sign-rpms.sh` uses, and uploads the tar to the release;
  - `.github/workflows/ci.yml`: run `scripts/offline-kit-e2e.sh` on pull requests that touch `packaging/offline/**`, `scripts/*offline*` or the spec, using the PR's unsigned RPMs with a test key;
  - `docs/components/offline-kit.md` (new component page) and `docs/components/README.md`.

**Interfaces:**
- `build-offline-kit.sh RPM_DIR OUT_DIR FEDORA` produces `OUT_DIR/openvibes-platform-<v>-offline-fedora<N>.tar`.
  - **Steps:**
    1. Copy `RPM_DIR`'s platform RPMs and `openvibes-rules-*` (passed in) into `packages/`.
    2. Run `dnf download --resolve --alldeps --destdir packages/ --setopt=install_weak_deps=False <the platform package names>` against Fedora's repos.
    3. Drop packages already in the `fedora:<N>` base image (compare `rpm -qa --qf '%{NAME}\n'`). Keep `postgresql-server` and its closure.
    4. Run `createrepo_c packages`.
    5. Write `README.txt` from the template, add `openvibes.gpg` (`packaging/rpm/openvibes-packages.gpg`), and write `LICENSES/fedora-packages.txt` (name, licence, source RPM, `https://src.fedoraproject.org/rpms/<name>`).
    6. Write `SHA256SUMS` over every file.
    7. Signing is the caller's job: `SHA256SUMS.asc`.
- **`packaging/offline/install`:** behaviour per spec §5, steps 1–8.
  - **Fingerprint:** a constant `KEY_FINGERPRINT=710AD8AFB7AFE6E864C0CDC4E134BAF37786DA36`.
  - **gpg:** runs with a temporary `GNUPGHOME`.
  - **dnf:**
    ```sh
    dnf -y --disablerepo='*' --repofrompath=openvibes-offline,"$kit/packages" --enablerepo=openvibes-offline --setopt=openvibes-offline.gpgcheck=1 install openvibes-admin openvibes-console openvibes-ingest openvibes-distribution openvibes-vulns openvibes-signer openvibes-llm openvibes-llm-model 'openvibes-rules-*'
    ```
    with the key imported by `rpm --import "$kit/openvibes.gpg"` only after the fingerprint check. Prefer importing for the transaction only; if rpm cannot, import and leave it, the same as an online install would.
  - **The model:** `--model FILE`, or a single `"$kit/../$LLM_MODEL_FILE"`, is passed to `openvibes-admin assistant model install FILE --sha256 <pin>`, reading the pin from `/usr/share/openvibes-llm/model.pin` after install.
  - **Setup:** unless `--no-setup`, run `exec openvibes-admin`.
- **The e2e** (`offline-kit-e2e.sh KIT_TAR`), run with `podman run --rm --network none -v KIT:/kit:ro fedora:44`:
  - **Run it:** `tar xf`, then `./openvibes-offline/install --check`, then `./openvibes-offline/install --no-setup`.
  - **Then assert:**
    - `rpm -q` for every OpenVIBES package and `postgresql-server`;
    - `/usr/share/openvibes-llm/model.pin` exists;
    - no network was needed (implicit: the container has none).
  - **A second run:**
    - with a tampered `SHA256SUMS`: `--check` must fail;
    - against a `fedora:43` image: it must refuse with the kit-name message;
    - the "does not exist" path: no Fedora version mismatch, but the `--model` file's SHA is wrong. It must fail at the model step after the packages are installed, with a clear message.

- [ ] **Step 1: Write `scripts/offline-kit-e2e.sh` first** and run it against a kit built by a stub `build-offline-kit.sh` (it should fail; nothing exists yet).
- [ ] **Step 2: Implement `build-offline-kit.sh`** and `packaging/offline/install` plus the README template. Build a kit locally from `bash scripts/build-rpm.sh` output, signed with a throwaway gpg key and with the fingerprint overridable by the env var `OPENVIBES_KEY_FINGERPRINT`, test-only, exactly as `install.sh` allows. Pass the rules RPMs from `~/.cache/openvibes-lab/packages/0.2.5` or a CI artifact. **This step downloads Fedora packages,** a few hundred MB: one heavy job at a time.
- [ ] **Step 3:** Run `bash scripts/offline-kit-e2e.sh target/offline/openvibes-platform-*-offline-fedora44.tar`; it passes, including the three negative cases. Report the kit size.
- [ ] **Step 4:** Add the release and CI workflow jobs. Check them with `actionlint` if installed; otherwise review the YAML carefully. The release job must not upload unless the e2e passed.
- [ ] **Step 5: Docs:** write `docs/components/offline-kit.md` (purpose, contents, the installer's flags and failure behaviour, how to test) and index it.
- [ ] **Step 6: Commit:** "Offline kit: the platform, its Fedora dependencies and an installer in one tar per release, tested without network".

### Task 5: Docs, gate, lab checks

**Files:** `docs/quick-setup.md` (the offline section), `docs/components/openvibes-llm.md` (already updated in Task 1; check it), `CHANGELOG` if any.

- [ ] **Step 1: Docs.** Add the offline section to `docs/quick-setup.md` with spec §6's steps word for word, linking `docs/components/offline-kit.md`.
- [ ] **Step 2: Gate** (`testing.md` §2 and §3, the Fedora job, because packaging changed): run in the background, waited on properly, with full logs.
- [ ] **Step 3:** The lab upgrade test and the lab offline test are run by the controller after the user's sweep ends; they are not part of this task.
- [ ] **Step 4: Commit the docs.**
