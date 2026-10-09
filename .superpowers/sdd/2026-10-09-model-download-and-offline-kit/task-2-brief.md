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

