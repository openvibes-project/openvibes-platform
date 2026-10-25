# TUI 4b: Import an Intermediate from Your PKI — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A third CA mode, "Import from your PKI": the admin gives a finished intermediate (PEM chain + key, or a `.p12`/`.pfx` with password) and OpenVIBES issues and renews from it like its other two modes; "Your CA signs our request" also accepts CAs between its root and our intermediate.

**Architecture:** Parsing and checking live in `platform-pki` (new files `keys.rs`, `chain.rs`). The unprivileged TUI checks everything at once, then hands the bundle to a new root helper verb `ca-import` on **stdin** (after sudo's password line, never argv), which re-checks and stages it in `/etc/openvibes/pki/request/import/` like `ca-accept` stages a signed request. The Setup `ca` step (new `CaMode::Import`) and 4a's `ca-replace` install from that staging. CAs between our intermediate and the root go in a new `/etc/openvibes/pki/chain.crt` (0644), appended to every server certificate; it is never a trust anchor.

**Tech Stack:** Rust, rcgen 0.14 (ring), x509-parser 0.18, new: `p12-keystore` 0.4.1 (brings `pkcs5` 0.8.1, `der` 0.8.2), ratatui TUI.

**Spec:** `docs/specs/2026-10-10-tui-rework-design.md` §5 step 3, §10 item 3; `docs/specs/tui-rework/approved.md` rule 56 (screens `docs/specs/tui-rework/certs4b.py`), rule 55 (4a Replace); workspace `decisions.md` 2026-10-25 "4b" entry. Recon: `~/.cache/openvibes-scratch/sp4b/recon.md`.

## Global Constraints

- Every file stays under 500 lines; near-full files (`helper.rs` 498, `setup/plan.rs` 479, `setup/pki.rs` 465, `tui/install/certs.rs` 440, `tui/install/certs_tests.rs` 480, `tui/maint/replace.rs` 454, `platform-pki/src/ca.rs` 419, `platform-host/src/setup.rs` 455) get new code in new files.
- A private key never appears on a command line, in the journal, in the audit log, or in an error message. Typed passwords and decrypted keys are held in `zeroize::Zeroizing`.
- The helper never trusts the TUI: `ca-import` re-runs every check on what it receives.
- Accepted keys: EC P-256, EC P-384, RSA 2048–4096 (ring's limit; Task 1 ruling), Ed25519; PEM labels `PRIVATE KEY`, `RSA PRIVATE KEY`, `EC PRIVATE KEY`, `ENCRYPTED PRIVATE KEY`; `.p12`/`.pfx` with PBES2 (AES) or legacy PBES1 (3DES/RC2).
- Our intermediate and every CA above it must be valid now and for at least 90 days more (`SERVER_DAYS`).
- New dependencies: `p12-keystore = "0.4.1"`, `pkcs5 = "0.8.1"` (features `pbes2`), `der = "0.8.2"` — the latter two are already in `p12-keystore`'s tree, so the lockfile gains only that family. `docs/dependencies.md` is updated in the same commit (versions, licences, indirect count). `cargo audit` stays clean.
- Copy is verbatim from `approved.md` rule 56 / `certs4b.py`, except where a Ruling below says otherwise.
- Cargo runs: `CARGO_BUILD_JOBS=6 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 nice -n 19 ionice -c3`, `CARGO_TARGET_DIR=~/.cache/openvibes-scratch/target-4b`. Database tests only via `eval "$(scripts/test-db.sh)"` … `scripts/test-db.sh stop`.
- Commits end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. Every component change updates its `docs/components/*.md` page in the same task.

## Rulings made while planning (tell the user)

- **P1 The root must be included.** `certs4b.py` #3 says "The root may be left out", but agents pin the root (`GET /v1/ca`, install-line fingerprint), so OpenVIBES needs it. The paste note becomes "Our intermediate first, then each CA above it, ending with the root." and a missing root shows the approved missing-CA line ("Signed by X, missing here: paste it below this one."). Cost if wrong: one string, and a root-less import path.
- **P2 Middle CAs never become trust anchors.** They go in `chain.crt`, not in `intermediate.crt`, because distribution trusts the whole `intermediate.crt` bundle for agent client certificates: a company sub-CA there would let any certificate it signs pass as an agent. Agent client chains stay leaf + our intermediate (ingest and distribution anchor at our intermediate). Cost if wrong: none for security; a file more.
- **P3 The key reaches the helper on stdin**, after sudo's password line (sudo `-S` reads one line). As root, the helper is run with the same input minus the password line. Cost if wrong: one Host API variant.
- **P4 The TUI decrypts the key** (it runs as the operator, who owns the file), checks it, and sends plain PKCS#8 to the helper, which converts and checks again. Cost if wrong: decryption moves into the helper.
- **P5 A name self-check:** after the key matches, the import issues a throwaway leaf and refuses when the leaf's issuer bytes differ from our intermediate's subject bytes (rcgen re-encodes the issuer name; some company CAs use encodings it does not reproduce). New red line: "OpenVIBES cannot reproduce X's name exactly, so its certificates would not chain: ask for a certificate with a UTF-8 name." Cost if wrong: one string; without it, agents would refuse every server certificate.
- **P6 Path lengths (RFC 5280):** our intermediate may carry any path length (it signs only leaves). A CA above it with path length N may have at most N CAs below it in the path, ours included; a pathlen-0 CA therefore cannot sit above ours: the approved line "X allows no CA below it: ask for one more level." Cost if wrong: refusals of chains a verifier would accept, or acceptance of chains agents would refuse.
- **P7 Certificates not on the path are ignored** (a `.pfx` often carries extras); only the path is stored. Cost if wrong: an extra refusal line later.
- **P9 "Your CA's certificate" takes the CAs above too** (Task 7): its note becomes "Your CA's certificate, then each CA above it up to the root." — the approved text assumed a direct root. Cost if wrong: one string.
- **P8 Three direct dependencies, one new family** (`p12-keystore`, plus its own `pkcs5` and `der` used directly for encrypted PKCS#8 and PKCS#1/SEC1 wrapping). Decisions.md said "one new PKCS#12 dependency"; this is still one new family in the lockfile. Two of them are pre-releases inside it (`cms 0.3.0-pre.1`, `pkcs12 0.2.0-pre.0`), as published by RustCrypto. Cost if wrong: hand-written PBES2 over ring cannot do AES-CBC, so there is no smaller route.

## Review Focus

1. A `.pfx` exported by Windows with the legacy 3DES/RC2 encryption and a friendly name and an extra unrelated certificate: it opens, the extra certificate is ignored. (Task 1 fixture `legacy.pfx`, Task 2 `extra_certificates_are_ignored`.)
2. The pasted chain in the wrong order (root first, then the sub-CA, then ours) or with Windows CRLF line ends: it is accepted, path built by signature. (Task 2 `order_and_crlf_do_not_matter`.)
3. A key that is valid but belongs to the previous intermediate on Replace: refused with the approved wrong-key line, nothing staged. (Task 6 `replace_refuses_the_old_key`.)
4. `chain.crt` lost or edited after install: Repair notices (server certificates no longer end in the stored chain) and reissues. (Task 4 `certificates_check_wants_the_chain`.)
5. Removing everything leaves no `chain.crt`, no `request/import/`; keep-data leaves them. (Task 4 `import_staging_is_removed_after_install` and the existing uninstall tests extended.)

---

### Task 1: Keys and `.p12` files (`platform-pki/src/keys.rs`)

**Files:**
- Create: `crates/platform-pki/src/keys.rs`, `crates/platform-pki/tests/keys.rs`, `crates/platform-pki/tests/fixtures/` (+ `make.sh`)
- Modify: `crates/platform-pki/src/lib.rs` (exports, `PkiError` variants), `crates/platform-pki/Cargo.toml`, `Cargo.toml`, `Cargo.lock`, `docs/dependencies.md`, `docs/components/platform-pki.md`

**Interfaces:**
- Produces:
  - `pub fn pkcs8_pem(key_pem: &str, password: Option<&str>) -> Result<Zeroizing<String>, PkiError>` — any accepted label → PEM `PRIVATE KEY`.
  - `pub fn is_locked(key_pem: &str) -> bool` — the first PEM block is `ENCRYPTED PRIVATE KEY`.
  - `pub struct KeyInfo { pub kind: KeyKind, pub bits: u32 }`, `pub enum KeyKind { Rsa, P256, P384, Ed25519 }`, `impl Display for KeyInfo` → `"an RSA key (3072 bits)"`, `"an EC P-256 key"`, `"an EC P-384 key"`, `"an Ed25519 key"`.
  - `pub fn key_info(pkcs8_pem: &str) -> Result<KeyInfo, PkiError>`.
  - `pub fn is_p12(bytes: &[u8]) -> bool` — DER SEQUENCE start and not PEM text.
  - `pub struct P12 { pub certs_pem: String, pub key_pem: Zeroizing<String> }` (`Debug` redacts the key).
  - `pub fn read_p12(bytes: &[u8], password: &str) -> Result<P12, PkiError>` — first private-key entry; its chain plus any loose certificates, as PEM; key as PKCS#8 PEM.
  - `PkiError` gains `KeyLocked` ("the private key is locked with a password"), `WrongPassword` ("wrong password"), `WeakKey(u32)` ("an RSA key of {0} bits is too weak"). `UnsupportedKey`'s text stays for agent CSRs; P-521 and DSA map to it.

- [ ] **Step 1: Fixtures.** `tests/fixtures/make.sh` (openssl 3.x, `set -euo pipefail`; every certificate valid 2026-01-01 to 2046-01-01 via `openssl x509 -not_before 20260101000000Z -not_after 20460101000000Z`, except `short.crt`; the script prints `openssl version` into `fixtures/README`) makes: `root.crt` + key (RSA 4096, "Lime Lab Root CA", pathlen 1), `issuing.crt` + key (EC P-384, "Lime Lab Issuing CA", pathlen 1: ours is a CA below it), `ours-rsa.crt`+`ours-rsa.key` (RSA 3072, "Lime Lab OpenVIBES CA", no pathlen), `ours-ec.crt` + key in all four PEM forms (`ours-ec.pkcs8.pem`, `ours-ec.sec1.pem`, `ours-ec.enc.pem` password `correct horse`), `ours-rsa.pkcs1.pem`, `weak.key` (RSA 1024), `modern.pfx` (`-keypbe AES-256-CBC -certpbe AES-256-CBC`, chain + key, password `correct horse`), `legacy.pfx` (`-legacy`, plus an unrelated self-signed "Lime Lab Web" certificate via `-certfile`), `p521.key`, `leaf-not-ca.crt` ("Lime Lab Web", CA:FALSE), `strict.crt` + key ("Lime Lab Strict CA", pathlen 0, under the root) and `under-strict.crt` + key (a CA it signed), `short.crt`/key (valid until 2026-12-01). Commit the outputs; tests never run openssl.

- [ ] **Step 2: Failing tests** in `tests/keys.rs`:

```rust
#[test] fn every_pem_form_gives_the_same_pkcs8() // pkcs8, sec1, enc (Some("correct horse")) of ours-ec → equal strings; ours-rsa.pkcs1 == pkcs8_pem(ours-rsa.key)
#[test] fn a_locked_key_needs_its_password()     // pkcs8_pem(enc, None) == Err(KeyLocked); is_locked(enc); !is_locked(sec1)
#[test] fn a_wrong_password_is_said()            // pkcs8_pem(enc, Some("wrong")) == Err(WrongPassword)
#[test] fn key_info_names_the_key()              // to_string() == "an RSA key (3072 bits)" / "an EC P-256 key"
#[test] fn weak_and_unknown_keys_are_refused()   // key_info(weak) == Err(WeakKey(1024)); pkcs8_pem(p521) or key_info == Err(UnsupportedKey)
#[test] fn modern_and_legacy_pfx_open()          // read_p12(modern,"correct horse") and legacy: key equals pkcs8_pem(ours-ec…); certs_pem holds ours, issuing, root (legacy also "Lime Lab Web")
#[test] fn a_pfx_with_the_wrong_password_is_said() // Err(WrongPassword)
#[test] fn is_p12_tells_der_from_pem()
#[test] fn an_imported_rsa_key_loads_as_issuer()  // Issuer::load(ours-rsa.crt, pkcs8_pem(rsa)) is Ok (SPKI matches byte for byte)
```

- [ ] **Step 3: Run** `cargo test -p platform-pki --test keys` → FAIL (unresolved imports).
- [ ] **Step 4: Implement.** PKCS#1 → PKCS#8: wrap in `PrivateKeyInfo { version 0, rsaEncryption + NULL, OCTET STRING }` with `der`; SEC1 → PKCS#8: curve OID from the ECPrivateKey `parameters [0]` (refuse when absent: `UnsupportedKey`); encrypted: `pkcs5::EncryptionScheme` from the `EncryptedPrivateKeyInfo` and `decrypt`. RSA bits from the modulus; `WeakKey` below 2048, `UnsupportedKey` above 8192 (ring's limit). Validate the result with `rcgen::KeyPair::try_from` so a returned key always loads.
- [ ] **Step 5: Run** → PASS; `cargo clippy -p platform-pki --all-targets` clean; `cargo audit` clean.
- [ ] **Step 6: Docs and commit.** `docs/dependencies.md` rows for the three crates; `platform-pki.md` Interface + accepted keys. `git commit -m "platform-pki: read company keys and .p12 files"`.

### Task 2: The chain check (`platform-pki/src/chain.rs`)

**Files:**
- Create: `crates/platform-pki/src/chain.rs`, `crates/platform-pki/tests/chain.rs`
- Modify: `crates/platform-pki/src/lib.rs`, `crates/platform-pki/src/ca.rs` (only `Issuer::with_chain`, `issue_server`), `docs/components/platform-pki.md`

**Interfaces:**
- Consumes: Task 1 `pkcs8_pem`, `key_info`, fixtures.
- Produces:
  - `pub struct Chain { pub ours: String, pub middle: Vec<String>, pub root: String, pub name: String, pub path: Vec<String>, pub not_after: DateTime<Utc> }` — PEM blocks, each ending in `\n`; `name` = our CN; `path` = CNs above ours, root last.
  - `pub enum ChainError { InvalidPem, NotCa(String), Missing(String), NoCaBelow(String), Expiring(DateTime<Utc>), Pki(PkiError) }` (`Clone, Debug, Eq, PartialEq`); the names are CNs ("an unnamed CA" when absent).
  - `pub fn check_chain(certs_pem: &str, now: DateTime<Utc>) -> Result<Chain, ChainError>`: first block is ours; CA:TRUE and keyCertSign when key usage is present (else `NotCa`); path built by signature (`verify_signed_by`) from the remaining blocks in any order (else `Missing(issuer CN)`); ends at a self-signed root (P1); P6 path lengths; every path cert valid at `now` and `not_after >= now + 90 days` (else `Expiring(earliest not_after)`); P7.
  - `pub fn check_key(chain: &Chain, pkcs8_pem: &str, now: DateTime<Utc>) -> Result<KeyInfo, ChainError>`: `key_info`, `Issuer::load` (`KeyMismatch` → `Pki(KeyMismatch)`), P5 self-check (`Pki(PkiError::NameMismatch)`, a new variant "the CA's name cannot be reproduced").
  - `impl Issuer { pub fn with_chain(self, middle_pem: &str) -> Result<Self, PkiError> }`; `issue_server`'s `cert_pem` becomes leaf + our CA + middle (unchanged when no chain).

- [ ] **Step 1: Failing tests** in `tests/chain.rs` (now = 2027-06-01):

```rust
#[test] fn a_full_chain_is_accepted()          // ours-ec + issuing + root → middle.len()==1, path == ["Lime Lab Issuing CA","Lime Lab Root CA"], name "Lime Lab OpenVIBES CA"
#[test] fn order_and_crlf_do_not_matter()      // root, issuing, … reversed after ours, with \r\n → same Chain
#[test] fn extra_certificates_are_ignored()     // + "Lime Lab Web" → middle.len()==1
#[test] fn a_gap_names_the_missing_ca()         // ours + root only → Err(Missing("Lime Lab Issuing CA")); ours alone → same
#[test] fn the_root_must_be_there()             // ours + issuing → Err(Missing("Lime Lab Root CA"))
#[test] fn a_leaf_is_not_a_ca()                 // leaf-not-ca first → Err(NotCa("Lime Lab Web"))
#[test] fn path_length_zero_allows_no_ca_below() // under-strict + strict + root → Err(NoCaBelow("Lime Lab Strict CA"))
#[test] fn ninety_days_are_needed()             // short.crt with now 2026-10-25 → Err(Expiring(2026-12-01))
#[test] fn the_key_must_match()                 // check_key(ec chain, rsa key) → Err(Pki(KeyMismatch)); right key → Ok(KeyInfo P256…)
#[test] fn server_certificates_carry_the_chain() // Issuer::load(ours, key)?.with_chain(issuing)?.issue_server(["limebox.lan"]) → 3 blocks: leaf, ours, issuing; leaf verifies to root through x509-parser
#[test] fn openvibes_made_cas_still_pass()      // generate_root + sign_intermediate → check_chain(int + root) Ok, middle empty
```

- [ ] **Step 2: Run** `cargo test -p platform-pki --test chain` → FAIL.
- [ ] **Step 3: Implement** in `chain.rs` (reuse `ca.rs`'s private `parse`/`valid_at` by making them `pub(crate)`).
- [ ] **Step 4: Run** → PASS, whole `cargo test -p platform-pki` PASS, clippy clean.
- [ ] **Step 5: Docs + commit** `platform-pki: check a company chain and its key`.

### Task 3: Helper verb `ca-import` (stdin), staging

**Files:**
- Create: `crates/openvibes-admin/src/setup/import.rs`, `crates/openvibes-admin/src/setup/import_tests.rs`, `crates/openvibes-admin/src/helper_ca.rs` (the CA verbs moved out of `helper.rs`, which is full)
- Modify: `crates/openvibes-admin/src/helper.rs`, `crates/platform-host/src/setup.rs` (or a new `setup_ca.rs` beside it for the CA variants' `args`/`journal`), `crates/platform-host/src/native.rs`, `crates/platform-host/src/lib.rs` (`Host::privileged_with_input` or the variant carrying input), `crates/openvibes-admin/src/tui/run.rs` (`Call::CaImport`), `crates/openvibes-admin/tests/helper.rs`, `docs/components/openvibes-admin.md`, `docs/components/platform-host.md`

**Interfaces:**
- Consumes: Task 2 `check_chain`, `check_key`; Task 1 `pkcs8_pem`.
- Produces:
  - `Privileged::CaImport(&'a Secret)` — argv `ca-import`; the bundle goes to stdin after the password line (as root: stdin is the bundle alone); journal `ca-import /etc/openvibes/pki/request`.
  - `Call::CaImport(Zeroizing<String>)` in `tui/run.rs`, executed through `Privileged::CaImport`.
  - Bundle format on stdin: the certificates PEM (ours first), then one `PRIVATE KEY` block; at most 1 MiB, else "The certificate and key are too large (over 1 MiB)."
  - `pub const IMPORT_DIR: &str = "/etc/openvibes/pki/request/import"` (0700 root) holding `intermediate.crt` (ours, 0644), `chain.crt` (middle, 0644, only when non-empty), `root.crt` (0644), `intermediate.key` (0600, written first).
  - `pub fn run_import(input: &str) -> ExitCode` (under the Setup lock like `run_request`); stdout `imported<TAB>{name}<TAB>{path joined " › "}<TAB>{until YYYY-MM-DD}`. When a CA is already installed (`installed()`, i.e. Replace), it also requires `chain.root` == installed `root.crt` (trim compare), else the approved Replace line.
  - `pub fn import_message(e: &ChainError, file: Option<&str>) -> String` (in `import.rs`), exact strings:
    - `NotCa(n)` → "{n} is not a CA, so it cannot sign agent certificates."
    - `Missing(n)` → "Signed by {n}, missing here: paste it below this one."
    - `IsRoot(n)` → "{n} is a root CA: paste the intermediate made for OpenVIBES first, then the CAs above it." (Task 2 ruling)
    - `NotYetValid(d)` → "Valid from {d:%Y-%m-%d}: not valid yet." (Task 2 ruling)
    - `NoCaBelow(n)` → "{n} allows no CA below it: ask for one more level."
    - `Expiring(d)` → "Valid until {d:%Y-%m-%d}: under the 90 days a server certificate lasts."
    - `Pki(WeakKey(b))` → "A {b}-bit RSA key is too weak: 2048 bits or more."
    - `Pki(WrongPassword)` → "Wrong password for {file}." (pasted key: "Wrong password.")
    - `Pki(KeyMismatch)` → "Not the key of {name}: paste the key it was made with."
    - `Pki(NameMismatch)` → P5's line; `Pki(UnsupportedKey)` → "This key type is not supported: use RSA (2048 to 4096 bits), EC P-256 or P-384, or Ed25519."; `InvalidPem` → "This is not a certificate in PEM form (-----BEGIN CERTIFICATE-----)."
    - different root → "Replace: under {new root}, not {installed root}, so agents would stop trusting this host. Ask for one under the same root."

- [ ] **Step 1: Failing tests.** `import_tests.rs` (fake runner, fixtures from `platform-pki/tests/fixtures` via `include_str!`): `stages_the_three_files_and_the_key` (modes 0600/0644, key first via `fake` write order), `refuses_and_writes_nothing` (wrong key → error text, `IMPORT_DIR` empty), `an_installed_ca_needs_the_same_root`, `chain_is_left_out_when_there_is_none`. platform-host: `ca_import_keeps_the_pem_out_of_argv_and_journal` (args == ["ca-import"], journal has no "BEGIN"), and a native test with a recording runner that stdin == "pw\n" + bundle (and bundle alone as root). `tests/helper.rs`: `ca-import` takes no arguments (an extra argument is refused).
- [ ] **Step 2: Run** `cargo test -p openvibes-admin import` and `-p platform-host ca_import` → FAIL.
- [ ] **Step 3: Implement**; move the CA verbs' clap variants and dispatch to `helper_ca.rs` so `helper.rs` shrinks.
- [ ] **Step 4: Run** → PASS; `cargo test -p openvibes-admin -p platform-host` PASS; clippy.
- [ ] **Step 5: Docs + commit** `admin: ca-import stages a company intermediate from stdin`.

### Task 4: `CaMode::Import` in Setup; `chain.crt` in issuing

**Files:**
- Create: `crates/openvibes-admin/src/setup/pki_import.rs`, `crates/openvibes-admin/src/setup/pki_import_tests.rs`
- Modify: `setup/plan.rs` (variant `Import`, TOML `"import"`, `--ca import`; `--root-key-out` stays quick-only), `setup/plan_args.rs`, `setup/pki.rs` (dispatch only), `setup/fake.rs`, `crates/openvibes-admin/src/ca.rs` (`IssueServer --chain PATH`, optional), `docs/components/openvibes-admin.md`, `docs/components/packaging.md`, `packaging/` uninstall lists if they name pki files

**Interfaces:**
- Consumes: Task 3 `IMPORT_DIR` files; Task 2 `Issuer::with_chain`.
- Produces:
  - `pub const CHAIN: &str = "/etc/openvibes/pki/chain.crt"` (0644 root).
  - `fn import(ctx) -> Result<StepState, String>` in `pki_import.rs`: installed → Done; all `IMPORT_DIR` files present → stage into `INT`, `import_and_install` (extended to copy `chain.crt` to `CHAIN` when staged, and remove a stale `CHAIN` when not), remove `IMPORT_DIR`; else `Waiting("add the certificate and its key from your PKI: Install › Certificates")`. `ca_check` for Import: Done when installed, else Waiting with that text.
  - `ca issue-server … [--chain PATH]`; `certificates_apply` passes `--chain CHAIN` when it exists.
  - `certificates_check` gains: when `CHAIN` exists, Todo unless each chosen server certificate's blocks after the first two equal `CHAIN`'s blocks.

- [ ] **Step 1: Failing tests** (`pki_import_tests.rs`): `import_installs_from_the_staging` (files, owners, modes, `ca import-intermediate` called with the staged root), `import_staging_is_removed_after_install`, `import_waits_until_staged`, `server_certificates_end_in_the_chain` (fake `issue-server` call has `--chain /etc/openvibes/pki/chain.crt`), `certificates_check_wants_the_chain`, `repair_never_imports_over_an_installed_ca` (staged files left alone when installed), plan round-trip `ca = "import"`.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** `cargo test -p openvibes-admin setup::` PASS; `cargo test -p openvibes-admin --test ca` with the test DB PASS.
- [ ] **Step 5: Docs + commit** `setup: install and renew from an imported intermediate`.

### Task 5: Install step 3 — Import from your PKI (TUI)

**Files:**
- Create: `crates/openvibes-admin/src/tui/install/import.rs` (rows, keys, checks), `crates/openvibes-admin/src/tui/install/import_tests.rs`, `crates/openvibes-admin/src/tui/install/import_file_tests.rs`
- Modify: `tui/install/mod.rs` (`Ca::Import`; `Which::{Cert, Key}`; fields below), `tui/install/certs.rs` (third radio, row indices), `tui/install/paste.rs` (dispatch `check` for the new `Which`), `tui/install/steps.rs` (`fill_from`, root-key row index), `tui/install/review.rs`, `tui/ca_request.rs` (`read_bytes(path) -> io::Result<Vec<u8>>`, 1 MiB cap), `docs/components/openvibes-admin.md`

**Interfaces:**
- Consumes: Tasks 1-3.
- Produces (fields on `Install`): `imported: Option<Imported>` where `struct Imported { chain: Chain, key: Option<(Zeroizing<String>, KeyInfo)>, from: Option<String> /* .p12 file */ }`; `secret: Option<PasswordPrompt>` + `locked: Option<Locked>` (`enum Locked { P12(PathBuf, Vec<u8>), Key(String) }`) for the bar's "Its password"; `import_done: Option<String>` (helper's `imported` line, gates Next).

Screens and copy (approved.md 56, `certs4b.py` #1-#9):
- Radios in this order: "Your own CA" / "your CA signs an intermediate for OpenVIBES"; "Import from your PKI" / "a finished intermediate and its key"; "OpenVIBES makes one" / "a new root CA; its key goes offline after". Help for Import: "Paste or pick the certificate and its key, or a .p12 with its password."
- Rows when Import is chosen: "Certificate" / "Private key": yellow "not added yet" or green "✓ added" + dim " · {name}" / " · matches the certificate"; "Next": "once both are added" / "ports".
- Add screens: "Add the certificate" with "Paste it" / "PEM text: ours first, then the CAs above it" and "From a file on this host" / "a .pem, or a .p12 / .pfx with the key in it"; "Add the private key" with "Paste it" / "the PEM text of the key" and "From a file on this host" / "a .pem or .key file".
- Paste titles "Paste the certificate" (note P1's text) / "Paste the private key" (note "It stays on this host, readable by root only."); green lines "{name} · may sign certificates · valid until {date}" and "Chain: {path joined " › "} (root, also added)"; key green line "{KeyInfo}" + (locked) ", locked with a password" → `"An RSA key (3072 bits), locked with a password"` (capitalised first letter).
- Bar while a password is asked: `Bar::Typing { label: "Its password", done: "Open it" (p12) | "Unlock" (key), note: wrong → "Wrong password." }`; Esc cancels and forgets the bytes.
- A `.p12` file fills both rows; help line "From {path}. Delete that file now: its key is kept here."
- Red lines: `import_message` (Task 3).
- Next with both rows added → `Call::CaImport(bundle)` under the sudo password (`Kind::Ca{accept:true}` reuse, verb "Add"); success sets `import_done`; Next again → ports. Review: "✗ Certificates: add the certificate and its key first." until `import_done`. `plan_args` maps `Ca::Import` → `--ca import`.

- [ ] **Step 1: Failing tests.** `import_tests.rs`: `import_is_the_second_choice` (screen order + help), `pasting_the_chain_fills_the_certificate_row`, `a_gap_shows_the_missing_ca_and_use_it_does_nothing`, `a_locked_key_asks_its_password_in_the_bar`, `a_wrong_key_is_red`, `next_sends_the_bundle_on_stdin_never_argv` (script host records `CaImport`, verb args == ["ca-import"]), `review_wants_both`, `choosing_openvibes_still_edits_the_root_key_row` (row index moved). `import_file_tests.rs`: `a_pfx_asks_its_password_then_fills_both_rows` (help line text), `a_wrong_pfx_password_says_so`, `a_key_file_is_accepted_in_the_key_row`, `a_binary_file_is_not_read_lossily`. Existing `certs_tests.rs`/`steps_tests.rs` row counts updated where the radio moved.
- [ ] **Step 2: Run** `cargo test -p openvibes-admin tui::install` → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS (whole crate), clippy.
- [ ] **Step 5: Render check** against `certs4b.py` at 80×24 (the TUI's `screen()` text vs the mockup lines for #1, #3, #5, #6, #7). **Commit** `tui: Install › Certificates › Import from your PKI`.

### Task 6: Maintenance › Certificates and Replace for an imported intermediate

**Files:**
- Create: `crates/openvibes-admin/src/tui/maint/replace_import.rs`, `…/replace_import_tests.rs`
- Modify: `tui/maint/certs.rs` (mode from `CaMode`, not a `quick` bool), `tui/maint/replace.rs` (dispatch only), `setup/replace.rs` (`CaMode::Import` branch: stage from `IMPORT_DIR`; `swap` also moves `chain.crt`, with the same rollback; previous chain not kept — server certificates are reissued at once), `docs/components/openvibes-admin.md`, `docs/components/packaging.md` ("Replacing the intermediate CA")

**Interfaces:**
- Consumes: Task 3 `ca-import` (same-root rule when installed), Task 5 rows/paste/password code (call it, do not copy it), 4a `ask_replace`, `Kind::Replace`.
- Produces: Certificates page rows for Import: "Intermediate" / "from your PKI · until {date}", "Signed by" / "{path joined " › "}" with the root bold; action "Replace the intermediate" / "import the next one from your PKI". Replace page (`certs4b.py` #11): note "The same screens as at install. Nothing changes until Replace."; rows "Certificate", "Private key", "Replace" / "agents move over in 30 days" (days = `client_certificate_days`); green "✓ Under the same root: agents keep working." after the helper staged it; Enter on Replace → `ca-import` already done → 4a question "Replace it?" · "agents keep working" → `Call::CaReplace(None)`.

- [ ] **Step 1: Failing tests:** `the_page_says_from_your_pki` (rows + Signed by), `replace_imports_then_asks` (calls: ca-import then ca-replace, order), `replace_refuses_another_root` (helper error line shown red, no ca-replace), `replace_refuses_the_old_key` (Review Focus 3), setup side `replace_installs_the_imported_one` and `swap_moves_the_chain_and_rolls_back` (failure after the bundle rename restores the old `chain.crt`).
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** `cargo test -p openvibes-admin` PASS, clippy.
- [ ] **Step 5: Docs + commit** `tui: replace an imported intermediate`.

### Task 7: "Your CA signs our request" accepts CAs in between

**Files:**
- Modify: `setup/request.rs` (`accept` uses `check_chain` on signed + the pasted CA certificates; stages `request/chain.crt`), `setup/pki.rs` `careful` (stage `chain.crt` when present), `setup/replace.rs` `careful` (root compare against the chain's root), `tui/install/paste.rs` (`Which::Root` check: one or more blocks, root last), `tui/maint/replace.rs` own-CA rows, tests `request_tests.rs` / `certs_accept_tests.rs` / `replace_tests.rs` (new cases in new files if a file would pass 500 lines), `docs/components/openvibes-admin.md`, `docs/components/packaging.md`

**Interfaces:**
- Consumes: Task 2 `check_chain`, Task 4 `CHAIN` handling.
- Copy: the box is still "Your CA's certificate"; its note becomes "Your CA's certificate, then each CA above it up to the root." (Ruling P9: new string, the approved one assumed a direct root.) The green line becomes "{root name} · a root CA (self-signed)" plus, with middles, "Chain: {path}". `Several(n)` is no longer an error; the pathlen-0 intermediate rule (`check_signed_request`) stays, since OpenVIBES makes this request.

- [ ] **Step 1: Failing tests:** `accept_takes_a_sub_ca_chain` (request signed by a sub-CA from `generate_root`→`sign_intermediate`-style helpers or the fixtures' issuing CA: staged `chain.crt` holds the sub-CA), `accept_still_refuses_a_gap`, `install_from_request_writes_chain`, `own_ca_replace_compares_roots_not_parents`.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** whole workspace `cargo test` with the test DB; clippy; the local gate `~/.cache/openvibes-scratch/g4b/gate.sh` (copy of g4a's with the 4b paths) GREEN.
- [ ] **Step 5: Docs + commit** `setup: your CA may sign through a sub-CA`.

After Task 7: final whole-branch review, then a lab walk on CI RPMs (brief: fake company PKI from `make.sh`-style openssl on the VM; Install with PEM paste, with `modern.pfx`, with `legacy.pfx`; agent enrols and reports through a 3-level chain; Replace under the same root; Replace under another root refused; Remove everything leaves no `chain.crt`).
