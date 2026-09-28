# Baseline rules 1: `openvibes-admin rules keygen|sign` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Two offline `openvibes-admin` commands that make a rule-signing key and sign a rule set into an envelope the agent and `rules publish` accept.

**Architecture:** A new module `rules_sign.rs` holds pure file operations; `RulesCommand` gains `Keygen` and `Sign` variants that `main.rs` dispatches before any config or database is touched, the same way offline CA commands are. Signing reuses the pinned `openvibes-rules` crate (`signing_preimage`, `RuleLoader`), so the format cannot drift from the agent's.

**Tech Stack:** Rust (edition as the workspace), clap derive, ed25519-dalek 3, ring (randomness), zeroize, openvibes-core / openvibes-rules (agent git pin).

**Spec:** `docs/specs/2026-09-28-baseline-rules-design.md` §4 (this plan is piece 1 of §3; pieces 2–4 get their own plans).

## Global Constraints

- Key file: exactly 32 raw bytes (Ed25519 seed), created new with mode 0600, never overwritten.
- `sign` refuses a key file that is not a regular file, not 32 bytes, or has any group/other permission bit (`mode & 0o077 != 0`).
- `--days` 1–3650, default 730; `--version` ≥ 1.
- Output envelope created new (existing file is an error), mode 0644.
- Key line format: `RULE_SET ISSUER_KEY_ID PUBLIC_KEY` (public key base64url, no padding) — the format of `baseline.key` and `rules trust add`'s arguments.
- No config, no database, no audit row for `keygen` and `sign`.
- Files stay under 500 lines; `cargo clippy … -D warnings -F unsafe-code` clean.
- Commits end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Review Focus

- Key file with mode 0640 or 0604 (only group or only other bits): refused, not just 0644 → test `sign_refuses_group_readable_key`.
- Output path that already exists (a previous release's `baseline.json`): refused with nothing overwritten → test `sign_refuses_existing_output`.
- A rule set that parses but fails validation (e.g. empty `rules`): refused before any file is written → test `sign_refuses_invalid_rules`.
- Signed envelope actually publishes on a real platform (not only loads in `RuleLoader`) → DB test `signed_envelope_publishes`.
- `keygen` into an existing path must not clobber a real key → test `keygen_refuses_existing_file`.

---

### Task 1: `rules keygen`

**Files:**
- Create: `crates/openvibes-admin/src/rules_sign.rs`
- Modify: `crates/openvibes-admin/src/rules.rs` (`RulesCommand` variants, `name()`, `is_offline()`, `run` arm)
- Modify: `crates/openvibes-admin/src/main.rs` (`mod rules_sign;`, offline dispatch next to the CA one at ~line 218)
- Create: `crates/openvibes-admin/tests/rules_sign.rs`

**Interfaces:**
- Produces: `rules_sign::keygen(path: &Path, rule_set: &str, issuer: &str) -> Result<String, String>` (returns the key line plus `\n`); `RulesCommand::is_offline(&self) -> bool`; `rules::run_offline(command: &RulesCommand) -> Result<String, String>`.

- [ ] **Step 1: Write the failing tests**

`crates/openvibes-admin/tests/rules_sign.rs`:

```rust
//! `openvibes-admin rules keygen|sign`: offline signing, no config or database.
// The test starts the CLI binary it verifies; this is not shipped code.
#![allow(clippy::disallowed_types)]

mod common;

use std::os::unix::fs::PermissionsExt;

use common::{offline, scratch_dir, stdout};

#[test]
fn keygen_writes_owner_only_key_and_prints_trust_line() {
    let dir = scratch_dir("keygen");
    let key = dir.join("rules.key");
    let output = offline(&[
        "rules", "keygen", key.to_str().unwrap(), "--rule-set", "baseline", "--issuer", "openvibes-1",
    ]);
    let line = stdout(&output);
    let parts: Vec<&str> = line.trim_end().split(' ').collect();
    assert_eq!(parts[..2], ["baseline", "openvibes-1"], "{line}");
    assert_eq!(parts[2].len(), 43, "32 bytes base64url without padding: {line}");
    let meta = std::fs::metadata(&key).unwrap();
    assert_eq!(meta.len(), 32);
    assert_eq!(meta.permissions().mode() & 0o777, 0o600);
}

#[test]
fn keygen_refuses_existing_file() {
    let dir = scratch_dir("keygen-exists");
    let key = dir.join("rules.key");
    std::fs::write(&key, b"keep me").unwrap();
    let output = offline(&[
        "rules", "keygen", key.to_str().unwrap(), "--rule-set", "baseline", "--issuer", "openvibes-1",
    ]);
    assert!(!output.status.success());
    assert_eq!(std::fs::read(&key).unwrap(), b"keep me");
}

#[test]
fn keygen_refuses_bad_identifier() {
    let dir = scratch_dir("keygen-id");
    let key = dir.join("rules.key");
    let output = offline(&[
        "rules", "keygen", key.to_str().unwrap(), "--rule-set", "../x", "--issuer", "openvibes-1",
    ]);
    assert!(!output.status.success());
    assert!(!key.exists(), "no key written for a refused id");
}
```

(`stdout` in `tests/common/mod.rs` asserts success and returns stdout; check its body and use `output.status` directly where the command must fail.)

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test --locked -p openvibes-admin --test rules_sign`
Expected: FAIL — clap reports `unrecognized subcommand 'keygen'`.

- [ ] **Step 3: Implement**

`crates/openvibes-admin/src/rules_sign.rs`:

```rust
//! `openvibes-admin rules keygen|sign`: offline rule signing on the
//! signer's machine. No config, database or audit row; the platform never
//! holds a rule-signing key.

use std::{
    fs::OpenOptions,
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::Path,
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::SigningKey;
use openvibes_core::Identifier;
use ring::rand::{SecureRandom, SystemRandom};
use zeroize::Zeroize;

fn identifier(label: &str, value: &str) -> Result<Identifier, String> {
    Identifier::new(value).map_err(|e| format!("{label}: {e}"))
}

/// Writes `bytes` to a file that must not exist yet.
fn create_new(path: &Path, mode: u32, bytes: &[u8]) -> Result<(), String> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .and_then(|mut file| file.write_all(bytes))
        .map_err(|e| format!("cannot create {}: {e}", path.display()))
}

/// Makes a new Ed25519 key in `path` (0600) and returns the trust line
/// `RULE_SET ISSUER_KEY_ID PUBLIC_KEY`.
pub fn keygen(path: &Path, rule_set: &str, issuer: &str) -> Result<String, String> {
    identifier("rule set", rule_set)?;
    identifier("issuer key id", issuer)?;
    let mut seed = [0u8; 32];
    SystemRandom::new()
        .fill(&mut seed)
        .map_err(|_| "no randomness available".to_owned())?;
    let written = create_new(path, 0o600, &seed);
    let public = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
    seed.zeroize();
    written?;
    Ok(format!("{rule_set} {issuer} {}\n", URL_SAFE_NO_PAD.encode(public)))
}
```

In `rules.rs`, add to `RulesCommand` (after `Retire`):

```rust
    /// Make a rule-signing key (offline: no config or database). Prints
    /// the line `rules trust add` and `baseline.key` take.
    Keygen {
        /// New private key file (created 0600; never overwritten).
        key_file: PathBuf,
        /// Rule set the key signs.
        #[arg(long)]
        rule_set: String,
        /// Issuer key id named in envelopes.
        #[arg(long)]
        issuer: String,
    },
```

and to `name()`: `Self::Keygen { .. } => "rules keygen",`, plus:

```rust
    /// Keygen and sign run on the signer's machine, before any config or
    /// database is opened.
    pub fn is_offline(&self) -> bool {
        matches!(self, Self::Keygen { .. })
    }
```

```rust
/// Runs an offline command (`is_offline`).
pub fn run_offline(command: &RulesCommand) -> Result<String, String> {
    match command {
        RulesCommand::Keygen { key_file, rule_set, issuer } => {
            crate::rules_sign::keygen(key_file, rule_set, issuer)
        }
        _ => unreachable!("run_offline takes only offline commands"),
    }
}
```

In `rules::run`, add the arm `RulesCommand::Keygen { .. } => unreachable!("offline, handled in main"),` (match must stay exhaustive).

In `main.rs`: `mod rules_sign;` in the module list, and directly after the offline CA block:

```rust
    // Offline rule signing runs on the signer's machine: no config, no
    // database, no audit row.
    if let Command::Rules { command } = command
        && command.is_offline()
    {
        return match rules::run_offline(command) {
            Ok(output) => {
                print!("{output}");
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("openvibes-admin: {error}");
                ExitCode::FAILURE
            }
        };
    }
```

- [ ] **Step 4: Run to verify they pass**

Run: `cargo test --locked -p openvibes-admin --test rules_sign`
Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add crates/openvibes-admin/src/rules_sign.rs crates/openvibes-admin/src/rules.rs crates/openvibes-admin/src/main.rs crates/openvibes-admin/tests/rules_sign.rs
git commit -m "admin: rules keygen makes an offline rule-signing key"
```

### Task 2: `rules sign`

**Files:**
- Modify: `crates/openvibes-admin/src/rules_sign.rs`
- Modify: `crates/openvibes-admin/src/rules.rs` (`Sign` variant, `name()`, `is_offline()`, `run_offline`, `run` arm)
- Test: `crates/openvibes-admin/tests/rules_sign.rs`

**Interfaces:**
- Consumes: `keygen`, `create_new`, `identifier` from Task 1.
- Produces: `pub struct SignArgs<'a> { pub key: &'a Path, pub rules: &'a Path, pub rule_set: &'a str, pub version: u64, pub issuer: &'a str, pub days: u32, pub out: &'a Path }`; `rules_sign::sign(args: &SignArgs<'_>, now_ms: i64) -> Result<String, String>` returning `signed SET vN, expires RFC3339, sha256 HEX\n`.

- [ ] **Step 1: Write the failing tests** (append to `tests/rules_sign.rs`)

```rust
const RULES: &str = r#"{"schema_version":1,"rules":[{"id":"port.redis.exposed","version":1,"title":"Redis is exposed","severity":"high","confidence":90,"expression":"'6379' in facts['port.tcp.exposed']","finding_message":"Redis listens on a non-loopback address (tcp 6379)"}]}"#;

/// A fresh key and rules file in `dir`; returns (key, rules) paths.
fn setup(dir: &std::path::Path) -> (String, String) {
    let key = dir.join("rules.key");
    let rules = dir.join("rules.json");
    std::fs::write(&rules, RULES).unwrap();
    stdout(&offline(&[
        "rules", "keygen", key.to_str().unwrap(), "--rule-set", "baseline", "--issuer", "openvibes-1",
    ]));
    (key.to_str().unwrap().to_owned(), rules.to_str().unwrap().to_owned())
}

fn sign_args<'a>(key: &'a str, rules: &'a str, out: &'a str) -> Vec<&'a str> {
    vec![
        "rules", "sign", key, rules, "--rule-set", "baseline", "--version", "3",
        "--issuer", "openvibes-1", "-o", out,
    ]
}

#[test]
fn sign_writes_an_envelope_over_the_exact_rules_bytes() {
    let dir = scratch_dir("sign");
    let (key, rules) = setup(&dir);
    let out = dir.join("baseline.json");
    let printed = stdout(&offline(&sign_args(&key, &rules, out.to_str().unwrap())));
    assert!(printed.starts_with("signed baseline v3, expires "), "{printed}");
    let envelope: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&out).unwrap()).unwrap();
    assert_eq!(envelope["payload"], RULES);
    assert_eq!(envelope["rule_set_version"], 3);
    assert_eq!(envelope["issuer_key_id"], "openvibes-1");
    let lifetime = envelope["expires_at_unix_ms"].as_i64().unwrap()
        - envelope["created_at_unix_ms"].as_i64().unwrap();
    assert_eq!(lifetime, 730 * 86_400_000);
}

#[test]
fn sign_refuses_group_readable_key() {
    for mode in [0o640, 0o604] {
        let dir = scratch_dir(&format!("sign-mode-{mode:o}"));
        let (key, rules) = setup(&dir);
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(mode)).unwrap();
        let out = dir.join("baseline.json");
        let output = offline(&sign_args(&key, &rules, out.to_str().unwrap()));
        assert!(!output.status.success(), "mode {mode:o} accepted");
        assert!(String::from_utf8_lossy(&output.stderr).contains("chmod 600"));
        assert!(!out.exists());
    }
}

#[test]
fn sign_refuses_short_key() {
    let dir = scratch_dir("sign-short");
    let (key, rules) = setup(&dir);
    std::fs::write(&key, [7u8; 31]).unwrap();
    let out = dir.join("baseline.json");
    assert!(!offline(&sign_args(&key, &rules, out.to_str().unwrap())).status.success());
    assert!(!out.exists());
}

#[test]
fn sign_refuses_invalid_rules() {
    let dir = scratch_dir("sign-invalid");
    let (key, rules) = setup(&dir);
    std::fs::write(&rules, r#"{"schema_version":1,"rules":[]}"#).unwrap();
    let out = dir.join("baseline.json");
    let output = offline(&sign_args(&key, &rules, out.to_str().unwrap()));
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("invalid rule set"));
    assert!(!out.exists());
}

#[test]
fn sign_refuses_existing_output() {
    let dir = scratch_dir("sign-exists");
    let (key, rules) = setup(&dir);
    let out = dir.join("baseline.json");
    std::fs::write(&out, b"previous release").unwrap();
    assert!(!offline(&sign_args(&key, &rules, out.to_str().unwrap())).status.success());
    assert_eq!(std::fs::read(&out).unwrap(), b"previous release");
}

#[test]
fn sign_refuses_zero_days() {
    let dir = scratch_dir("sign-days");
    let (key, rules) = setup(&dir);
    let out = dir.join("baseline.json");
    let mut args = sign_args(&key, &rules, out.to_str().unwrap());
    args.extend(["--days", "0"]);
    assert!(!offline(&args).status.success());
    assert!(!out.exists());
}
```

(`serde_json` is already a dev-dependency through `tests/rules.rs`; if not, add it to `[dev-dependencies]`.)

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test --locked -p openvibes-admin --test rules_sign`
Expected: the 6 new tests FAIL (`unrecognized subcommand 'sign'`); the 3 keygen tests pass.

- [ ] **Step 3: Implement** (add to `rules_sign.rs`; merge the `use` lists)

```rust
use std::{fs, os::unix::fs::PermissionsExt};

use chrono::{DateTime, SecondsFormat};
use ed25519_dalek::Signer;
use openvibes_core::{PayloadEncoding, ResourceLimits, RuleSet, SchemaVersion, SignedRuleEnvelope, Validate};
use openvibes_rules::{LoadContext, RuleLoader, TrustedRuleKey, signing_preimage};
use sha2::{Digest, Sha256};

const DAY_MS: i64 = 86_400_000;

pub struct SignArgs<'a> {
    pub key: &'a Path,
    pub rules: &'a Path,
    pub rule_set: &'a str,
    pub version: u64,
    pub issuer: &'a str,
    pub days: u32,
    pub out: &'a Path,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Reads a private key that only its owner can access.
fn read_key(path: &Path) -> Result<SigningKey, String> {
    let shown = path.display();
    let meta = fs::metadata(path).map_err(|e| format!("cannot read {shown}: {e}"))?;
    if !meta.is_file() {
        return Err(format!("{shown} is not a regular file"));
    }
    if meta.permissions().mode() & 0o077 != 0 {
        return Err(format!(
            "{shown} is accessible to group or others: chmod 600 {shown}"
        ));
    }
    let mut bytes = fs::read(path).map_err(|e| format!("cannot read {shown}: {e}"))?;
    let seed: Result<[u8; 32], _> = bytes.as_slice().try_into();
    bytes.zeroize();
    let mut seed = seed.map_err(|_| format!("{shown} must hold exactly 32 bytes"))?;
    let key = SigningKey::from_bytes(&seed);
    seed.zeroize();
    Ok(key)
}

/// Signs the exact bytes of a rule set file into a new envelope file,
/// after proving the agent's loader accepts it.
pub fn sign(args: &SignArgs<'_>, now_ms: i64) -> Result<String, String> {
    let id = identifier("rule set", args.rule_set)?;
    let issuer = identifier("issuer key id", args.issuer)?;
    let key = read_key(args.key)?;
    let payload = fs::read_to_string(args.rules)
        .map_err(|e| format!("cannot read {}: {e}", args.rules.display()))?;
    let rules: RuleSet =
        serde_json::from_str(&payload).map_err(|e| format!("invalid rule set: {e}"))?;
    rules
        .validate(ResourceLimits::V1)
        .map_err(|e| format!("invalid rule set: {e}"))?;
    let expires = now_ms + i64::from(args.days) * DAY_MS;
    let mut envelope = SignedRuleEnvelope {
        schema_version: SchemaVersion::V1,
        rule_set_id: id.clone(),
        rule_set_version: args.version,
        issuer_key_id: issuer.clone(),
        created_at_unix_ms: now_ms,
        expires_at_unix_ms: expires,
        payload_encoding: PayloadEncoding::Json,
        payload_sha256_hex: hex(&Sha256::digest(payload.as_bytes())),
        payload,
        signature_base64url: String::new(),
    };
    let preimage = signing_preimage(&envelope, ResourceLimits::V1).map_err(|e| e.to_string())?;
    envelope.signature_base64url = URL_SAFE_NO_PAD.encode(key.sign(&preimage).to_bytes());
    let bytes = serde_json::to_vec_pretty(&envelope).map_err(|e| e.to_string())?;
    // Prove the agent accepts it before writing it.
    let trusted = TrustedRuleKey::new(id.clone(), issuer, key.verifying_key().to_bytes())
        .map_err(|e| e.to_string())?;
    RuleLoader::new(vec![trusted], ResourceLimits::V1)
        .and_then(|loader| {
            loader.load_json(
                &bytes,
                LoadContext { expected_rule_set_id: &id, now_unix_ms: now_ms, last_accepted: None },
            )
        })
        .map_err(|e| format!("the signed envelope does not load: {e}"))?;
    create_new(args.out, 0o644, &bytes)?;
    let expires_at = DateTime::from_timestamp_millis(expires)
        .ok_or("expiry out of range")?
        .to_rfc3339_opts(SecondsFormat::Secs, true);
    Ok(format!(
        "signed {} v{}, expires {expires_at}, sha256 {}\n",
        args.rule_set,
        args.version,
        hex(&Sha256::digest(&bytes))
    ))
}
```

In `rules.rs`, add the variant:

```rust
    /// Sign a rule set file into an envelope (offline: no config or
    /// database). The envelope wraps the file's exact bytes.
    Sign {
        /// Private key file from `rules keygen` (must be 0600).
        key_file: PathBuf,
        /// Rule set JSON (schema 1).
        rules_file: PathBuf,
        /// Rule set id.
        #[arg(long)]
        rule_set: String,
        /// Rule set version; must be above the published one.
        #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
        version: u64,
        /// Issuer key id (as given to keygen).
        #[arg(long)]
        issuer: String,
        /// Days until the envelope expires.
        #[arg(long, default_value_t = 730, value_parser = clap::value_parser!(u32).range(1..=3650))]
        days: u32,
        /// New envelope file (never overwritten).
        #[arg(short, long)]
        out: PathBuf,
    },
```

`name()`: `Self::Sign { .. } => "rules sign",`. `is_offline`: `matches!(self, Self::Keygen { .. } | Self::Sign { .. })`. `run` arm: `RulesCommand::Keygen { .. } | RulesCommand::Sign { .. } => unreachable!("offline, handled in main"),`. `run_offline` arm:

```rust
        RulesCommand::Sign { key_file, rules_file, rule_set, version, issuer, days, out } => {
            crate::rules_sign::sign(
                &crate::rules_sign::SignArgs {
                    key: key_file,
                    rules: rules_file,
                    rule_set,
                    version: *version,
                    issuer,
                    days: *days,
                    out,
                },
                Utc::now().timestamp_millis(),
            )
        }
```

- [ ] **Step 4: Run to verify they pass**

Run: `cargo test --locked -p openvibes-admin --test rules_sign`
Expected: 9 passed.

- [ ] **Step 5: Commit**

```bash
git add crates/openvibes-admin/src/rules_sign.rs crates/openvibes-admin/src/rules.rs crates/openvibes-admin/tests/rules_sign.rs
git commit -m "admin: rules sign wraps a rule set in a verified envelope"
```

### Task 3: A signed envelope publishes on a real platform

**Files:**
- Test: `crates/openvibes-admin/tests/rules.rs` (database test, next to the existing publish tests)

**Interfaces:**
- Consumes: the `rules keygen` / `rules sign` CLI from Tasks 1–2; `Fixture`, `offline`, `scratch_dir`, `stdout` from `tests/common`.

- [ ] **Step 1: Write the test**

```rust
#[tokio::test]
async fn signed_envelope_publishes() {
    let fixture = Fixture::create().await;
    let dir = scratch_dir("signed-publishes");
    let key = dir.join("rules.key");
    let rules = dir.join("rules.json");
    let out = dir.join("baseline.json");
    std::fs::write(
        &rules,
        r#"{"schema_version":1,"rules":[{"id":"port.ssh.exposed","version":1,"title":"SSH is exposed","severity":"low","confidence":90,"expression":"'22' in facts['port.tcp.exposed']","finding_message":"SSH listens on a non-loopback address (tcp 22)"}]}"#,
    )
    .unwrap();
    let line = stdout(&common::offline(&[
        "rules", "keygen", key.to_str().unwrap(), "--rule-set", "baseline", "--issuer", "openvibes-1",
    ]));
    let [set, issuer, public]: [&str; 3] =
        line.split_whitespace().collect::<Vec<_>>().try_into().unwrap();
    stdout(&common::offline(&[
        "rules", "sign", key.to_str().unwrap(), rules.to_str().unwrap(), "--rule-set", "baseline",
        "--version", "1", "--issuer", "openvibes-1", "-o", out.to_str().unwrap(),
    ]));
    stdout(&fixture.run(&["rules", "trust", "add", set, issuer, public]));
    assert_eq!(
        stdout(&fixture.run(&["rules", "publish", out.to_str().unwrap()])),
        "published baseline v1\n"
    );
    fixture.drop().await;
}
```

(Match the existing publish test's exact expected stdout; if it prints more than `published baseline v1\n`, assert with `starts_with`.)

- [ ] **Step 2: Run it**

Run: `eval "$(scripts/test-db.sh)" && cargo test --locked -p openvibes-admin --test rules signed_envelope_publishes`
Expected: PASS (this proves Tasks 1–2 end to end; if it fails, the defect is in `sign`, not in this test).

- [ ] **Step 3: Commit**

```bash
git add crates/openvibes-admin/tests/rules.rs
git commit -m "admin: test that a rules sign envelope publishes"
```

### Task 4: Docs, gate, PR

**Files:**
- Modify: `docs/components/openvibes-admin.md` ("Rules commands" table and a short paragraph)
- Modify: `docs/components/packaging.md:328-333` (single-host test step 2)

- [ ] **Step 1: Document the commands** — add two rows to the Rules commands table:

```markdown
| `rules keygen KEY_FILE --rule-set SET --issuer ISSUER` | offline (no config or database): writes a new Ed25519 private key to `KEY_FILE` (32 bytes, 0600, never overwritten) and prints `SET ISSUER PUBLIC_KEY`, the arguments of `rules trust add` and the line of a package's `.key` file |
| `rules sign KEY_FILE RULES_JSON --rule-set SET --version N --issuer ISSUER [--days 730] -o OUT` | offline: signs the exact bytes of a schema-1 rule set into a new envelope (valid now + `--days`, 1–3650), checks the agent's loader accepts it, and prints `signed SET vN, expires TIME, sha256 HEX`. Refuses a key file group or others can access, a key that is not 32 bytes, an invalid rule set, and an existing `OUT`. |
```

and after the table: "Keep the key file off the platform host; `keygen` and `sign` are meant for the signer's machine. The project's baseline rule set is signed this way (`openvibes-rules` repository)."

- [ ] **Step 2: Update packaging.md step 2** to:

```markdown
2. **Rules:** on your signing machine, make a key and sign a rule set
   (`openvibes-admin rules keygen KEY --rule-set baseline --issuer org.rules`
   prints the trust line; `openvibes-admin rules sign KEY rules.json
   --rule-set baseline --version 1 --issuer org.rules --days 30 -o
   bundle.json`), then on the platform:
```

- [ ] **Step 3: Run the full gate** (`testing.md` §2, from the worktree root, stop at the first failure):

```sh
eval "$(scripts/test-db.sh)"
bash scripts/build-console.sh
cargo fmt --all --check
bash scripts/check-names.sh
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings -F unsafe-code
RUSTDOCFLAGS="-D warnings" cargo doc --locked --workspace --all-features --no-deps
cargo test --locked --workspace --all-features
cargo audit --deny warnings
```

Expected: all green, `OPENVIBES_TEST_DATABASE_URL` set.

- [ ] **Step 4: Commit, push, open the PR**

```bash
git add docs/components/openvibes-admin.md docs/components/packaging.md
git commit -m "docs: rules keygen and sign"
git push -u origin baseline-rules
gh pr create --title "admin: rules keygen and sign (baseline rules 1)" --body "…spec §4, gate results…"
```

The PR also carries the spec and this plan. Post the PR number in the chat for `@claude`.
