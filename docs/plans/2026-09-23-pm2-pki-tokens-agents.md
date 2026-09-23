# PM2: Built-in PKI, Enrollment Tokens, Agent Commands — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Operators can build the built-in CA hierarchy, issue server certificates, create and revoke enrollment tokens, and list, inspect, and revoke agents; and `platform-pki` can check agent CSRs and issue client certificates, ready for ingest (PM3).

**Architecture:** New crate `platform-pki` (no I/O, no network: PEM strings in, PEM strings out) built on `rcgen` + `x509-parser`. `platform-store` gains migration 0002 (`ca_certificates`) and token, agent, and CA queries. `openvibes-admin` gains `ca`, `token`, and `agent` subcommands; the three **offline** `ca` commands never touch a database.

**Tech Stack:** Rust 1.95, rcgen 0.14.10 (`crypto`, `pem`, `ring`, `x509-parser`), x509-parser 0.18 (`verify`), time 0.3, ring 0.17 (randomness, SHA-256), chrono 0.4, PostgreSQL 18.

**Spec:** `docs/specs/2026-09-23-ingest-subproject-design.md` sections 4, 5, 7, 10 (PM2 exit: "issued chains validate; tokens stored only as hashes"); architecture spec section 5.

## Global Constraints

- Everything in the PM0/PM1 plan's Global Constraints still applies (toolchain, lints, `--locked`, commit trailer, component docs in `docs/components/` in the same change, `CARGO_NET_GIT_FETCH_WITH_CLI=true`, tests via `scripts/test-db.sh`).
- All keys ECDSA P-256. Root: 10 years, path length 1. Intermediate: 2 years, path length 0. Server: 90 days. Client: `client_certificate_days` (default 30).
- Client certificates: empty subject, SAN URI `openvibes:agent:<agent_id>`, EKU client auth, not a CA, serial = 16 bytes with the first two bits `01` (corrected after review: a cleared top bit alone lets DER strip a leading zero byte).
- CSR checks: valid signature, P-256 key, empty subject, at most 1 MiB; requested extensions ignored. (Corrected after review: parse and verify with x509-parser and take the key from the SPKI; rcgen's CSR parser derives the key algorithm from the signature algorithm.)
- Private key files are written `0600` with `create_new` (never overwritten); certificates `0644`.
- Tokens: 32 random bytes, base64url without padding, printed **once**; only the SHA-256 is stored.
- New workspace dependency for tokens: `base64 = { version = "0.23.1", default-features = false, features = ["std"] }` (the agent's pin).
- Offline `ca` commands (`init-root`, `intermediate-request`, `sign-intermediate`) need no config and no database and write no audit row; every other command is audited as in PM1, with the target set.

## Review Focus

- A CSR whose signature does not match its key, whose subject is non-empty, or whose key is not P-256 is refused. (Task 2.)
- `import-intermediate` with a key that does not match the certificate, or a certificate the root did not sign, records nothing. (Task 4.)
- No `ca` command ever overwrites an existing key file. (Task 4.)
- `token list` and the audit log never contain a token; the database holds only its hash. (Task 5.)
- Revoking an unknown or already-revoked agent is a clear error and is still audited. (Task 6.)

---

### Task 1: `platform-pki` — CA hierarchy and server certificates

**Files:** Create `crates/platform-pki/{Cargo.toml,src/lib.rs,src/ca.rs,tests/ca.rs}`, `docs/components/platform-pki.md`; add to workspace members; add to workspace deps `rcgen = { version = "0.14.10", default-features = false, features = ["crypto", "pem", "ring", "x509-parser"] }`, `x509-parser = { version = "0.18", features = ["verify"] }`, `time = "0.3"`, `ring = "0.17"`.

**Interfaces (produces):**
```rust
pub struct KeyAndCert { pub cert_pem: String, pub key_pem: String }
pub fn generate_root(now: DateTime<Utc>) -> Result<KeyAndCert, PkiError>;
pub fn intermediate_request() -> Result<(String /* csr_pem */, String /* key_pem */), PkiError>;
pub fn sign_intermediate(root: &KeyAndCert, csr_pem: &str, now: DateTime<Utc>) -> Result<String, PkiError>;
pub struct Issuer { /* rcgen::Issuer<'static, KeyPair>, cert_pem, not_after */ }
impl Issuer {
    pub fn load(cert_pem: &str, key_pem: &str) -> Result<Issuer, PkiError>; // key must match, cert must be a CA
    pub fn cert_pem(&self) -> &str;
    pub fn issue_server(&self, names: &[String], now: DateTime<Utc>) -> Result<KeyAndCert, PkiError>;
}
pub fn verify_signed_by(cert_pem: &str, issuer_cert_pem: &str) -> Result<(), PkiError>;
pub fn sha256_fingerprint(cert_pem: &str) -> Result<[u8; 32], PkiError>;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PkiError { InvalidPem, InvalidCsr, UnsupportedKey, NonEmptySubject, KeyMismatch, NotCa, NotSignedBy, Generation }
```

- [ ] **Step 1:** Write `tests/ca.rs` (fails: crate empty):

```rust
use chrono::Utc;
use platform_pki::{Issuer, PkiError, generate_root, intermediate_request, sign_intermediate, verify_signed_by};

fn hierarchy() -> (platform_pki::KeyAndCert, Issuer) {
    let now = Utc::now();
    let root = generate_root(now).unwrap();
    let (csr, key) = intermediate_request().unwrap();
    let cert = sign_intermediate(&root, &csr, now).unwrap();
    (root, Issuer::load(&cert, &key).unwrap())
}

#[test]
fn root_signs_intermediate_signs_server() {
    let (root, intermediate) = hierarchy();
    verify_signed_by(intermediate.cert_pem(), &root.cert_pem).unwrap();
    let server = intermediate.issue_server(&["ingest.example".into()], Utc::now()).unwrap();
    verify_signed_by(&server.cert_pem, intermediate.cert_pem()).unwrap();
    assert_eq!(verify_signed_by(&server.cert_pem, &root.cert_pem), Err(PkiError::NotSignedBy));
}

#[test]
fn lifetimes_and_constraints_follow_the_spec() {
    let (root, intermediate) = hierarchy();
    let parse = |pem: &str| {
        let der = x509_parser::pem::parse_x509_pem(pem.as_bytes()).unwrap().1.contents;
        let (_, cert) = x509_parser::parse_x509_certificate(&der).unwrap();
        let days = (cert.validity().not_after.timestamp() - cert.validity().not_before.timestamp()) / 86_400;
        let constraints = cert.basic_constraints().unwrap().map(|c| (c.value.ca, c.value.path_len_constraint));
        (days, constraints)
    };
    assert_eq!(parse(&root.cert_pem), (3652, Some((true, Some(1)))));
    assert_eq!(parse(intermediate.cert_pem()), (730, Some((true, Some(0)))));
    let server = intermediate.issue_server(&["ingest.example".into()], Utc::now()).unwrap();
    assert_eq!(parse(&server.cert_pem).0, 90);
}

#[test]
fn a_mismatched_key_or_a_non_ca_certificate_cannot_issue() {
    let (root, intermediate) = hierarchy();
    let (_, other_key) = intermediate_request().unwrap();
    assert_eq!(Issuer::load(intermediate.cert_pem(), &other_key).err(), Some(PkiError::KeyMismatch));
    let server = intermediate.issue_server(&["x.example".into()], Utc::now()).unwrap();
    assert_eq!(Issuer::load(&server.cert_pem, &server.key_pem).err(), Some(PkiError::NotCa));
    assert_eq!(Issuer::load("garbage", &root.key_pem).err(), Some(PkiError::InvalidPem));
}
```

- [ ] **Step 2:** Run `cargo test --locked -p platform-pki --test ca`: FAIL (unresolved imports).
- [ ] **Step 3:** Implement `ca.rs`. Validity: convert `now` with `time::OffsetDateTime::from_unix_timestamp(now.timestamp())`; root `not_after = now + 3652 days`, intermediate `+ 730`, server `+ 90`. Root: `CertificateParams::new(vec![])`, `distinguished_name` CN `OpenVIBES Root CA`, `is_ca = IsCa::Ca(BasicConstraints::Constrained(1))`, `key_usages = [KeyCertSign, CrlSign]`, `CertifiedIssuer::self_signed`. Intermediate request: `KeyPair::generate()`, params with CN `OpenVIBES Intermediate CA`, `serialize_request(&key)?.pem()`. `sign_intermediate`: parse CSR with `CertificateSigningRequestParams::from_pem` (verifies the signature), replace `params` fields (validity, `Constrained(0)`, key usages, fresh 16-byte serial from `ring::rand::SystemRandom` with `bytes[0] &= 0x7f`), sign with `Issuer::from_ca_cert_pem(&root.cert_pem, KeyPair::from_pem(&root.key_pem)?)`. `Issuer::load`: parse the certificate with x509-parser; `NotCa` unless basic constraints `ca`; `KeyMismatch` unless `KeyPair::from_pem(key).public_key_der()` equals the certificate's `subject_pki.raw`; then `rcgen::Issuer::from_ca_cert_pem`. `issue_server`: EKU server auth, SANs from `names`, 90 days, random serial. `verify_signed_by`: x509-parser `verify_signature(Some(issuer.public_key()))`, map failure to `NotSignedBy`. Map every parse error to `InvalidPem`, rcgen generation errors to `Generation`.
- [ ] **Step 4:** Run: PASS (3). Write `docs/components/platform-pki.md` (purpose, interface above, lifetimes, errors, test command) and add it to the components index. Clippy clean. Commit: `Add platform-pki with the built-in CA hierarchy`.

### Task 2: `platform-pki` — CSR checks and client certificates

**Files:** Create `crates/platform-pki/src/client.rs`, `crates/platform-pki/tests/client.rs`; update `docs/components/platform-pki.md`.

**Interfaces (produces, consumed by PM3 ingest):**
```rust
pub struct CheckedCsr { /* der */ pub spki_sha256: [u8; 32] }
pub fn check_csr(csr_pem: &str) -> Result<CheckedCsr, PkiError>;
pub struct IssuedClient { pub serial: [u8; 16], pub spki_sha256: [u8; 32], pub not_before: DateTime<Utc>, pub not_after: DateTime<Utc>, pub chain_pem: Vec<String> /* leaf, intermediate */ }
impl Issuer { pub fn issue_client(&self, csr: &CheckedCsr, agent_id: &str, now: DateTime<Utc>, days: u32) -> Result<IssuedClient, PkiError>; }
pub fn spki_sha256_of_cert(cert_pem: &str) -> Result<[u8; 32], PkiError>;
```

- [ ] **Step 1:** Write `tests/client.rs`. Build CSRs with rcgen directly: a good one (`KeyPair::generate()`, `CertificateParams::new(vec![])` with an **empty** `DistinguishedName::new()`, `serialize_request`); one with CN `evil`; one with a P-384 key (`KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384)`); one whose base64 body has a byte flipped in the signature; `"not a csr"`. Assert: good → `Ok` and `spki_sha256` equals SHA-256 of the key's `public_key_der()`; CN → `NonEmptySubject`; P-384 → `UnsupportedKey`; flipped → `InvalidCsr`; garbage → `InvalidCsr`; a 1 MiB + 1 string → `InvalidCsr`. Then issue for `agent.00000000-0000-4000-8000-000000000001`, 30 days, and assert with x509-parser: signed by the intermediate (`verify_signed_by`), subject empty, SAN contains exactly URI `openvibes:agent:<id>`, EKU client auth only, basic constraints absent or `ca == false`, serial 16 bytes with top bit clear, `not_after - not_before == 30 days`, `chain_pem == [leaf, intermediate.cert_pem()]`, and `spki_sha256_of_cert(leaf) == csr.spki_sha256`. Two issuances give different serials.
- [ ] **Step 2:** Run: FAIL.
- [ ] **Step 3:** Implement `client.rs`. `check_csr`: reject over 1 MiB (`InvalidCsr`); `CertificateSigningRequestParams::from_pem` (signature verified; any error `InvalidCsr`); parse the DER with `x509_parser::certification_request::X509CertificationRequest::from_der`; `NonEmptySubject` unless the subject has no RDNs; `UnsupportedKey` unless the SPKI algorithm is `id-ecPublicKey` with parameter `prime256v1`; `spki_sha256 = ring::digest::digest(&SHA256, spki.raw)`. `issue_client`: fresh `CertificateParams::new(vec![])`, `subject_alt_names = [SanType::URI(format!("openvibes:agent:{agent_id}").try_into()?)]`, EKU `ClientAuth`, `is_ca = NoCa`, random serial, validity `now .. now + days`, public key from the CSR; sign with the loaded issuer. Every extension is set by the platform; nothing from the CSR's requested extensions is copied.
- [ ] **Step 4:** Run: PASS. Update the component page (CSR rules, client profile, `spki_sha256` meaning). Commit: `Check agent CSRs and issue client certificates`.

### Task 3: Migration 0002 and store queries

**Files:** Create `migrations/0002_ca_tokens_agents.sql`, `crates/platform-store/src/{ca.rs,tokens.rs,agents.rs}`, `crates/platform-store/tests/{tokens.rs,agents.rs}`; bump `SCHEMA_VERSION` to 2 and add the migration to `MIGRATIONS`; update `docs/components/platform-store.md`.

**Interfaces (produces).** Every function takes `client: &platform_store::Client`; every timestamp is `chrono::DateTime<Utc>`.
```rust
pub mod ca { pub async fn record(client, role: &str /* "root"|"intermediate" */, fingerprint: [u8;32], pem: &str, not_after: DateTime<Utc>) -> Result<(), StoreError>; pub async fn list(client) -> Result<Vec<CaCertificate>, StoreError>; }
pub mod tokens {
    pub struct NewToken { pub token_sha256: [u8; 32], pub label: Option<String>, pub created_by: String, pub expires_at: DateTime<Utc>, pub max_uses: i32 }
    pub struct TokenInfo { pub token_id: String, pub label: Option<String>, pub created_at: DateTime<Utc>, pub expires_at: DateTime<Utc>, pub max_uses: i32, pub uses: i64, pub revoked: bool }
    pub async fn create(client, &NewToken) -> Result<String /* token_id */, StoreError>;
    pub async fn list(client) -> Result<Vec<TokenInfo>, StoreError>;
    pub async fn revoke(client, token_id: &str, now) -> Result<bool /* was usable */, StoreError>;
}
pub mod agents {
    pub struct AgentInfo { pub agent_id: String, pub status: String, pub enrolled_at: DateTime<Utc>, pub revoked_at: Option<DateTime<Utc>>, pub last_seen_at: Option<DateTime<Utc>>, pub scanner_version: Option<String>, pub certificates: i64 }
    pub enum Filter { All, Offline, Revoked }
    pub async fn list(client, Filter, now) -> Result<Vec<AgentInfo>, StoreError>;
    pub async fn show(client, agent_id: &str) -> Result<Option<AgentInfo>, StoreError>;
    pub enum Revoke { Revoked, AlreadyRevoked, Unknown }
    pub async fn revoke(client, agent_id: &str, now) -> Result<Revoke, StoreError>;
}
```

- [ ] **Step 1:** Write `0002_ca_tokens_agents.sql`: `CREATE TABLE ca_certificates (fingerprint_sha256 bytea PRIMARY KEY CHECK (length(fingerprint_sha256) = 32), role text NOT NULL CHECK (role IN ('root','intermediate')), pem text NOT NULL, not_after timestamptz NOT NULL, recorded_at timestamptz NOT NULL DEFAULT now()); GRANT SELECT ON ca_certificates TO openvibes_ingest;`. Tokens and agents already exist in 0001.
- [ ] **Step 2:** Write failing tests. `tokens.rs`: create two tokens (one `max_uses 2`), `list` shows both with `uses 0` and the stored hash is the given one (`SELECT token_sha256`), `revoke` returns `true` then `false`, unknown id (a valid random UUID) returns `false`, a malformed id is `StoreError::Query`, and `status().tokens_usable` drops by one after revocation. `agents.rs`: insert three agents by SQL (active and recently seen, active and silent 16 min, revoked); `list(All)` 3, `list(Offline)` 1, `list(Revoked)` 1; `show` returns the certificate count; `revoke` on the active one → `Revoked` and sets `revoked_at`, again → `AlreadyRevoked`, unknown → `Unknown`. Migration test: `schema_version` is now 2 after `migrate`.
- [ ] **Step 3:** Run: FAIL. Implement with plain parameterised SQL (`gen_random_uuid()` for token ids, `token_id::text` in results, `$1::uuid` in parameters). Revocation uses `UPDATE agents SET status='revoked', revoked_at=$2 WHERE agent_id=$1 AND status='active'` and distinguishes the outcomes with a follow-up existence check.
- [ ] **Step 4:** Run the whole store suite: PASS. Update the component page. Commit: `Add migration 2 and CA, token, and agent queries`.

### Task 4: `openvibes-admin ca …`

**Files:** Modify `crates/openvibes-admin/src/main.rs` (split into `src/main.rs`, `src/ca.rs`, `src/files.rs` if it passes ~300 lines); create `crates/openvibes-admin/tests/ca.rs`; update `docs/components/openvibes-admin.md`.

Commands:
- `ca init-root --out DIR` → `DIR/root.crt` (0644), `DIR/root.key` (0600). Offline.
- `ca intermediate-request --out DIR` → `DIR/intermediate.csr`, `DIR/intermediate.key` (0600). Run on the ingest host.
- `ca sign-intermediate --root DIR --csr FILE --out FILE` → the intermediate certificate. Offline.
- `ca import-intermediate --cert FILE --key FILE --root-cert FILE` → checks `Issuer::load(cert, key)` and `verify_signed_by(cert, root)`, then records root and intermediate in `ca_certificates`. Audited, target = intermediate fingerprint (hex).
- `ca issue-server NAME [--san NAME]… --issuer-cert FILE --issuer-key FILE --out DIR` → `DIR/NAME.crt` (leaf + intermediate), `DIR/NAME.key` (0600). Audited, target = NAME.

- [ ] **Step 1:** Write failing tests (drive the binary as in `tests/cli.rs`): the full offline chain in a temp dir, then `import-intermediate` against a fresh database records two rows; file modes are `0o600` for keys and `0o644` for certificates; running `init-root` twice into the same directory fails and leaves the first key byte-for-byte unchanged; `import-intermediate` with the wrong key exits non-zero, records nothing, and writes an `error` audit row; `import-intermediate` with an intermediate signed by a different root does the same; offline commands succeed with `--config` pointing at a nonexistent file.
- [ ] **Step 2:** Run: FAIL. Implement: offline subcommands dispatch before config loading. Files via `OpenOptions::new().write(true).create_new(true).mode(0o600|0o644)`; bounded reads (1 MiB) for PEM inputs. Errors print fixed messages (never file contents).
- [ ] **Step 3:** Run: PASS. Update the component page (offline vs host commands, the operator flow root → request → sign → import → issue-server). Commit: `Add openvibes-admin ca commands`.

### Task 5: `openvibes-admin token …`

**Files:** Modify admin sources; create `crates/openvibes-admin/tests/token.rs`; update docs.

Commands: `token create --expires DURATION [--uses N] [--label TEXT]` (DURATION `Nd` or `Nh`, 1 hour to 365 days; `--uses` 1 to 100000) prints the token id and the token once; `token list` prints id, label, created, expires, uses/max, state; `token revoke ID`.

- [ ] **Step 1:** Write failing tests: `create --expires 7d --uses 3 --label lab` prints a line `token <43 base64url chars>`; the database `token_sha256` equals SHA-256 of those decoded bytes and no column holds the token; `list` output and every `audit_log` row do not contain the token string; `--expires 0d`, `--expires 366d`, `--expires 7x`, `--uses 0` exit 2 before any change; `revoke` of that id succeeds and `status` shows `tokens usable 0`; revoking again prints `already revoked` and exits non-zero (audited `error`).
- [ ] **Step 2:** Run: FAIL. Implement: 32 bytes from `ring::rand::SystemRandom`, base64url without padding (`base64` crate with `URL_SAFE_NO_PAD`, as in the agent), SHA-256 with `ring::digest`. Audit target = token id, never the token.
- [ ] **Step 3:** Run: PASS. Update docs. Commit: `Add openvibes-admin token commands`.

### Task 6: `openvibes-admin agent …`

**Files:** Modify admin sources; create `crates/openvibes-admin/tests/agent.rs`; update docs.

Commands: `agent list [--offline | --revoked]` (one line per agent: id, status, last seen, version), `agent show ID` (all fields and certificate count), `agent revoke ID`.

- [ ] **Step 1:** Write failing tests with agents inserted by SQL: list filters return the right ids; `show` of an unknown id exits non-zero with `unknown agent`; `revoke` prints `revoked <id>`, then again `already revoked` (non-zero); unknown id `unknown agent` (non-zero); each of the three revoke attempts adds an audit row with target = the id and result `ok`, `error`, `error`.
- [ ] **Step 2:** Run: FAIL. Implement over `platform_store::agents`.
- [ ] **Step 3:** Run the whole workspace (fmt, clippy, doc, tests): PASS. Update docs and the components index. Commit: `Add openvibes-admin agent commands`.

## Exit (PM2)

CI green; the offline chain root → intermediate → server and client certificates verifies in tests; tokens exist only as hashes; `agent revoke` works and is audited. PM3 consumes `check_csr`, `Issuer::issue_client`, `spki_sha256_of_cert`, and the token and agent queries.
