# TUI 4c: The Console's Own Certificate — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Maintenance › Certificates can put the admin's own certificate on the console (for the browser) and go back to the platform's; Status warns 30 days before it ends. Nothing at Install, no ACME, no proxy mode.

**Architecture:** A pure check in `platform-pki` (`server.rs`) reuses 4b's key reading. The TUI checks at once and sends certificate + key on stdin to a new root helper verb `console-cert-set`, which re-checks and keeps them as `/etc/openvibes/tls/console-own.crt` (0644) and `console-own.key` (0600 root). The Setup certificates step installs the own pair as the console's chain/key instead of issuing one, never renews it, and exempts it from the "signed by the intermediate" check. `console-cert-reset` removes the pair and reissues the platform's. The console's Host allow-list already comes from its certificate's names, so names on the own certificate work in the browser with no other change.

**Tech Stack:** Rust, platform-pki (x509-parser, 4b's `keys.rs`), ratatui TUI, root helper verbs as in 4b.

**Spec:** `docs/specs/tui-rework/approved.md` rule 57 (screens `docs/specs/tui-rework/certs4c.py`), which replaces rule 36's web address question; workspace `decisions.md` 2026-10-26 entries ("Browsers are never asked to import a root", "4c simplified"). Recon: `~/.cache/openvibes-scratch/sp4c/recon.md`.

## Global Constraints

- Copy verbatim from approved.md 57 / `certs4c.py`.
- Files under 500 lines; near-full files (`platform-host/src/setup.rs` 498, `tui/install/certs.rs` 490, `setup/pki.rs` 471, `platform-pki/src/keys.rs` 408, `ca.rs` 406, `tui/database.rs` 401) get new code in new files.
- The key never on argv, journal, audit, errors or Debug; held in `Zeroizing`; the helper re-checks everything (as 4b).
- No new dependencies.
- Agents' certificates (ingest, distribution) are never affected by the console's own certificate.
- Cargo: `CARGO_BUILD_JOBS=6 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 nice -n 19 ionice -c3`, `CARGO_TARGET_DIR=~/.cache/openvibes-scratch/target-4c`; DB tests only via `scripts/test-db.sh`.
- Commits end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`; each component change updates its `docs/components/*.md` page.

## Rulings made while planning

- **Q1 Name coverage:** the certificate must cover at least one of the console's names (`certificate_names`: plan names + host addresses). A DNS SAN `*.x.y` covers exactly one label (`a.x.y`, not `x.y`, not `a.b.x.y`); IP SANs match exactly; CN is ignored when SANs exist. Cost if wrong: refusals.
- **Q2 The chain:** blocks after the first are kept and served (the CAs above it); the root may be included or not; nothing is checked about them beyond being certificates (the browser decides trust). Cost if wrong: one more check.
- **Q3 Expiry:** an expired or not-yet-valid certificate is refused; one valid for any time is accepted (no 90-day floor: a company may issue short ones). Status warns at ≤30 days (amber), red once ended. Cost if wrong: thresholds.
- **Q4 Storage is the switch:** "own" means `/etc/openvibes/tls/console-own.crt` + `.key` exist. No plan field. Cost if wrong: a plan field later.
- **Q5 Names change after:** if Names later drops every name the own certificate covers, the certificate stays in use and Status says "Console certificate: covers none of this console's names". Cost if wrong: one more check.

## Review Focus

1. A Setup/Repair/renewal run never overwrites the own console certificate, and never reports Todo forever because it is "not signed by the intermediate" (4a check). (Task 2 `renewal_leaves_your_own_console_certificate`, `own_console_is_not_signed_by_the_intermediate_and_that_is_fine`.)
2. Replace the intermediate leaves the own console certificate in place and reissues only agents' certificates. (Task 2 `replace_keeps_your_own_console_certificate`.)
3. A wildcard covers one label only. (Task 1 `a_wildcard_covers_one_label`.)
4. Going back issues the platform's console certificate again at once and removes the own pair. (Task 3 `reset_reissues_the_platforms`.)
5. The own key file is 0600 root, the installed console key 0640 root:openvibes-console as today; Remove everything removes both own files. (Tasks 2-3 tests.)

---

### Task 1: The check (`platform-pki/src/server.rs`)

**Files:** Create `crates/platform-pki/src/server.rs`, `crates/platform-pki/tests/server.rs`, fixtures via `tests/fixtures/make.sh` (own step: a server certificate `*.limebox.se` + key signed by the fixture issuing CA, one with EKU clientAuth only, one expired, one not yet valid); modify `lib.rs`, `docs/components/platform-pki.md`.

**Interfaces — Produces:**
- `pub struct ServerCert { pub name: String /* first SAN or CN */, pub covers: Vec<String> /* which of the given names */, pub chain_pem: String /* ours first, then the rest, canonical PEM */, pub not_after: DateTime<Utc> }`
- `pub enum ServerCertError { InvalidPem, IsCa, NotForServers, Expired(DateTime<Utc>), NotYetValid(DateTime<Utc>), CoversNone, Pki(PkiError) }`
- `pub fn check_server_cert(certs_pem: &str, names: &[String], now: DateTime<Utc>) -> Result<ServerCert, ServerCertError>` — first block is ours: not a CA; EKU absent or containing serverAuth; valid now; covers ≥1 of `names` (Q1).
- `pub fn check_server_key(cert: &ServerCert, pkcs8_pem: &str) -> Result<KeyInfo, ServerCertError>` — key matches the first certificate's SPKI; `key_info` limits as 4b.
- `pub fn covers(cert_pem: &str, name: &str) -> bool`.

- [ ] Step 1: failing tests `a_server_certificate_is_accepted` (covers == ["openvibes.limebox.se"] with names ["limebox.lan","openvibes.limebox.se"]), `a_wildcard_covers_one_label`, `an_ip_san_matches_exactly`, `a_ca_is_refused` (IsCa), `client_only_is_refused` (NotForServers), `expired_and_not_yet_valid_are_refused`, `covering_no_name_is_refused` (CoversNone), `the_key_must_match`, `the_chain_is_kept_in_order`.
- [ ] Step 2: run `cargo test -p platform-pki --test server` → FAIL. Step 3: implement. Step 4: PASS, clippy. Step 5: docs + commit `platform-pki: check a server certificate for the console`.

### Task 2: Setup honours the own certificate

**Interfaces — Produces:** `OWN_CERT` = `/etc/openvibes/tls/console-own.crt`, `OWN_KEY` = `/etc/openvibes/tls/console-own.key` (defined here; Task 3 writes them).

**Files:** Create `crates/openvibes-admin/src/setup/pki_console.rs` (+ tests); modify `setup/pki.rs` (dispatch only), `setup/remove*.rs` if they list tls files, docs `openvibes-admin.md`, `packaging.md`.

**Behaviour:**
- `certificates_check`: when the own pair exists, the console entry is Done when `console-chain.pem` equals `OWN_CERT` (DER compare) and the key matches; no expiry/renew/intermediate/chain.crt checks for the console; Todo otherwise. Ingest and distribution unchanged.
- `certificates_apply`: console with own pair → copy `OWN_CERT` to `console-chain.pem` (0644), `OWN_KEY` to `console-key.pem` (0640 root:openvibes-console), try-restart the console; never `issue-server` for it. Without the pair → as today.
- Renewal and Replace the intermediate go through the same step, so they leave it alone.

- [ ] Steps: failing tests `renewal_leaves_your_own_console_certificate`, `own_console_is_not_signed_by_the_intermediate_and_that_is_fine`, `replace_keeps_your_own_console_certificate`, `apply_installs_your_own_with_the_console_modes`, `remove_everything_takes_both_own_files`; RED, implement, GREEN, commit `setup: the console keeps your own certificate`.

### Task 3: Helper verbs `console-cert-set` / `console-cert-reset`

**Files:** Create `crates/openvibes-admin/src/setup/console_cert.rs` (+ `_tests.rs`); modify `helper_ca.rs`, `platform-host` (new `Privileged::ConsoleCertSet(&Secret)` with stdin as `CaImport`, `Privileged::ConsoleCertReset`; put them in a new file beside `setup.rs`), `tui/run.rs` (`Call::ConsoleCertSet(Bundle)`, `Call::ConsoleCertReset`), docs `openvibes-admin.md`, `platform-host.md`.

**Interfaces — Produces:**
- Uses `OWN_CERT` / `OWN_KEY` from Task 2.
- `console-cert-set`: stdin = certificate PEM blocks then one `PRIVATE KEY` (≤1 MiB, as 4b's `split`); re-checks with `certificate_names(ctx)`; writes key first (0600 root), then cert (0644), atomic as 4b's staging with cleanup on failure; then runs the certificates step (Task 2) so the console uses it and restarts; stdout `set<TAB>{name}<TAB>{until YYYY-MM-DD}`. Under the Setup lock.
- `console-cert-reset`: removes both files, runs the certificates step (reissues the platform's console certificate, restarts); stdout `reset`.
- Journal: `console-cert-set /etc/openvibes/tls/console-own.crt`, `console-cert-reset /etc/openvibes/tls/console-own.crt`.
- `pub fn console_cert_message(e: &ServerCertError, file: Option<&str>) -> String`, exact sentences (approved.md 57): IsCa "This is a CA certificate: pick the console's own certificate."; NotForServers "Not for servers (its extended key usage): ask for a server certificate."; Expired(d) "Expired on {d}: ask for a new one."; NotYetValid(d) "Valid from {d}: not valid yet."; CoversNone "Covers none of this console's names: add one under Names first."; Pki(KeyMismatch) "Not the key of {name}: paste the key it was made with."; others as 4b's `import_message` for keys/passwords.

- [ ] Steps: failing tests (`set_keeps_the_pair_and_installs_it`, `set_refuses_and_writes_nothing`, `reset_reissues_the_platforms`, `the_key_never_reaches_argv_or_journal`), RED, implement, GREEN, commit `admin: console-cert-set and console-cert-reset`.

### Task 4: Status

**Files:** Create `crates/openvibes-admin/src/tui/console_cert_check.rs` (+ tests); modify `tui/database.rs` (dispatch), platform-host's certificate list if needed.

**Behaviour:** with the own pair: the console row is judged on its own: ≤30 days → amber problem "Console certificate: yours ends {date}, in {n} days" with the help "Use a new one in Maintenance › Certificates."; ended → red "Console certificate: yours ended on {date}"; covering none of the console's names (Q5) → "Console certificate: covers none of this console's names". The "automatic renewal is failing" sentence never applies to it. Home counts these like other problems.

- [ ] Steps: failing tests `yours_warns_30_days_before`, `yours_is_red_once_ended`, `yours_never_says_renewal_is_failing`, `names_dropped_after_says_so`; RED, implement, GREEN, commit `tui: Status watches your own console certificate`.

### Task 5: Maintenance › Certificates (TUI)

**Files:** Create `crates/openvibes-admin/src/tui/maint/console_cert.rs` (+ tests); modify `tui/maint/certs.rs` (rows and the third action), reuse 4b's install import rows/paste/.p12/password code by calling it (with a checker for `Which::Cert`/`Which::Key` that uses Task 1 and `console_cert_message`), docs `openvibes-admin.md`.

**Copy:** `certs4c.py` #1-#13 verbatim: rows "Agents" / "Console"; action "Console certificate" ("use your own" / "use a new one, or go back to the platform's"); page "Use your own certificate", note, rows, green lines "{name} · for server use · valid until {date}" and "Covers {first covered}, one of this console's names."; question "Use it?" · "the console restarts" → `Call::ConsoleCertSet`; result "The console uses your certificate · until {date}"; "The console's certificate" page ("Yours: {name}, until {date}.", "Use a new one", "Go back to the platform's" · "renewed automatically with the agents"); "Go back?" · "the console restarts" → `Call::ConsoleCertReset`; result line for going back "The console uses the platform's certificate again" (ruling: new string).

- [ ] Steps: failing tests for each screen's key lines and the calls (`use_your_own_sends_set_on_yes`, `no_sends_nothing`, `go_back_sends_reset`, `a_pfx_fills_both_rows`, `covers_none_is_red_and_use_it_does_nothing`); RED, implement, GREEN; render check against `certs4c.py`; commit `tui: Maintenance › Certificates › Console certificate`.

### Task 6: Docs and the reverse-proxy note; gate

**Files:** `docs/components/openvibes-admin.md` (Certificates), `docs/components/openvibes-console.md` (a "Behind a reverse proxy" note: forward to https://host:{console port}, keep the Host header, put the proxy's name under Names, turn proxy buffering off for `/api/v1/agents/events`, the console sends HSTS), `docs/quick-setup.md` if it mentions certificates, spec `docs/specs/2026-10-10-tui-rework-design.md` §5 step 3 / §6 (a note that approved.md 57 replaces the web address question).

- [ ] Steps: write the docs; run `~/.cache/openvibes-scratch/g4c/gate.sh` (copy of g4b's with 4c paths) → GATE GREEN; commit `docs: the console's own certificate; behind a reverse proxy`.
