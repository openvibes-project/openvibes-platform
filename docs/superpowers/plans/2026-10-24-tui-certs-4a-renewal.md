# TUI sub-project 4a: automatic certificate renewal — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The server certificates (console, ingest, distribution) renew themselves before they expire, Status warns only when renewal fails, and Maintenance › Certificates shows this and can replace the intermediate without breaking enrolled agents.

**Architecture:** A root systemd timer runs a new helper verb, `certificates-renew`, once a day. The verb runs the existing Setup `certificates` step, whose check now asks for renewal (`Todo`) 30 days before expiry, so the same code that issues certificates at install also renews them. Replacing the intermediate writes a trust bundle (new first, old second) to `intermediate.crt`, so ingest and distribution accept agent certificates from both while agents renew onto the new one. The renewal verb drops the old certificate from the bundle once its last agent certificate can have ended.

**Tech Stack:** Rust (openvibes-admin, platform-pki, platform-host), ratatui TUI, systemd units in the RPM, rcgen and x509-parser (already present). No new dependencies.

**Spec:** `docs/specs/2026-10-10-tui-rework-design.md` §6 (Certificates), §10 item 5, §12 item 4. Approved mockups: `docs/specs/tui-rework/certs2.py` (the page, Replace for your own CA) and `certs4a.py` (Replace when OpenVIBES made the CA, the run, the page afterwards; **approval pending with this plan**). Rules in `docs/specs/tui-rework/approved.md`: 6, 33, 34, 36, 48. Decisions: workspace `decisions.md`, "2026-10-24: TUI sub-project 4 … split in three". Recon: `~/.cache/openvibes-scratch/sp4/recon.md`.

## Global Constraints

- This host is the user's production platform. Never touch its own OpenVIBES services, `/etc/openvibes` or the system postgres. Tests that need a database run only under `eval "$(scripts/test-db.sh)"`, followed by `scripts/test-db.sh stop`.
- Every cargo command: `CARGO_BUILD_JOBS=6 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 nice -n 19 ionice -c3 cargo …`, with `CARGO_TARGET_DIR=$HOME/.cache/openvibes-scratch/target-4a`.
- Files stay under 500 lines; split a module before it passes that.
- Every component change updates its page in `docs/components/` in the same commit (`openvibes-admin.md`, `packaging.md`, `platform-pki.md`, `platform-host.md` where present).
- Commits end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. Implementers never push.
- Nothing the platform does automatically gets a button (approved.md 33): there is no Renew entry.
- Status warns only on failure (rule 34): a certificate that renews on time never shows a problem.
- Questions are asked in the bar, with Yes/No buttons; the brackets mark the chosen button (rule 54). The sudo password is asked in the bar, never stored.
- No leftovers: every new unit, file and state file is removed by uninstall (Remove everything) and by `%preun`/`%postun`, as the existing units are.
- Renewal margins: `RENEW_AT_DAYS = 30` (renew when 30 days or fewer are left on a 90-day certificate); `RENEW_DAYS = 14` stays the Status warning for server certificates; `INTERMEDIATE_WARN_DAYS = 60` for the intermediate.

## Review Focus

1. **Renewal while an install, Repair or Update holds the Setup lock:** the timer run must skip quietly (exit 0, one journal line) and try again the next day, never fail the unit or wait.
2. **A host that was never set up, or was uninstalled with Keep the data:** the timer must not fail every day. The service has `ConditionPathExists=/etc/openvibes/setup.toml` and `/etc/openvibes/tls/setup-names`.
3. **Agents enrolled before Replace:** they must keep connecting after Replace, through the bundle. A test issues a client certificate from the old intermediate and verifies it against the new bundle.
4. **The certificate handed to agents after Replace:** enrollment and renew must return leaf + new intermediate only, never the old one (`Issuer::load` reads only the first certificate of a bundle).
5. **An upgrade from a release whose console chain is 0640:** the first timer run makes it readable to Status (0644), with no manual step.

---

### Task 1: platform-pki reads the first certificate of a bundle

**Files:**
- Modify: `crates/platform-pki/src/ca.rs` (`Issuer::load` :152, plus a new `first_certificate`)
- Test: `crates/platform-pki/src/ca.rs` tests module (or its existing tests file)
- Docs: `docs/components/platform-pki.md`

**Interfaces:**
- Produces: `pub fn first_certificate(pem: &str) -> Result<String, PkiError>`, the first `CERTIFICATE` block re-encoded as PEM with a trailing newline (`InvalidPem` if there is none). `Issuer::load` keeps only that block as `cert_pem`, so `issue_client`'s `chain_pem` is leaf + issuer only.

- [ ] **Step 1: Write the failing tests**
  - `issuer_from_a_bundle_uses_the_first_certificate`: make root A with intermediate A1, and root A with intermediate A2. `Issuer::load(&(a2 + a1), &a2_key)` succeeds. A client certificate it issues has `chain_pem.len() == 2` and `chain_pem[1] == first_certificate(&(a2 + a1))`, which equals A2's PEM.
  - `first_certificate_of_one_is_itself`: `first_certificate(a1)` equals `a1`, modulo a trailing newline.
- [ ] **Step 2: Run them:** `cargo test -p platform-pki first_certificate issuer_from_a_bundle`. Expected: FAIL (the function is not defined).
- [ ] **Step 3: Implement** `first_certificate` with `x509_parser::pem::parse_x509_pem` (already used by `der_of`) and `pem::encode`. Call it at the start of `Issuer::load`.
- [ ] **Step 4: Run** `cargo test -p platform-pki`. Expected: all pass.
- [ ] **Step 5: Commit:** `pki: an issuer bundle issues from its first certificate only`.

### Task 2: Renewal: check, helper verb, timer

**Files:**
- Modify: `crates/openvibes-admin/src/setup/pki.rs`:
  - `certificates_check` :332: under `RENEW_AT_DAYS` it returns `Todo`, not `Failed`; it also returns `Todo` when the console chain's mode is not 0644.
  - `certificates_apply` :357: the console chain is written 0644 `root:openvibes-console` (the key stays 0640); the chain uses `first_certificate(INTERMEDIATE)`.
  - Fix the comments at :314 and :345 so they match.
- Modify: `crates/openvibes-admin/src/setup/mod.rs`:
  - `run_step` comment :210.
  - New `pub fn renew() -> ExitCode`.
- Modify: `crates/openvibes-admin/src/helper.rs`: a new verb `CertificatesRenew` (`certificates-renew`), dispatched to `setup::renew()`.
- Create: `packaging/rpm/openvibes-certificates.service` and `packaging/rpm/openvibes-certificates.timer`.
- Modify: `packaging/rpm/openvibes-platform.spec`: install both units next to the maintenance ones (:208), and add them to the same `%systemd_post`, `%preun` and `%postun` lines and `%files`.
- Modify: `crates/platform-host/src/unit.rs`: add `Unit::Certificates`:
  - name `openvibes-certificates.timer`;
  - short name `certificates`;
  - label `certificate renewal`;
  - no readiness URL;
  - placed after `Maintenance` in `ALL` (now 9).
- Modify: `crates/openvibes-admin/src/tui/status.rs:48`: `idles` includes `Unit::Certificates`.
- Modify: `crates/openvibes-admin/src/helper.rs::journal_units`: Certificates → timer + `openvibes-certificates.service`.
- Tests: `crates/openvibes-admin/src/setup/` (next to the existing pki and setup tests), `helper.rs` journal test, and the tests that count `Unit::ALL` (they will fail and name themselves).
- Docs:
  - `docs/components/packaging.md`: replace "Renewing the server certificate" :496-511 with how the timer renews and how to see its log.
  - `docs/components/openvibes-admin.md` :251-252.

**Interfaces:**
- Consumes: `platform_pki::first_certificate` (Task 1).
- Produces:
  - `pub(crate) const RENEW_AT_DAYS: i64 = 30` in `setup/pki.rs`.
  - `setup::renew() -> ExitCode`.
  - `Unit::Certificates`.
  - `pub(crate) fn drop_previous<R: Runner>(ctx: &Ctx<R>) -> Result<Option<String>, String>` in `setup/pki.rs`. Here it is a stub returning `Ok(None)`; Task 4 fills it in. `renew` calls it after the step.

`renew()` behaviour, in order:
1. If `system::lock` returns the "in progress" error, print `certificate renewal skipped: another Setup run is in progress` and exit 0.
2. If no plan can be loaded, print `certificate renewal skipped: OpenVIBES is not set up on this host` and exit 0.
3. Run `run_step(&host_ctx(&plan, true), Step::Certificates)` and print its `.line()`.
4. Call `drop_previous` and print its line, if any.
5. Exit `FAILURE` only when the step state is `Failed` or `Waiting`, or `drop_previous` returned `Err`.

The service unit:
- `Type=oneshot`, `User=root`, `ExecStart=/usr/bin/openvibes-admin helper certificates-renew`;
- `ConditionPathExists=/etc/openvibes/setup.toml` and `ConditionPathExists=/etc/openvibes/tls/setup-names`;
- `After=network-online.target`, `UMask=0077`, `NoNewPrivileges=yes`, `PrivateTmp=yes`, `ProtectHome=yes`.

Do not use `ProtectSystem=strict`: the step writes `/etc/openvibes/tls` and `/run` and calls systemctl.

The timer: `OnCalendar=daily`, `RandomizedDelaySec=1h`, `Persistent=true`, `WantedBy=timers.target`.

- [ ] **Step 1: Write the failing tests** (with the existing `Ctx` test fixture over a temporary root and a fake runner, as in the pki and setup tests):
  - `certificates_due_for_renewal_are_todo`: certificates with 29 days left give `StepState::Todo`. With 31 days left and a 0644 console chain, they give `Done`.
  - `a_console_chain_not_world_readable_is_todo`: 60 days left but the chain is 0640 gives `Todo`.
  - `renewal_writes_the_console_chain_0644_with_one_intermediate`: after `certificates_apply`, the chain is 0644 and holds exactly two certificates, even when `intermediate.crt` is a bundle of two.
  - `the_renewal_timer_logs_include_its_service`: `journal_units(Unit::Certificates) == ["openvibes-certificates.timer", "openvibes-certificates.service"]`.
  - A test for `renew`'s skip on a held lock. Factor the decision into `fn renew_outcome(locked: Result<…>, …) -> (String, ExitCode)` if `renew` itself cannot run in tests.
- [ ] **Step 2: Run** `cargo test -p openvibes-admin certificates_ renewal_ journal`. Expected: FAIL.
- [ ] **Step 3: Implement** the changes in the Files list.
- [ ] **Step 4: Run** `cargo test -p openvibes-admin` and `cargo test -p platform-host`. Expected: pass. Update the `Unit::ALL` count tests and the status fixtures ("All 8 services" becomes 9 only where the timer is installed, as for Maintenance).
- [ ] **Step 5: Run** `rpmspec -P packaging/rpm/openvibes-platform.spec | grep certificates`. Expected: both units appear in install, `%files` and the systemd macros.
- [ ] **Step 6: Commit:** `setup: server certificates renew themselves (daily timer, 30 days ahead)`.

### Task 3: Status warns only when renewal fails

**Files:**
- Modify: `crates/platform-host/src/lib.rs:94`: add `/etc/openvibes/tls/console-chain.pem` to `CERTIFICATES` (now 4).
- Modify: `crates/openvibes-admin/src/tui/database.rs::checks` :74.
- Test: the existing `database.rs` tests file (or its `checks` tests).
- Docs: `docs/components/openvibes-admin.md` Health :248-255.

**Interfaces:**
- Consumes: `RENEW_DAYS` (14). Adds `pub(crate) const INTERMEDIATE_WARN_DAYS: i64 = 60` in `setup/pki.rs`.

Exact problem texts (`{path}`, `{days}`, `{date}` as today):
- Server certificate with fewer than 14 days left: `{path}: expires in {days} days ({date}): automatic renewal is failing, see Status › certificate renewal › Logs`.
- Intermediate (`/etc/openvibes/pki/intermediate.crt`, judged by its first certificate) with fewer than 60 days left: `{path}: expires in {days} days ({date}): replace the intermediate in Maintenance › Certificates`.
- Expired: unchanged (`{path}: expired on {date}`).
- Otherwise the line is not a problem, as today.

- [ ] **Step 1: Write the failing tests:**
  - `a_server_certificate_close_to_expiry_says_renewal_is_failing`: 10 days left gives a problem with the exact text.
  - `a_server_certificate_with_20_days_is_fine`: 20 days left is not a problem (renewal is due, not failing).
  - `an_intermediate_within_60_days_says_replace_it`: 50 days left gives a problem with the replace text.
  - `the_console_chain_is_checked`: `CERTIFICATES` contains the console chain.
- [ ] **Step 2: Run** `cargo test -p openvibes-admin checks`. Expected: FAIL.
- [ ] **Step 3: Implement.** The intermediate is matched by its path constant.
- [ ] **Step 4: Run** `cargo test -p openvibes-admin` and `-p platform-host`. Expected: pass. Fixtures that list three certificates now list four.
- [ ] **Step 5: Commit:** `status: certificates warn only when renewal fails; the console's is checked`.

### Task 4: Replace the intermediate (backend)

**Files:**
- Create: `crates/openvibes-admin/src/setup/replace.rs` (with `replace_tests.rs` next to it).
- Modify: `crates/openvibes-admin/src/setup/pki.rs`: the real `drop_previous`.
- Modify: `crates/openvibes-admin/src/helper.rs`: verb `CaReplace` (`ca-replace`), with optional `--root-key PATH`.
- Modify: `crates/openvibes-admin/src/setup/mod.rs`: `pub fn ca_replace(root_key: Option<&Path>) -> ExitCode` under `begin()` and `setup_guard()`, like `step()`.
- Modify: `packaging/rpm/openvibes-operators.sudoers`: one line for `helper ca-replace *`, in the same form as the other verbs.
- Modify: `crates/openvibes-admin/src/setup/remove.rs` only if purge does not already remove `/etc/openvibes` whole. The recon says it does (remove.rs:72); add a test only if it does not.
- Docs:
  - `docs/components/packaging.md`: replace the manual runbook "Replacing the intermediate CA" :513-543 with what Replace does, and what it means for agents.
  - `docs/components/openvibes-admin.md`: the CA and helper verb list.

**Interfaces:**
- Consumes: `request::{REQUEST_DIR, accept}`, `pki::{certificates_apply, INTERMEDIATE, ROOT_CERT, INTERMEDIATE_KEY}` (made `pub(crate)` as needed), `platform_pki::{first_certificate, Issuer::load, check_intermediate, not_after}`.
- Produces:
  - `pub(crate) const PREVIOUS: &str = "/etc/openvibes/pki/previous.crt"`.
  - `pub(crate) const PREVIOUS_UNTIL: &str = "/etc/openvibes/pki/previous-until"`, which holds one RFC 3339 instant.
  - `pub fn replace<R: Runner>(ctx: &Ctx<R>, root_key: Option<&str>) -> Result<String, String>`, which returns the result detail.
  - The helper prints one line per finished stage, using exactly the TUI's step names: `Making the new intermediate`, `Trusting the old and the new one`, `Issuing the server certificates`, `Restarting the services`. Then a final `done\t{new not_after YYYY-MM-DD}\t{previous until YYYY-MM-DD}`. Failures go to stderr, prefixed `openvibes-admin helper: `.

`replace` behaviour:
1. **Where the new intermediate comes from:**
   - Plan `CaMode::Careful`: the four files must be in `REQUEST_DIR` (after `ca-request` and `ca-accept`). `REQUEST_DIR/root.crt` must equal `ROOT_CERT` (after trimming): agents trust only that root. Otherwise: `Your CA's certificate is not this host's root: agents trust only that one.`
   - Plan `CaMode::Quick`: `root_key` is required. The key must match `ROOT_CERT`, checked with `Issuer::load(root_cert, key)`. Otherwise: `Not the key of this host's root: pick the root key kept at install.` Then, in `/run/openvibes-ca` as at install: copy `root.crt` and the key into ROOT_DIR (0600, openvibes-admin), run `ca intermediate-request`, then `ca sign-intermediate`. The key copy lives only in tmpfs and is removed at the end, also on failure.
2. **Trust both:**
   - write the current `intermediate.crt`'s first certificate to `PREVIOUS` (0644);
   - write `PREVIOUS_UNTIL` = now + `client_certificate_days` (read from `/etc/openvibes/ingest.toml`, default 30) + 1 day;
   - `intermediate.crt` becomes new + previous;
   - the new key goes to `INTERMEDIATE_KEY` (0600 openvibes-ingest).
   - Record the new intermediate in `ca_certificates` with `ca import-intermediate`, as `import_and_install` does: the bundle's first certificate and the key, `--root-cert ROOT_CERT`.
3. **Issue:** `certificates_apply(ctx)`. It reissues ingest, distribution and console from the new first certificate, then try-restarts them.
4. Remove `REQUEST_DIR` (careful) and the stage.

`drop_previous`:
- When `PREVIOUS_UNTIL` has passed: `intermediate.crt` becomes its first certificate only; remove `PREVIOUS` and `PREVIOUS_UNTIL`; `systemctl try-restart openvibes-ingest openvibes-distribution`; return `Some("previous intermediate no longer trusted")`.
- Before then, or without the files: `Ok(None)`.

- [ ] **Step 1: Write the failing tests** (temporary root and fake runner, as in `request_tests.rs` and `pki_root_key_tests.rs`):
  - `replace_careful_trusts_old_and_new`: after `replace`, `intermediate.crt` holds two certificates, new first. A client certificate issued by the OLD intermediate verifies against the bundle (`verify_signed_by` on either entry, or the agent-server verifier if the test can reach it). `PREVIOUS_UNTIL` is 31 days ahead with the default config.
  - `replace_careful_refuses_another_root`: the request's root.crt differs from ROOT_CERT gives the exact error, and nothing is changed.
  - `replace_quick_refuses_a_foreign_key`: the exact error, and nothing is changed.
  - `replace_quick_removes_the_key_copy`: no `root.key` remains under `/run/openvibes-ca`, also when `sign-intermediate` fails (the fake runner fails it).
  - `drop_previous_waits_then_drops`: before the date, `None` and no change. After it, the bundle holds one certificate, both files are gone, and the runner saw `try-restart openvibes-ingest openvibes-distribution`.
- [ ] **Step 2: Run** `cargo test -p openvibes-admin replace drop_previous`. Expected: FAIL.
- [ ] **Step 3: Implement** `replace.rs`, the verb, `drop_previous` and the sudoers line.
- [ ] **Step 4: Run** `cargo test -p openvibes-admin`. Expected: pass.
- [ ] **Step 5: Commit:** `setup: replace the intermediate with old and new trusted until agents move over`.

### Task 5: Maintenance › Certificates page and Replace screens

**Files:**
- Modify: `crates/openvibes-admin/src/tui/maint/certs.rs`, the page (certs2.py), and its tests `certs_tests.rs`.
- Create: `crates/openvibes-admin/src/tui/maint/replace.rs` and `replace_tests.rs`, the Replace screen and run.
- Shared code: the request, paste and file-pick pieces in `crates/openvibes-admin/src/tui/install/{certs.rs,paste.rs}` serve both Install and Replace. Move what both need into `crates/openvibes-admin/src/tui/ca_request.rs`, keeping Install's tests green unchanged. If that would push a file over 500 lines, split it along the same lines.
- Modify: `crates/openvibes-admin/src/tui/maint/mod.rs`: the new page and the `Kind` for the run.
- Docs: `docs/components/openvibes-admin.md`, Maintenance › Certificates.

**Interfaces:**
- Consumes:
  - helper verbs `ca-request`, `ca-accept` (with the installed `ROOT_CERT` as the root: "kept") and `ca-replace [--root-key PATH]` (Task 4) and its output lines;
  - `RENEW_AT_DAYS`, `PREVIOUS`, `PREVIOUS_UNTIL` (Tasks 2 and 4);
  - `Host::certificates()` (now four files).

The page, exactly as certs2.py (`OWN`/`OURS`, `ACTS_OWN`/`ACTS_OURS`) and certs4a.py screen 10:
- **Web and agents** (from the earliest of the server certificates):
  - green `renewed automatically` · `next {earliest not_after − 30 days}`;
  - when that date is today or past but more than 14 days are left: `renewed automatically · due today`;
  - with fewer than 14 days left: red `renewal is failing · see Status`.
- **Names:** as today.
- **Intermediate:** `signed by {issuer CN} · until {date}` for your own CA; `signed by the OpenVIBES root · until {date}` for Quick.
- **Previous intermediate:** dim `trusted until {PREVIOUS_UNTIL date}, as agents move over`, only while that file exists.
- **Root key:** dim `offline: needed only to replace the intermediate`, Quick only.
- **Actions:** `Names` · `add or remove a name agents use`. `Replace the intermediate` · `a new request for your CA` (own CA) or `needs the offline root key file` (Quick).

Replace, your own CA (certs2.py screens 3-4):
- rows `Show the request` / `Signed certificate` / `Your CA's certificate` (`✓ {CN} (kept)`) / `Replace`;
- the request is made with `ca-request` on opening;
- the paste and file pick are exactly the install's, checked at once;
- Replace is enabled once the signed certificate is accepted.

Replace, OpenVIBES made the CA (certs4a.py screens 2-6):
- rows `Root key file` / `Replace`, under the note line;
- the file browser is the install's Root key picker;
- the picked file is checked at once on this side: read it (as the operator, at most 64 KiB) and `Issuer::load(ROOT_CERT, key)`. This is the same check the helper repeats as root. Lines in green and red as mocked;
- Enter on Replace asks `Replace the intermediate?` · `agents keep working`, starting on Yes;
- then the sudo password in the bar;
- then the step list (four steps for Quick, the last three for your own CA), and one result line.

The result line: `Replaced · agents move over in {client days} days · put the key offline again ({elapsed})` for Quick, and `Replaced · agents move over in {client days} days ({elapsed})` for your own CA.

- [ ] **Step 1: Write the failing tests** (TestBackend 80×24, compared as text, as the other maint tests do):
  - `certificates_page_own_ca_matches_certs2`, `certificates_page_ours_matches_certs2`.
  - `certificates_page_shows_the_previous_intermediate`.
  - `renewal_due_today_and_failing_texts`.
  - Key-by-key flows with the fake host:
    - `replace_quick_wrong_key_then_right_key_then_runs` (red line, then green, question on Yes, password, the four steps, the result);
    - `replace_own_ca_paste_then_replace`;
    - `esc_on_replace_changes_nothing` (no helper call besides `ca-request`).
- [ ] **Step 2: Run** `cargo test -p openvibes-admin certificates_page replace_`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `cargo test -p openvibes-admin`. Expected: pass, including every Install test unchanged.
- [ ] **Step 5: Commit:** `tui: Certificates shows automatic renewal and replaces the intermediate`.

### Task 6: Lab walk (after the local gate, before the PR)

- [ ] On a lab VM with the RPMs from this branch:
  - **Quick install.** Then `systemctl list-timers openvibes-certificates.timer` shows it.
  - **Renewal.** Make renewal due by moving the clock forward 61 days (`timedatectl set-ntp false; date -s '+61 days'`). Then `systemctl start openvibes-certificates.service`: the certificates are new, the services were restarted, and Status shows no certificate problem.
  - **Lock held.** With Repair running in the TUI, starting the service logs `skipped` and exits 0.
  - **Replace (Quick).** Enroll an agent, then Replace with the root key file. The agent keeps reporting, and after its next renew its certificate is signed by the new intermediate. Move the clock past `previous-until` and start the service: the bundle holds one certificate and the agent still reports.
  - **Replace (own CA)** with `ca sign-intermediate` from a lab root.
  - **Remove everything.** No `openvibes-certificates.*` unit and no `/etc/openvibes/pki` file is left.
  - Report: `~/.cache/openvibes-scratch/sp4/walk-4a.md`.
