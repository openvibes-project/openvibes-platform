# TUI rework 3: Install — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A host without OpenVIBES opens on the approved Install screens:
Welcome, Quick install, the five steps of Choose what to install
(Optional, Names, Certificates, Ports, Review), Installing and Finished.
They replace today's one-page Setup form, including the #87 refill.

**Architecture:** The new screens live in `crates/openvibes-admin/src/tui/install/`
behind a new `Screen::Install(Stage)`. One `Install` state holds every
choice and builds the `setup-plan` arguments.

The install runs on the worker thread like every Maintenance run:
`app.begin` with a new `Call::Setup(Step)` (`setup-step STEP`, no
`--repair`), the bar asks for the password once, and `ui/steps.rs` draws
the progress.

"Your own CA" gets the request before install. Two new root helper verbs
handle it:
- `ca-request` makes a key and CSR, or reuses them, in
  `/etc/openvibes/pki/request/`.
- `ca-accept` stores the signed certificate and your CA's certificate
  there after checking them.

The careful CA step then installs from that folder, so the install runs
start to finish without pausing.

**Tech Stack:** Rust 2024, ratatui and crossterm (bracketed paste),
platform-pki (rcgen and x509-parser), the existing helper and run plumbing.

**Spec:** `docs/specs/2026-10-10-tui-rework-design.md` §5, §10 item 3 and §12
item 3. The mockups are in `docs/specs/tui-rework/`:
- `install.py` (Welcome, Installing, Finished);
- `quick.py`;
- `advanced.py` (steps line, Optional, Names, Ports, Review);
- `ca.py` and `ca2.py` (the own-CA rows, the request, the paste box);
- `full_advanced.py` (the whole approved flow, 16 screens).

The decisions are in `approved.md` 21–27 and 42. Where a mockup and the
spec text differ, `approved.md` and `full_advanced.py` win: they are the
later decisions.

## Global Constraints

- Copy is exactly the mockups' text. Examples:
  - "This host does not run OpenVIBES yet.", "Choose what to install",
    "components, names, ports".
  - "Quick install", "everything, with default names and ports".
  - "Quick install: only what OpenVIBES cannot know".
  - "(•) Your own CA", "your CA signs an intermediate for OpenVIBES",
    "( ) OpenVIBES makes one", "a new root CA; its key goes offline after".
  - "OpenVIBES is installed", "shown only now: write it down",
    "Enter Continue to Home".
- Location line: "HOST · Install", "HOST · Install › Quick install",
  "HOST · Install › Optional|Names|Certificates|Ports|Review", and
  "HOST · Install › Certificates › Request|Signed certificate|Your CA's certificate".
- The steps line is `✓ done · ● current · ○ to come` over Optional, Names,
  Certificates, Ports, Review. Enter on Next moves on, and Esc goes back a step.
- Checkbox rows: Space selects, and the bar says "Space Select"
  (`checkbar()`). Radio rows: Space chooses, and the bar says "Space Choose".
  Enter opens, edits or starts.
- The core is always installed and never offered: ingest, console,
  distribution, vulns, rules, signer (approved 25). Only Agent on this host
  (default **on**, approved 24) and Assistant (default off) are choices.
- The password is asked once, in the bar, when Install starts. It is never
  stored. Run as root (`sudo openvibes-admin`), nothing is asked (#82).
- Screens are tested at 80×24 with `TestBackend`, asserting on the rendered
  text (the existing `script_host::screen` style).
- No file over 500 lines (tests included). Each new module gets a line in
  `docs/components/openvibes-admin.md`.
- Every cargo command runs as
  `export CARGO_TARGET_DIR=~/.cache/openvibes-scratch/target CARGO_BUILD_JOBS=6 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0; nice -n 19 ionice -c3 cargo …`.
  Database tests run only under `eval "$(scripts/test-db.sh)"`.

## Rulings (Claude's, for review)

1. **Two CA modes only:** "Your own CA" (`--ca careful`) and "OpenVIBES
   makes one" (`--ca quick`), as in approved 26. Importing a finished
   intermediate, PKCS#12, the web certificate and ACME are sub-project 4.
2. **The request lives in `/etc/openvibes/pki/request/`** (root, 0700).
   It holds `intermediate.key`, `intermediate.csr`, then `intermediate.crt`
   and `root.crt` once accepted.
   - It survives a reboot, unlike today's `/run` stage, because signing
     can take days.
   - `ca-request` reuses an existing key, so a request already sent to the
     CA stays valid.
   - The CA step removes the folder after installing from it, and so does
     Quick mode.
   - Remove everything already clears `/etc/openvibes`. Keep the data
     keeps it.
3. **The CSR copy** goes to a free name in the operator's home,
   `~/openvibes-intermediate.csr` (then `-2`, … via `maint::backup::free_path`).
   It is written by the helper, mode 0644. It is public data.
4. **"Your CA's certificate" must be the root that signed the
   intermediate.** Today's import checks a one-level chain. A company PKI
   with a sub-CA is sub-project 4. The message says so in plain words.
5. **The install runs through `app.begin`** (worker thread, password in
   the bar), with `Kind::Install`. The 14 backend steps are grouped into
   the mockup's rows:
   - Packages [Packages]
   - PostgreSQL [Postgres]
   - Database [Operators, Database, Schema]
   - Certificate authority [Ca]
   - Certificates [Certificates]
   - Console [Console]
   - Services [Services, Rules]
   - Firewall [Firewall]
   - Agent on this host [Agent], only when ticked
   - Ready [Ready]
   - Assistant [AssistantModel], only when ticked; it stays last, after
     Ready, as the backend runs it.

   The first call is `SetupPlan(args)` inside the Packages row.
6. **Quick install** uses OpenVIBES's own CA and the default ports. A
   default port that is taken gets the free port `propose_ports` finds.
   The Install row's help line then says "443 is in use by nginx: the
   console uses 8443". The Finished screen shows the real address.
7. **No model question:** ticking Assistant means `--model fetch`. Its
   value says "2.7 GB download". A staged model (offline kit) is used as
   today.
8. **#87 (a plan but no CA):** the TUI opens Choose what to install at
   step 1, filled from `setup.toml`, with a free root key name. Esc on
   step 1 goes Home (Uninstall stays reachable). On a fresh host, Esc on
   step 1 goes to Welcome. With your own CA, step 3 reads the request
   folder's state, so a signed certificate added before the stop is
   still there.
9. **Paste:** the TUI enables bracketed paste. `Key::Paste(String)`
   carries a whole paste.
   - Terminals without it send lines as keys: Enter adds a new line until
     an `-----END` line is present.
   - After that, Enter is "Use it", and only when the check passed.
10. **"From a file on this host"** reuses the folder browser, with files
    shown. Picking a file reads at most 64 KiB.
11. **A failed install step** shows ✗ with its reason. The bar says
    "Enter Try again · Esc Back". Try again resumes at that step and asks
    the password again when needed. Esc goes to Review while there is no
    CA, and Home once there is (today's rule).
12. **The old Setup form goes:**
    - `tui/setup.rs`, `setup_form.rs`, `setup_view.rs` and their tests;
    - `Tab::Setup`, `Phase` and `Setup` in `App`.

    `Screen::Legacy` keeps only Settings files.

## Review Focus

1. **A pasted chain** (the signed certificate plus the CA, two blocks) in
   "Signed certificate". Expect "That is 2 certificates: paste only the one
   signed for OpenVIBES", not acceptance and not a crash. Test in Task 4.
2. **Leaving and coming back** after sending the request. `ca-request`
   must reuse the key and CSR, so the certificate signed later still
   matches. Test in Task 1 (helper) and Task 4 (TUI shows "✓ added" after
   a restart).
3. **A certificate signed for another request, a non-CA certificate, an
   expired one, or the wrong root.** Each gets its own plain sentence, and
   Next stays disabled. Tests in Task 1 (checks) and Task 4 (screen).
4. **A failure halfway.** Try again resumes at the failed row. Esc before
   the CA exists goes to Review, and after it goes Home. Test in Task 2.
5. **A root key file that exists, is relative, or is in a missing
   folder.** Flagged in the field before Install; Install refused. Test in
   Task 3.

---

### Task 1: Request before install (backend)

**Files:**
- Create: `crates/openvibes-admin/src/setup/request.rs` and `request_tests.rs`
- Modify: `crates/platform-pki/src/ca.rs` (two checks), `crates/openvibes-admin/src/setup/pki.rs` (`careful`, `quick`),
  `crates/openvibes-admin/src/helper.rs` (verbs), `crates/platform-host/src/setup.rs` (`Privileged`)
- Test: `crates/platform-pki/src/ca_tests.rs` (or the crate's existing test module), `setup/request_tests.rs`

**Interfaces:**
- Produces, in platform-pki:
  - `pub fn check_signed_request(csr_pem: &str, cert_pem: &str, now: OffsetDateTime) -> Result<Signed, PkiError>`.
    The certificate's public key equals the CSR's, it is a CA with
    path_len 0, and it is valid now.
  - `pub struct Signed { pub subject: String, pub issuer: String, pub not_after: String /* YYYY-MM-DD */ }`.
  - `pub fn check_root_signed(root_pem: &str, cert_pem: &str, now: OffsetDateTime) -> Result<String /* root CN */, PkiError>`.
    The root is a self-signed CA, valid now, and has signed `cert_pem`.
  - New `PkiError` variants: `NotForRequest`, `Several(usize)`, `NotRoot`.
- Produces, in `setup::request`:
  - `pub const REQUEST_DIR: &str = "/etc/openvibes/pki/request"`.
  - `pub fn request(ctx: &Ctx, copy: Option<&Path>) -> Result<RequestState, String>`.
    It makes or reuses the key and CSR (0700 folder, 0600 key) and writes
    `copy` once if given and absent.
  - `pub fn accept(ctx: &Ctx, cert_pem: &str, root_pem: &str) -> Result<Signed, String>`.
    It runs both checks against the stored CSR, then writes
    `intermediate.crt` and `root.crt`.
  - `pub enum RequestState { Request { csr: String }, Signed { csr: String, issuer: String } }`.
  - `pub fn message(e: &PkiError) -> String`, the plain sentences of
    Review Focus 1 and 3.
- Produces, in platform-host:
  - `Privileged::CaRequest(Option<&'a str> /* copy path */)` gives `ca-request [--copy PATH]`.
  - `Privileged::CaAccept(&'a str, &'a str)` gives
    `ca-accept --cert PEM --root-cert PEM`, journalled as `ca-accept`.
  - The output format: line 1 is `request` or `signed<TAB>ISSUER`, and
    the CSR PEM follows.

- [ ] **Step 1: Write the failing tests.**
  - platform-pki:
    - `signed_request_matches_its_csr` returns `Signed` with the subject
      and issuer CNs.
    - `certificate_for_another_request_is_refused` gives `NotForRequest`.
    - `end_entity_certificate_is_refused` gives `NotCa`.
    - `expired_certificate_is_refused` gives `IssuerExpired`.
    - `wrong_root_is_refused` gives `NotSignedBy`.
    - `two_pem_blocks_are_refused` gives `Several(2)`.
  - `request_tests.rs`, with `Ctx` on a temp root:
    - `request_is_reused`: the CSR is byte-equal on the second call.
    - `request_copy_is_written_once`.
    - `accept_writes_both_and_state_is_signed`.
    - `accept_refuses_other_request_and_writes_nothing`.
    - `careful_installs_from_request_dir_and_removes_it`, using the
      existing `import_and_install` fake chain from `pki` tests.
    - `quick_removes_a_leftover_request_dir`.
- [ ] **Step 2: Run them, and see them fail.**
  Run `… cargo test -p platform-pki ca && … cargo test -p openvibes-admin request`.
  They must fail to compile on the missing functions.
- [ ] **Step 3: Implement.**
  - The platform-pki checks use x509-parser: compare `SubjectPublicKeyInfo`
    bytes between the CSR and the certificate.
  - `request.rs` as above.
  - `pki::careful()` first checks whether `REQUEST_DIR` holds all four
    files. If so, it runs `import_and_install` from there, then removes
    the folder. Otherwise it keeps today's `/run` path for the CLI.
  - `import_and_install` takes the source folder as a parameter.
  - `pki::quick()` removes `REQUEST_DIR` if present.
  - The helper verbs `ca-request` and `ca-accept` run as root, follow the
    output format above, and print errors through `message`.
- [ ] **Step 4: Run them, and see them pass, plus the whole crate.**
  Run `… cargo test -p platform-pki && … cargo test -p openvibes-admin`.
- [ ] **Step 5: Commit** with "admin: the CA request before install (sub-project 3)".

### Task 2: Installing and Finished on the worker thread

**Files:**
- Create: `crates/openvibes-admin/src/tui/install/mod.rs` (state, `Stage`, keys), `install/run.rs`, `install/finished.rs`, `install/run_tests.rs`
- Modify: `tui/run.rs` (`Call::Setup(Step)`, `Kind::Install`), `tui/nav.rs` (`Screen::Install(Stage)`), `tui/app.rs` (`install: Install`)

**Interfaces:**
- Produces:
  - `pub struct Install`, with these fields:
    - `agent: bool`, `assistant: bool`, `hostname: String`, `sans: String`;
    - `ca: Ca`, `root_key_out: String`;
    - `console_port`, `ingest_port`, `distribution_port: String`;
    - `request: Option<RequestState>`, `signed: Option<String>`, `root_added: Option<String>`.
  - `pub enum Ca { Own, OpenVibes }`.
  - `pub enum Stage { Welcome, Quick, Step(u8 /* 0..=4 */), Request, Add(Which), Running, Finished }`
    and `pub enum Which { Signed, Root }` (the two certificates to add).
  - `impl Install { pub fn plan_args(&self) -> Vec<String>; pub fn work(&self) -> Work }`:
    - `plan_args` gives `--components` (the core plus the ticked
      optional parts), `--hostname`, `--san`…, and `--ca careful|quick`.
    - With quick it adds `--root-key-out`. With the assistant it adds
      `--model fetch`. It adds the three ports.
    - `work` gives `Work::grouped(Kind::Install, …)`, with the rows of
      ruling 5.
  - `pub fn finished_rows(states) -> Vec<Row>`, using the labels from
    `install.py` and `full_advanced.py`:
    - Open the console, Sign in as, and Password (with "shown only now:
      write it down");
    - then either Root key (with "move it to a USB stick and keep it
      offline") or Certificates ("signed by X" and "browsers that trust
      your CA show no warning");
    - then the Next line ("…then add hosts under Enrollment.", ruling:
      the console page is called Enrollment).
    - The port appears in the address when it is not 443.
    - Parsing reuses `setup_view`'s `done`/`between` helpers. Move them
      into `finished.rs`.

- [ ] **Step 1: Write the failing tests** in `run_tests.rs`, with the
  script host and answers per call:
  - `install_rows_group_the_steps`: no agent and no assistant give 9 rows,
    the titles in order.
  - `install_runs_plan_then_every_step`: the calls are `setup-plan …`,
    then `setup-step packages` … `setup-step assistant-model`, without
    `--repair`.
  - `installing_shows_current_row_and_step_count`: shows "Step 2 of 9: PostgreSQL".
  - `failure_offers_try_again_and_resumes_at_that_step` (Review Focus 4).
  - `esc_after_failure_goes_to_review_without_ca_and_home_with_ca`.
  - `finished_own_root_shows_root_key_row`.
  - `finished_own_ca_shows_signed_by`.
  - `finished_console_port_in_address`.
  - `finished_enter_goes_home`.
- [ ] **Step 2: Run them, and see them fail.**
  Run `… cargo test -p openvibes-admin install::run`.
- [ ] **Step 3: Implement.** `Call::Setup(step)` maps to
  `Privileged::SetupStep(step)`. The Running and Finished stages draw
  with `frame::draw` and `steps::lines`. The keys are as in ruling 11.
- [ ] **Step 4: Run them, and see them pass, plus the whole crate.**
- [ ] **Step 5: Commit** with "tui: Installing and Finished run on the worker (sub-project 3)".

### Task 3: Welcome, Quick install, and the start

**Files:**
- Create: `tui/install/welcome.rs`, `tui/install/quick.rs`, `tui/install/fields.rs` (host name, other names, root key file and port checks shared by Quick and the steps), `install/quick_tests.rs`
- Modify: `tui/app.rs` (`App::lazy` and `start_screen`: a fresh host goes to `Screen::Install(Stage::Welcome)`)

**Interfaces:**
- Consumes: `Install`, `Stage` and `Install::work` (Task 2), and
  `ports::parse` and `Setup::propose_ports`'s logic. Move it to
  `fields::propose_ports(host, &mut Install) -> Option<String /* note */>`.
- Produces:
  - `fields::check_root_key(path, exists) -> Result<(), String>`. It
    returns "The path must start with /.", "That file already exists:
    choose another name." or "The folder X does not exist.".
  - `fields::check_names(hostname, sans) -> Result<(), String>`, built on
    `plan::check_name` / `check_san` / `MAX_SANS`.
  - `Install::new(hostname, home)`: agent **on** (ruling: spec over
    `agent_by_default`, which is removed), default ports, Ca::Own, and
    `root_key_out` = `default_root_key(home)`.

- [ ] **Step 1: Write the failing tests:**
  - `fresh_host_opens_welcome_on_choose_what_to_install`: the text matches
    `install.welcome(0)`.
  - `welcome_quit_and_q_quit`.
  - `quick_install_rows_and_help`: four rows, plus Install with its help
    lines from `quick.py`.
  - `quick_agent_row_space_unticks`: the bar shows "Space Select" on that
    row.
  - `quick_edits_in_place`: Enter, type, Enter; Esc cancels.
  - `quick_root_key_existing_relative_missing_folder_flagged` (Review
    Focus 5).
  - `quick_install_starts_with_quick_ca_and_core_components`, asserting
    the exact `setup-plan` arguments.
  - `quick_taken_port_moves_and_says_so` (ruling 6).
  - `esc_on_quick_goes_to_welcome`.
- [ ] **Step 2: Run them, and see them fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run them, and see them pass, plus the whole crate.**
- [ ] **Step 5: Commit** with "tui: Install Welcome and Quick install (sub-project 3)".

### Task 4: Choose what to install, the five steps

**Files:**
- Create: `tui/install/steps.rs` (steps line, Optional, Names, Ports, Review), `tui/install/certs.rs` (step 3, request rows, Request, Add), `tui/install/paste.rs` (paste box), `install/steps_tests.rs`, `install/certs_tests.rs`
- Modify:
  - `tui/mod.rs`: `EnableBracketedPaste` on start and `Disable…` on exit;
    `Event::Paste(s)` becomes `Key::Paste(s)`.
  - `tui/app.rs`: `Key::Paste(String)`.
  - `tui/maint/folder.rs`: a files mode for `Browse` (`show_files: bool`)
    that picks a file.
  - `tui/app.rs`: `start_screen` on #87 opens `Stage::Step(0)`, filled
    from `setup.toml` (ruling 8).

**Interfaces:**
- Consumes:
  - `Privileged::CaRequest` and `CaAccept`, and `request::message`'s
    sentences, through a new `Call::CaRequest(Option<String>)` and
    `Call::CaAccept(String, String)` (Task 1);
  - the `fields` checks (Task 3);
  - `platform_pki::check_signed_request` and `check_root_signed`,
    called in-process for the instant check while pasting;
  - `maint::ports::port_note`, for "443 is in use by nginx · 8443 proposed".

- [ ] **Step 1: Write the failing tests:**
  - `steps_line_marks_done_current_to_come`.
  - `optional_has_agent_on_and_assistant_off_and_next`. Help lines from
    `advanced.comp`.
  - `names_edits_in_place_and_flags_a_bad_name`.
  - `certs_own_ca_is_default_space_chooses`.
  - `certs_openvibes_shows_root_key_file_row`.
  - `own_ca_next_makes_request_and_shows_rows`. The call is `ca-request
    --copy /home/u/openvibes-intermediate.csr`, and the rows match
    `full_advanced.CA_ROWS`.
  - `request_screen_shows_pem_and_saved_path`.
  - `paste_checked_at_once_then_use_it`: the two ✓ lines from `ca2.paste`.
  - `paste_of_chain_says_two_certificates` (Review Focus 1).
  - `paste_wrong_request_and_wrong_root_say_why` (Review Focus 3).
  - `typed_lines_without_bracketed_paste_end_at_end_line` (ruling 9).
  - `file_pick_lists_files_and_reads_one`.
  - `next_disabled_until_both_added`: Next's value is "once both are
    added".
  - `both_added_calls_ca_accept_and_review_says_signed_by`.
  - `restart_with_signed_request_shows_added` (Review Focus 2).
  - `ports_flags_taken_and_proposes`, then `ports_accept_typed_port`.
  - `review_lists_every_choice_enter_jumps_to_step`.
  - `review_install_asks_password_in_bar_once`.
  - `esc_walks_back_a_step`, then `esc_on_step_one_goes_welcome_or_home`
    (ruling 8).
  - `issue_87_opens_step_one_filled_from_plan`.
- [ ] **Step 2: Run them, and see them fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run them, and see them pass, plus the whole crate.**
- [ ] **Step 5: Commit** with "tui: Choose what to install, five steps with your own CA (sub-project 3)".

### Task 5: The old form goes; docs

**Files:**
- Delete: `tui/setup.rs`, `setup_form.rs`, `setup_view.rs`, `setup_tests.rs`, `setup_form_tests.rs`, `setup_done_tests.rs`
- Modify:
  - `tui/app.rs`: drop `Tab::Setup` and `setup`.
  - `tui/nav.rs`: Legacy keeps Configuration only; fix the module comment.
  - `tui/script_host.rs`: move what the new tests use; drop the rest.
  - `docs/components/openvibes-admin.md`: Setup becomes the Install
    section, with the request folder, the two helper verbs, and the
    rulings that change behaviour.
  - `setup/fleet.rs`: drop `agent_by_default` if nothing else uses it.

- [ ] **Step 1:** Delete the files, fix the compile errors, and move any
  still-needed test (e.g. "the console step detail hides the password")
  next to the new code.
- [ ] **Step 2:** Run the whole crate's tests and
  `… cargo clippy --workspace --all-targets -- -D warnings`.
- [ ] **Step 3:** Update the docs, then run `scripts/check-names.sh`.
- [ ] **Step 4: Commit** with "tui: the old Setup form goes; docs for Install (sub-project 3)".

After the last task: the local gate (`testing.md` §2), then a lab walk on
the PR's CI RPMs:
- Quick install on a fresh VM;
- the five steps with your own CA, signing the request with
  `openvibes-admin ca sign-intermediate` on the host;
- #87.
