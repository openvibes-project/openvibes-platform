# openvibes-admin

Local operator CLI. Until the admin API exists it is **break-glass access**:
whoever can run it with the admin database role has full rights. Every
command, including failed ones, appends an `audit_log` entry with the
invoking OS user and `ok` or `error`, except a successful status read that
shows no host or finding data (`status`, `feeds status`, `rules list`,
`rules show`, `rules trust list`, `agent list`): the TUI's Health and
Database screens run those on every refresh. `agent show`, `vulns …`,
`token list` and `user …` stay audited. The actor is the real uid, which the
caller cannot choose, with `$USER` as a readable hint: `alice (uid 1000)`,
or `uid 1000` when `USER` is unset (timers, containers). Run through sudo
(`sudo -u openvibes-admin …`), the person is appended from `SUDO_USER`:
`openvibes-admin (uid 994) via sudo by alice`.

Database commands need the `openvibes-admin` account: only it reads
`admin.toml` (0640) and has the database's peer login. With the packaged
`/etc/openvibes/admin.toml` (#79, `src/run_as.rs`), an operator who cannot
read it is started again through `sudo -n -u openvibes-admin` when the
operators' sudoers rule allows that without a password, and root through
`runuser -u openvibes-admin`; otherwise the error names the file, "permission
denied", and the `sudo -u openvibes-admin` form. A `--config` given on the
command line is used as is.

## Administration TUI

`openvibes-admin` with no subcommand opens the administration TUI: the
host-side work the web console deliberately does not do (admin TUI spec,
`docs/specs/2026-09-27-admin-tui-design.md`). It runs as the invoking user,
never listens on the network, needs no config file to open, and works over
SSH at 80×24 with the keyboard only; states are written as text. Without a
terminal (a pipe, cron) it exits 2 with a message; subcommands work as
before.

Who can use it: members of `openvibes-operators` (created by the RPM; add a
person with `usermod -aG openvibes-operators NAME`, then they log in again).
They start, stop and restart the OpenVIBES units through a polkit rule, and
read logs and read and save configuration files through the root helper,
without a password. A set-up host opens on Home (Status, Maintenance,
Quit); `Enter` opens the highlighted entry, `Esc` goes back one screen, `?`
shows the keys, and `q` quits from Home. Maintenance lists, in this order, Update OpenVIBES, Repair, Optional parts, Ports and addresses, Certificates, Database, Console sign-in, Back up, Shell and Uninstall; later entries are added by their pages. A host not set up
opens on the install form, which `Esc` does not leave. In any field being
edited, `Ctrl+U` empties it (other Ctrl chords are ignored, never typed as
letters). Every new screen (Home, Status, Service, the full log,
Maintenance and Help) shows the block logo ("OPEN" in white, "VIBES" in the
brand teal `#36b9e0`), a location line (host, where you are, the version
and any available update; a long host name is cut with `…` first), and a
key bar. With `NO_COLOR` set there is no
colour. The code is in `src/tui/` (`nav.rs` the screen stack, `home.rs`
Home, Maintenance and Help, `status.rs` Status, `ui/` the shared frame).

**Help** (`?` on Home, Maintenance, Status, Service and the full log, not on today's screens): the keys, and what Enter does on the screen you came from; the line "Here (page): …" says what the keys do on that page and wraps to the frame; `Esc` closes it (its bar is `Esc Close` only) and you land on the row and scroll position you left; `Esc` from any screen does the same. On the Linux text console (`TERM=linux`) the bar and lists use the plain `↑↓←→` arrows instead of the `⭡⭣⭠⭢` glyphs; with `NO_COLOR` set the same screens render without colour. Tests: `TestBackend` renders in `src/tui/nav_tests.rs`, `status_tests.rs` and `service_tests.rs`, and unit tests in `src/tui/ui/` (`cargo test -p openvibes-admin`).

**Work in the background**: helper steps (Update, Back up, Repair, Uninstall) run on their own thread, so the screen keeps drawing. The password is asked in the bar ("Your password (sudo)"; root is not asked), handed to that thread and dropped when the work ends. A wrong password is said in the bar with the tries left; after three, nothing more runs. Home's status line shows the running work, then its result (on a line of its own when both do not fit 80 columns). `q` (or Ctrl+C) while work runs asks "Quit when it is done?": Yes quits once it has finished, and a second Ctrl+C quits at once. Tests: `src/tui/run_tests.rs`; each Maintenance page has its own in `src/tui/maint/*_tests.rs` (`update_tests.rs`, `repair_tests.rs`, `backup_tests.rs`, `uninstall_tests.rs`), and the step list they share is drawn by `ui/steps.rs`.

**Status** (from Home): "Needs attention" first, then "Services" (installed
units only: name, state, ready, `since 18:40` or `since 2026-10-10`), then
"Checks" (the health checks that are fine, one entry each, `N ok` on the
heading). Under the list the highlighted problem or check is shown in
full, wrapped over up to 3 dim lines (cut with `…` only after the third). A problem is an
installed unit that is failed or inactive (`■ NAME is stopped`; not the
model server or the maintenance timer, which idle by design), a unit not
enabled at boot (`▲ NAME does not start at boot`; there is no boot switch),
a certificate renewal whose last run failed (`openvibes-certificates.service`
failed, `ServiceStatus::last_run_failed`; its timer keeps its own state and
actions, and its Service page adds "▲ The last renewal failed: see Full log.":
"certificate renewal failed: see Status › certificate renewal › Logs"),
or a health check (certificates, a lost `chain.crt`, disk, feeds, signer, audit, tuning). `Enter`
on a service opens it; on a stopped or not-enabled unit it starts or enables
it (a Yes/No question in the bar, or the sudo password typed in the bar;
see Service); on a health problem or a check it does nothing. A refresh
keeps the highlight on the same item. The name column is as wide as the
longest installed unit's name ("certificate renewal"), so the states line
up. Home's summary line counts the problems (health is collected at start,
on a thread, and again on the way back to Home once they are 10 s old or a
run ended since: they run on the UI thread, so not on every Esc), is red (■) when one is red
or a unit is stopped and amber (▲) otherwise, says "No services
installed" when none are, and shows a failed unit refresh in red; Status and
Service show it in the bar. Tests: `src/tui/status_tests.rs`,
`home_tests.rs`.

**Service** (`Enter` on a service in Status): the unit's state (running or
not, ready, since), its actions as entries (a running unit offers Restart
and Stop, a stopped one Start; all offer Full log) and the "Recent log"
below (tracing JSON read as in the log view). `Enter` on an action asks a
Yes/No question in the bar (`Restart ingest?` with what it means as detail;
`←`/`→` or `y`/`n` choose, `Enter` confirms, `Esc` is No). Yes sends the
action and the bar shows a spinner (`Restarting ingest…`) while the screen
polls the unit about once a second. It ends in one result line, kept until
the next key: `✓ ingest restarted and ready (N s)` (no time under a second, as every result line) when the unit is active
(and not "not ready"; Stop: not active; Restart: also a new start time,
since the restart is queued and the old process answers until then), or `✗ NAME did not start within 30 s:
<its last journal line>` after `ACTION_TIMEOUT` (30 s); a refusal (not an
operator) is the result line too. Fixing "does not start at boot" asks
`Your password (sudo):` in the bar (masked, `Enter` enables, `Esc`
cancels) and ends `✓ NAME now starts at boot`. `q` on Home asks `Quit while
it runs?` while an action is still running (the unit keeps going). Full log
shows up to 500 lines, newest at the bottom; `↑`/`↓` scroll back, no further than the first line (`⭡ N more` / `⭣ N more`); `Esc`
returns. Code: `service.rs` (screen), `work.rs` (questions, prompt, polling),
tests `service_tests.rs`.

**Install**: opens first on a host without `/etc/openvibes/setup.toml`
(code in `src/tui/install/`). Location line ` · Install`. There is no
other install form: Maintenance has the optional parts, ports and
addresses, and certificates once the host is set up.

- *Welcome*: "This host does not run OpenVIBES yet." with Choose what to
  install, Quick install and Quit.
- *Quick install*: only what OpenVIBES cannot know, edited in place: the
  host name, other names, the root key file and whether the agent runs on
  this host (ticked; Space). Everything else is the defaults: OpenVIBES's
  own CA, the default ports, no assistant. The root key file defaults to
  the first free name in the home directory (`openvibes-root-ca.key`, then
  `-2`, `-3`…), since Remove everything keeps the old key. Enter on
  Install asks for the password.
- *Choose what to install*, five steps on a steps line (Enter on Next goes
  on, Esc goes back a step, fields are edited in place): 1 Optional (the
  agent on this host, the assistant; ingest and console are always
  installed), 2 Names (host name, other names), 3 Certificates, 4 Ports (each
  checked as typed; a default another program holds is moved to a free
  port with its reason in yellow, unless the platform's own service holds
  it, #115), 5 Review (every choice on one screen; Enter on a line goes
  back to its step; Install asks for the password once, and when sudo asks
  none its row reads "install now" and its help leaves the password out).
- *Certificates* (step 3): your own CA (the default), Import from your PKI,
  or OpenVIBES makes one (then the root key file is asked). Import takes a
  finished intermediate and its key: the Certificate row takes the chain
  (ours first, then each CA above it, ending with the root) by paste or a
  file, or a .p12 / .pfx whose password is asked in the bar ("Its
  password", not sudo's), which fills both rows; the Private key row takes
  a PEM key, and a locked one asks its password in the bar too. Each is
  checked at once in the TUI, which decrypts the key; Next sends the chain
  and the plain PKCS#8 key to `helper ca-import` on stdin (never argv)
  under the sudo password, and the decrypted key is forgotten once the
  helper has it, or when Import or the step is left. With your own CA, Next first makes the
  request, before anything is installed: `helper ca-request` writes
  `/etc/openvibes/pki/request/` (the request and what is needed to sign
  it) and the screen shows the request to copy. The two certificates (the
  signed one, and your CA's: the CA that signed it, then each CA above it
  up to the root) are then added by paste box (a bracketed paste
  arrives whole; without it, lines are typed and Enter adds a line until an
  `-----END` line) or "From a file on this host" (a file browser). Each is
  checked at once in the TUI; once both are in, `helper ca-accept` checks
  and keeps them under the request folder, and only then does Next go on:
  the careful CA step installs from them. The request can be signed on
  the host with `openvibes-admin ca sign-intermediate`. A copy of the
  request is also saved in the home folder (`~/openvibes-intermediate.csr`,
  or `-2`, `-3`… beside another file): it is public, and OpenVIBES
  removes it once the CA is installed, or when the package is removed
  unused.
  An abandoned request leaves its key in `/etc/openvibes/pki/request/`
  until a CA step or Remove everything; removing the `openvibes-admin`
  package on a host never installed (no `setup.toml`) deletes it too.
- *Installing*: one row per group of steps (Packages, PostgreSQL, Database,
  Certificate authority, Certificates, Console, Services, Firewall,
  Baseline rules, then Agent on this host and Assistant when chosen, Ready),
  each with its state; the step a run stopped at has its whole reason
  under the rows and the rows fold to make room. The password is asked once
  (masked, over the screen the install started from; as root, #82, none is
  asked), the plan is written by `helper setup-plan`, and the steps run by
  `helper setup-step` on the worker like every other long job, so the screen
  stays responsive while a step blocks (e.g. dnf). A stop keeps the
  password for Enter, "Try again", which goes on from that step; the
  assistant's failure never stops the run (its row shows a note). Esc after
  a stop goes back to where the install began (Quick install or Review)
  while there is no CA, and Home once there is. The console step's
  generated admin password is not shown while the run goes: only on
  Finished.
- *Finished*: labelled rows: Open the console (the address), Sign in as
  (admin), Password (generated, "shown only now: write it down"), Root key
  (where the only copy was written, to move to a USB stick and keep
  offline; only with OpenVIBES's CA) or Certificates ("signed by <your CA>";
  browsers that trust your CA show no warning; only with your own CA), then
  the next steps (sign in, change the password, add hosts under
  Enrollment, and that the operator can run openvibes-admin without sudo
  after logging in again). A detail in a wording the screen does not know
  is shown as it is. No agent install line: hosts are added from the
  console; `agent command` prints one for scripts. Enter goes Home.

The ports a plan moves away from (Maintenance › Ports and addresses) are
recorded in `/etc/openvibes/setup-moved-from` by `helper setup-plan` and
closed in firewalld once Readiness is done, as the CLI's Repair does; only
ports the Firewall step itself opened are closed, as recorded in
`/etc/openvibes/setup-opened-ports` (one open before Setup ran is never
Setup's; installs from before the record close nothing), and one another
program listens on, per `ss`, stays open with who uses it.

*#87*: a host with `setup.toml` but no `/etc/openvibes/pki/intermediate.crt`
(a first install that stopped before its CA step) starts on step 1 of
Choose what to install, filled from the plan (agent and assistant from its
components, names, CA mode, ports) with a free root key name, and installs
again, not a Repair, which refuses to make a CA. A port the plan chose that
another program holds now is moved to a free one and said on Ports. Not
while a job is half done (`/run/openvibes-admin/job`): a Remove everything
that stopped after deleting the CA but before `setup.toml` starts on Home,
whose Status offers to finish it. The CA's presence is read at start and on
each refresh. A plan that does not parse keeps the defaults and says its
error in red on step 1. Esc on step 1 goes Home (whose Maintenance ›
Uninstall still works; Repair refuses to make the CA), and the next start
opens the steps again; on a fresh host it goes to Welcome.

As root no password is asked (#82): the TUI started with `sudo
openvibes-admin` runs its helper directly, keeping `SUDO_USER` so Setup
still names the person who started it (operators group, root key owner);
otherwise the password prompt suggests starting it that way (#92). The
install's steps are those of `setup --quick` (below). Tests:
`src/tui/install/*_tests.rs`.

**Boot state**: `helper unit-enable` (through the user's own sudo; polkit cannot
limit boot changes to OpenVIBES units) enables a unit at boot. Service
actions go through polkit for operators and are written to the journal
(`journalctl -t openvibes-admin`). Not an operator: the TUI names the group
to join. Unit states refresh every 5 s on Status and Service; logs are read
on opening a service, after an action and on returning from the full log,
since each read goes through sudo and the auth log. `llm` is
`openvibes-llm.socket`: it has no readiness probe, and the model server is
inactive whenever the assistant is idle (see [openvibes-llm.md](openvibes-llm.md)).

**Configuration**: there is no settings editor in the TUI any more (the old
Maintenance › Settings files screen went with TUI rework step 6d). The limits,
timeouts, feed addresses, proxy and assistant options are changed in the
console, Settings › General ([platform-settings.md](platform-settings.md)).
Setup and Repair write what they own: the listen ports (Maintenance › Ports
and addresses, which also keeps the console's public address in step) and the
certificate files they issue. Maintenance › Database only reports. Everything
else in `/etc/openvibes/` (`ingest.toml`, `distribution.toml`, `vulns.toml`,
`console.toml` with the assistant's `[assistant]` section, `admin.toml`;
`llm.conf` is an environment file) is changed by hand with an editor, as
root: `database_url` (in all five files) and `database_pool_size`, the
certificate, key and CA file paths (`server_certificate_file`,
`server_key_file`, `client_ca_file`, `issuing_certificate_file`,
`issuing_key_file`), each `health_listen`, the console's `transport_mode`,
`development_listen`, `unix_socket_file`, `trusted_proxy_addresses` and
`trusted_proxy_uids`, `osv_dir`, and the assistant's file paths
(`api_key_file`, `ca_file`, `client_certificate_file`, `client_key_file`). A
service reads its file at start, so restart it afterwards (Status › the
service). There is no helper verb that writes a service file any more
(`config-write` was removed with the screen); `config-read` stays for
Certificates › Replace.

**Database** (Maintenance › Database): a report only (spec §6). It shows the schema ("N · up to date", or "migration pending"), the database size with its disk's size and use ("3.1 GB on a 120 GB disk (41% used)"), the data kept (90 days, set in the console), and the automatic nightly clean-up with the date of its last run ("ran today") and what it removed. The timer's time of day is not shown: no host call reads it. These are read on another thread (the disk too) from `status` (run as `openvibes-admin`) and from the maintenance service's journal (`helper logs` now reads `openvibes-maintenance.service` along with the timer). Migrations run in Update; the clean-up has no button.

**Update OpenVIBES** (Maintenance): the installed version and whether a newer one is available (from the package check made at start), then Back up first, Update now and What's new. Back up first is off on a first update; afterwards it is ticked or not as you chose last time (`--remember-choice`), and the help line says why. Ticked, it shows Save in folder (as in Back up; no folder until you choose one) and the backup goes there with a new name (`openvibes-<installed version>-<date>-<HHMM>.dump`: named for the version whose data it holds, which a restore needs). Update now is offered when any installed OpenVIBES package has a newer version (the version shown is the admin's, else the installed one). It asks "Update to X?" (X is the admin's new version; when only other packages are newer, "Install updates (agent 0.2.9)?", and the result reads "Updated: agent 0.2.9") and runs the six update steps on the worker (Back up, Stop services, Install packages, Update the database, Start services, Ready), each shown with ✓, the spinner or ·; a skipped backup shows as –. A stop at Stop services or Install packages starts the services again (`update-step start`, then `ready`, which starts the agent and clears the half-done mark) and says so, without claiming nothing changed (a dnf transaction may be part applied). Finishing a half-done update runs no such rescue: the services stay stopped and Try again goes on. A stop at the database step keeps them stopped and says why; Try again goes on. A failed step shows a red ✗, what failed, what to do and what was left as it was. Enter after a successful update starts the new version of the menu (`exec` of `/usr/bin/openvibes-admin`). What's new lists every package's version change and the release notes' address. A half-done update (the helper's mark `/run/openvibes-admin/job`, now 0644 so the TUI can read it) is a problem on Status ("Enter Finish it"), and the page then offers Finish the update without a backup, even when nothing newer exists. A half-done uninstall is a Status problem too ("An uninstall stopped half way"); Enter opens Uninstall to finish it.

**Optional parts** (Maintenance): tick or untick the agent and the assistant, as in `setup.toml`; the Apply row says what it will do ("install the assistant", "remove the agent", joined with " and "). Apply with nothing changed does nothing. Adding asks "Install the assistant?" (Yes first); any removal asks "Remove the agent?" starting on No. One run, four kinds of row: Save the choice (`setup-plan` with the whole edited plan, `--model fetch` when the assistant is added), then for each removed part Stop / Remove / Remove its data (`remove-step … --components <part>`, which purges the part's data and account because the plan no longer holds it), then Install the part (the Repair steps Packages to Agent) and Download the model, and Ready (the remaining Repair steps and the status). Every Apply runs each Repair step once. While Download the model runs its row reads `1.2 of 2.7 GB` (`1.2 GB downloaded` when the total is unknown, `about 2.7 GB` without progress): the root helper's model step (`src/model_progress.rs`) writes `<done> <total>` to `/run/openvibes-admin/model-progress` (0644, replaced atomically, twice a second) from the size of the growing partial file in the models directory, and removes it when the step ends, fails or panics (uninstall's last step removes one left by a killed run); the total is the pinned model's size constant `MODEL_BYTES` (2.74 GB, no network request). The TUI only reads it. The model download never stops the run: its row shows the step's own state as a dim note, not a red cross. Apply is refused up front, with no question, while other work runs ("Wait: other work is still running"), under a half-done update or uninstall (Repair's words), when the plan changed since the page opened ("The setup changed meanwhile: open the page again.") and for a plan from before the port choices ("Run Repair first: this plan is from an older version.", also shown when the page opens: its real ports are in root-only service files, and Repair saves them into the plan). After a failed run past Save the choice, the page offers only Try again (the saved plan is already the new choice). A part out of the plan whose removal did not finish, seen without sudo by one of its packages in the package list Update reads or by its data folder (`/var/lib/openvibes-agent`, `/var/lib/openvibes-llm`), shows unticked with "removal not finished"; Apply then says "finish removing the agent", asks "Remove the agent?" and runs only that part's Stop / Remove / Remove its data groups (no Save: the plan is already without it) and Ready. In the Maintenance menu, Optional parts and Ports and addresses say "cannot be read" when the plan cannot be read. Tests: `src/tui/maint/parts_tests.rs`, `parts_finish_tests.rs`, `apply_tests.rs`.

**Ports and addresses** (Maintenance): lists the console's port with its web address (`:port` only when not 443), Agent connections (ingest), Rule distribution and Network devices (`514/udp`, information only). Enter on a port types a new one (digits, at most five), checked at once by `port_note`: free on this host (the row's saved port counts as free, the platform's own service holds it), used by another program (`Host::listeners`), already used by another row, or refused (zero, reserved, not a number, below 1024 for Agent connections and Rule distribution, whose units cannot bind low ports; `check_ports` refuses the same for the CLI and Setup), or a port another row is leaving only at Apply; an `Err` is red and Enter then does nothing, Esc keeps the old value. A changed row shows `* name` and `new · was old`; the Apply row appears only then and says whether agents need their install line again. Apply asks ("Move agents to <p>?", "Move distribution to <p>?", "Move the console to <p>?", "Move <n> ports?") and is refused up front as Optional parts' is (other work running, a half-done job, a changed or older plan). One run: Save the ports (`setup-plan` with the whole edited plan), Restart with the new port (Repair Packages to Console and Services), Open the new port (Firewall to Agent), Close the old port (Ready), Ready (model step and status). A failed run reopens on Try again. Tests: `src/tui/maint/ports_tests.rs`.

**Certificates** (Maintenance, after Ports and addresses; `src/tui/maint/certs.rs`, certs2.py, certs4a.py, certs4b.py #10, certs4c.py #1, #9, #13): a report read from the certificate files (`Host::certificates()`), not the plan; how the CA was made (`CaMode`) is the plan's. Agents comes from the earliest of `ingest.crt`, `distribution.crt` and `console-chain.pem` (without `console-chain.pem` while the console uses your own certificate, which you renew): green `renewed automatically` · `next <end − RENEW_AT_DAYS (30)>`, `· due today` once that date is today or past, and red `renewal is failing · see Status` with fewer than `RENEW_DAYS` (14) left (rule 34: no Renew button). Console follows it: green `from the platform` · `renewed with the agents`, or, with your own (`Host::own_console_cert()`), bold `your own` · `<name> · until <date>` (the name as `check_server_cert` gives it, `install::server_check::name_of`), amber `your own · ends <date>, in <n> days` within 30 days (`console_cert_check::WARN_DAYS`) and red `your own · ended on <date>` once ended. Names (the SANs of `ingest.crt`), Intermediate (its first certificate: `signed by <issuer CN, bold> · until <date>` with your own CA, `signed by the OpenVIBES root · until <date>` for a quick CA, `from your PKI · until <date>` for an imported one, then Signed by: the CNs of `chain.crt`'s CAs and of `root.crt`, joined ` › `, the root bold; for an import always (just the root for a two-level PKI), in every other mode whenever `chain.crt` exists; red `chain.crt is missing` instead, in any mode, when it is gone and the root did not sign ours itself, `setup::pki_import::lost`), Previous intermediate (dim `trusted until <date>, as agents move over`, only while `/etc/openvibes/pki/previous.crt` exists; the date from `previous-until`, RFC 3339, both 0644); certs2.py's Root key row is gone (certs4c.py #1: Replace's own line says the key is needed). With no certificate it says `No certificates yet: run Repair.` Three entries: Names (opens the Names page; coming back, Esc or Enter, reads the files again), Replace the intermediate (`a new request for your CA`, `needs the offline root key file` for a quick CA, or `import the next one from your PKI`) and Console certificate (`use your own`, or `use a new one, or go back to the platform's` once yours is in). With every row there (an import's Signed by and a previous intermediate) the entries scroll (`⭡ 1 more`). While the previous intermediate is trusted, Enter on Replace opens nothing and says in red `The previous intermediate is still trusted until <date>, while agents move over: replace it again after that.` (`setup::replace::still_trusted`, the helper's own refusal); any move or Enter takes it away. The Maintenance menu's line is `signed by <issuer CN> · until <date>`, the date being `ingest.crt`'s, the issuer the intermediate's; `cannot be read` when either cannot, `no certificates yet` without `ingest.crt`. Agents pin the root (`root.crt`, the install line's fingerprint): with your own CA or one imported from your PKI that is the company root, so any certificate the company PKI issues for this host's names also passes on agents. This is a design choice (decisions.md), not a gap: whoever runs that PKI is trusted as this host is. Before any intermediate from a company PKI is used (import, `ca-accept`, every Replace but the OpenVIBES-made one), the self-check verifies a throwaway server certificate as agents do (platform-pki `check_key`): one agents would refuse is refused there ("X may not sign server certificates (its extended key usage): ask for one without that limit."). Tests: `src/tui/maint/certs_page_tests.rs`.

**Certificates › Replace** (`src/tui/maint/replace.rs`, `replace_import.rs`, `replace_own.rs`; certs2.py #3-4, certs4a.py #2-10, certs4b.py #11): one run (`Kind::Replace`) of `helper ca-replace [--root-key PATH]` (`Call::CaReplace`), or, for an import, `ca-import` then `ca-replace`. *Imported from your PKI*: the note `The same screens as at install. Nothing changes until Replace.`, then Certificate, Private key (the install's Import rows, screens, paste, file, .p12 and password bar as they are; `Install::import_rows`; their location reads ` · Maintenance › Certificates › Replace › Certificate` or `› Private key`, and after a .p12 the page says "From <file>. Delete that file now: its key is kept here." under its line, `Install::p12_hint`) and Replace (`agents move over in <client_certificate_days> days`, read with `config-read ingest`, 30 when it cannot be). Both added, the chain is checked here: its root must be this host's `root.crt` (as DER), else the red `Replace: under …` line (`setup::import::another_root`), and ours must not be the intermediate in use (the bundle's first certificate), else red `This is the intermediate already in use: ask your PKI for a new one.` (`setup::import::IN_USE`); otherwise green `✓ Under the same root: agents keep working.` and Enter on Replace asks the question below. Only Yes sends anything: one run (`Kind::Replace`) of `ca-import` (`Install::import_call`, the bundle on stdin) then `ca-replace`, under one password; the helper checks everything again, and a refusal by `ca-import` stops the run with its sentence in red, no `ca-replace`. No and Esc stage nothing. The run's bundle is wiped and the key forgotten once it ends; Esc forgets the import. *Your own CA*: the note `The same steps as at install. Nothing changes until Replace.`, then Show the request, Signed certificate, Your CA's certificate (`✓ <CN> (kept)`: `/etc/openvibes/pki/root.crt` then `chain.crt`'s CAs when there is one, read as the operator; Enter adds them again, as at install, since a new intermediate may come from another CA under the same root: the row then reads as the install's) and Replace. Opening it makes or reuses the request with `ca-request` (the password in the bar) into the install's own state (`App.install`, its host name set from the plan); Show the request and Signed certificate open the install's screens as they are (request, the two ways, paste box, file pick; their location reads ` · Maintenance › Certificates › Replace › …`, as for any install screen opened from Replace), and Use it runs `ca-accept` with the kept CAs (or those added again) as the CAs' PEM; a different root is refused by `ca-replace` ("Your CA's certificate is not this host's root: agents trust only that one."). Replace is enabled once the signed certificate is kept (`Install::accepted`). *OpenVIBES made the CA*: the note `Needs the root key kept offline at install. Nothing changes until Replace.`, then Root key file and Replace. Enter opens the install's file browser (`Browse::files_at` the operator's home, `ca_request::pick`); the file picked is read at once (as the operator, at most 64 KiB, `ca_request::read`) and checked with `Issuer::load(root.crt, key)`, as the helper checks it again as root: green `✓ The key matches the OpenVIBES root on this host.` (and the cursor on Replace) or red `✗ Not the key of this host's root: pick the root key kept at install.` (`setup::replace::NOT_THE_KEY`); a path under the home shows as `~/…`. Enter on Replace asks `Replace it?` · `agents keep working` (on Yes; short enough for the Yes / No buttons at 80 columns, ruling 10), then the sudo password in the bar (`Enter Replace`), then the step list: Making the new intermediate (quick only; your own CA and an imported one show the last three), Trusting the old and the new one, Issuing the server certificates, Restarting the services. While it runs, the helper also writes each finished stage line to `/run/openvibes-admin/ca-replace-progress` (0644, replaced whole through `model_progress::replace_file`, emptied when a run starts, removed when it succeeds; a failed run's file stays until the next run, a reboot or uninstall, whose last step removes it with the model download's); the TUI reads it on each draw, as the model download's, and shows `⠹ Step N of M: <step>` with the running row bold (Issuing adds `ingest, distribution, console`) and the later ones dim. Once done, the rows are ticked from the lines it printed. One result line: `Replaced · agents move over in <client days> days · put the key offline again (<time>)` for a quick CA (the time, as on every Maintenance result line, is left out under a second: `Run::took`), without the key clause for your own CA; the days are `previous-until` (from the `done<TAB>NEW<TAB>PREVIOUS` line) less today, less the one day the helper adds. A failure ticks the stages the progress file lists, marks the next ✗, leaves the rest dim and shows the helper's sentence in red. Enter (or Esc) goes back to Certificates, on Names, which shows the previous intermediate. Esc before Replace changes nothing (with your own CA only `ca-request` has run). Shared with the install: `src/tui/ca_request.rs` (the helper's sentence, the file browser's keys, the capped read). Tests: `src/tui/maint/replace_tests.rs`, `replace_import_tests.rs`.

**Certificates › Console** (`src/tui/maint/console_cert.rs`, `src/tui/install/server_check.rs`; certs4c.py #2-#11, approved.md 57): the console's own certificate, for the browser only; agents keep the platform's. Without one, Console certificate opens *Use your own certificate*: the note `For the console in the browser only; agents keep the platform's.`, then 4b's Certificate and Private key rows, screens, paste box, file pick, .p12 and password bar as they are (`Install::import_rows`, `p12_hint`; their location reads ` · Maintenance › Certificates › Console › Certificate` or `› Private key`) and Use it (`once both are added`, then `the console restarts`). While the page is open `Install.server` holds the console's names (`console_cert_check::console_names`: the plan's names, then `Host::addresses()`, as Status), and the rows check a server certificate for them instead of an intermediate (`Install::cert_of`, `key_fits`; `Added::Server`): the paste box's note is `The console's certificate first, then the CAs above it.`, and it says green `<name> · for server use · valid until <date>` and `Covers <first name covered>, one of this console's names.` (`check_server_cert`), or the one red line of `setup::console_cert::console_cert_message`: a CA certificate, not for servers, expired, not valid yet, covers none of the names (with the green line above it: `Covers none of this console's names: add one under Names first.`), or the key of another certificate (`check_server_key`). A .p12 fills both rows. Enter on Use it asks `Use it?` · `the console restarts`; only Yes sends anything: `console-cert-set` (`Call::ConsoleCertSet`, the certificates then the plain key on stdin, `Install::import_call`; `Kind::ConsoleCert`, the sudo password in the bar). The result line is `The console uses your certificate · until <date>` (from the helper's `set<TAB>NAME<TAB>UNTIL`, with the time as every result line), or the helper's sentence in red. The run's bundle is wiped and the key forgotten when the run ends (the rows stay added: `Install.import_done`), and Esc forgets what was added. Once yours is in, Console certificate opens *The console's certificate*: `Yours: <name>, until <date>.`, then Use a new one (`paste or pick, as before`: the page above, Esc comes back) and Go back to the platform's (`renewed automatically with the agents`): `Go back?` · `the console restarts`, then `console-cert-reset` (`Call::ConsoleCertReset`) and, back on Certificates, `The console uses the platform's certificate again`. Tests: `src/tui/maint/console_cert_tests.rs`.

**Certificates › Names**: Host name, one Other name row per SAN of the plan, Add a name (at most 16 other names, `plan::MAX_SANS`) and, once something changed, Apply. Enter types a value, checked at once by the plan's own rules (`plan::check_name` for the host name, `plan::check_san` for other names: a lowercase DNS name or an IP address; letters are lowercased as typed, and `PlanArgs::plan` lowercases the host name and every SAN, so Setup and the CLI store them lowercase too); a red note keeps Enter from doing anything, Esc cancels. Enter on an emptied Other name removes it; the Host name cannot be emptied. Apply asks "Issue new certificates?" ("for these names") and is refused up front as Optional parts' is (other work running, a half-done job, a changed or older plan). One run: Save the names (`setup-plan` with the whole edited plan), New certificates (Repair Packages to Certificates), Restart services (Console to Agent), Ready. The result line reads the new `ingest.crt` again for `valid until <date>`. The Certificates step itself runs `systemctl try-restart openvibes-ingest openvibes-distribution openvibes-console` after issuing (the services read their certificate at start; none reloads it, and a stopped service is left stopped). Tests: `src/tui/maint/certs_tests.rs`.

**Install, in detail** (`src/tui/install/`): `Install` holds the choices (agent, assistant, names, `Ca::Own`, `Ca::Import` or `Ca::OpenVibes`, root key file, three ports) and writes the `setup-plan` arguments (`--ca careful|import|quick`; `--root-key-out` only with OpenVIBES' own root; `--model fetch` with the assistant). The install runs on the worker (`Kind::Install`, the password asked once in the bar; root is not asked) as `setup-plan` then `setup-step STEP` (no `--repair`), in rows: Packages (holds the plan), PostgreSQL, Database, Certificate authority, Certificates, Console, Services, Firewall, Baseline rules, Agent on this host (only when ticked), Ready, Assistant (only when ticked, last; its failure never stops the run; while it runs its row reads `Assistant  1.2 of 2.7 GB`, from the progress file Optional parts reads, through the same `maint::with_progress`). Installing shows `Step N of M: TITLE`; a stop shows ✗ with the reason, Enter is Try again (resumes at that step) and Esc goes back where the install began (`Install.origin`: Quick install, or Review, `Stage::Step(4)`) while there is no CA, to Home once there is. Finished (`install/finished.rs`) shows the console address (with the port when not 443), `admin`, the generated password once, then the root key file, or the root certificate's path (or "signed by X") with its SHA-256 whole under it (`Root CA SHA-256`, 16 bytes a line, since it is compared by hand), and Enter goes Home, reading the health checks again first so Home's count matches Status. A host without `setup.toml` opens on **Welcome** (`install/welcome.rs`: Choose what to install, Quick install, Quit; `q` quits). **Quick install** (`install/quick.rs`; location ` · Install › Quick install`) asks only Host name, Other names, Root key file (edited in place: Enter types, Enter keeps, Esc cancels), "Agent on this host" (ticked; Space) and Install; it installs the core components, OpenVIBES' own CA (`--ca quick --root-key-out`), the default ports and no assistant. A default port another program holds gets the free one `fields::propose_ports` finds, and the Install row's help line says so ("443 is in use by nginx: the console uses 8443"). `install/fields.rs` holds the shared checks: `check_names` (host name and other names, as the plan checks them), `check_root_key` (absolute, new: a dangling link counts as there; in an existing folder that is a folder; the CA step checks the same before `ca init-root`) and `Install::problem`, whose first flagged field is said in red under the list; Install does nothing while one is flagged. **Choose what to install** (`install/steps.rs`, `review.rs`, `certs.rs`, `paste.rs`, `import.rs`, `import_paste.rs`; advanced.py, ca.py, ca2.py, full_advanced.py, certs4b.py) is five steps under a steps line (`✓ done · ● current · ○ to come`; location ` · Install › Optional|Names|Certificates|Ports|Review`). Enter on Next moves on, Esc goes back a step. *Optional*: Agent on this host (ticked) and Assistant (2.7 GB download; its help line gives the model's licence link, broken after a `/`), Space ticks; the core is always installed. *Names*: host name and other names edited in place (empty Other names read `none`, as on Quick install, until typed); a bad one is said in red and Next refuses. *Certificates*: "(•) Your own CA" (default, `--ca careful`), "( ) Import from your PKI" (`--ca import`) or "( ) OpenVIBES makes one" (`--ca quick`, which adds a Root key file row checked by `fields::check_root_key`); Space chooses. *Import from your PKI* adds the rows Certificate and Private key (yellow "not added yet", or "✓ added · <our CN>" and "✓ added · matches the certificate") and Next ("once both are added"); Private key opens once the certificate is added ("Add the certificate first: the key is checked against it."). Add the certificate (` › Certificates › Certificate`): "Paste it" ("Our intermediate first, then each CA above it, ending with the root."; a bundle pasted root first works too: ours is then the one CA in it that signed none of the others) or "From a file on this host" (read as bytes, at most 1 MiB, `ca_request::read_bytes`; a .p12 / .pfx, `platform_pki::is_p12`, is kept as its bytes and its password asked in the bar, `Bar::Typing` "Its password" · "Open it"; any other file must be UTF-8 text holding a certificate and no key). The box checks with `platform_pki::check_chain`: green "<CN> · may sign certificates · valid until <ours' end>" and "Chain: <path joined ›> (root, also added)", or one red line from `setup::import::import_message` (a gap keeps our green line above it: "Signed by X, missing here: paste it below this one."); Use it needs a whole chain. Add the private key (` › Certificates › Private key`): "Paste it" ("It stays on this host, readable by root only.") or a file holding a PEM key; a file holding the certificate and then its key is used as the key; a .p12 / .pfx picked there is refused (".p12 and .pfx files go in the Certificate row: they hold the key too."). `pkcs8_pem` converts it and `check_key` checks it against the certificate added and the names typed (host name, other names, `localhost`, `127.0.0.1`, as `Plan::names`; none while they are not valid, and then name constraints are left to Replace): green "An EC P-256 key" (", locked with a password" when it was), or red ("Not the key of <CN>: paste the key it was made with.", "<CN> may not sign server certificates (its name constraints): ask for one without that limit."). The paste box's check is made again only when the text or what it is checked against changes (`Install.checked`, a hash keyed per run), not on every draw: each key check copies the key. A locked key (`is_locked`) asks "Its password" · "Unlock" in the bar; a wrong password says "Wrong password." there and asks again (a .p12's also says "✗ Wrong password for <file>." under the two ways); Esc forgets the typed password, the file's bytes and the box's text. An opened .p12 fills both rows from its chain and key (`read_p12`), and the help line says "From <file>. Delete that file now: its key is kept here." (a .p12's path under the operator's home reads `~/…` in every line, `Install::shown`) A certificate added again keeps the key only if it is the new one's. Once both rows are added (as with your own CA's `ca-accept`), `helper ca-import` runs at once (`Call::CaImport`, `Kind::Ca { accept: true }`, the sudo password in the bar): the chain (ours, the CAs above, the root) then one plain `PRIVATE KEY` block on stdin; its `imported<TAB>NAME<TAB>PATH<TAB>UNTIL` line sets `Install.import_done`, the cursor goes to Next ("ports") and Next goes to Ports; a refusal shows its sentence in red and keeps both rows, and Next (or the password cancelled) sends them again. The decrypted key (`Imported.key`, `Install.unlocked`, both `Zeroizing`) is forgotten when the helper has it (and the run's copy of the bundle is wiped), when another choice is made (which forgets the whole import), and on Esc back from the step (the certificate stays); the paste box's text is wiped when it closes. With your own CA, Next runs `helper ca-request --copy ~/openvibes-intermediate.csr` (the helper takes its own copy there again, or writes `-2`, `-3`… beside another file, and says which in its `copy<TAB>PATH` line) through the worker (`Kind::Ca`, password in the bar), and the step shows Show the request, Signed certificate, Your CA's certificate and Next ("once both are added", disabled). Show the request (` › Certificates › Request`) shows the PEM to copy with the terminal and where the copy was saved (⭡⭣ scroll, the END line kept in view). Each certificate is added by "Paste it" or "From a file on this host" (the folder browser of `maint/folder.rs` in files mode, `Browse::open_files`; a file is read up to 64 KiB into the paste box, then titled for the file, e.g. "Your CA's certificate, from root.crt"; a file holding a `PRIVATE KEY` PEM block is refused in the browser, "That file holds a private key: pick the certificate.", as is one holding no `-----BEGIN CERTIFICATE-----` block, "That file holds no certificate: pick the certificate."; a refused file's text is never kept or shown, and each pick or folder clears the last refusal). The paste box checks in-process at once: the signed certificate with `platform_pki::check_signed_request` against the request (the sentences are `setup::request::message`'s, e.g. "That is 2 certificates: paste only the one signed for OpenVIBES."); your CA's certificate ("Your CA's certificate, then each CA above it up to the root.") with `check_chain`, after the signed certificate once it is added, else on its own (a lone root as it is): green "<root> · a root CA (self-signed)", then "Chain: <path joined ›>" with CAs between, or, with the signed certificate added, "Signed the intermediate directly" or "Signed through <path joined ›>" (two lines at most: there is no room for a third at 80×24), or one red line from `setup::import::import_message` (e.g. "Signed by X, missing here: paste it below this one."); Enter is "Use it" only once an `-----END` line is there and the check passed, and before that adds a new line (terminals without bracketed paste send the lines as keys). Both added, `helper ca-accept` checks and keeps them; on success `Install.signed` is the issuer (Finished then says "signed by X") and Next goes on. Install with your own CA is refused until then: the careful CA step would otherwise make a new request that does not match what the CA signed. With a request already signed (`signed<TAB>ISSUER` from `ca-request`, e.g. after a restart), both rows show "✓ added". Both stay kept after `ca-accept` (they are public), so one added again sends both to `ca-accept` again. A refused `ca-accept`, or Esc back to the choice, forgets both certificates added, so both rows can be added again. Helper failures show only their sentence (the `openvibes-admin helper: ` prefix is dropped). *Ports*: Console, Agent connections, Rule distribution (Enter types, checked as typed with `maint::ports::port_note`; Enter keeps only a usable port), Network devices (514/udp, said, not edited); a moved default reads "443 is in use by nginx · 8443 proposed" in yellow until Enter keeps it or a digit types another. *Review*: Optional, Names, Certificates ("your own CA · ✓ signed by X", "from your PKI · ✓ <CN>" or "OpenVIBES makes one · PATH"; Import is refused with "✗ Certificates: add the certificate and its key first." until the helper kept it), Ports and Install; Enter on a line goes to its step, Enter on Install asks the password once in the bar and runs the install; what still blocks it is said in red. The TUI turns bracketed paste on at start and off on every path that gives the terminal back (quit, the shell, the new version, a panic); a paste arrives whole as `Key::Paste`, which only the paste box takes: a field being typed or a password in the bar takes its characters without line ends, and anywhere else it is dropped (a stray paste never presses Enter or `q`). Tests: `src/tui/install/run_tests.rs`, `quick_tests.rs`, `steps_tests.rs`, `certs_tests.rs`, `certs_accept_tests.rs`, `certs_chain_tests.rs`, `import_tests.rs`, `import_file_tests.rs`.

**Repair** (Maintenance): it asks for the password and checks every step first (`helper setup-status`), then lists the steps that need attention with why (wrapped under its column, whole when the rows above the actions allow, as the ✗ view wraps; else up to 2 lines each, `…` after the second; else one line each, and past that as many as fit and `⭣ N more`: the Fix entry names every step). The ones that pass fold into one line ("✓ 11 other steps in order"), since 14 do not fit 80×24. Fix N problems runs every step with `--repair` (never a new CA) on the worker, then checks again; the bar says what is left. A step that stops is marked ✗ with its error, and Try again goes on from it. Check again re-reads. A half-done update blocks repair runs (`job_guard`), so Repair says so and offers no Fix until the update is finished in Update OpenVIBES, and a half-done uninstall the same way in Uninstall (each has its "Finish the …" entry there). Tests: `src/tui/maint/repair_tests.rs`.

A repaired step reads "repaired: ..." in the list, and the journal line of each setup, update and remove step carries its detail (first 300 characters), e.g. `setup-step firewall --repair ok: repaired: open: 18423/tcp` (#292).

**Console sign-in** (Maintenance › Console sign-in): for when nobody can sign in to the console any more. Enter asks "Reset the admin password?" ("old one stops", Yes first), then the sudo password, and runs the helper's `admin-reset` on the worker: a new one-time password for `admin` (4 groups of 4 characters, no look-alikes), which also clears the account's lock and re-enables it (`--recover`). The page then shows `Sign in as admin` and the password with "shown only now"; the bar is Enter Done. The password is moved out of the run's result into a `Zeroizing<String>` the moment the run ends and dropped when the page is left (Enter or Esc); it is never journalled, and opening the page again shows the entry, not the password. When the helper fails (no `admin` user, the database down, `setup.toml` unreadable) its words show in red as `✗ <text>` (e.g. "There is no local account named admin.", or the database error with "Repair first."), no password shows, and Enter is Try again; a `done` with no password counts as failed. Tests: `src/tui/maint/signin_tests.rs`.

**Appliance Home and System** (`src/tui/system.rs`, `system_tests.rs`, `home.rs`; system.py, approved.md 43; step 8a): `Host::is_appliance()` is true when the empty file `/etc/openvibes/appliance` exists (the future image puts it there; `platform_host::APPLIANCE_FILE`). Then Home lists Status, Maintenance, **System** and, instead of Quit, **Log out** (it ends the session like Quit, with the same wait for running work). System holds Restart (`os-restart`) and Shut down (`os-power-off`), each asking first starting on No; the running or failed run shows on the page itself and Enter on a failure tries again. Time, Login password and SSH join this page in 8c and 8d. A normal install never shows System.

**System › Network** (`src/tui/network/`: `mod.rs` state and checks, `draw.rs`, `keys.rs`, `tests.rs`; step 8b-2): shown first on System where `Host::network_info()` finds a wired NetworkManager connection (read when System opens; its line is `192.168.1.50 · DHCP · eth0`). One page: `(•) DHCP` / `( ) Fixed address` (the fixed fields start from what DHCP gave), Address, Gateway, `[x] Use the DNS from DHCP` or DNS servers, Search domain, Host name, and Apply once something differs. Each value is checked as typed (`platform_host::network`); a gateway off the address's network is refused at once. Apply re-checks everything with `network::change`, asks each own DNS server a UDP query first (`Host::dns_answers`; a silent one is only a warning in the question, `9.9.9.9 does not answer from here, so feeds may fail`, and Yes still applies), then asks (`Apply the network settings?` · `undone in a minute unless kept`, Yes first) and runs `hostname-set` (when the host name changed) and `net-apply`. When the helper answers `pending`, the page shows `▲ The new settings are in use. Keep them? The old ones come back in N s.` with Keep these settings (`net-keep`) and Put the old ones back (`net-revert`); each asks for the sudo password again (no secret is kept between runs). With nobody answering, the helper's timer puts the old settings back and the page, past the minute, reads the host again and says so (or, if the change is still pending, offers Keep and Put back again). The countdown follows the helper's pending file, so opening the page again shows the time really left; a Keep that comes too late says so. A connection whose IPv4 method this page does not manage (link-local, shared) offers only the host name. Never tried on a real appliance.

**Operating system** (Maintenance, second entry; `src/tui/maint/os.rs`, `os_tests.rs`; os2.py, approved.md 58): the distribution, kernel and last check, what dnf says is waiting, and the actions as entries. Everything it shows is read without a password from `Host::os_info()` (`/etc/os-release`, `/proc/sys/kernel/osrelease` and `/etc/openvibes/os-updates`, written by `os-check`); a host without `/usr/bin/dnf` shows the page with only a red line. Check again runs `os-check` at once (`Kind::Os(OsAction::Check)`, the sudo password in the bar) and the finished run is dropped so the page itself shows the new counts; Update everything asks `Install N updates?` and runs `os-update`; Restart now asks `Restart this host?` (No first) and runs `os-restart`. The run outlives the page like every Run (Home shows `N packages updated`, the number the update really upgraded). While the update unit runs (also one started from another session) the page shows only that. When the last check says a restart is needed, Status counts "A restart is needed for the updates" and Enter opens this page (`Fix::Open`). The Maintenance menu value comes from `os::summary`.

**Shell** (Maintenance › Shell, second to last): the operating system's command line, for experts. It has no page: Enter on the menu row (bar `Enter Open the shell`) asks "Open a shell?" ("for experts; logged", Yes first), then "Your login password:" in the bar (Enter Open, Esc Cancel; the same sudo password, said as the operator knows it). The password runs the helper's `shell-open` on the worker, which does nothing but is checked by sudo and journalled and audit-noted as `shell-open OPERATOR`; while it runs the bar spins over Maintenance. Under `sudo openvibes-admin` no password is asked. When the run is done, the main loop restores the terminal, prints `OpenVIBES shell · type exit to go back to the menu. Logged as USER, HH:MM.` (USER is the name the journal records) (teal) and `Changes here are yours: Repair can put OpenVIBES' own files right again.` (dim; both plain under `NO_COLOR`), runs `Host::shell` (the `SUDO_USER`'s login shell through `runuser -l` under sudo, otherwise the user's own), then takes the terminal back and redraws Maintenance with Shell highlighted. A shell that cannot start shows `✗ The shell could not start: <error>`; three wrong passwords show `✗ The shell did not open: three wrong passwords: nothing more was run` and open nothing; while other work runs the Yes is refused with "Wait: other work is still running". The finished run is dropped, so Home shows no result for it. Tests: `src/tui/maint/shell_tests.rs`.

**Back up** (Maintenance › Back up): what a backup holds, Save in folder and Back up now. The folder is typed in place and checked as typed: a full path (text only, on every key), then, once the typing pauses (or on Enter), on its own thread: that it exists, is a folder, is not reached through a symbolic link (the real path is named), is writable for you (a probe file) and how much space is left (`df`). That thread gives up after 5 seconds, so a dead mount cannot freeze the screen. Tab browses folders instead (Enter opens, Use this folder picks, ? is Help; symbolic links are not listed; the listing itself still runs on the UI thread). No folder is shown or assumed until you choose one; the helper remembers it after the first backup written there (`/etc/openvibes/backup.toml`; a remembered folder that is not a full path, or holds control characters, is ignored). Every backup gets a new name, `openvibes-<version>-<date>-<HHMM>.dump` (`-2`, `-3`... within the same minute, or when a stray `.dump.roles.sql` of that name exists). It runs `helper update-step backup --backup FILE` on the worker, then shows the file and its size, and says to copy it off this host. The helper refuses a folder whose path goes through a symbolic link, and removes the dump again if its `.roles.sql` cannot be written, so no half backup is left. *Ceiling:* a root-squashed NFS folder passes the check (you can write there) but the helper, as root, cannot: the backup then fails with that error and nothing else runs.

**Health**: one line per check, problems first, each marked `problem` or
`ok`, with the problem count in the title: each installed unit (a problem
unless active and, where it has an endpoint, ready); the ingest and
distribution server certificates, the console's chain (read by its leaf) and
the intermediate. A server certificate is a problem only under 14 days to
expiry, when the daily renewal timer has failed ("automatic renewal is
failing, see Status › certificate renewal › Logs"); a certificate with more
days left is no problem, however near its renewal. The intermediate (judged
by its first certificate) is a problem under 60 days: "replace the
intermediate in Maintenance › Certificates". An expired one always is, drawn red (`Check::red`, as the expired server certificates). When
our intermediate is not signed directly by `root.crt` and `chain.crt` is
missing, the setup check's sentence is a problem too ("/etc/openvibes/pki/chain.crt
is missing: restore it from a backup (agents could not reach the root)",
`setup::pki_import::lost`, the files from `Host::root_and_chain`; not while
a Replace cut short by a crash left its staged `.new` files, which Repair
finishes or undoes). Also a
problem when a
server certificate misses an address this host now has, e.g. after DHCP:
"run Repair in Maintenance"; a CA certificate, which names no host, is not
checked for addresses);
with the admin's own console certificate (`console-own.crt`, `Host::own_console_cert`)
the console's chain is left to `tui/console_cert_check.rs` instead: an amber problem
at 30 days or less ("Console certificate: yours ends DATE, in N days", "in 1 day"
or "today"; the dim line under the list says "Use a new one in Maintenance ›
Certificates."), a red one once ended ("yours ended on DATE"), or when it covers
none of the console's names (the plan's names and this host's addresses,
`platform_pki::covers`; judged only when the plan can be read); never the renewal sentence;
feed errors from `feeds
status` (an unreachable database is a problem here); disk use of
`/var/lib/pgsql` and each `/var/lib/openvibes-*` (a problem from 90 %);
each published rule set's current bundle from `rules list` (a problem under
90 days to expiry or expired, with the fix: install the newer rules package
and run Repair, or publish a newer bundle; retired sets and sets without a
bundle are left out). With distribution installed and no rule set
published at all, a problem: agents get no rules (board #111). The site's own sets `site` and `site-alarms` (board
#107) warn under 30 days instead, with "publish again in the console to
renew": the signer re-signs only with a live password. With the signer set
up, also its `status.json`: no version state is a problem ("run Repair");
refusals in the last day are listed by code, a problem when they include
`rate`, `throttled`, `unavailable` or `version_state` (a wrong password now
and then is not); and the site key's first characters, noting that agents
need its lines from `agent command` and that after a reinstall agents
trusting an old site key refuse the site rules. Loaded on opening and on
`R`.

Every TUI action (service action, boot change, config save, Setup step) is
also recorded in `audit_log` when the database is reachable, through
`openvibes-admin audit note ACTION TARGET RESULT` (hidden; run as
`openvibes-admin`, so the actor names the operator via `SUDO_USER`). ACTION
and TARGET are 1 to 128 printable characters, RESULT is `ok`, `failed`,
`waiting` or `todo`; the note is the only row written. The journal line is
the record when the note cannot be written (no database yet during Setup).

`openvibes-admin helper` (hidden) is the root helper the TUI calls through
sudo; it checks its arguments first and refuses unless run as root:

- `logs UNIT LINES`: the unit must be one of the six, LINES 1 to 500;
- `config-read SERVICE`: prints `/etc/openvibes/SERVICE.toml` (`ingest`,
  `distribution`, `vulns`, `console`, `admin`; regular files only);

## Configuration

`/etc/openvibes/admin.toml` (or `--config PATH`), bounded and strict like
every platform config:

```toml
database_url = "postgresql:///openvibes?host=/run/postgresql&user=openvibes-admin"
```

The admin role owns the schema and needs `CREATEROLE` (migration 1 creates
`openvibes-ingest`).

## Commands

| Command | Does | Prints |
|---|---|---|
| `migrate [--additive]` | applies pending migrations; refuses a newer schema. `--additive` (the `openvibes-migrate` unit after a package upgrade, #77) applies nothing when a pending migration changes stored data and says to run Update, which backs up first | `schema version N` |
| `status` | summary (requires the current schema) | `schema version`, `agents active/offline/revoked`, `imported hosts`, `tokens usable`, `partitions OLDEST..NEWEST` or `none`, `partition count N`, `database size N MiB` |
| `sso status` / `sso off` | prints whether single sign-on is `on`, `off` or `not set up`; `off` stores `sso.enabled` = false (audited `settings.changed`), `already off` and `not set up` change nothing. Used by Maintenance › Console sign-in ([console-sso.md](console-sso.md)) | one word |
| `maintenance [--retention-days N] [--history-days 400]` | creates any missing partition from the finding retention cutoff to today + 7 days, drops older finding partitions (never today's), and deletes at most 10,000 expired audit events using the configured audit policy, deletes change-log rows older than 90 days ([change-log.md](change-log.md)), then forgets expired single sign-on requests and removes single sign-on people inactive for `sso.remove_inactive_days` ([console-sso.md](console-sso.md)), then records today's per-host counts in `host_daily_counts` and deletes history older than `--history-days`. `--retention-days` (default: the console setting “Keep findings” `ingest.finding_retention_days`, else 90) must be 1 to 36500 and `--history-days` 30 to 3650 (else exit 2, before any change) | `created N partitions, dropped M, deleted K expired audit events` then `recorded history for N hosts, deleted M old rows` |
| `user create --username NAME --display-name LABEL [--role ROLE_ID] [--password-stdin] [--must-change]` | creates a local console account holding the role with that id (refused when no such role exists); role defaults to `admin`, the Administrator; `--must-change` makes the password one-time (the user sets their own at first console sign-in, as with the console's New user) | prompts twice for the password without terminal echo; with `--password-stdin`, reads one line from standard input instead (scripts and Setup), same password rules |
| `user list` | lists usernames, status, active role names, display names, and last activity; never reads or prints password hashes | tab-separated rows |
| `user disable USERNAME` | disables the account and revokes its sessions atomically | `disabled local user NAME` |
| `user unlock USERNAME` | clears an active per-account login lock and audits the recovery; source-address throttles remain active | `unlocked local user NAME` |
| `user reset-password USERNAME [--password-stdin] [--must-change] [--recover]` | replaces the password and revokes all sessions atomically; it does not enable a disabled account; `--recover` (break-glass, passed only by `helper admin-reset`) then also enables a disabled account (`user.enabled`) and clears an account lock (`user.unlocked`), after the password is replaced, so a failed replace leaves a disabled account disabled; `--must-change` makes the password one-time (the user sets their own at the next console sign-in), without it the user is not asked to change it | prompts twice without terminal echo; with `--password-stdin`, reads one line from standard input instead, same password rules |

Usernames are normalized to lowercase ASCII and limited to 64 characters.
Passwords use the same console NFC normalization, 15–128 Unicode-character
policy, Argon2id parameters, and local common-passphrase blocklist as browser
login. Passwords are never accepted as command-line arguments or written to
the audit log. The built-in common-passphrase list is a small seed list, not a
full compromised-password corpus.

Commands other than `migrate` refuse to run on an outdated schema ("run
openvibes-admin migrate", or "this upgrade changes stored data … run Update"
when a pending migration needs a backup) or a newer one ("upgrade
openvibes-admin"). A migration that deletes or rewrites rows, or drops or
retypes columns or tables, starts with a `-- openvibes: needs-backup` line;
a unit test holds every migration to that (13, 14, 16, 20 and 24, from
before the marker, are listed in `platform-store`). Setup's `schema` step
reports such a change as failed in Check and Repair (Repair migrates only
with `--additive`); a first install migrates fully. Errors
never print SQL or connection strings. If the audit entry cannot be
written, the command exits non-zero with a warning.

## User commands

The user commands are audited, including failed attempts. Creation provisions
the user, credential, initial role binding, and user-created audit event in one
store transaction. Disable and password reset invalidate all browser sessions.
Unlock clears only an active account bucket; IP/source throttles still protect
the service. The first account can be created after schema 23 is applied.

## Agent commands

| Command | Prints |
|---|---|
| `agent list [--offline \| --revoked \| --imported \| --health STATUS]` | one line per agent: id, status, last seen, version, and `claims ID` for an imported host whose files named an agent id; active agents end with `health <status>` and, when degraded, the reasons in brackets (protocol P12). `--offline` = active with no heartbeat for 3 minutes; `--imported` = hosts from export files (status `imported`, id `import.<install_id>`); `--health healthy\|degraded\|offline\|unknown` = active agents with that health. |
| `agent show ID` | id, status, enrolled (first import for an imported host), revoked, last seen, version, certificate count, and `claims ID` when set; for an active agent, its health and reasons, then the latest report: queue (pending, oldest age, dropped, rejected by reason), last scan and rule counts, each collector's outcome, each rule set's version, expiry and refusal, storage errors, threat alarms (`alarms on (eBPF)`, or `alarms off: why; fix: what to do`, then `alarms fix command: …` when there is one), clock jump, and when the report was written; `unknown agent` (exit 1) if absent |
| `agent revoke ID` | `revoked ID`; `agent already revoked`, `unknown agent`, or `imported hosts have no identity to revoke` are errors. The agent's next request gets `identity_revoked` (PM3). |
| `agent command [--platform HOST] [--root-cert PATH]` | the one-line command that installs and enrolls an agent on another host (`curl -fsSL https://openvibes-project.github.io/install.sh \| sudo sh -s -- --agent --platform HOST --token TOKEN --ca-sha256 FINGERPRINT`), with the platform's standing token (see `token fleet`): the same token every run, created on first use, so repeated runs add no rows; audited with the token's id. HOST defaults to Setup's hostname (`setup.toml`) and must be a DNS name or IP address; the fingerprint is the root certificate's (default `/etc/openvibes/pki/root.crt`). With the baseline rules package installed and its set served with a bundle signed by that same key (current, non-retired, issuer and trusted key equal to `baseline.key`), the line ends with `--rules SET,ISSUER,KEY` from `/usr/share/openvibes/rules/baseline.key`, and the installer configures the agent to fetch and trust that rule set (the key rides the same fingerprint-checked line). With the rule signer set up and `--rules` on the line, it also prints the `[[rule_sets]]` lines for the site's own sets (`site`, `site-alarms`, from `/etc/openvibes/site-rules.trust`, which Setup saves from `openvibes-signer seed`), to paste into each agent's `agent.toml`: the installer doesn't take them yet. No `restricted` key, so the agent restricts both; after a signer reinstall the key is new and the lines must be replaced. |

`show` and `revoke` are audited with the agent id as target. Health is
computed by `platform_store::health` (thresholds in the platform-store
page); an agent before P12 shows `unknown`.

## Token commands

| Command | Does |
|---|---|
| `token fleet` | the **standing token** every agent can enroll with: it never expires and has no use limit. Created on first use (also by `agent command` and Setup), shown again on every later run (its secret is kept in `standing_token_secret`, readable only by the admin account; ingest and the console see the hash). Only one is live at a time. To rotate it, `token revoke ID`: agents already enrolled keep their certificates and keep working, only new enrollments need the new token (the next `token fleet` or `agent command` makes it). One agent is cut off with `agent revoke`. `token create` still makes short-lived, limited-use tokens. |
| `token create --expires Nh\|Nd [--uses N] [--label TEXT]` | 32 random bytes, base64url; printed **once** with its id. Only the SHA-256 is stored. `--expires` 1h to 365d, `--uses` 1 to 100000 (default 1); out-of-range values exit 2 before any change. |
| `token list` | id, state (usable, expired, used up, revoked), uses/max, expiry, label. Never shows tokens. |
| `token revoke ID` | revokes; an already-revoked or unknown id is an error. |

The audit target is the token id, never the token.

## Device commands

Network devices that send events to `openvibes-netlog`
([openvibes-netlog.md](openvibes-netlog.md)). These are database work only:
netlog reloads devices every 30 seconds, so nothing needs root. They are for
the lab and tests; end users will add devices in the console.

| Command | Does |
|---|---|
| `device add --name NAME --address IP [--kind unifi]` | Adds a device. A mapped IPv6 address (`::ffff:192.168.1.1`) is stored as IPv4. A second active device at the same address is refused. Prints where to point its SIEM server (this host, UDP 514). |
| `device list` | Lists each device with its id, name, address, kind, last packet and counters. When nothing arrived in the 10 minutes after adding, or nothing in a day, it adds a line: check the router's SIEM setting and that UDP 514 is open. |
| `device remove ID` | Removes the device. Its alarms stay. An unknown or already removed id is an error. |
| `device suppress ALARM --scope device\|signature --note TEXT` | Quiets a device alarm's rule from now on: on its device (`device`) or on every device (`signature`). New matches arrive closed as false positives, with one history row. |
| `device suppressions` | Lists active device suppressions: id, scope, rule, device, note. |
| `device unsuppress ID` | Removes a suppression. It stays as history. |

The audit target is the device id.

**Readiness heads-up:** when ingest is planned, firewalld runs and
514/udp is not open permanently, Setup's Readiness step ends with
"heads-up: UDP 514 is not open in firewalld, …". It never opens the port
itself (spec 2026-10-10 §6).

## Rules commands

Rule sets for the distribution service. Keys and bundles are signed
offline; the platform never holds a rule-signing key.

| Command | Does |
|---|---|
| `rules trust add RULE_SET ISSUER_KEY_ID PUBLIC_KEY_B64URL` | trusts a 32-byte Ed25519 key (base64url, no padding; weak keys refused) for the set, creating the set. A key (1 in 64) or an id starting with `-` is taken as a value, not a flag; no `--` is needed (also for `trust remove`). Prints `trusted` or `already trusted`. An id already used for a different or removed key is refused: ids are never re-used. |
| `rules trust list [RULE_SET]` | `SET ISSUER KEY added TIME [removed TIME]` per key |
| `rules trust remove RULE_SET ISSUER_KEY_ID` | stops trusting the key for future publishing; served bundles are unchanged (agents trust keys themselves) |
| `rules publish FILE` | verifies the envelope with the agent's own `openvibes-rules` loader against the set's currently trusted keys, then stores its exact bytes. Prints `published SET vN`, or `unchanged: …` for the same version with the same bytes. |
| `rules publish-site --user USER --set site\|site-alarms [--password-stdin] [--socket PATH] FILE` | the site's own rules (board #107): asks for USER's console password (or reads it from stdin's first line), has the rule signer sign FILE (the signer checks the password, `site_rules.publish` and its limits itself, and picks the version), then publishes the envelope like `rules publish`. Refusals are explained in plain words (wrong username or password, locked, not allowed, over a limit, hourly limit, no version state). Setup puts `openvibes-admin` in the socket's group and trusts the site key for both sets. |
| `rules list` | `SET vN\|none keys K expires TIME\|- [signer-removed] [retired]`. `signer-removed`: the current bundle's key was removed; it is still served, but agents that dropped the key refuse it, so publish one signed by a trusted key. |
| `rules show RULE_SET` | per bundle, newest first: version, SHA-256, issuer, size, when and by whom published, expiry |
| `rules retire RULE_SET` | stops serving the set (404 to agents) and refuses further publishing; bundles are kept |
| `rules keygen KEY_FILE --rule-set SET --issuer ISSUER` | offline (no config or database): writes a new Ed25519 private key to `KEY_FILE` (32 bytes, 0600, never overwritten) and prints `SET ISSUER PUBLIC_KEY`, the arguments of `rules trust add` and the line of a package's `.key` file. `rules keygen --show-public KEY_FILE --rule-set SET --issuer ISSUER` prints that line again for an existing key (same permission checks as `sign`, nothing written), for when the first output was lost |
| `rules sign KEY_FILE RULES_JSON --rule-set SET --version N --issuer ISSUER [--days 730] -o OUT` | offline: signs the exact bytes of a schema-1 rule set into a new envelope (0644; valid from now for `--days`, 1–3650), checks that the agent's loader accepts it, and prints `signed SET vN, expires TIME, sha256 HEX`. Refuses a key file that group or others can access, a key that is not 32 bytes, an invalid rule set, and an existing `OUT`. |

Keep the key file off the platform host: `keygen` and `sign` are meant for
the signer's machine and write no audit row. The project's baseline rule
set is signed this way (the `openvibes-rules` repository).

`publish` refuses (exit 1, nothing stored):
- a file over 1,048,576 bytes (`envelope is larger than 1048576 bytes`), or
  one that is not an envelope (`not a signed rule envelope`);
- an unknown set, no trusted key, or a removed key (`untrusted issuer`);
- a bad signature or digest (`invalid signature`);
- an expired envelope, or one created in the future;
- a version not above the current one (`version N is not above current
  version C`), or the current version with different bytes (`version N
  already published with different content`);
- a retired set.

It warns on stderr when the bundle expires in less than 7 days. Publishers
of one set are serialized, so concurrent identical publishes store one row.

Audit targets: `SET vN sha256:HEX` for `publish` (none if the file is not
an envelope), `SET/ISSUER` for the trust commands, the set for `show`,
`retire`, and `trust list RULE_SET`.

## Vulnerability commands

| Command | Does |
|---|---|
| `feeds import FILE --source fedora-<rel>-<arch>` | imports a downloaded `updateinfo.xml` or `.xml.zst` (offline platforms), re-matches that release: `imported N advisories into SOURCE; M open on fedora REL` |
| `feeds import FILE --source rocky-N\|almalinux-N\|debian-N\|ubuntu-YY.MM` | imports an OSV `all.zip` (the ecosystem's, from `osv-vulnerabilities.storage.googleapis.com/<Ecosystem>/all.zip`) for that release and re-matches it: `imported N advisories into debian-12; M open` (unreadable records are counted and skipped) |
| `feeds import FILE --source kev\|epss\|nvd\|euvd` | imports a CISA KEV JSON, an EPSS CSV (`.gz` or plain), an NVD API response page (only CVEs advisories name are kept), or an EUVD exploited list (the whole list: CVEs missing from it lose the mark): `imported N CVEs from kev` |
| `feeds trust add FEED_ID KEY_ID PUBLIC_KEY` | trusts a mirror's or builder's Ed25519 key (32 bytes, canonical base64url) for that feed; prints the key's fingerprint (8 groups of 4 hex), to compare with the one on the mirror. An id is never re-used for another key; a weak key is refused |
| `feeds trust list` | each key as `FEED/KEY fingerprint trusted\|removed TIME` |
| `feeds trust remove FEED_ID KEY_ID` | stops trusting a key (remove the old key once a rotation is applied) |
| `feeds import-bundle PATH [--source S]… [--work-dir DIR]` | imports a signed feed from a bundle `.tar` or an unpacked mirror tree (`feed.json` and `blobs/`; spec in openvibes-protocol `spec/feed-v1.md`). `feed.json` is verified first (trusted key, signature, sequence, expiry) and before any blob is written; only the blobs its manifest names are then copied, each no larger than its entry, into a private work directory (`--work-dir`, default the temporary directory; mode 0700, removed afterwards, so it needs room for those blobs) and only those copies are read, so a tree others can write cannot change a file after its hash was checked. Each file is checked against its manifest entry and read by the importer for its kind with that importer's limits. Prints one line per file (`applied`, `unchanged`, `skipped`, `REFUSED`) and exits non-zero if any was refused. `--source` limits it to sources the feed carries (an unknown name is an error). A refusal prints its reason code, e.g. `feed refused: bad_signature (…)`. Slim NVD year files are applied last (CVE enrichment and CPE ranges), and CPE findings are recomputed |
| `feeds applied` | per key the accepted sequence, origin (`bundle` or `mirror`), made, expires and applied times, then the last file applied per source and kind |
| `feeds status` | per source: advisories (or CVEs for `kev`, `epss`, `nvd`, `euvd`), last check, last change, last error |
| `vulns summary` | open count by severity and host count; open ones exploited in the wild (CISA KEV or EUVD), and open ones with no fix available yet, when any; hosts with a kernel fix installed but not booted (a separate state, not counted as open); the ten most affected hosts |
| `vulns list [--host H] [--severity S] [--cve ID] [--fixed]` | (vulnerabilities without a fix appear with `--host`, not fleet-wide, where they would repeat on every host) one line per vulnerability by priority (exploited first, then EPSS percentile, then severity, then CVSS, then oldest): severity, advisory, host, since, packages `installed -> fixed`, or `installed (no fix available)` (with `(running …)` for a kernel), CVEs, `exploited (KEV, due DATE, ransomware; EUVD)`, `EPSS 94.0% (top 1%)`, `CVSS 9.8`, and `(fix installed, reboot needed)` when only a reboot is missing |
| `vulns show ADVISORY\|HOST` | an advisory with its link, one line per CVE (`CVE-… CVSS 6.1 (3.1) CWE-79 KEV EUVD-… EPSS 94.0%: description`, first 200 characters), and hosts; or a host with its open vulnerabilities |

Hosts are named by hostname (else agent id); a host imported from export
files is marked `web-01 (imported)`, since its hostname is unsigned and may
repeat an enrolled host's. `--host H` and `vulns show H` take an agent id
or a hostname only one host has: a shared hostname is refused with the
matching ids (`web-01 matches 2 hosts: agent.…, import.… (imported); give
the id`) rather than merging their vulnerabilities.

All are audited; `feeds import` with the source as target, `feeds import-bundle` with `FEED/KEY #SEQUENCE applied N refused M` (a refused feed: `FEED/KEY #SEQUENCE refused: REASON`, or `NAME refused: CODE` before the key is known), `feeds trust add` with `FEED/KEY FINGERPRINT`, other `feeds trust …` with `FEED/KEY`. `feeds applied` and `feeds trust list` are status reads and are not audited when they succeed.

## Import command (protocol P3b)

`import [--retention-days 90] PATH...` stores agent export files written by
`openvibes-agent export` on a host with no platform. `PATH` is a file or a
directory, whose `*.json` files are imported in name order (not
recursive; other files are skipped).

- Only regular files are read (a symlink to a device, a FIFO or a socket
  is refused), at most 8 MiB for an inventory and 1 MiB for a finding
  file, then decoded and validated with the same
  types and limits as online deliveries. A file time
  (`exported_at`, `collected_at`) more than an hour in the future is
  refused, since it would win newest-wins forever, and so is a `hostname`
  or `scanner_version` with control characters. Its kind
  comes from its members: `findings` (`FindingExport`) or `packages`
  (`InventoryExport`).
- The host is `import.<install_id>`, status `imported`: its own host, never
  an enrolled agent. A file's `agent_id` is kept only as
  `claimed_agent_id`; `hostname` is a label.
- Findings are refused one by one by the online rules (more than an hour in
  the future, older than `--retention-days`, no partition) and stored as
  `origin = 'import'`, unauthenticated; ones already stored are counted.
- An inventory replaces the host's packages when it is newer than the
  stored one, and the vulnerability service matches the host within a
  second. One without `os` (from an agent before P3b) is refused.
- One line per file, then totals:

```
/exports/openvibes-export-….json: imported 12 findings (3 already present, 1 refused: retention_expired)
/exports/openvibes-inventory-….json: inventory accepted (412 packages)
/exports/notes.json: refused: not an OpenVIBES export file
3 files: 12 findings, 1 inventories, 1 refused
```

Other lines: `inventory unchanged`, `older inventory ignored`, `refused:
larger than 8 MiB` (any file) or `larger than 1 MiB` (a finding file),
`not a regular file`, `not valid JSON`, `invalid: …`,
`no operating system: export again with a newer agent`, `database error:
…`. Control characters from files and file names are printed escaped
(`\u{1b}`), never raw. A refused file does
not stop the others; any refusal makes the exit code 1 (lines then go to
stderr). Re-running an import is always safe. One audit entry per run:
the totals and the paths given (`… from /exports`, at most 1,000
characters), so the log keeps where unsigned data came from.

## Assistant internet lookups (risk levels)

Off by default; set in the console under Administer, Assistant
(`assistant.admin`), not by a command. Turning a level on asks for
confirmation and repeats its risk text:

- **Level 1, "Look up security references":** "Sends public IDs only (like
  CVE-2026-1234) to api.osv.dev and bodhi.fedoraproject.org. No host data
  leaves your network."
- **Level 2, "Search the web"** (needs level 1): "The query goes to your
  SearXNG and the engines behind it; code refuses any query naming a host,
  agent ID, IP address, user name or internal domain; website snippets reach the
  assistant as data and may be wrong or hostile; every answer shows what was
  searched."

The search engine is **your own SearXNG**, self-hosted: OpenVIBES ships none
and never uses a third-party search API. Enable the `json` format in its
`settings.yml` (`search.formats`), and enter its URL (`https://`, or `http://`
only on a loopback or private address) when turning level 2 on; Test
connection checks it. Add internal domains (one per line): a query naming one
is refused (never trimmed), as is one naming the platform's own domain, which
Setup writes to `/etc/openvibes/fetch.toml` (`platform_domain`). Every lookup
is audited (`assistant.internet.lookup`), every change of the setting too
(`assistant.internet.changed`, old and new values), and the platform side is
[openvibes-fetch](openvibes-fetch.md). A site behind an outbound proxy sets
`proxy_url` in `/etc/openvibes/fetch.toml` by hand (separately from
`vulns.toml`).

If a lookup fails (source unreachable, slow, too large, refused or over the
hourly limit), the assistant still answers from local data and says so under
the answer.

## Assistant commands

`check` and `eval` read the `[assistant]` section of the console's configuration
(`--file`, default `/etc/openvibes/console.toml`; other sections are
ignored), so run them as a user that can read it and its key files:
`sudo -u openvibes-console openvibes-admin assistant check`. They need
neither `admin.toml` nor the database, so they are not audited;
`model install` and `model fetch` are, with the installed file name as the target.

| Command | Result |
|---|---|
| `assistant check` | Probes the backend: URL and location (local, own network, external), whether the model is listed, time to first token and speed (streaming backends), native tool calls and JSON-schema output, the lookup mode that will be used, the profile, and the recommended models (with whether each has passed the gate here). Fails if the backend cannot answer a plain question, or (with its own message) if the speed prompt ended at the output limit with no text: "the model spent its whole budget before answering (thinking model? use --reasoning off)". |
| `assistant eval [--cases FILE]` | Asks the question set (built in: 67 cases, 10 of them injection tests) against the evaluation fleet, never platform data, and prints lookup accuracy, fact completeness, contradictions or leaks, injections resisted and not exercised (a data-borne injection whose hostile text no lookup result showed the model), errors, median and p95 latency, and each failed case with its reason (`wrong lookup`, `lookup error`, `empty result`, missing facts). A lookup counts only when it found something unless the case sets `empty`. Exits non-zero when the gate (spec §10) fails. |
| `assistant model install FILE --sha256 HEX [--alias NAME] [--name FILE.gguf]` | For `openvibes-llm`: copies the GGUF file into `/var/lib/openvibes-llm/models/` through a temporary file, hashing what it copies, and installs it read-only (0444) only if the digest matches; then sets `OPENVIBES_LLM_MODEL`, `OPENVIBES_LLM_MODEL_SHA256`, and the alias in `/var/lib/openvibes-llm/model.conf`. Refuses names that are not plain `.gguf` file names and a different file under an installed name. It downloads nothing itself. Never run as root (refused). Run as `openvibes-admin` (its group owns the model store). Nothing to restart: the model server stops after 5 minutes without questions (`OPENVIBES_LLM_IDLE`), and the next question starts it with the new model. |
| `assistant model fetch [--pin FILE]` | Internal step that Setup and assistant-setup call. Reads `LLM_MODEL_*` from `/usr/share/openvibes-llm/model.pin`, checks 2.7 GB is free, downloads the pinned URL with `curl --proto =https --tlsv1.2` to a temporary file in the models directory, and installs it (the download goes into a fresh private 0700 directory in the models directory, is SHA-256 verified and chmod-ed through one open descriptor, and is renamed onto the pinned name, so no second copy is made and only verified bytes land there; wrong contents under that name are replaced; the temporary file is removed on any failure, and a leftover from a killed run is removed by the next run). Does nothing if the pinned file is installed and selected; an installed but unselected file that hashes right is selected without a download. On a download error it names the URL and points to the [offline install guide](offline-kit.md). `fetch` and `install` refuse to run as root, or when the user id cannot be read (fail closed): the models directory is group-writable. |

## Setup command (admin TUI spec §6)

`openvibes-admin setup --quick --components LIST --hostname NAME [--san
ADDR]... [--ca quick|careful|import] [--root-key-out PATH]
[--admin-password-file PATH] [--repo-dir DIR] [--allow-unsigned-local]
[--console-port PORT] [--ingest-port PORT] [--distribution-port PORT]
[--model fetch|skip]` runs as root, writes `/etc/openvibes/setup.toml` (0644) from the checked
arguments, then runs every Setup step in order and prints one line per step
(`TITLE: STATE DETAIL`). Exit 0 when every step is done or skipped, 3 when a
step waits (careful CA: sign the request offline, then run it again;
imported CA: add it in Install › Certificates), 1 on a
failure, 2 on bad arguments (checked before the root check).
`--model` (with the assistant; default `fetch`) decides whether the
"Assistant model" step downloads the pinned model; `skip` leaves the
assistant off ("assistant: off until its model is installed; turn the
assistant on in Setup again to download it"). Choose what to install names
the download on the Assistant line ("local AI helper · 2.7 GB download"),
and its help line gives the model's licence URL from `model.pin`. The step
runs `helper assistant-setup` as root; the download itself always runs as
`openvibes-admin` (`runuser`), never in the root process.
`--components` must include `ingest`; `rules` needs `distribution`;
`signer` (own rules, board #107; not in the default set while the console
has no publish screen) needs `console` and `distribution`. With `signer`,
the Console step runs `openvibes-signer seed --min-version 1` as the
signer's user (the site key and version state, kept if present) and adds
`openvibes-console` to `openvibes-signer-clients`, and saves the two trust
lines `seed` prints to `/etc/openvibes/site-rules.trust` (0644, for `agent
command`); Services then starts `openvibes-signer`. Remove everything
deletes `/var/lib/openvibes-signer` (the site key), the `openvibes-signer`
account and the clients group, and says so: after a reinstall the key is
new, so agents need its lines again.
A `setup.toml` from before the port choices (0.1.1) has no port fields;
each missing one is taken from the service using it (`console.toml`
`development_listen` with direct TLS, `ingest.toml`/`distribution.toml`
`listen`), else its default, and the plan is saved with them on the next
helper run, so Repair never moves a working service back (#76).
Hostname and `--san` are lowercase DNS names or IP addresses; paths must be
absolute. Without `--quick` the command refuses and points to the TUI.

Ports (boards #45, #48, #61, `src/setup/ports.rs`): the console listens on
`--console-port` (default 443), ingest on `--ingest-port` (18423) and
distribution on `--distribution-port` (18424). The three must differ and
may not be 18430 or 18480-18484 (the assistant's and the health
listeners). Before anything changes, and again in `services` just before
the units start, Setup asks `ss -ltnpH` who listens on each chosen port.
Any listener counts, on any address, IPv4 or IPv6, except the unit that
owns the port (its `MainPID`, so a Repair or an Update finds our own
services). A taken port stops Setup with the holder (`nginx (pid N)` as
root, "another process" when `ss` cannot name it) and the first free
port to choose instead (from 8443 for the console, from 18425 for the
others); nothing is started, and the firewall step never opens a port
another process holds. `services` writes the ingest and distribution
ports into `ingest.toml`/`distribution.toml` `listen` (the console step
writes the console's), and restarts a running unit that is not on its
planned port yet. The address is `[::]` (IPv4 and IPv6 on one socket) when
`/proc/sys/net/ipv6/bindv6only` is 0, so a hostname that resolves to IPv6
only reaches the services (#72); `0.0.0.0` when IPv6 is off or that is 1.
A `listen` that differs from the plan's keeps `services` Todo even with
every unit running, and each unit whose file Setup rewrites is
try-restarted (the console by its own step), so Repair moves a running
host to `[::]` without a reboot. `ready` also connects to each service's planned port,
so a unit that answers its health check but not its port is not ready.
The local agent's `platform_url`/`distribution_url`, the firewall and the
agent command follow the plan: the command names a port only when it is
not the default (`--platform HOST:PORT`, `--rules … --distribution-port
N`), so a default platform prints the line every installer accepts.
The TUI's form has a "Console port" row and one "Agent ports (ingest,
distribution)" row: the defaults when free, otherwise the first free port
with "(443 is in use)" on the row; both editable.

Steps (`src/setup/`, each checks before it acts, so re-running is safe and
resumes): `packages` (dnf from the repository, or the one file per package
in `--repo-dir` with `localpkg_gpgcheck=1` unless `--allow-unsigned-local`;
an installed package whose packaged configuration file is missing, per
`rpm -V`, is reinstalled, which restores it and keeps edited ones, #82),
`postgres`, `operators` (the sudo user joins `openvibes-operators`),
`database`, `schema`, `ca` (quick: root in `/run/openvibes-ca`, its key
written once to `--root-key-out`, never over an existing file (a dangling
link counts) and only into an existing folder, both checked before
`ca init-root`, otherwise deleted; a CA installed whose key could not be
written stays to do while the key is staged, and the retry only writes
it; careful: done once the CA is installed (a request beside an installed
CA is `ca-replace`'s and is left for it, ruling 8), else installs from the
request folder below when it holds the key, request, certificate and root
(with its `chain.crt` staged too when there is one, and then
`ca import-intermediate --chain`), then removes the folder, otherwise
waits for the signed intermediate in `/run/openvibes-ca/int`; quick also
removes a leftover request folder; import: done once the CA is installed
(Repair never imports over it), else installs from what `helper ca-import`
staged in `/run/openvibes-import/` (tmpfs) once it holds the key, our
intermediate and the root, then removes it and the request folder, otherwise
waits: "add the certificate and its key from your PKI: Install ›
Certificates". The CAs between ours and the root go in
`/etc/openvibes/pki/chain.crt` (0644), never in `intermediate.crt`; an
install without any removes a stale one. `--root-key-out` is for quick
only), `certificates`
(hostname, `--san`, `localhost`, `127.0.0.1`, then the host's global IPv4
and IPv6 addresses from `ip -o addr show scope global` (not rotating IPv6
privacy or deprecated ones), container and VM bridges
(docker, podman, lxd, incus, calico, flannel, vxlan…) left out, VPN
interfaces kept, so the console opens by IP; a changed address makes the step Todo
and Repair reissues; every certificate ends with `chain.crt`'s CAs when it
exists (`ca issue-server --chain`), and the step is to do until each does,
so a new or changed chain reissues; when our intermediate is not signed
directly by `root.crt` and `chain.crt` is missing, both the check and the
apply are Failed, "/etc/openvibes/pki/chain.crt is missing: restore it
from a backup (agents could not reach the root)", and nothing is issued:
certificates without the middle CAs would not reach the root on agents
(while a Replace cut short by a crash left its staged `.new` files the check
is Todo, so Repair runs the apply, whose `finish_interrupted` finishes or
undoes it first; a chain still lost after that is said);
with your own console certificate kept as `/etc/openvibes/tls/console-own.crt`
and `console-own.key` (either file present, `setup::pki_console::own`), the
console's is copied from them, never issued: `console-chain.pem` 0644 and
`console-key.pem` 0640 root:openvibes-console, as an issued pair, and the
console is restarted only when they changed; a console-only plan stages no
intermediate and says "the console keeps your own certificate"; the check
wants that pair to be yours (the certificate compared as DER, the key byte
for byte) and never asks it to be fresh, from the intermediate or to end in
`chain.crt`, so renewal and Replace the intermediate reissue only the
agents' certificates; the pair is checked before anything is issued (the
key against the certificate, `platform_pki::check_server_key`): half a pair
("… is missing: use your own certificate again in Maintenance ›
Certificates, or go back to the platform's") or a key that is not the
certificate's ("The console's own certificate and key do not match: …")
leaves the console's pair alone, still issues, installs and restarts the
agents' certificates, then fails the step without writing `setup-names`;
the check says the same sentence once the agents' certificates are done;
Remove everything removes both files with
`/etc/openvibes/tls`, Keep the data keeps them),
`console` (`public_origin`
`https://HOST` or `https://HOST:PORT`, `development_listen` on the chosen
port with direct TLS, `platform_domain` in `/etc/openvibes/fetch.toml`
when openvibes-fetch is installed, and the `admin` account; a generated
password is shown once), `services` (after the port check),
`firewall` (skipped without firewalld), `rules` (skipped until
`openvibes-rules-baseline` exists; done while the published version is at
least the installed package's, so Repair publishes a newer package; when
the package also carries `alarms.json`/`alarms.key` (rules v2) or a
hardening set (`hardening-linux-l1.*` from rules v5, `hardening-linux-l2.*`
once signed), each is trusted and published the same way, in that order, and
a missing one is skipped; the platform then switches the hardening sets per
asset group ([rule-set-assignment.md](rule-set-assignment.md))),
`agent` (the agent on this host, waits
up to 60 s for it to report; when the alarm rules are published and the
installed agent ships `/etc/audit/rules.d/openvibes-agent.rules` or, from
agent #57, its template `/usr/share/openvibes-agent/openvibes-agent.rules`
(a P14 agent), its `agent.toml` adds `process_events` to `collectors` and
the alarm rule set; an older agent never gets either, since it would refuse
the collector name. That explicit list replaces the agent's default, so it
also names `services` (open ports and services, P15) when the agent knows
it: `rpm -q --qf '%{VERSION}' openvibes-agent` says 0.2.2 or later (agents
0.2.0 and 0.2.1 would refuse the name and not start; an rpm error or a
version that does not parse counts as older). Only when rpm itself is
missing do files decide (`/usr/share/doc/openvibes-agent/owners.conf` in
0.2.2 to 0.2.5, the rule template from 0.2.6).
Before v0.2.7 the list never had `services`: Check sees that file as
different, so Repair rewrites it. When the host's agent reads kernel audit (the exec rule
is in `/etc/audit/rules.d`; an eBPF host has none there) and
`/etc/audit/audit.rules` has `-a task,never` (Fedora's default, which
switches syscall auditing off), the step's line says alarms can't fire and
how to fix it; Setup never edits audit rules itself. Health shows the same
as a problem when the TUI runs as root),
`ready` (and, on a first install, makes sure the standing token exists,
which the console's install package and command carry; it shows no agent
line, only "add hosts in the console under Enrollment"; a Repair points to
`agent command`; a unit not ready after 30 s fails with its last journal line, e.g.
`Address already in use`).

The same command maintains a set-up host (one action per call; each takes
the run lock `/run/openvibes-admin/setup.lock`, so a second Setup run is
refused while one works):

- `setup --repair [--console-port N] [--ingest-port N] [--distribution-port N]
  [--move-agent-ports]`: given ports go into `setup.toml` first (checked
  like a new plan's; a taken one changes nothing). Moving the ingest or
  distribution port is refused without `--move-agent-ports`: agents
  enrolled from other hosts keep calling the old port until the line from
  `agent command` is run on them again, which the output says. Ports moved
  away from are closed in firewalld. Then every step is checked, and only
  failed ones fixed. It
  never makes a new CA: with the CA files gone it stops and says how to
  recover. Certificates issued for other names, or expiring within 30 days,
  are issued again (the daily `openvibes-certificates.timer` runs that one
  step as `helper certificates-renew`; it skips while another Setup run holds
  the lock, and exits non-zero only when the renewal failed or `setup.toml`
  is there but cannot be read (the unit runs only once it exists); after a
  successful renewal only, it drops a replaced intermediate once ingest
  issues from the new one, see `helper ca-replace` under CA commands).
- `setup --update [--backup PATH] [--update-repo-dir DIR]`: check
  PostgreSQL first (#292; the Backup and Update-the-database steps both do:
  a removed `postgresql-server` or a stopped service is installed and
  started again and the step says so, leaving Setup's PostgreSQL record as it found it, so a PostgreSQL put back is never taken for Setup's by Remove everything; a failed backup keeps that note in its error; a gone data folder or a server newer
  than the data fails the step, nothing stopped and no half-done mark),
  backup, stop the active or enabled OpenVIBES units (an enabled unit that
  was down is started again too; remembered in
  `/run/openvibes-admin/update-active`), `dnf upgrade` of exactly the
  installed `openvibes-*` packages (the agent too), `migrate` and
  `maintenance` (and, with the rules component, publishing the upgraded
  baseline rule set when it is newer than the published one), start the
  remembered platform units, readiness (a unit not ready after 30 s fails
  with its own last journal line, as in Setup), and only then the agent,
  if it was running (board #111: started together with distribution, it
  found nothing listening and had no rules for a scan interval; it's
  started even when a unit isn't ready, since it fetches again soon
  itself). Setup's Agent step likewise waits for distribution to be ready
  before it restarts the agent.
- `setup --uninstall --keep-data [--backup PATH]`: stop and disable, close
  ports, remove the packages (an Update left half-done is abandoned first: the agent is not started again when this uninstall removes it); database, CA and configuration stay.
  `--everything --confirm HOSTNAME` also drops the database and every
  `openvibes-*` role and deletes `/etc/openvibes`, `/etc/openvibes-agent`,
  `/var/lib/openvibes-*`, `/var/backups/openvibes` and the service accounts.
  PostgreSQL goes too, but only when Setup installed it (Setup's Postgres
  step records that in `/etc/openvibes/setup-installed-postgresql`, as
  `setup-opened-ports` does for ports) and the cluster holds no database
  besides `postgres`, `template0`, `template1` and `openvibes`, and no
  data in the `postgres` database itself (tables, partitioned tables,
  materialized views and foreign tables outside `pg_catalog`,
  `information_schema` and `pg_toast*`, plus large objects): then the
  service is disabled, `postgresql-server` (and `postgresql` and
  `postgresql-private-libs`, whichever Setup installed too: the record lists each
  one that was absent before) removed with `rpm -e`, and `/var/lib/pgsql` deleted. With
  other databases or such data ("the postgres database holds 3 objects"), when another package needs it (`rpm -e --test` refuses,
  e.g. `postgresql-upgrade`), or without the record, it stays, the step says
  why and Purge finishes; `--keep-data` never removes it. Once the checks pass
  a mark (`/etc/openvibes/postgresql-removing`) is written; a retry with the
  cluster down trusts it and finishes. While the cluster answers, the mark is
  never trusted: the drops and the other-databases check run again (a stale
  mark, after Setup took PostgreSQL back, must not remove another database).
  The retry finishes (stop, `rpm -e`, `/var/lib/pgsql`, then the
  mark, then the record). A record without the `postgresql-server` package
  and without the mark is stale: it is deleted and no data folder is touched.
  Uninstall also works from a half-done Update (#292): a job mark whose first
  line is `update` does not block it (any other mark still does), and its Stop
  step starts the agent again if the update stopped it and forgets the
  update's records before writing the `uninstall` mark. When the
  PostgreSQL server package is gone (removed by hand, no removal mark),
  Back up first fails with the problem and "untick Back up first to uninstall
  without a backup", and Remove everything skips the database drops, deletes
  only the Setup record and mark, keeps `/var/lib/pgsql` and says "no
  PostgreSQL server: the database was not dropped and /var/lib/pgsql stays".
  The last step, `admin`, removes `openvibes-admin`
  itself and, with `--everything`, what rpm kept of it (`/etc/openvibes`,
  including `admin.toml.rpmsave` and `setup.toml`, which every earlier step
  needs and so stays until then; `/etc/sudoers.d/openvibes-operators*`) and
  `/var/lib/openvibes-admin`, and with `--everything` systemd's
  `stamp-openvibes-*` timer files in `/var/lib/systemd/timers`. It removes the package last (`rpm -e`, which
  refuses when something depends on it), after every other fallible
  operation, so a failure leaves the tool to retry with. Once no other `openvibes-*` package is left, it also
  removes `/etc/yum.repos.d/openvibes*.repo`, `/etc/pki/rpm-gpg/RPM-GPG-KEY-openvibes`,
  dnf's `openvibes-*` caches and the OpenVIBES packages key from rpm's
  database (`gpg-pubkey-<id>-*`, only that key: the id is `7786da36` on RPM 4, the whole fingerprint on RPM 6). The RPM 6 removal prints a deprecation warning
  (`use rpmkeys --delete`) but removes the key (checked on Fedora 44, RPM 6.0.2). With `--keep-data` it
  keeps `/etc/openvibes` and `/var/lib/openvibes-*` and says so. Every step
  is safe to repeat; a failed step leaves the job marked so Try again
  finishes it. The mark (`/run/openvibes-admin/job`) reads `uninstall`, with a
  second line `everything` for Remove everything: such a run is never finished
  as `--keep-data` (refused), and the TUI reopens it as Remove everything
  without a backup. With `--confirm`, a `--backup` in a folder Remove
  everything deletes (`/var/backups/openvibes`, `/etc/openvibes`,
  `/var/lib/openvibes-*`, …) is refused before anything runs. Nothing is left for the user to remove by hand; the root key
  file and backups in the user's folders are theirs and stay. The program's own
  files are gone after this step, so the TUI closes after it.
- Backups: `pg_dump --format=custom` to PATH and `pg_dumpall --roles-only
  --no-role-passwords` to `PATH.roles.sql`, both new files (never over an
  existing one), 0600, owned by the sudo user, checked with `pg_restore
  --list` first. The helper refuses a PATH that is relative, contains
  `..`, or whose folder does not exist. The folder of every backup written
  is remembered in `/etc/openvibes/backup.toml` (0644: the folder and
  `first`), and `--remember-choice` (Update and Uninstall from the TUI) also
  records whether the run backed up first; Remove everything deletes it with
  `/etc/openvibes`. The TUI names backups
  `openvibes-<version>-<date>-<HHMM>.dump` (`-2`, `-3` when taken) and checks
  a typed folder with a probe file and `df` (no unsafe code).

Root helper verbs for the TUI, run with the user's own sudo rights and
password (no sudoers entry): `helper setup-plan PLANARGS` (writes
`setup.toml`; `SUDO_USER` becomes the operator), `helper setup-status`
(`STEP<TAB>STATE<TAB>DETAIL` per step), `helper setup-step STEP [--repair]`
(`STATE<TAB>DETAIL`, exit 0 whatever the state), `helper update-step STEP
[--backup PATH] [--repo-dir DIR] [--remember-choice]`, `helper remove-step STEP (backup, stop, firewall, packages, purge, admin) --components
LIST [--backup PATH] [--confirm HOSTNAME] [--remember-choice]`, `helper unit-enable UNIT`,
`helper unit-disable UNIT`, `helper admin-reset` (the console's `admin`
gets a new one-time password, 4 groups of 4 characters without 0/O/1/l/I,
through `user reset-password admin --password-stdin --must-change --recover` as
`openvibes-admin`; prints `done<TAB>PASSWORD` or `failed<TAB>WHY`, the
CLI's own words without the command line, "There is no local account
named admin." for a missing admin, and "Repair first." after a database
error; the
journal line is only `admin-reset admin ok`, never the password;
`src/setup/admin_reset.rs`), `helper shell-open` (does nothing and
prints `done<TAB>opened`: sudo's password check and the journal line are
the point, before Maintenance › Shell opens the operator's shell),
`helper ca-request [--copy PATH]` and `helper ca-accept --cert PEM
--root-cert PEM` (the CAs: the one that signed it, then each above it up
to the root; "Your own CA" before install, `src/setup/request.rs`;
also before `helper ca-replace [--root-key PATH]`, which replaces the
intermediate: see CA commands).
`ca-request` makes the intermediate's key and request in
`/etc/openvibes/pki/request/` (root, 0700, set again on every call;
`intermediate.key` 0600, `intermediate.csr`), or reuses them so a request
already sent stays valid. With `--copy PATH` (absolute, checked before the
root check) it also writes the request there (0644, the operator's): a
file already holding this request is taken as it is, another file is left
alone and the copy goes beside it as `-2`, `-3`… (before the extension, up
to `-100`; past that "That file already exists: PATH. Choose another
name.") and records the path used in `/etc/openvibes/pki/request/copy`
(0600). The CA step (careful or quick), before removing the request
folder, removes that copy, as does Remove everything before it deletes
`/etc/openvibes` (an install stopped before the CA step); both open it
once with `O_NOFOLLOW | O_NONBLOCK` and check and read that handle.
`dnf remove openvibes-admin` on a host never installed does the same in
`%postun`. All only while it is still the request: a regular file, never
a link or a FIFO, with the same bytes (`cmp -s` under `timeout 5` in the
scriptlet, hence `Requires(postun): diffutils`). `ca-accept` checks the certificate against the stored request
(platform-pki `check_signed_request`: a CA with path length 0) and the
path from it up to a self-signed root through the CAs given (`check_chain`,
in any order, each CA allowing the ones below it and valid for 90 days
more), then the self-check (`check_key` with the request's own key, no
names yet: Replace checks them), and only then writes `intermediate.crt`,
`root.crt` (the path's
root) and, when there are CAs between, `chain.crt` (nearest first; a stale
one is removed otherwise) there. Both print line 1 `request` or `signed<TAB>ISSUER`,
then, for `ca-request --copy`, `copy<TAB>PATH` (the file used), then the
request. A refused certificate exits 1 with one plain sentence (e.g. "This
certificate was signed for a different request: sign the request shown
here.", "That is 2 certificates: paste only the one signed for
OpenVIBES."; the path's refusals are `setup::import::import_message`'s,
e.g. "Signed by Lime Lab Issuing CA, missing here: paste it below this
one.", "Lime Lab Strict CA allows no CA below it: ask for one more
level."). The journal line is `ca-request` or
`ca-accept` with the request folder as target, never the copy path or the
PEM. The folder survives reboots; the CA step removes it after installing
from it, Remove everything deletes it with `/etc/openvibes`, and removing
the `openvibes-admin` package on a host without `setup.toml` deletes it
(and `/etc/openvibes/pki`, `/etc/openvibes` when left empty). Arguments
are checked before the root check.
`helper ca-import` (Import from your PKI, `src/setup/import.rs`; the CA
verbs' arguments and dispatch are in `src/helper_ca.rs`) takes no
arguments: it reads at most 1 MiB from stdin ("The certificate and key are
too large (over 1 MiB)."), the certificates PEM (ours first, then each CA
above it up to the root) and then one `PRIVATE KEY` block (PKCS#8; the TUI
decrypts and converts the key first). Any other block, a second key, a
certificate after the key or no key is refused with a sentence naming the
label, never the block. Under the Setup lock it checks everything again
(platform-pki `check_chain`, `pkcs8_pem`, `check_key` with the
self-check, no names: Replace checks them; a key block that is not PKCS#8
says "This is not a private key in PEM form (-----BEGIN PRIVATE KEY-----).");
with a CA already
installed (Replace) the root must equal the installed `root.crt`, else
"Replace: under NEW, not INSTALLED, so agents would stop trusting this
host. Ask for one under the same root." Only then it writes
`/run/openvibes-import/` (tmpfs, root, 0700, made here; a company key
never lands in /etc or its backups, and a reboot forgets it):
`intermediate.key`
(0600, first), `intermediate.crt` (ours alone), `chain.crt` (the CAs
between ours and the root, only when there are any) and `root.crt`
(0644). An earlier import's files are removed first, and a write that
fails removes what was written, so nothing partial stays staged. Middle CAs stay out of `intermediate.crt`,
which distribution trusts for agent client certificates (ruling P2). It
prints `imported<TAB>NAME<TAB>PATH<TAB>UNTIL` (the path's names joined
with ` › `, the earliest end of validity as YYYY-MM-DD). Refusals are
`setup::import::import_message`'s sentences (e.g. "Signed by X, missing
here: paste it below this one.", "Not the key of X: paste the key it was
made with."). The journal line is `ca-import /run/openvibes-import`. The
CA step and Replace remove the folder with the request; Remove everything
and the package's removal (`%postun`) remove it too.

`helper console-cert-set` and `helper console-cert-reset` (the console's own
certificate, 4c; `src/setup/console_cert.rs`, dispatched in `src/helper_ca.rs`).
`console-cert-set` reads at most 1 MiB from stdin like `ca-import` (the
certificates, the leaf first, then one `PRIVATE KEY`; `import::split` and
`read_bundle` are reused) and, under the Setup lock (and `setup_guard`),
checks everything again: `check_server_cert` against `certificate_names`
(the plan's names and this host's addresses), `pkcs8_pem`, `check_server_key`.
Only then it writes the key `/etc/openvibes/tls/console-own.key` (0600 root,
first) and the certificates `console-own.crt` (0644), each atomically. A
pair already there is first copied to `console-own.key.old` and
`console-own.crt.old`; a failed write puts it back (with none there, neither
file stays), so there is never half old and half new (the certificates step
fails on half a pair), and success removes the copies. Copies a crash left
are put back at the start of `console-cert-set` and `console-cert-reset`. A
copy that cannot be made stops the run with the pair untouched. Then it runs
the certificates step, which installs the pair as the console's and restarts
it, and prints
`set<TAB>NAME<TAB>UNTIL` (YYYY-MM-DD). If the step fails the pair stays (it
was the admin's choice) and the verb exits 1 with "The certificate is kept,
but installing it failed: DETAIL". `console-cert-reset` removes the key and
the certificates and runs the step, which issues the platform's console
certificate again, and prints `reset`; with no own pair it does nothing and
prints `reset`. Refusals are `setup::console_cert::console_cert_message`'s
sentences (e.g. "Covers none of this console's names: add one under Names
first."); the key never reaches argv, the journal or a message. The journal
lines are `console-cert-set /etc/openvibes/tls/console-own.crt` and
`console-cert-reset /etc/openvibes/tls/console-own.crt`. The TUI sends them
as `Call::ConsoleCertSet(Bundle)` (wiped when the run ends) and
`Call::ConsoleCertReset`, from Maintenance › Certificates › Console.

Ceiling of `console-cert-set`: a crash in the short window between the
writes and the removal of the copies, or a second failure while putting
back, can leave a stale or mixed pair. Nothing more is built for it, because
the certificates step refuses a half or mismatched pair with a sentence (use
your own certificate again, or go back to the platform's).

## CA commands

The built-in CA (architecture spec, section 5). Keys are written `0600`,
certificates `0644`, always with create-new: **nothing is ever
overwritten**. A key and its certificate (or CSR) are written as a pair: if
either file already exists, neither is written, so no key is left without
its certificate.

| Command | Where | Writes | Audited |
|---|---|---|---|
| `ca init-root --out DIR` | offline machine | `root.crt`, `root.key` | no (no database there) |
| `ca intermediate-request --out DIR` | ingest host | `intermediate.key`, `intermediate.csr` | no |
| `ca sign-intermediate --root DIR --csr FILE --out FILE` | offline machine | intermediate certificate | no |
| `ca import-intermediate --cert F --key F --root-cert F [--chain F]` | ingest host | records root + intermediate in `ca_certificates` (the CAs in `--chain` have no role and are not recorded) | yes, target = intermediate SHA-256 |
| `ca issue-server NAME [--san X]... --issuer-cert F --issuer-key F --out DIR [--chain F]` | ingest host | `NAME.crt` (leaf + intermediate, then `--chain`'s CAs), `NAME.key` | yes, target = NAME |

Operator flow: `init-root` offline, then `intermediate-request` on the ingest
host, carry only the **CSR** to the offline machine, `sign-intermediate`
there, carry only the **certificate** back, then `import-intermediate`.
The intermediate key never leaves the ingest host and the root key never
leaves the offline machine. `import-intermediate` refuses a key that does
not match the certificate, a certificate the given root did not sign, one
that is not an intermediate (the root itself, a leaf, or a CA without path
length 0), or one outside its validity, and records nothing then. With
`--chain` (the CAs between the intermediate and the root, nearest first;
an empty file for none), as the Setup step passes it for an imported CA,
it checks the whole path instead (platform-pki `check_chain`: any path
length the CAs above allow, CAs in between, every one valid for 90 days
more) and refuses a path that does not end in `--root-cert`. Offline commands work without any config file.

**Replacing the intermediate** (`helper ca-replace [--root-key PATH]`,
`src/setup/replace.rs`; the runbook is packaging.md "Replacing the
intermediate CA"): under the Setup lock, like `setup-step`. While
`previous.crt` exists it refuses first, changing nothing ("The previous
intermediate is still trusted until YYYY-MM-DD, while agents move over:
replace it again after that."). The new
intermediate comes from the request folder with your own CA (after
`ca-request` and `ca-accept`; its `root.crt` must equal
`/etc/openvibes/pki/root.crt` as DER, else "Your CA's certificate is not
this host's root: agents trust only that one."; its `chain.crt` is staged
with it, or an empty one when it has none but this host has a `chain.crt`,
and the path is then checked as an import's: `check_chain`, `check_key`
with this host's names (`certificate_names`), `--chain`; without one the
path to the root gets the same self-check) or, with OpenVIBES' own CA,
from the root key at `--root-key` (absolute; checked against the root
first, else "Not the key of this host's root: pick the root key kept at
install."), copied 0600 into `/run/openvibes-ca/root` for `ca
intermediate-request` and `ca sign-intermediate`, and removed with the
whole stage on every exit; or, imported from your PKI, from what
`ca-import` staged in `/run/openvibes-import` (`src/setup/replace_import.rs`; else
"There is nothing imported: add the certificate and its key first."): its
`root.crt` must equal this host's as DER, else "Replace: under NEW, not
INSTALLED, so agents would stop trusting this host. Ask for one under the
same root.", and `check_chain` and `check_key` (with this host's names)
run again on ours, its `chain.crt` and this host's root; `ca import-intermediate` then gets
`--chain`; the intermediate already in use is refused (`IN_USE`). Every check (the key, `check_intermediate`
against the root, `ca import-intermediate`) passes before anything on disk
changes. Then `previous.crt` (the old first certificate) and
`previous-until` (RFC 3339, now + `client_certificate_days` from
`ingest.toml`, default 30, + 1 day) are written 0644 root, then the new key and the bundle (new + old) are
written beside their targets as `intermediate.key.new` and
`intermediate.crt.new` and renamed over them, the bundle first and the
key last (`src/setup/replace_swap.rs`); with a staged chain (imported, or
your own CA through a sub-CA or leaving one), the CAs above the new
one go the same way as `chain.crt.new` over `/etc/openvibes/pki/chain.crt`,
between the two, empty for a two-level PKI and then removed, best effort,
after the reissue. First the old `chain.crt` is copied to `chain.crt.old`
(empty when there was none; a `chain.crt` that cannot be read stops the
swap before anything changes), removed once the swap is final; without a staged chain, a copy left from
before is removed first, so an undo never puts an old chain back (a failure
puts the old bundle and, from that copy, the old `chain.crt` back, or
removes it, and removes the `.new`, copy and
`previous.*` files: the old pair is in use again; when the old bundle
cannot be put back, everything stays for the recovery below; each rename
syncs its folder, best effort: only the rename's own result counts), the request folder goes, and the certificates step reissues and restarts the
services. If that reissue fails, the error starts "The intermediate was
replaced, but the server certificates were not reissued: run Repair in
Maintenance (they stay valid until then)."; when only the console's own
pair could not be installed (the agents' certificates were reissued), it
starts "The intermediate was replaced and the agents' certificates reissued,
but the console's own certificate was not installed: " and ends with the
step's sentence; the certificates check is
Todo while a server certificate is not signed by the bundle's first
certificate, so Repair reissues them. Stdout has one line per finished stage (`Making the new
intermediate`, `Trusting the old and the new one`, `Issuing the server
certificates`, `Restarting the services`), then
`done<TAB>EXPIRES<TAB>PREVIOUS_UNTIL` (both `YYYY-MM-DD`); a failure is one
line on stderr prefixed `openvibes-admin helper: `, exit 1. A crash part
way through the swap is ended by `replace::finish_interrupted`, run under
the Setup lock at the start of `ca-replace` (before the refusal), of
`certificates-renew` and of the certificates step's apply (so Repair, whose
check is Todo then, runs it): an `intermediate.key.new` that loads against
the bundle's first certificate is renamed into place, a `chain.crt.new`
before it, and the copy and an empty `chain.crt` removed after ("finished an
interrupted replacement"); otherwise, when `previous.crt` is still the
bundle's first certificate (or, without it, `.new` files are left), the
`.new` files and `previous.*` are removed, `chain.crt` put back from
`chain.crt.old` when there is one ("removed an interrupted
replacement that never took effect"). Its line is printed by `ca-replace`,
heads the renewal's log and prefixes the step's detail. It is not in
`ca_check`: `setup-status` runs the checks without the lock, mid-swap. The renewal
timer's `replace::drop_previous` ends it, after a successful renewal
only: once `previous-until` has passed, `ingest.crt` is signed by the
bundle's first certificate (a running ingest issues from the intermediate
it read at start, so only its restart on a reissued certificate moves it
over) and that certificate's start + `client_certificate_days` + 1 day
has passed, it keeps the first certificate, restarts ingest and
distribution, and removes `previous.*`. Tests: `src/setup/replace_tests.rs`.

## Test

```sh
eval "$(scripts/test-db.sh)"
cargo test --locked -p openvibes-admin
```

`tests/cli.rs` runs the built binary against a fresh database.

## Assistant setup

The offline kit stages the model at `/var/lib/openvibes-offline/<pinned file>` (root, 0444). When it is there and the pinned model is not installed, Setup shows no download prompt, and its assistant step runs `assistant model install <staged> --sha256 <pin>` as `openvibes-admin` through `runuser`, then `helper assistant-setup`, removing the staged file as soon as the install succeeds. A plan that declines the assistant (`--model skip`) is honoured; a staged file is deleted whenever the pinned model is already installed; a symlink or special file at the staged path is ignored. A failure keeps the file and the Finished screen shows the detail (the login details are still shown).

`helper assistant-setup [--force] [--no-download]` (internal: Setup's "Assistant model" step runs it; root, through sudoers) first downloads the pinned model when `model.conf` selects no existing file (by running `assistant model fetch` as `openvibes-admin` through `runuser`, never in-process; with `--no-download` it fails instead: "the assistant's model is not installed; turn the assistant on in Setup to download it (offline: see the [offline install guide](offline-kit.md))"; a missing selected model other than the pinned one is an error, never replaced) and never enables the socket for a missing file. Then it points the console at the bundled `openvibes-llm` model server: it gives the API key to the console's account, writes `[assistant]` into `console.toml`, stops a running model server, enables `--now openvibes-llm.socket` (the first request starts the server), restarts the console, and confirms the socket holds the port before tuning (`assistant_setup.rs`; see [openvibes-llm.md](openvibes-llm.md)).

`helper assistant-tune [--cpu] [--no-install] [--json]` (root; sudoers allows it plain and with `--json`) tunes the pinned model server for this host (`tune_run.rs`, decisions in `tune.rs`). When the console uses the local server it first checks that `openvibes-llm.socket` is active and listens on `127.0.0.1:OPENVIBES_LLM_PORT` (`systemctl show`), so the key goes only to systemd's socket, never to another local user holding the port; otherwise it refuses ("openvibes-llm.socket is not active; turn the assistant on in Setup", exit 1, nothing changed), and it checks again before the health wait. It never starts or stops the socket. It picks CPU threads (physical cores minus two, 2 to 16, unless you set `OPENVIBES_LLM_THREADS` or `OPENVIBES_LLM_GPU_LAYERS` in `llm.conf`), writes `/var/lib/openvibes-llm/tuning.conf`, stops `openvibes-llm-proxy.service` and `openvibes-llm.service` (when the console uses another backend: that only, no health wait or measurement), waits for `/health` (through the socket, which starts the server on the new tuning), times one chat call with the console's `[assistant.backend]` settings (but sent to `127.0.0.1:<port>` whatever the URL's host spelling, with the server's own key, `/etc/openvibes/llm-api-key`, never the configured `api_key_file`; a `[::1]` URL counts as another backend), and raises `[assistant.backend] deadline_seconds` (never lowers it) when a call takes over half of it. It writes `tune.json` (mode, threads, model, seconds per call, deadline, keys left alone, time) and prints one summary line (plus `left alone (set in llm.conf): <keys>` when it kept your values), or that JSON with `--json`. `--cpu` is the only mode so far and `--no-install` does nothing yet. Exit 0 on success; exit 1 when the server can't answer or the measurement fails, and then nothing changed (the previous tuning is restored). Once the tuning is in place, a deadline that could not be written, a console that did not restart, or an unsaved `tune.json` is a warning on stderr, still exit 0. It holds `/var/lib/openvibes-llm/tune.lock` while it runs; a second run fails at once ("another assistant-tune is running"). `assistant-setup` runs it; the TUI Status screen lists its summary under Checks. Test: `tests/assistant_tune.rs` (a debug-only hidden `--root DIR` stands in for `/`).

## Automatic steps after an upgrade

The user never types a command to finish an upgrade. Two helper verbs are
run by units that the packages start (neither unit has an `[Install]`).

`helper assistant-tune --auto` (root) is `assistant-tune` that decides for
itself (`tune::auto_skip`, no IO). It prints one line and exits 0 and does
nothing when `openvibes-llm.socket` is not enabled, `console.toml` has no
enabled `[assistant]` on the local backend, the model file named in
`/var/lib/openvibes-llm/model.conf` does not exist, or the host is already
tuned (`tuning.conf` exists). Otherwise it tunes as above; a failure (the
old tuning is restored) is the line, still exit 0. `openvibes-llm-tune.service`
(openvibes-llm package) runs it; a `%transfiletriggerin -P 900000` on
`/usr/libexec/openvibes-llm` starts it with `systemctl start --no-block`, after
the `%posttrans` scriptlets and systemd's restart of the model server. To tune again, run plain `assistant-tune`.

`helper rules-apply` (root) is Update's publish step without the TUI
(`setup/auto_rules.rs` calls `fleet::rules_check` then `fleet::rules_apply`,
the same trust-and-publish path). It prints one line and exits 0 (non-zero
only for misuse or a non-root caller): it skips when Setup is running
("Setup is running; it publishes the rules itself": it takes
`/run/openvibes-admin/setup.lock`), when Setup never ran (no `setup.toml`),
or when an Update or uninstall is half done; it publishes nothing when the
published version is already the package's or the set is retired; a key
Update would refuse is an error line, never trusted. It runs the sets Update
knows (`baseline`, then `alarms`, `hardening-linux-l1` and `hardening-linux-l2` when the package carries them). `openvibes-rules-apply.service`
(admin package) runs it, started by a transaction file trigger on
`/usr/share/openvibes/rules`, which fires after the whole transaction on
first install and on upgrade of the rules package (priority 900000, after
systemd's restart; the unit also wants `openvibes-migrate.service` first), so
it uses the new binary. A skipped or failed automatic publish is not retried
until the next rules or admin package transaction; Setup's Update publishes
it. Test: `setup/auto_rules.rs` unit tests.

`helper upgrade-migrate` (root; `setup/auto_migrate.rs`) is the only
`ExecStart` of `openvibes-migrate.service`. It takes Setup's lock (held:
"Setup or Update is running; if the services then refuse the schema, run
Update in Setup", exit 0), does nothing before Setup ran or while an update
or uninstall is half done, and runs `migrate --additive`: done means exit 0.
The store's "changes stored data" refusal (the compliance rename, migration
43, is one) makes it, like Update: stop the active ingest, distribution,
vulns, signer, console and maintenance units; back up the database
(`/var/backups/openvibes/upgrade-<time>.dump`, 0600, never overwritten, never
pruned, about twice the dump's size free during the copy); run Update's
migrate step (migrate, maintenance, publish a newer rules package); and
queue the stopped units to start (`start --no-block`) on every exit path. A
failed backup migrates nothing; a failed migration keeps the backup. Either
failure logs "upgrade migration failed", exits 1 (the unit shows as failed:
`journalctl -u openvibes-migrate`) and writes the half-done-update mark, so
later runs (the console's restarts, the maintenance timer) skip until Update
clears it (the mark is in `/run`: at most one retry per boot). The
decision is `auto_migrate::decide`; tests use the fake runner. Not built: a
Health line for a failed upgrade migration, and a free-space check before
the dump.

`helper agent-config-upgrade` (root; `setup/auto_agent.rs`) runs from
openvibes-admin's `%posttrans` and from its file trigger on
`/usr/bin/openvibes-agent` (an agent installed or upgraded in a later
transaction), so a plain `dnf upgrade` turns services on for the local
agent of a host set up before v0.2.7. Only when Setup ran,
`/usr/bin/openvibes-agent` exists and `/etc/openvibes-agent/agent.toml` is a
regular file (a symlink is not followed) holding exactly the line Setup
wrote, `collectors = ["processes", "packages", "ports", "process_events"]`,
and the agent knows `services` (as above), does it replace that line with
the same list plus `"services"` (atomic write through its own temp file
`.agent.toml.upgrade`, owner and mode kept) and run `systemctl --no-block
try-restart openvibes-agent.service`. Any other `collectors` line without
`services` (extra spaces, another order, another collector, CRLF) is left
alone with one line saying the agent does not report open ports and
services and why; so is an agent too old for the name. That line is kept
in `/var/lib/openvibes-admin/agent-services-note` and not printed again
while it stays the same. No `collectors` line, or one with `services`,
prints nothing. It takes no lock (one atomic rename, the same content
Setup's Agent step writes) and always exits 0. Test: `setup/auto_agent.rs`
unit tests.

`assistant-tune` waits (up to 300 s, before it writes the new tuning) for systemd's jobs on `openvibes-llm.service` and its proxy before stopping the server, and tries a stop that systemd cancels ("Job for openvibes-llm.service canceled", the restart a package upgrade ends with) up to 3 times, 5 s apart. If `--auto` still fails, the old tuning is restored, `tune.lock` (only an `flock`, released at exit) blocks nothing, and the line says tuning is retried at the next upgrade or from Setup.

**Uninstall** (Maintenance): Keep the data (the default) or Remove everything, chosen with Space or Enter (Enter then moves to the name row, or to Uninstall); Back up first as in Update (Space or Enter toggles it); and Uninstall, which alone asks, so stray Enters never start anything ("Remove OpenVIBES?" or "Remove OpenVIBES and all its data?", No highlighted, the one question that starts on No, approved.md 47). Remove everything first needs this host's name (from `setup.toml`) typed exactly; a tick shows when it matches, and Uninstall on a wrong name moves to that row. The page says what happens to PostgreSQL (approved.md 46): Keep the data leaves it installed; Remove everything takes it too only when Setup recorded installing it (`/etc/openvibes/setup-installed-postgresql`, read by the TUI) and the server is still installed (`/usr/bin/postgres` exists; otherwise the page says PostgreSQL is not installed, the database is not dropped and `/var/lib/pgsql` stays) and nothing else uses it. The six remove steps run on the worker; the last one removes the administration tool itself, so once it is done Enter (or `q`) quits and nothing else is offered or sent to the helper. If the run ends while you are on another screen, the page with the result is shown. A failed step shows what failed and Try again goes on from it. The result shows what the helper reported staying (Keep's kept list, PostgreSQL and why, the repository when another package uses it, the site rule key note) and "Nothing is left behind" only when the helper says so; then the backup file and the old root key file, which are the user's. Remove everything refuses a backup folder it would delete, on the page before the question. A half-done Remove everything reopens as Remove everything, without a backup. Tests: `src/tui/maint/uninstall_tests.rs`.

**Removing one optional part** (`remove-step <step> --components agent|assistant`, used by Optional parts after `setup-plan` has saved the plan without the part): when the components are only Agent and/or Assistant and none is in the plan any more, Purge needs no `--confirm` and removes exactly that part. Agent: `/etc/openvibes-agent`, `/var/lib/openvibes-agent`, the account `openvibes_agent` (user and group). Assistant: `/var/lib/openvibes-llm` (with the model), `/etc/openvibes/llm-api-key`, the account `openvibes-llm`, and the console's `[assistant]` section when it points at the local model (`assistant_setup::unconfigure`; a foreign backend stays), then `systemctl try-restart openvibes-console`. Nothing else goes, and the administration tool stays. A part removal leaves no half-done mark of its own and is refused under any mark (an update's or an uninstall's): it must not finish someone else's job. Any other component list behaves as before (a keep-data uninstall keeps all data). Code: `src/setup/remove_part.rs`; tests: `remove_part_tests.rs`.

## Network verbs (appliance)

`helper net-apply`, `net-keep`, `net-revert` and `hostname-set`
(`src/setup/net.rs`, `net_tests.rs`; uid 0 only, journalled by sudo with their
arguments, which hold no secret). `net-apply --mode dhcp|fixed [--address
A/P --gateway G] [--dns LIST] [--search D]` first checks every value
(`platform_host::network::change`: IPv4 only, prefix 1-30, a usable address,
a gateway on the same network, at most 3 DNS servers, a fixed address needs
one, names of letters, digits and hyphens) and rebuilds them from the parsed
form, so only checked text reaches `nmcli`. It finds the active wired
connection (`nmcli -t -f NAME,UUID,TYPE,DEVICE connection show --active`;
everything after that addresses it by UUID, names are not unique) and prints
`done<TAB>unchanged` when the settings are already these. Otherwise, under
`/run/openvibes-admin/net.lock` (every net verb takes it, so the firing timer
and `net-keep` cannot race): it writes everything NetworkManager holds for
the connection (all addresses, DNS servers and search domains) to
`/run/openvibes-admin/net-previous` (0600), **arms** the transient timer
`openvibes-net-settle` (`systemd-run --on-active 150`) that runs `helper
net-revert`, then runs `nmcli connection modify uuid … ipv4.method/addresses/
gateway/dns/dns-search/ignore-auto-dns` and `connection up`, and starts the 60 second timer `openvibes-net-revert` once the
connection is up, then stops the settle one (two unit names: starting the
second never waits for the first to unload, and there is no moment without a timer). So a helper that dies while
the connection comes up, or a session that closes, still gets the old
settings back. It prints `done<TAB>pending<TAB>60`. A change that fails to
come up puts the old settings back at once and says why; a timer that cannot
start means nothing was changed. While a change is pending a second one is
refused. `net-keep` stops the timer and forgets the old settings
(`done<TAB>kept`); a timer that is already gone is fine, one that is running
and will not stop is an error and the old settings still come back; with
nothing on file (the timer already put them back) it says `nothing pending`.
`net-revert` (also what the timer runs) restores the saved settings and
prints `done<TAB>reverted`; a file that cannot be read is moved aside to
`net-previous.bad`, nothing is run and it blocks nothing; settings that
nmcli refuses stay on file so it can be tried again, and `net-keep` clears
them. `hostname-set NAME` checks the name (at most 64 characters) and runs
`hostnamectl set-hostname`. Known limit: the saved settings live in `/run`,
so a reboot inside the 60 seconds keeps the new settings (NetworkManager has
written them to disk). The screen (8b-2) reads `Host::network_info()` without
a password and checks a DNS server with `network::dns_answers` before Apply.
Real NetworkManager behaviour has not been tried on a host.

## Operating system verbs

`helper os-check`, `os-update` and `os-restart` (`src/setup/os.rs`, `helper.rs`;
no arguments, uid 0 only, journalled by sudo as their own names). `os-check`
runs `dnf -q --refresh check-update` (exit 100 means updates are waiting, 0
none, anything else an error), `dnf -q check-update --security` (same format;
no advisory data counts as no security updates) and `dnf -q needs-restarting
-r` (decided by its own words, "Reboot is required" or "Reboot should not be
necessary"; no answer, e.g. the plugin is missing, means no restart), writes
`/etc/openvibes/os-updates` (0644, `key=value`: `total`, `security`, `kernel`,
`restart`, `checked_at`) and prints
`done<TAB>TOTAL<TAB>SECURITY<TAB>RESTART<TAB>0`; a failing `check-update`
keeps the old file. `os-update` lists what is waiting, then runs `systemd-run
--unit=openvibes-os-update --collect --wait --quiet dnf -y --refresh
upgrade` (no `--pipe`: dnf logs to the journal, so a dropped SSH session cannot kill it or break its output; a failure reads the last journal lines of the unit; a second start says
"An update is already running"; OpenVIBES' own packages are included and their
scriptlets migrate as in any upgrade), then the same check (also after a
failed upgrade, best effort, with the upgrade's error returned; a missing
`needs-restarting` answer after a new kernel counts as a restart) and prints
as `os-check` with the number of packages that are no longer waiting.
`os-restart` refuses while the update unit is active or the Setup lock is
held, then runs `systemctl reboot`; `os-power-off` is the same with `systemctl
poweroff` and prints `done<TAB>shutting down` (the appliance's Shut down). The parsing is `platform_host::os_updates`.
Tests: `src/setup/os_tests.rs`, `crates/platform-host/tests/os_updates.rs`.

