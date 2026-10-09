# SDD ledger — plan: docs/superpowers/plans/2026-10-09-model-download-and-offline-kit.md
Spec: docs/superpowers/specs/2026-10-09-model-download-and-offline-kit-design.md

## Pre-flight scan
| pair / task | produces vs consumes | finding |
|---|---|---|
| T1 ↔ T2 | T1 installs /usr/share/openvibes-llm/model.pin; T2 read_pin default path | consistent |
| T1 ↔ T2 | T2 adds Requires: curl to openvibes-admin in the same spec file T1 edits | sequential, fine |
| T2 ↔ T3 | fetch/Downloader/Curl/read_pin consumed by assistant_setup and Setup | consistent |
| T1 ↔ T4 | kit installs openvibes-llm-model (bridge) and reads model.pin after install | consistent |
| T4 self | e2e negative case 3 wording ("does not exist" path / SHA wrong) is muddled | Ruling below |
| T1 self | Step 2 build downloads the model unless OV_LLM_MODEL=0 | handled in the step |
| T5 | lab tests by controller | consistent |
Ruling: T4 e2e third negative case = a --model file with a wrong SHA-256 fails at the model step (packages already installed) with a clear message — why: the plan text garbled two cases; this is the meaningful one — cost if wrong: none
Ruling: heavy builds (rpm, full cargo test) wait until the user's lab sweep ends (~18:15); T1 runs in two phases (edit + light checks now, build/check after) — why: one heavy job at a time; sweep measures CPU/memory — cost if wrong: ~25 min delay
Task 1: phase A dispatched (no builds until the sweep ends)
Task 1: phase A implemented d418063 (spec/bridge/check-rpm OV_CHECK_BUILT/ci.yml join removed; light checks only)
Task 1: phase A review Approved (opus; upgrade walkthrough holds: GGUF kept via same %ghost path, model.conf identical digest no .rpmnew, parts erased harmlessly, no old scriptlet touches files)
Task 1: minors applied before push (CI assertions re-added, runtime pin in %posttrans, inline define, pipefail-safe check, docs on future pin changes)
Ruling: the lab upgrade test uses the CI build of the pushed branch (draft PR) — why: a local build has the same EVR as 0.2.5 and would not upgrade; CI also keeps heavy builds off the host during the sweep — cost if wrong: none
Task 1: fixes 0eabb59 pushed; draft PR #230 for CI RPMs; phase B (local build) replaced by CI's build + check-rpm built mode; then T1 complete after a scoped re-review
Task 1: CI RPM check false positive (%ghost .gguf listed by rpm -qlp) → fix sent (check sizes/ghost flag)
Task 1: CI RPMs pass (rerun after crates.io outage); lab upgrade test (with #231/#232) confirmed: model + model.conf survive, parts gone, bridge installed
Task 1: complete (commits 29dac4c..d51d333, review clean + lab)
Ruling (user rule 2026-10-09, no commands): Task 3 — users add the assistant through Setup's switch; `assistant model fetch` stays an internal/admin step, never shown to users as an instruction
Task 2: dispatched edit-only (host busy with another session's sweep), sonnet
Task 2: phase A bda32ce (fmt only)
Ruling: file present but not selected → re-run install (re-hash + select) — Setup must end with a working assistant — cost if wrong: one extra hash (~10 s)
Ruling: free_bytes via `stat -f` (unsafe forbidden), unknown = 0 = refuse — cost: refusal on odd filesystems
Task 2: phase B dispatched (waits while lab VMs run)
Task 2: phase B 0ee9a75 (tests 233+7 fetch, clippy, doc green)
Task 2 review: Needs fixes (double copy vs 2.7 GB check; no drop guard; wrong-contents pinned file unrecoverable; proto-redir + tests; package msgs tell users commands)
Ruling: fetch moves the verified temp in place (no 2nd copy) instead of raising the check to 5.3 GB — spec says 2.7 GB — cost: a second install path to maintain
Ruling: fetch replaces a wrong-contents file at the pinned name (verified bytes only) — users can't type rm — cost: overwrites a hand-placed foreign file of that exact name
Ruling: package messages say "turn the assistant on in Setup" — user rule no commands
Task 2: fix round 1 dispatched (resume implementer)
Task 2: fix round 1 f3b82ab (237 tests green)
Task 2 re-review: approve; round 2 (sync_all before rename, real post-download guard test, llm.md typed commands) dispatched
Ruling (Task 3 vs user rule): no message tells users to type a command. --no-download error and Setup's "skipped" final text say "turn the assistant on in Setup to download its model (offline: see the offline install guide)"; spec §6 "adding later" = Setup's switch — cost: admins scripting must read the admin reference
Security review (commit): TOCTOU in fetch temp file (group-writable models dir, root fetch via sudo assistant-setup) → symlink overwrite / unverified swap. Ruling: private 0700 fetch dir + fd-based verify; folded into round 2 (priority). Follow-up: models dir 0775 group-writable vs root installs
Task 2: round 2 7eaa01e + security fix b9a3b2b (private 0700 dir, fd-based verify)
Security re-review (opus) of b9a3b2b: High — dir-rename symlink attack (no sticky bit) + read_config follows symlinked model.conf (root leaks /etc/shadow); Low — FIFO hang, curl -q, PATH lookup
Ruling: fetch + install refuse uid 0 (root already reruns as openvibes-admin by default); Task 3 calls fetch via runuser; read_config O_NOFOLLOW|O_NONBLOCK + fd is_file; curl -q, absolute paths, --max-filesize — cost if wrong: a root-only setup path needs runuser
Task 2: security round 2 dispatched
Task 2: security round 2 94b15c9 (uid0 refused, read_config nofollow, curl -q/abs paths)
Security re-check: SAFE; latent — refuse_root only in model::run; fails open when uid unknown
Task 2: complete (d51d333..94b15c9; reviews + 2 security rounds clean)
Ruling: refuse_root moves into fetch() and install() and fails closed (only Some(non-zero) allowed) — done as step 0 of Task 3 — cost: none for tests (non-root)
Task 3: dispatched (fresh implementer, sonnet), BASE 94b15c9
Task 3: c4d0e29 (252 tests green); concerns: other messages still name commands (tune_run, post-setup check, tuning skipped)
Task 3 review (opus): Needs fixes — download failure stops run before Ready (lose URL/password); curl meter fills failure detail + frozen TUI; root FIFO hang in installed()
Ruling: AssistantModel last (after Ready), Finished shows URL+failure line — spec §7 — cost: Ready doesn't vouch for assistant
Ruling: external backend → step Skipped; declined text keeps semicolon
Open: "open Setup (`openvibes-admin`)" in quick-setup — reopening Setup needs typing its name; product question for user, left as is
Spec §2/§6 still name commands (contradict ruling) — controller updates spec in Task 5
Task 3: fix round 1 dispatched
Task 3: fix round 1 d1b6d64 (255 tests green)
Task 3 re-review: Approved
Task 3: complete (94b15c9..d1b6d64)
Parked (fix in Task 5 round): repair --quick leaves moved ports open when only AssistantModel failed (exclude it from the all-Done check, setup/mod.rs ~404); external() treats any configure error as external (match the "already sends" error); Finished detail keeps checked() prefix "/usr/bin/openvibes-admin helper assistant-setup:" (strip); link the offline install guide; remaining "run sudo" strings in assistant_setup/tune_run
Task 4: dispatched (sonnet) BASE d1b6d64; ruling: installer copies an unreadable --model file to a private /var/tmp dir for the openvibes-admin user (fetch/install refuse root)
Task 4: 002695a DONE_WITH_CONCERNS — e2e green (54 MB kit, 3+2 negative cases); blocker: model install needs DB (before Setup)
Ruling: installer stages model in /var/lib/openvibes-offline (root 0755/0444, SHA-checked); Setup's AssistantModel installs a staged model without prompting — spec §5.5 "Setup sees the model" + keeps audit — cost: Setup code change in Task 4
Ruling: ship full --alldeps closure (no drop by name) — older F44 hosts need newer libs — cost: bigger kit
Task 4: fix round 1 dispatched
Task 4: fix round 1 d5db2d8 (kit 92 MB; Setup installs staged model; e2e green)
Sonar #230: S8233 release.yml:10 workflow-level write permission → job level; fold into Task 4 fix round
Task 4 review (opus): Needs fixes — rerun doesn't upgrade (dnf5 install no-op); Fedora key not supplied with --disablerepo; staged model lingers; minors
Ruling: check() honours explicit Skip even with staged model
Task 4: fix round 2 dispatched (incl. merge main after #232, Sonar S8233)
User ruling (via coordinator): opening Setup with `sudo openvibes-admin` may be named in docs/messages; no other commands. Task 5 docs follow it
Task 4: fix round 2 f3ea40e (merged main; 95 MB; upgrade + third-key e2e green; 260 tests + integration)
Task 4 re-review: Approved (N1 upgrade-failure "nothing changed" wrong; N2 CI higher-release build ungated; N3 Fedora key not in --check; N4 bare upgrade touches unrelated host packages; N5 noted)
Task 4: complete (d1b6d64..f3ea40e)
Ruling: N1-N4 go into Task 5's round (N4: upgrade names the OpenVIBES packages + postgresql-server)
Task 5: dispatched (sonnet) phase A edits: spec update, quick-setup offline section, N1-N4, Task 3 parked fixes; phase B gate after #231 gate
Task 5: phase A eff73c8 + bd294de (unbuilt); review dispatched; phase B waits for #231 gate
Task 5 review: Needs fixes — README.txt.in not §6 verbatim; database.rs:188 + run_as.rs:71 name commands; quick-setup:19 no sudo; fixture newline
Follow-up (out of scope): quick-setup.md:38/137/143 show CLI commands (setup --repair --console-port, agent list, import) — review against the no-commands rule later
Task 5: fix round 1 dispatched (edits only)
Task 5: fix round 1 8455943 (mechanical; verified by phase B gate instead of re-review)
