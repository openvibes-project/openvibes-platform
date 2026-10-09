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
