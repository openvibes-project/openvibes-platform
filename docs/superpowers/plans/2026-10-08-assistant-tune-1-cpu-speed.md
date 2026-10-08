# Assistant tune 1: threads, speed check, deadline — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `openvibes-admin assistant tune` sets the model server's threads from the host's cores, measures a realistic call, raises the console's deadline when the host is slow, and reports one summary line (CLI, file, TUI Health); `assistant-setup` runs it.

**Architecture:** A pure decision module (`tune.rs`: core count, merge rules, decision table, summary text) with injected inputs, and a thin root-side runner (`tune_run.rs`) that reads `/sys`, writes `/var/lib/openvibes-llm/tuning.conf` and `tune.json`, restarts the unit through `SystemRunner`, and times one chat call through `platform_assistant::BackendClient`. The unit reads `tuning.conf` between `llm.conf` and `model.conf`. GPU detection is plan 2; this plan always writes CPU mode.

**Tech Stack:** Rust (clap, serde, toml_edit), systemd, `platform-assistant` client.

**Spec:** `docs/superpowers/specs/2026-10-07-assistant-tune-design.md` §3 (steps 4–5, CPU part), §6 (deadline route only; small model is plan 3), §7, §8.

## Global Constraints

- Root only, through the helper: `sudo openvibes-admin helper assistant-tune [--cpu] [--no-install] [--json]`; sudoers lines added like `assistant-setup`'s. `--no-install` is accepted now (no installs exist in this plan) so scripts can pass it from day one.
- Threads = physical cores − 2, clamped to 2..=16. Physical cores = distinct `core_cpus_list` values under `/sys/devices/system/cpu/cpu*/topology/`; fallback: logical CPUs / 2 (min 1).
- **Ruling (spec gap):** the packaged `llm.conf` sets every key (`THREADS=4`, `GPU_LAYERS=0`), so "keys absent from llm.conf" would never apply. A key counts as operator-set when its value in `llm.conf` differs from the packaged default (`THREADS=4`, `GPU_LAYERS=0`); tune writes only keys that are not operator-set and prints which it left alone.
- **Ruling:** the speed check times one real call (system prompt + ~750 tokens of fixed text, `max_tokens` 200) by wall clock instead of estimating from token rates: `t` = measured seconds.
- Deadline route: if `t > 0.5 × deadline_seconds` (console.toml `[assistant.backend] deadline_seconds`, default 60 local), set `deadline_seconds = min(180, ceil(2 × t))`, restart the console (`try-restart`), warn "this host answers slowly (about N s per question)". Never lower a deadline the operator set higher.
- tune never edits `llm.conf`; edits `console.toml` only for `deadline_seconds` (toml_edit, layout and comments kept, through `config_file::replace` like `assistant_setup.rs`).
- Exit codes (spec §8): 0 unless the server cannot answer at all after the final restart (exit 1) or the measurement fails (exit 1, nothing changed).
- Summary line format: `assistant: CPU (<n> threads) · model <alias> · ~<t> s per call[ · deadline raised to <d> s]`; `tune.json` = `{"mode":"cpu","threads":n,"model":alias,"seconds_per_call":t,"deadline_seconds":d,"left_alone":[...],"at":RFC3339}` (0644).
- Gate: `testing.md` §2 and §3 (unit file and sudoers change → Fedora job).

## Review Focus

1. An operator who set `OPENVIBES_LLM_THREADS=6` in `llm.conf` keeps 6 after tune (Task 1 test).
2. A host with 2 physical cores gets 2 threads, not 0 (Task 1 test).
3. The model server not answering after restart: tune exits 1 and changes no deadline (Task 3 test).
4. An operator deadline of 300 s is never lowered to 2t (Task 1 test).
5. Running tune twice gives the same files (idempotent) (Task 3 test).

---

### Task 1: Decision module `tune.rs` (pure)

**Files:** Create `crates/openvibes-admin/src/tune.rs` (+ `mod tune;` in `main.rs`); tests in the same file (`#[cfg(test)]`).

**Interfaces — Produces:**
```rust
pub const DEFAULT_THREADS: u32 = 4;
pub const DEFAULT_GPU_LAYERS: u32 = 0;
pub fn physical_cores(core_lists: &[String], logical: usize) -> u32;
pub fn threads_for(physical: u32) -> u32;                        // clamp(p - 2, 2, 16)
pub struct Plan { pub threads: Option<u32>, pub gpu_layers: Option<u32>, pub left_alone: Vec<&'static str> }
pub fn plan(llm_conf: &BTreeMap<String, String>, threads: u32) -> Plan; // None = operator-set, leave alone
pub fn tuning_conf(plan: &Plan) -> String;                        // KEY=value lines + header comment
pub enum Deadline { Keep, Raise(u32) }
pub fn deadline(seconds_per_call: f64, current: u32) -> Deadline;
pub fn summary(threads: u32, alias: &str, t: f64, raised: Option<u32>) -> String;
```

- [ ] **Step 1: Failing tests**
```rust
#[test] fn cores_from_sibling_lists() {
    let lists = ["0,12","1,13","0,12","1,13"].map(String::from);
    assert_eq!(physical_cores(&lists, 4), 2);
    assert_eq!(physical_cores(&[], 8), 4);
    assert_eq!(physical_cores(&[], 1), 1);
}
#[test] fn threads_keep_two_cores_free_within_bounds() {
    assert_eq!(threads_for(12), 10); assert_eq!(threads_for(2), 2); assert_eq!(threads_for(1), 2);
    assert_eq!(threads_for(64), 16);
}
#[test] fn operator_values_are_left_alone() {
    let mut conf = BTreeMap::new();
    conf.insert("OPENVIBES_LLM_THREADS".into(), "6".into());
    conf.insert("OPENVIBES_LLM_GPU_LAYERS".into(), "0".into());
    let p = plan(&conf, 10);
    assert_eq!(p.threads, None); assert_eq!(p.gpu_layers, Some(0));
    assert_eq!(p.left_alone, ["OPENVIBES_LLM_THREADS"]);
    conf.insert("OPENVIBES_LLM_THREADS".into(), "4".into());
    assert_eq!(plan(&conf, 10).threads, Some(10));
}
#[test] fn deadline_rises_only_when_slow_and_never_drops() {
    assert!(matches!(deadline(20.0, 60), Deadline::Keep));
    assert!(matches!(deadline(40.0, 60), Deadline::Raise(80)));
    assert!(matches!(deadline(120.0, 60), Deadline::Raise(180)));
    assert!(matches!(deadline(100.0, 300), Deadline::Keep));
}
#[test] fn summary_line() {
    assert_eq!(summary(10, "qwen3-4b", 8.4, None), "assistant: CPU (10 threads) · model qwen3-4b · ~8 s per call");
    assert_eq!(summary(2, "qwen3-4b", 40.2, Some(81)), "assistant: CPU (2 threads) · model qwen3-4b · ~40 s per call · deadline raised to 81 s");
}
```
- [ ] **Step 2:** `cargo test -p openvibes-admin tune::` — FAIL.
- [ ] **Step 3:** Implement (deadline: `Raise(min(180, ceil(2t)))` only if `t > 0.5 × current` and that value > `current`; seconds in the summary rounded to whole seconds, `~<1 s` when below 1).
- [ ] **Step 4:** PASS. **Step 5:** commit `"Admin: assistant tune decisions"`.

### Task 2: Unit reads `tuning.conf`; check script accepts it

**Files:** `packaging/rpm/openvibes-llm.service` (add `EnvironmentFile=-/var/lib/openvibes-llm/tuning.conf` between the two existing lines, comment above it), `crates/openvibes-llm/src/lib.rs` (if `check_environment` rejects unknown names, allow nothing new — this plan writes only THREADS and GPU_LAYERS), `docs/components/openvibes-llm.md` (files table row for `tuning.conf` and `tune.json`; precedence llm.conf < tuning.conf < model.conf; the "operator-set = differs from default" rule).

- [ ] **Step 1:** Edit the unit; `systemd-analyze verify packaging/rpm/openvibes-llm.service` (or in the Fedora container) — no errors.
- [ ] **Step 2:** Spec file: `%dir`/`%ghost` entries so the RPM owns `/var/lib/openvibes-llm/tuning.conf` and `tune.json` as ghosts (`%ghost %attr(0644, root, root)`), following how `model.conf` is listed (`grep -n model.conf packaging/rpm/openvibes-platform.spec`).
- [ ] **Step 3:** Commit `"LLM unit: read tuning.conf"`.

### Task 3: `tune_run.rs` and the helper command

**Files:** Create `crates/openvibes-admin/src/tune_run.rs`; modify `helper.rs` (new `AssistantTune { cpu, no_install, json }` command and `Verb`), `assistant_setup.rs` (call tune after enabling the services; print its summary), `packaging/rpm/openvibes-operators.sudoers` (lines for `helper assistant-tune`, `--cpu`, `--json`, `--no-install` combinations used by setup and the TUI — follow the file's exact-argument style), `crates/openvibes-admin/src/tui/` Health (one check line from `tune.json`: OK with the summary, or "run `sudo openvibes-admin helper assistant-tune`" when absent).
Test: `crates/openvibes-admin/tests/assistant_tune.rs`.

**Interfaces — Consumes:** Task 1 functions; `config_file::{read, replace}` and `Service::Console` (as in `assistant_setup.rs`); `platform_assistant::{AssistantConfig, BackendClient}` (as `assistant.rs` loads `[assistant]`); `SystemRunner`/`Program::Systemctl`.
**Produces:** `pub fn run(opts: &TuneOptions, root: &Path) -> Result<String, String>` where `root` prefixes every absolute path (`/` in production; a temp dir in tests through a hidden `--root` flag that exists only in debug builds, `#[cfg(debug_assertions)]`, so a release binary run as root can never be pointed at another tree).

Flow: read `/sys` core lists → `plan` against `/etc/openvibes/llm.conf` → write `tuning.conf` atomically (temp + rename, 0644) → `systemctl restart openvibes-llm` → wait for `/health` ok (poll 1 s, up to 120 s) → time one chat call (fixed prompt in `tune.rs` as a `const`, ~750 tokens of neutral platform text, `max_tokens` 200) with the console's `[assistant]` backend settings and API key (root can read it) → `deadline` → if Raise, edit `console.toml` and `try-restart openvibes-console` → write `tune.json` → return the summary.

- [ ] **Step 1: Failing integration test** using a fake model server (a `TcpListener` thread answering `/health` and `/v1/chat/completions` after a fixed sleep, like `tests/assistant.rs`'s `plain_backend`) and a temp `--root` holding `etc/openvibes/{llm.conf,console.toml}`, `sys/devices/system/cpu/cpu{0..3}/topology/core_cpus_list`, and a fake `systemctl` (the test sets `PATH`-independent behaviour: inject the runner — add `trait Restarter` with a no-op test impl rather than shelling out).
  Cases: (a) fast server → `tuning.conf` has `OPENVIBES_LLM_THREADS=2`, console.toml unchanged, exit 0, summary line printed; (b) server sleeping 40 s with deadline 60 → console.toml `deadline_seconds = 80` (use a 4 s sleep and deadline 6 → 8 to keep the test fast); (c) server never answering → exit 1, console.toml unchanged; (d) running (a) twice → identical files.
- [ ] **Step 2:** FAIL. **Step 3:** implement. **Step 4:** PASS; `cargo clippy -p openvibes-admin --all-targets -- -D warnings`.
- [ ] **Step 5:** Docs: `docs/components/openvibes-admin.md` (assistant commands table row for `helper assistant-tune`), `docs/components/openvibes-llm.md` ("Out of the box" section: setup now tunes). Commit `"Admin: assistant tune"`.

### Task 4: Gate

- [ ] `testing.md` §2 and §3 (Fedora job: RPM builds, unit verifies, sudoers parses with `visudo -cf`). On a real host (this machine), after installing the CI RPMs: `sudo openvibes-admin helper assistant-tune` prints a CPU summary and the dock answers. Open the PR.
