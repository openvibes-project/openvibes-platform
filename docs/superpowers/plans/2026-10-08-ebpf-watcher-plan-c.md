# eBPF Process Watcher, Plan C (platform and lab) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The platform keeps the agent's `health.alarms.source`/`fallback`, and the console shows per host whether threat alarms are on and from which source, or why they are off and the one command that fixes it; the lab proves it end to end on five distributions.

**Architecture:** The platform pins `openvibes-core` (the agent's wire types) at an old commit whose `AlarmHealth` has no `source`/`fallback`; ingest re-serializes health through that type, so today both fields are dropped before storage. Task 1 bumps the pin. Task 2 derives an `AlarmsStatus` from the stored `AlarmHealth` in `platform-store` (one function, shared by the console API and the admin CLI, text included). Task 3 shows it in the console. Task 4 is a lab command that raises a real alarm on every agent machine and checks the console API.

**Tech Stack:** Rust (platform-store, openvibes-ingest, openvibes-console, openvibes-admin), PostgreSQL JSONB, React/TypeScript (console web, vitest, Playwright demo), bash (openvibes-lab).

**Spec:** `openvibes-agent/docs/specs/2026-10-08-ebpf-process-watcher-design.md` §1 goal 4, §3.3, §5, §7 (lab bullet). Protocol: `openvibes-protocol/spec/contracts-v1.md` ("alarms": `source`, `fallback`), merged in protocol #43 (`4de89af`).

## Global Constraints

- `health.alarms.source`: `ebpf` | `audit` | `none`; a missing `source` means `audit` (agents before the watcher).
- `fallback`: `{detail: no_btf|capability|lockdown|lsm_denied|verifier|other, audit_rule_loaded: bool}`, present when eBPF could not be used. `audit_rule_loaded` turns true with the first keyed audit record (agent `alarms/thread.rs::on_starts`); no agent restart is needed after `audit-fallback`.
- `source: none` means no reader opened at all (the collector outcome says why); the agent must be restarted after the fix.
- Console host page: "Threat alarms: on (eBPF)", "on (audit)", or "off — why — the fix", e.g. "this kernel has no BTF: run `sudo /usr/libexec/openvibes-agent/audit-fallback` on the host".
- The Hosts list badges only hosts whose alarms are off (quiet by default).
- The interface comes first: fast, uncluttered, clear (workspace `decisions.md`).
- Never restart services or reboot on the user's behalf; the console only names the command.
- Lab: one heavy thing at a time; `LAB_HEADROOM_MB=4096`, never raised; lab ssh never uses the user's agent.
- Commits end with `Co-Authored-By: Claude <noreply@anthropic.com>`; PRs only after the workspace `testing.md` gate; every component change updates its `docs/components/` page.

**Decision made here (for the user's review):** a host whose health has no `alarms` object (process events not in its `collectors`, e.g. an upgrade that kept an old `agent.toml`) shows "Threat alarms: off — process events are not enabled — add "process_events" to collectors in /etc/openvibes-agent/agent.toml" on its page, but gets **no** Hosts-list badge: that is the admin's choice, not a fault. Badges go only to hosts where alarms are on in the configuration but nothing feeds them.

## Review Focus

1. **An agent before the watcher (0.2.5)**: `alarms` without `source` → "on (audit)", never "off" (Task 2 test `missing_source_is_audit`).
2. **A fallback host that has seen no program start yet** (`audit_rule_loaded: false` for its first seconds): shows off with the audit-fallback fix — acceptable only because a real host starts programs within seconds; the text says "no program start seen through audit yet" so it reads right in that moment (Task 2 test `fallback_without_rule_is_off_with_the_fallback_command`).
3. **Stored health that no longer parses** (a future agent field the pinned type refuses, or a corrupt row): alarms status absent ("unknown", no badge), never a 500 (Task 2 test `unparsable_alarms_is_unknown`).
4. **Offline or stale hosts**: the status is from the last report; the Hosts list badge shows only for active hosts (an offline host already has its own badge) (Task 3 test in `rows.test.ts`).
5. **A viewer without `agents.read` on that host's group**: the field rides on the existing agent views, which are already scoped; nothing new to leak (Task 3: no new endpoint).

---

## File structure

```
openvibes-platform/
  Cargo.toml, Cargo.lock                      openvibes-core/-transport/-rules rev → agent main
  protocol (submodule)                        → 4de89af
  crates/openvibes-ingest/tests/heartbeat*.rs  stored health keeps alarms.source/fallback
  crates/platform-store/src/alarms_status.rs  new: AlarmsStatus + alarms_status() + text
  crates/platform-store/src/lib.rs            mod alarms_status
  crates/platform-store/src/console_read.rs   Agent.alarms (select a.health -> 'alarms')
  crates/platform-store/src/agents.rs         (CLI agent) alarms line
  crates/openvibes-admin/src/agent.rs         `agent show` prints the alarms line
  crates/openvibes-console/src/api.rs         AgentView.alarms: Option<AgentAlarmsView>
  crates/openvibes-console/web/src/...        generated.ts, AgentPanel, Agents list, demo data
  docs/components/{platform-store,console,admin}.md
openvibes-lab/
  lib/alarms.sh, lab (alarms subcommand), tests/test_alarms.sh, README.md
```

---

### Task 1: Bump the agent crates and the protocol; keep `source` and `fallback`

**Files:** `Cargo.toml` (three `rev =` lines), `Cargo.lock`, `protocol` submodule, `crates/openvibes-ingest/tests/` (the existing heartbeat-with-health test file; find it with `grep -ln '"alarms"' crates/openvibes-ingest/tests`), plus whatever the bump breaks.

**Interfaces:**
- Produces: `openvibes_core::{AlarmHealth, AlarmSource, AlarmFallback, FallbackDetail}` with `source: Option<AlarmSource>`, `fallback: Option<AlarmFallback>` available to every platform crate.

- [ ] **Step 1: Failing test.** In the ingest heartbeat test, send a heartbeat whose `health.alarms` carries `"source":"audit","fallback":{"detail":"no_btf","audit_rule_loaded":false}` (copy the body from `protocol/fixtures/v1/heartbeat/valid-alarms-fallback.json` after Step 2's submodule bump, or inline it now), then:

```rust
let stored: serde_json::Value = client
    .query_one("SELECT health -> 'alarms' FROM agents WHERE agent_id = $1", &[&agent_id])
    .await?
    .get(0);
assert_eq!(stored["source"], "audit");
assert_eq!(stored["fallback"], serde_json::json!({"detail": "no_btf", "audit_rule_loaded": false}));
```

Run `cargo test -p openvibes-ingest --test <file>` (needs the test database as in `testing.md` §2) — Expected: FAIL (`stored["source"]` is null: the old type dropped it).

- [ ] **Step 2: Bump.** Set the three `openvibes-*` `rev` values in `Cargo.toml` to the agent's current `main` (`git -C ../openvibes-agent rev-parse origin/main`; at writing `d06505e…`, use the full 40-character hash), `cargo update -p openvibes-core -p openvibes-transport -p openvibes-rules`, and `git -C protocol checkout 4de89af` (`git add protocol`). Build: `cargo build --workspace --all-targets`. Fix each compile error the newer agent crates cause with the smallest change (new struct fields in test literals take `..Default::default()` where the type has `Default`, else the field's empty value). Record each fix in the commit message.
- [ ] **Step 3: Run** the Step 1 test and the whole platform gate (`testing.md` §2: fmt, clippy `-D warnings`, `cargo test --workspace`, the web checks) — Expected: PASS.
- [ ] **Step 4: Commit** `deps: agent crates at <short>, protocol at 4de89af (alarms source and fallback are stored)`.

---

### Task 2: `AlarmsStatus`, derived once in `platform-store`

**Files:** Create `crates/platform-store/src/alarms_status.rs`; modify `crates/platform-store/src/lib.rs`, `crates/platform-store/src/console_read.rs` (the three agent queries at the `a.health -> 'rule_sets', a.health_at` lines and `agent_from_row`), `crates/platform-store/src/agents.rs` + `crates/openvibes-admin/src/agent.rs` (`agent show`), `docs/components/platform-store.md`, `docs/components/admin.md` (or the admin CLI's page).

**Interfaces:**
- Consumes: `openvibes_core::AlarmHealth` (Task 1).
- Produces:

```rust
/// Threat alarms on one host, from its last health report.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AlarmsStatus {
    /// Alarms are fed; `source` is "ebpf" or "audit".
    On { source: &'static str },
    /// Alarms are off. `reason` is a code; `text` says why, `fix` is the
    /// command or setting that turns them on (shown verbatim).
    Off { reason: &'static str, text: String, fix: String, fault: bool },
}
/// `None` when the host never reported health. `alarms`: the stored
/// `health -> 'alarms'` value (JSON null when absent).
pub fn alarms_status(reported: bool, alarms: Option<&serde_json::Value>) -> Option<AlarmsStatus>;
```

`fault` is false only for `not_enabled` (the Hosts list badges `fault` hosts). `console_read::Agent` gains `pub alarms: Option<AlarmsStatus>`.

- [ ] **Step 1: Failing tests** in `alarms_status.rs` (`#[cfg(test)]`), one per row of this table; `j(..)` is `serde_json::json!`:

| Test | Input `alarms` | Expected |
|---|---|---|
| `never_reported_is_none` | reported=false | `None` |
| `no_alarms_object_is_not_enabled` | reported, `Null` | `Off{reason:"not_enabled", fault:false, fix contains "process_events"}` |
| `ebpf_is_on` | `{collector:"ok", source:"ebpf", …counts}` | `On{source:"ebpf"}` |
| `missing_source_is_audit` | 0.2.5 shape, no `source` | `On{source:"audit"}` |
| `audit_with_rule_is_on` | `source:"audit", fallback:{no_btf, true}` | `On{source:"audit"}` |
| `fallback_without_rule_is_off_with_the_fallback_command` | `source:"audit", fallback:{no_btf, false}` | `Off{reason:"audit_not_set_up", fault:true, text contains "no BTF" and "no program start seen through audit yet", fix == "sudo /usr/libexec/openvibes-agent/audit-fallback"}` |
| `none_is_off_and_needs_a_restart` | `source:"none", collector:"permission_denied", fallback:{capability, false}` | `Off{reason:"no_source", fault:true, text names the eBPF detail and the collector outcome, fix == "sudo /usr/libexec/openvibes-agent/audit-fallback && sudo systemctl restart openvibes-agent"}` |
| `each_detail_has_its_own_words` | each of the six `detail` values | six distinct `text` values |
| `unparsable_alarms_is_unknown` | `j!("garbage")` | `None` |

Build the "counts" from a valid fixture: `include_str!("../../../protocol/fixtures/v1/heartbeat/valid-alarms-fallback.json")`, take `["health"]["alarms"]`, and edit the fields per test.

Run `cargo test -p platform-store alarms_status` — Expected: FAIL (module missing).

- [ ] **Step 2: Implement.** Parse with `serde_json::from_value::<openvibes_core::AlarmHealth>(v.clone()).ok()?` (unparsable → `None`). Words for `detail` (one place, used in `text`):

```rust
fn detail_words(detail: FallbackDetail) -> &'static str {
    match detail {
        FallbackDetail::NoBtf => "this kernel has no BTF",
        FallbackDetail::Capability => "the agent lacks CAP_BPF or CAP_PERFMON (check its systemd unit)",
        FallbackDetail::Lockdown => "kernel lockdown forbids eBPF",
        FallbackDetail::LsmDenied => "a security module (SELinux or AppArmor) refused eBPF",
        FallbackDetail::Verifier => "the kernel refused the agent's eBPF program",
        FallbackDetail::Other => "eBPF could not be started (see the agent's log)",
    }
}
```

Rules, in order: no `fallback` and `source` ∈ {ebpf, audit, missing} → `On`; `source == none` → `no_source`; `fallback.audit_rule_loaded == false` → `audit_not_set_up` with text "`<detail_words>`, and no program start seen through audit yet: the exec audit rule is probably not loaded"; else `On{audit}`. `not_enabled` text: "process events are not enabled on this host"; fix: `add "process_events" to collectors in /etc/openvibes-agent/agent.toml, then sudo systemctl restart openvibes-agent`.

Wire it: add `a.health -> 'alarms'` after `a.health_at` in the three agent queries (index 14) and set `alarms: alarms_status(rule_sets_at.is_some(), row.get::<_, Option<Value>>(14).as_ref())` in `agent_from_row`. `agent show` prints one line: `alarms: on (eBPF)` / `alarms: off — <text> — fix: <fix>`.

- [ ] **Step 3: Run** `cargo test -p platform-store` and `cargo test -p openvibes-admin` — Expected: PASS. Add one store test (existing DB-backed `console_read` tests) that an agent with stored `health.alarms.source = "ebpf"` reads back `Some(On{source:"ebpf"})`.
- [ ] **Step 4: Docs, commit** `store: threat-alarms status per host (source, or why off and the fix)`.

---

### Task 3: Console: the host page line and the Hosts-list badge

**Files:** `crates/openvibes-console/src/api.rs` (`AgentView`, its builder), the OpenAPI snapshot (`docs/api/` and `web/src/api/generated.ts`, regenerated by the repo's script — find it with `grep -rn generated.ts package.json scripts` in `crates/openvibes-console/web`), `web/src/panels/AgentPanel.tsx`, `web/src/views/Agents.tsx`, `web/src/views/rows.ts` + `rows.test.ts`, `web/src/demo/data.ts` (demo hosts: one eBPF, one audit, one off), `web/src/views/Alarms.tsx:125` (the empty-state sentence says "only when auditd runs": now wrong), `docs/components/console.md`.

**Interfaces:**
- Consumes: `console_read::Agent.alarms` (Task 2).
- Produces (API, additive):

```rust
/// Threat alarms on this host, from its last health report; absent before one.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct AgentAlarmsView {
    /// `on` or `off`.
    pub state: String,
    /// `ebpf` or `audit` when on.
    pub source: Option<String>,
    /// Why off: `not_enabled`, `audit_not_set_up`, `no_source`.
    pub reason: Option<String>,
    /// Why off, in words.
    pub text: Option<String>,
    /// The command or setting that turns them on, shown verbatim.
    pub fix: Option<String>,
    /// Off by a fault, not by choice (the Hosts list badges these).
    pub fault: bool,
}
```

`AgentView.alarms: Option<AgentAlarmsView>`.

- [ ] **Step 1: Failing tests.** Console HTTP test (existing agents API test file): an agent with stored `source:"none"` returns `alarms.state == "off"`, `fault == true`, `fix` = the Task 2 command. `rows.test.ts`: `alarmsBadge(agent)` is `true` only for `status === "active" && alarms?.fault`. Run `cargo test -p openvibes-console --test <file>` and `npm test` in `web` — Expected: FAIL.
- [ ] **Step 2: Implement.** Host page, Identity section after Capabilities:

```tsx
{data.alarms && <><dt>Threat alarms</dt><dd>{data.alarms.state === "on"
  ? <>on <span className="subtle">({data.alarms.source === "ebpf" ? "eBPF" : "audit"})</span></>
  : <div className="stack stack--tight"><span className="warn-text">off — {data.alarms.text}</span><CopyCode text={data.alarms.fix!} /></div>}</dd></>}
```

(`CopyCode`: use the existing copy-to-clipboard code component; find it with `grep -rn "clipboard" web/src/ui`.) Hosts list: in the Status column render `<StatusBadge status={a.status} />` plus, when `alarmsBadge(a)`, a small `<span className="badge badge--warn" title={a.alarms.text}>Alarms off</span>` (reuse the existing badge classes). Fix the Alarms empty-state sentence: "Agents report process starts when "process_events" is in their collectors; a host's page says whether its alarms are on."
- [ ] **Step 3: Run** the console tests, `npm test`, `npm run lint`/`typecheck` as `testing.md` §2 lists, and look at it in the demo build (Firefox, `npm run dev` demo mode): the three demo hosts read right at desktop and phone widths. Expected: PASS, no layout shift in the Identity list.
- [ ] **Step 4: Docs, commit** `console: threat alarms on the host page; Hosts list badges hosts whose alarms are off`. Then the platform PR (Tasks 1–3), gate green first.

---

### Task 4: Lab: `lab alarms`, a real alarm on every agent machine

**Repo:** `openvibes-lab`. **Files:** create `lib/alarms.sh`, `tests/test_alarms.sh`; modify `lab` (dispatch `alarms) alarms_cmd "$@" ;;` and usage), `README.md`.

**Interfaces:**
- Consumes: a ready fleet (`lab up` with `platform` and agent machines, installed by `lab install --rpms DIR` with the agent and platform from Tasks 1–3 and Plan B); `console_login` from `lib/sweep.sh` (move it to `lib/common.sh` if `alarms.sh` cannot source `sweep.sh` cleanly); `lab_ssh`.
- Produces: `lab alarms [NAME...]` (default: every agent machine that exists). Per machine prints `NAME source=<ebpf|audit> alarm=<seconds>s` or `NAME FAIL <why>`; exits non-zero on any failure. Option `--fallback NAME`: first sets `process_events_source = "audit"` in that machine's agent.toml (the agent's test switch), runs `sudo /usr/libexec/openvibes-agent/audit-fallback`, restarts the agent, and expects `source=audit`.

- [ ] **Step 1: Failing unit test** `tests/test_alarms.sh` (the repo's `tests/lib.sh` style, stubbing `lab_ssh` and `curl`): given a canned `/api/v1/agents` JSON with one host `alarms.source = "ebpf"` and a canned `/api/v1/alarms?agent_id=…` containing a `message` "A web server started a shell" with `args` containing the run's nonce, `alarms_check fedora` prints `fedora source=ebpf alarm=…s` and returns 0; with no matching alarm after the (stubbed) deadline it prints `fedora FAIL no alarm within 30s` and returns 1. Run `tests/run.sh test_alarms` — Expected: FAIL.
- [ ] **Step 2: Implement** `alarms_check NAME`: nonce `lab-$(date +%s)-$RANDOM`; `lab_ssh NAME "sudo install -m 0755 /bin/bash /tmp/fake-nginx && /tmp/fake-nginx -c \"sh -c 'true $nonce'\""`; poll every 2 s, up to 30 s, `GET /api/v1/alarms?agent_id=<id>` with the console session for an alarm whose args contain the nonce; then read `alarms.source` from `GET /api/v1/agents/<id>` (waiting up to 6 minutes for the health report, which is saved on the 5-minute heartbeat write). Agent id: from `/api/v1/agents` by hostname.
- [ ] **Step 3: Run** the unit test, then on the real lab, **one batch at a time** (memory): `lab up platform fedora debian && lab install --rpms DIR && lab alarms && lab alarms --fallback fedora && lab down`, then the same with `ubuntu alma arch`. Expected: every machine `source=ebpf` with an alarm within seconds; `--fallback fedora` gives `source=audit` with an alarm. Save the output in `results/` as the repo does for sweeps.
- [ ] **Step 4: Commit** `lab alarms: a real alarm per agent machine, eBPF and forced fallback`; PR in `openvibes-lab` (private).

**Not covered, said plainly:** spec §7's "no-BTF case" needs a kernel without BTF; none of the lab's five systems ships one. The forced-fallback run exercises the same audit path; a real no-BTF kernel (e.g. a custom build) stays a manual check, noted in the lab README.
