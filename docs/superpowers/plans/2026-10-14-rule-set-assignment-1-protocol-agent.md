# Rule-set assignment, part 1: protocol P20 and the agent — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The agent knows the project's own rule sets and adds the ones of its OS family when it has a distribution service; the platform can answer `410 Gone` for an assignable set to switch it off per host, and the agent stops using it (keeping its rollback floor) and reports `not_assigned`.

**Architecture:** Protocol P20 first (schema descriptions, a new optional `state` on the heartbeat's per-set health, fixtures, and a shared vector `vectors/project-rule-sets.json` holding the project-set table and the 404/410 cases). In the agent, the transport names the rule-bundle 404 (`NotFound`) and 410 (`NotAssigned`); a new module `project_sets.rs` holds the compiled-in table and adds missing sets at config load; `scan.rs` turns a 404 for an added set into "not offered" (quiet) and a 410 for an assignable added set into "not assigned" (stop, mark the stored bundle withdrawn so it is never used again while the rollback floor stays, health state), while every other 404/410 stays a refused answer. The service ends the P13 matches of a set that is no longer running.

**Tech Stack:** Rust 1.95 workspace (`openvibes-core`, `openvibes-transport`, `openvibes-storage`, `openvibes-agent`), `ureq`/`rustls`, SQLite via `rusqlite`; JSON Schema draft 2020-12 and `tools/validate.py` in the protocol repo.

**Spec:** `/home/lime/Projects/OpenVIBES/openvibes-platform-assign/docs/specs/2026-10-14-rule-set-assignment-design.md` (§3, §4, §7 steps 1–2), completing `/home/lime/Projects/OpenVIBES/openvibes-platform-assign/docs/specs/2026-10-09-hardening-rules-design.md` step 5. Rules RPM + platform are plan 2; the console is plan 3.

## Global Constraints

- TDD: every behaviour change starts with a failing test, run and seen failing, before the code.
- Files stay under 500 lines; a touched file that would cross 500 is split in the same task (this plan moves `scan.rs`'s and `client.rs`'s unit tests into `scan/tests.rs` and `client/tests.rs`). `service.rs` (1,310), `matches.rs` (717) and `tests/platform.rs` (761) are already over: this plan changes one expression in `service.rs`, adds new tests in new files, and does not split them.
- Every component change updates its `docs/components/<name>.md` page in the same commit.
- Commits end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. Git identity in every new worktree: `git config user.name itismelime` and `git config user.email 26064407+itismelime@users.noreply.github.com`.
- Anything crossing agent/platform is changed in `openvibes-protocol` first (Task 1), and the agent re-pins its `protocol/` submodule in the change that uses it (Task 3; final pin to protocol `main` in Task 7).
- Agent gate (AGENTS.md / `testing.md` §4), all green before a PR:
  `cargo fmt --all --check`; `cargo clippy --locked --workspace --all-targets --all-features -- -D warnings -F unsafe-code`; `cargo test --locked --workspace --all-features`; `RUSTDOCFLAGS="-D warnings" cargo doc --locked --workspace --all-features --no-deps`; `cargo audit --deny warnings`. Protocol gate: `.venv/bin/python tools/validate.py`.
- Every cargo command runs as `nice -n 19` with `CARGO_TARGET_DIR=$HOME/.cache/openvibes-scratch/target` (never `/tmp`: it is RAM on this host). Shorthand used below: `C='env CARGO_TARGET_DIR=$HOME/.cache/openvibes-scratch/target nice -n 19 cargo'` then `$C test ...` (bash: `C="env CARGO_TARGET_DIR=$HOME/.cache/openvibes-scratch/target nice -n 19 cargo"`).
- This host runs the user's production platform: never start, stop, restart, or touch any `openvibes-*` service, unit, database or file under `/etc/openvibes*`, `/var/lib/openvibes*`. No `sudo`.
- The agent never gains a privilege, a capability, or runs a program for this (no `std::process::Command`; clippy bans it).
- Security: a `410` never removes a non-assignable set (baseline, alarms, a site set) or any set named in `agent.toml`; for those it is a refused answer and the last accepted bundle keeps running. A platform cannot silently remove the baseline.
- Agent starting point: a worktree from `origin/main` **after agent PRs #71 (`ports-imply-services`) and #73 (`alarms-by-default`) are merged**; if they are not merged yet, branch from `origin/alarms-by-default` and rebase onto `origin/main` once they are. Never undo them: this plan does not touch `collectors()` or `Collectors::default()` in `config.rs`. `cargo audit` fails on main until #72 (rustls 0.23.46) is merged; rebase onto it before the gate.
- Read main with `git -C <repo> fetch -q` then `git show origin/main:<path>`; the main checkouts are on other branches and must not be switched.

## Review Focus

1. **An older platform (or one without the rules package) answers 404 for the added sets** → no health problem: no error, no early retry, the sets are not listed in health. Test: `scans::an_older_platform_without_the_project_sets_sees_no_change` (Task 6).
2. **A 410 for the baseline (or the alarms)** → refused like any 4xx, the stored baseline keeps running and its bundle and floor are kept. Test: `scans::a_410_for_a_set_that_is_not_assignable_is_refused` (Task 6).
3. **410 on one scan, 200 on a later one** → the set runs again on that next scan (asked without `current_version`, so a platform holding the same version answers 200, not 204), its P13 matches had ended so the platform sees them start again, and a switch-off/on cannot roll it back: an older bundle is still refused against the kept floor, and a withdrawn set never falls back to its stored bundle. Tests: `scans::an_unassigned_set_stops_and_comes_back`, `scans::a_reassigned_set_keeps_its_rollback_floor` and `a_set_no_longer_assigned_is_not_running` (Task 6); `withdrawing_keeps_the_floor_and_accept_clears_the_mark` (Task 4).
4. **`agent.toml` names a project set with its own key** → that entry wins whole (its keys, its `restricted`), the project key is not added for it, and a 410 for it is refused. Tests: `a_configured_entry_wins_whole` (Task 5), `a_configured_project_set_keeps_its_own_keys_and_restricted` (Task 5), vector case "an assignable set named in the configuration, answered 410" (Task 6).
5. **No `distribution_url`** (local-only, or a platform without distribution) → nothing is added; the agent keeps exactly its configuration. Test: `project_sets_are_added_only_with_a_distribution_service` (Task 5), which also checks that Windows/macOS add only `baseline`.

---

## File map

Protocol (`/home/lime/Projects/OpenVIBES/openvibes-protocol-p20`, branch `p20-not-assigned`):
- Modify `schemas/v1/rule-bundle-request.schema.json` (description), `schemas/v1/heartbeat.schema.json` (`state` on `rule_sets` items).
- Create `fixtures/v1/heartbeat/valid-health-not-assigned.json`, `fixtures/v1/heartbeat/invalid-health-rule-set-state-with-space.json`; modify `fixtures/v1/heartbeat/valid-health-unknown-values.json`.
- Create `vectors/project-rule-sets.json`; modify `tools/validate.py`.
- Modify `spec/contracts-v1.md`, `PLAN.md`, `README.md`.

Agent (`/home/lime/Projects/OpenVIBES/openvibes-agent-p20`, branch `p20-project-sets`):
- `crates/openvibes-transport/src/client.rs` (+ new `client/tests.rs`), new test `crates/openvibes-transport/tests/rule_bundle.rs`.
- `crates/openvibes-core/src/health.rs`, `crates/openvibes-core/src/lib.rs`.
- `crates/openvibes-storage/src/rules.rs`, `crates/openvibes-storage/tests/rules.rs`.
- New `crates/openvibes-agent/src/project_sets.rs`; `config.rs`, `lib.rs`, `scan.rs` (+ new `scan/tests.rs`), `service.rs` (one expression), `health.rs` (test literal).
- New test `crates/openvibes-agent/tests/project_sets.rs`; `tests/distribution.rs` (one helper).
- Docs: `docs/components/openvibes-transport.md`, `openvibes-core.md`, `openvibes-storage.md`, `openvibes-agent.md`; `AGENTS.md` (one sentence); `protocol` submodule pin.

---

### Task 1: Protocol P20 — `410`, `not_assigned`, fixtures, project-set vector

**Files:**
- Modify: `schemas/v1/rule-bundle-request.schema.json`, `schemas/v1/heartbeat.schema.json` (the `rule_sets` item `properties`, after `refused`)
- Create: `fixtures/v1/heartbeat/valid-health-not-assigned.json`, `fixtures/v1/heartbeat/invalid-health-rule-set-state-with-space.json`, `vectors/project-rule-sets.json`
- Modify: `fixtures/v1/heartbeat/valid-health-unknown-values.json`, `tools/validate.py`, `spec/contracts-v1.md`, `PLAN.md`, `README.md`

**Interfaces:**
- Produces (wire): `POST /v1/rule-bundle` may answer `410`, no body. Heartbeat `health.rule_sets[].state`: optional, `null` or an identifier; `not_assigned` defined. `vectors/project-rule-sets.json` = `{ "note", "sets": [{id, os_family: "any"|"linux", assignable}], "cases": [{name, rule_set_id, configured, status: 404|410, agent: "not_offered"|"not_assigned"|"refused"}] }`, read by the agent in Tasks 5–6 and by plan 2 (platform).

- [ ] **Step 1: Worktree and identity**

```bash
set -e
cd /home/lime/Projects/OpenVIBES/openvibes-protocol
git fetch -q origin
git worktree add ../openvibes-protocol-p20 -b p20-not-assigned origin/main
cd ../openvibes-protocol-p20
git config user.name itismelime
git config user.email 26064407+itismelime@users.noreply.github.com
test -x ../openvibes-protocol/.venv/bin/python && ln -s ../openvibes-protocol/.venv .venv
```

(If the main checkout has no `.venv`: `python3 -m venv .venv && .venv/bin/pip install --no-deps -r tools/requirements.txt`. `.venv` is ignored by git; check with `git status --short`.)

- [ ] **Step 2: Write the fixtures and the vector (failing)**

`fixtures/v1/heartbeat/valid-health-not-assigned.json`:

```json
{
  "schema_version": 1,
  "agent_id": "agent.1",
  "scanner_version": "0.3.0",
  "hostname": "db-primary-01",
  "observed_at_unix_ms": 1790000000000,
  "capabilities": [],
  "health": {
    "queue": {
      "pending": 0,
      "oldest_pending_age_s": 0,
      "bytes": 81920,
      "max_bytes": 268435456,
      "dropped_total": 0,
      "rejected_total": {}
    },
    "last_scan": {
      "finished_at_unix_ms": 1790000000000,
      "interval_s": 3600,
      "rules_evaluated": 42,
      "rules_unavailable": 0,
      "rules_failed": 0,
      "collectors": {
        "packages": "ok"
      }
    },
    "rule_sets": [
      {
        "id": "baseline",
        "version": 7,
        "expires_at_unix_ms": 1790600000000,
        "refused": null
      },
      {
        "id": "hardening-linux-l1",
        "version": null,
        "expires_at_unix_ms": null,
        "refused": null,
        "state": "not_assigned"
      }
    ],
    "storage_errors": 0,
    "clock_jump_s": null
  }
}
```

`fixtures/v1/heartbeat/invalid-health-rule-set-state-with-space.json`: the same document with the second rule set's `"state": "not assigned"` (a space: not an identifier).

`fixtures/v1/heartbeat/valid-health-unknown-values.json`: in `health.rule_sets[0]`, after `"refused": "quarantined"`, add `"state": "paused"` (a later value; readers must accept it).

`vectors/project-rule-sets.json`:

```json
{
  "note": "Protocol P20. The project's own rule sets, which an agent with a distribution_url adds when its configuration does not name them, and what a 404 or 410 from /v1/rule-bundle means to the agent. configured: the agent's configuration names the set. agent: not_offered (runs nothing, reports nothing, asks again next scan), not_assigned (stops evaluating, stops using its stored bundle while keeping the rollback floor, health state not_assigned, asks again next scan without current_version) or refused (like any other 4xx: the last accepted bundle keeps running).",
  "sets": [
    { "id": "baseline", "os_family": "any", "assignable": false },
    { "id": "baseline-alarms", "os_family": "linux", "assignable": false },
    { "id": "hardening-linux-l1", "os_family": "linux", "assignable": true },
    { "id": "hardening-linux-l2", "os_family": "linux", "assignable": true }
  ],
  "cases": [
    { "name": "an assignable set the agent added, answered 410", "rule_set_id": "hardening-linux-l1", "configured": false, "status": 410, "agent": "not_assigned" },
    { "name": "the baseline answered 410", "rule_set_id": "baseline", "configured": false, "status": 410, "agent": "refused" },
    { "name": "the alarms answered 410", "rule_set_id": "baseline-alarms", "configured": false, "status": 410, "agent": "refused" },
    { "name": "an assignable set named in the configuration, answered 410", "rule_set_id": "hardening-linux-l2", "configured": true, "status": 410, "agent": "refused" },
    { "name": "a site set answered 410", "rule_set_id": "site.web", "configured": true, "status": 410, "agent": "refused" },
    { "name": "an added set the platform does not publish", "rule_set_id": "hardening-linux-l2", "configured": false, "status": 404, "agent": "not_offered" },
    { "name": "a configured set the platform does not publish", "rule_set_id": "baseline", "configured": true, "status": 404, "agent": "refused" }
  ]
}
```

- [ ] **Step 3: Run the validator, see it fail**

Run: `.venv/bin/python tools/validate.py`
Expected: exit 1 with `FAIL heartbeat/invalid-health-rule-set-state-with-space.json` (or the validator's equivalent line): without a `state` property in the schema, any value passes.

- [ ] **Step 4: Schema and validator**

`schemas/v1/heartbeat.schema.json`, in the `rule_sets` item `properties`, after the `refused` property:

```json
              "state": {
                "anyOf": [
                  {
                    "$ref": "common.schema.json#/$defs/identifier"
                  },
                  {
                    "type": "null"
                  }
                ],
                "description": "Optional (P20): not_assigned when the distribution service answered 410 for this assignable project set; the agent runs nothing for it and no longer uses its stored bundle (the rollback floor is kept). Absent or null: in use. Readers ignore a value they do not know (later versions may add values)."
              }
```

`schemas/v1/rule-bundle-request.schema.json` `description`:

```json
  "description": "POST /v1/rule-bundle to the distribution service over mTLS. 200 answers with the SignedRuleEnvelope exactly as signed; 204 means nothing newer than current_version; 404 means the service does not publish this set; 410 with no body (P20) means the set is not assigned to this host. The agent honours 410 only for an assignable project set it added itself (vectors/project-rule-sets.json); for any other set 404 and 410 are refused answers.",
```

`tools/validate.py`, before `print(f"{checked} fixtures checked, {failures} failures")`:

```python
    # Project rule sets (P20): the agent's tests run the cases; here the
    # shape, and that every case follows the rule in spec/contracts-v1.md.
    project = json.loads((ROOT / "vectors/project-rule-sets.json").read_text())
    assignable = {s["id"]: s["assignable"] for s in project["sets"]}
    if len(assignable) != len(project["sets"]) or any(
        s["os_family"] not in ("any", "linux") for s in project["sets"]
    ):
        print("FAIL project rule sets: duplicate id or unknown os_family")
        failures += 1
    for case in project["cases"]:
        checked += 1
        added = not case["configured"]
        if case["status"] == 404:
            want = "not_offered" if added else "refused"
        elif case["status"] == 410:
            want = "not_assigned" if added and assignable.get(case["rule_set_id"]) else "refused"
        else:
            want = None
        if (added and case["rule_set_id"] not in assignable) or case["agent"] != want:
            print(f"FAIL project rule sets case {case['name']!r}")
            failures += 1
```

- [ ] **Step 5: Run the validator, see it pass**

Run: `.venv/bin/python tools/validate.py`
Expected: exit 0, `… fixtures checked, 0 failures`. Then flip one vector case's `agent` to `refused`, run again, see `FAIL project rule sets case …`, and restore it.

- [ ] **Step 6: Spec, PLAN and README**

`spec/contracts-v1.md`:

1. Replace the health bullet that starts ``- `rule_sets`: each configured rule set's version`` (ends `` `rolled_back`, `invalid`); ``) with:

```markdown
- `rule_sets`: each rule set's version in use and its expiry
  (`null` before a bundle was accepted), `refused`: `null`, or why the
  last provisioned bundle was refused (`signature`, `expired`,
  `rolled_back`, `invalid`), and `state` (P20, optional): `not_assigned`
  when the distribution service answered `410` for this assignable
  project set; absent or `null` means in use, and readers ignore a value
  they do not know. A project set the service does not publish (`404`)
  is not listed;
```

2. In "Rule Distribution", the table row becomes:

```markdown
| `/v1/rule-bundle` | required | `RuleBundleRequest` | `200`: `SignedRuleEnvelope`; `204`: none; `404`: not published; `410`: not assigned to this host (P20) |
```

3. Replace the paragraph that starts "Assignment is local." (through "serve refused bundles.") with:

```markdown
Assignment (P20). The agent asks for the rule sets named in its own
configuration, each with its own trusted keys, and, with a
`distribution_url`, for the project's own rule sets of its OS family that
its configuration does not name (`vectors/project-rule-sets.json`: id, OS
family, assignable). The agent package carries those sets' public key
(issuer `openvibes-1`, the key the rules repository signs every set with);
like every rule-signing key it reaches the host out of band, in the agent
release, never over this protocol. The agent polls once before every scan.

- `404` for a project set the agent added means the service does not
  publish it: the agent runs nothing for it, lists nothing for it in
  health, and asks again at the next scan.
- `410 Gone`, no body, means the set is not assigned to this host. The
  agent honours it only for an **assignable** project set it added: it
  stops evaluating the set, stops using its stored bundle (the rollback
  floor is kept), reports `state: not_assigned` in health, and asks again
  at every scan without `current_version`, so a later `200` brings the set
  back. That bundle is accepted only at or above the kept floor: a
  switch-off and on cannot roll a set back.
- For any other set (the baseline, the alarms, a site set, or any set
  named in the agent's configuration) `404` and `410` are refused answers
  like any other `4xx`, and the last accepted bundle keeps running.

A distribution service therefore cannot add rule sets, re-scope keys or
sign rules: it serves envelopes signed offline. Per host it can withdraw
only the assignable project sets, never the baseline. Otherwise the worst
it can do is withhold updates or serve refused bundles.
```

`PLAN.md`:
- Row 6, Agent column: `done; P20 project sets and 410 todo`; Ingest column: `done (openvibes-distribution); P20 410 todo`.
- Row 10, Agent column: `done (per rule set; the project's own key ships in the agent package, P20)`.
- Open question 4, append: ` Extended 2026-10-14 by P20: the agent also adds the project's own sets, and the distribution service may answer 410 for an assignable one.`
- Append after the P19 section:

```markdown
# P20 — Rule-set assignment: "not assigned" (user, 2026-10-14)

The agent package knows the project's own rule sets and their key; the
platform switches the assignable ones (hardening L1, L2) per asset group
by answering `410` per host. Spec
`openvibes-platform/docs/specs/2026-10-14-rule-set-assignment-design.md`.

- [x] Contract: `410` on `/v1/rule-bundle`, health `rule_sets[].state`
  `not_assigned`, `vectors/project-rule-sets.json` (table and cases).
- [ ] Agent: compiled-in project sets added with a `distribution_url`, a
  quiet `404` for them, `410` for assignable ones, health.
- [ ] Rules: the RPM ships `hardening-linux-l1`.
- [ ] Platform: assignment tables and audit, distribution `410`, ingest
  closes findings on `not_assigned`, Setup/`rules-apply` publish the
  hardening sets, console switches.
```

`README.md`, "What the protocol covers" table:
- `| Signed rule bundles | agent → distribution | `/v1/rule-bundle`, default port 18424; `410`: not assigned to this host (P20) | Built on both sides |` — status stays as is until plan 2; write `Built on both sides (P20: in progress)`.
- `| Enrollment token, platform CA, rule-signing keys | operator → agent | out of band (install time; the project's own rule key ships in the agent package, P20) | Built |`

- [ ] **Step 7: Validate and commit**

```bash
set -e
.venv/bin/python tools/validate.py
git add schemas fixtures vectors tools spec PLAN.md README.md
git status --short
git commit -m "P20: 410 not assigned, health state, project rule sets

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2: Transport — rule-bundle `404` is `NotFound`, `410` is `NotAssigned`

**Files:**
- Modify: `crates/openvibes-transport/src/client.rs` (enum `TransportError` ~:20-63, `Display` ~:66-84, `fetch_rule_bundle` ~:292-303, status match ~:383-424, path constants ~:428-439, test module ~:484-513)
- Create: `crates/openvibes-transport/src/client/tests.rs` (moved unit test), `crates/openvibes-transport/tests/rule_bundle.rs`
- Modify: `docs/components/openvibes-transport.md`

**Interfaces:**
- Produces: `TransportError::NotAssigned` (new variant, `Copy`); `PlatformClient::fetch_rule_bundle(&RuleBundleRequest) -> Result<Option<Vec<u8>>, TransportError>` now returns `Err(NotFound)` on 404 and `Err(NotAssigned)` on 410; every other path's mapping is unchanged.

- [ ] **Step 1: Agent worktree, identity, submodule**

```bash
set -e
cd /home/lime/Projects/OpenVIBES/openvibes-agent
git fetch -q origin
git log --oneline -1 origin/main   # #71 and #73 merged? (see Global Constraints)
git worktree add ../openvibes-agent-p20 -b p20-project-sets origin/main
cd ../openvibes-agent-p20
git submodule update --init
git config user.name itismelime
git config user.email 26064407+itismelime@users.noreply.github.com
```

- [ ] **Step 2: Move the unit test out of `client.rs` (513 lines)**

Create `crates/openvibes-transport/src/client/tests.rs` with exactly the body of the current `mod tests { … }` at the end of `client.rs` (the `use super::{DEFAULT_DISTRIBUTION_PORT, DEFAULT_PLATFORM_PORT, with_default_port};` line and the `default_port_is_added_only_when_absent` test), and replace that block in `client.rs` with:

```rust
#[cfg(test)]
mod tests;
```

Run: `$C test --locked -p openvibes-transport --lib`
Expected: PASS (1 test).

- [ ] **Step 3: Write the failing test**

`crates/openvibes-transport/tests/rule_bundle.rs`:

```rust
//! The rule-bundle answers (protocol P20): 404 is `NotFound` (not
//! published), 410 is `NotAssigned` (not assigned to this host); any
//! other 4xx stays `Rejected`, and a 410 elsewhere is a plain refusal.

use openvibes_core::{Identifier, ResourceLimits, RuleBundleRequest, SchemaVersion};
use openvibes_testkit::{Pki, Seen, serve, status};
use openvibes_transport::{
    DEFAULT_DISTRIBUTION_PORT, PlatformClient, TransportConfig, TransportError,
};

#[test]
fn rule_bundle_answers_404_and_410_by_name() {
    let pki = Pki::new();
    let (url, _) = serve(
        pki.server_config(false, false),
        vec![
            Box::new(|_: &Seen| status(404)),
            Box::new(|_: &Seen| status(410)),
            Box::new(|_: &Seen| status(400)),
            Box::new(|_: &Seen| status(204)),
        ],
    );
    let config = TransportConfig {
        base_url: url,
        default_port: DEFAULT_DISTRIBUTION_PORT,
        server_roots_pem: pki.roots_pem(),
        proxy_url: None,
        limits: ResourceLimits::V1,
    };
    let client = PlatformClient::new(&config, None).unwrap();
    let request = RuleBundleRequest {
        schema_version: SchemaVersion::V1,
        rule_set_id: Identifier::new("hardening-linux-l1").unwrap(),
        current_version: None,
    };
    assert_eq!(client.fetch_rule_bundle(&request), Err(TransportError::NotFound));
    assert_eq!(client.fetch_rule_bundle(&request), Err(TransportError::NotAssigned));
    assert_eq!(client.fetch_rule_bundle(&request), Err(TransportError::Rejected));
    assert_eq!(client.fetch_rule_bundle(&request), Ok(None));
}

#[test]
fn a_410_on_another_endpoint_is_rejected() {
    let pki = Pki::new();
    let (url, _) = serve(
        pki.server_config(false, false),
        vec![Box::new(|_: &Seen| status(410))],
    );
    let config = TransportConfig {
        base_url: url,
        default_port: DEFAULT_DISTRIBUTION_PORT,
        server_roots_pem: pki.roots_pem(),
        proxy_url: None,
        limits: ResourceLimits::V1,
    };
    let client = PlatformClient::new(&config, None).unwrap();
    let heartbeat: openvibes_core::Heartbeat = serde_json::from_str(include_str!(
        "../../../protocol/fixtures/v1/heartbeat/valid.json"
    ))
    .unwrap();
    assert_eq!(client.heartbeat(&heartbeat), Err(TransportError::Rejected));
}
```

(If `serde_json` is not a dev-dependency of `openvibes-transport`, it is a normal dependency already: `client.rs` uses it.)

- [ ] **Step 4: Run it, see it fail**

Run: `$C test --locked -p openvibes-transport --test rule_bundle`
Expected: compile error `no variant named NotAssigned`; after adding only the variant, `left: Err(Rejected) right: Err(NotFound)`.

- [ ] **Step 5: Implement**

In `TransportError`, change the `Rejected` and `NotFound` docs and add the variant after `FindingsResync`:

```rust
    /// The platform refused the request (a 4xx other than 401, 403, 408 and
    /// 429, and the 404 and 410 named below) or redirected; sending the same
    /// request again will not help.
    Rejected,
```

```rust
    /// The platform does not offer this endpoint (404 on the P11 changes,
    /// P13 finding changes, P14 alarms or P15 services endpoint: an older
    /// platform), or does not publish the asked rule set (404 on
    /// `/v1/rule-bundle`).
    NotFound,
```

```rust
    /// The rule set is not assigned to this host (410 on `/v1/rule-bundle`,
    /// P20). The agent honours it only for an assignable project set it
    /// added; for any other set it is a refusal.
    NotAssigned,
```

`Display`, after `Self::FindingsResync => …`:

```rust
            Self::NotAssigned => "the rule set is not assigned to this host",
```

Path constants, after `HEARTBEAT`:

```rust
/// Rule bundles, on the distribution service (404 and 410: P20).
const RULE_BUNDLE: &str = "/v1/rule-bundle";
```

`fetch_rule_bundle`: `match self.send(request, RULE_BUNDLE)? {` (instead of the literal), and its doc gains: `` `NotFound`: the service does not publish the set; `NotAssigned`: it is not assigned to this host (P20). ``

Status match in `send_with`, directly before the `409 if path == CHANGES …` arm:

```rust
            // P20: a set the service does not publish (404) or does not
            // assign to this host (410). The agent decides what each means
            // for the set; everything else on this path keeps its mapping.
            404 if path == RULE_BUNDLE => Err(TransportError::NotFound),
            410 if path == RULE_BUNDLE => Err(TransportError::NotAssigned),
```

If the build reports a non-exhaustive `match` on `TransportError` anywhere else (the agent's crates), add `NotAssigned` to the arm that holds `Rejected`.

- [ ] **Step 6: Run the tests, see them pass**

Run: `$C test --locked -p openvibes-transport`
Expected: PASS, including `rule_bundle` and `platform`. `wc -l crates/openvibes-transport/src/client.rs` < 500.

- [ ] **Step 7: Docs and commit**

`docs/components/openvibes-transport.md`, "Failure behaviour", append to the first paragraph:

```markdown
`fetch_rule_bundle` (`POST /v1/rule-bundle` on the distribution service):
`204` is `Ok(None)`; a 404 is `NotFound` (the service does not publish the
set) and a 410 is `NotAssigned` (P20: the set is not assigned to this
host). The agent decides what each means for the set; any other 4xx there
stays `Rejected`, and a 410 on any other endpoint is `Rejected`.
```

```bash
set -e
git add crates/openvibes-transport docs/components/openvibes-transport.md
git commit -m "Transport: name the rule-bundle 404 and 410 (P20)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 3: Core health — `RuleSetHealth.state` (`not_assigned`) and the protocol re-pin

**Files:**
- Modify: `crates/openvibes-core/src/health.rs` (`RuleSetHealth` ~:218-231, after `BundleRefusal`'s `Deserialize` ~:250-260, tests ~:357-385)
- Modify: `crates/openvibes-core/src/lib.rs` (`pub use health::{…}` ~:42-46)
- Modify: `crates/openvibes-agent/src/health.rs` (test literal ~:166-171), `crates/openvibes-agent/src/scan.rs` (literal ~:103-112)
- Modify: `protocol` submodule pin; `docs/components/openvibes-core.md` (~:35)

**Interfaces:**
- Consumes: Task 1's fixtures (via the submodule).
- Produces: `openvibes_core::RuleSetState { NotAssigned, Other }` (`Clone, Copy, Debug, Eq, PartialEq, Serialize`, open `Deserialize`); `RuleSetHealth.state: Option<RuleSetState>` (serialized only when `Some`).

- [ ] **Step 1: Re-pin `protocol` to the P20 branch**

```bash
set -e
cd /home/lime/Projects/OpenVIBES/openvibes-agent-p20/protocol
git fetch -q /home/lime/Projects/OpenVIBES/openvibes-protocol p20-not-assigned
git checkout -q FETCH_HEAD
cd ..
git status --short   # " M protocol"
```

(Task 7 re-pins to the merged protocol `main` commit.)

- [ ] **Step 2: Write the failing tests**

In `crates/openvibes-core/src/health.rs` tests, inside `the_protocol_fixtures_agree`, after the `later.rule_sets[0].refused` assertion:

```rust
        assert_eq!(
            later.rule_sets[0].state,
            Some(super::RuleSetState::Other),
            "a later state value parses"
        );
        let unassigned = fixture("valid-health-not-assigned.json")
            .unwrap()
            .health
            .unwrap();
        assert_eq!(unassigned.rule_sets[0].state, None);
        assert_eq!(
            unassigned.rule_sets[1].state,
            Some(super::RuleSetState::NotAssigned)
        );
```

and add `"invalid-health-rule-set-state-with-space.json",` to the `for invalid in [...]` list. New test in the same module:

```rust
    #[test]
    fn a_set_in_use_sends_no_state() {
        let set = super::RuleSetHealth {
            id: Identifier::new("baseline").unwrap(),
            version: Some(1),
            expires_at_unix_ms: None,
            refused: None,
            state: None,
        };
        let json = serde_json::to_value(&set).unwrap();
        assert!(json.get("state").is_none(), "older platforms see the same document");
        let unassigned = super::RuleSetHealth {
            version: None,
            state: Some(super::RuleSetState::NotAssigned),
            ..set
        };
        assert_eq!(serde_json::to_value(&unassigned).unwrap()["state"], "not_assigned");
    }
```

- [ ] **Step 3: Run, see it fail**

Run: `$C test --locked -p openvibes-core`
Expected: compile errors `no field state` / `RuleSetState not found`.

- [ ] **Step 4: Implement**

`RuleSetHealth`, after `refused`:

```rust
    /// P20: `Some(NotAssigned)` when the platform answered 410 for this
    /// assignable project set; `None` while the set is in use.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<RuleSetState>,
```

After `impl<'de> Deserialize<'de> for BundleRefusal { … }`:

```rust
/// A rule set's state other than in use (P20). A value from a later
/// version reads as `Other`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleSetState {
    /// The platform answered 410: not assigned to this host. The agent
    /// runs nothing for it and no longer uses its stored bundle.
    NotAssigned,
    /// A value from a later version.
    Other,
}

impl<'de> Deserialize<'de> for RuleSetState {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(match open_code(deserializer)?.as_str() {
            "not_assigned" => Self::NotAssigned,
            _ => Self::Other,
        })
    }
}
```

`lib.rs`: add `RuleSetState` to the `pub use health::{…}` list (keep it sorted as rustfmt does).

Agent literals: `crates/openvibes-agent/src/health.rs` test `RuleSetHealth { … refused: Some(BundleRefusal::Invalid), state: None, }` and `crates/openvibes-agent/src/scan.rs` `report.rule_sets.push(RuleSetHealth { … refused: …, state: None, });`.

- [ ] **Step 5: Run, see it pass**

Run: `$C test --locked -p openvibes-core && $C test --locked -p openvibes-agent --lib`
Expected: PASS, including `protocol_fixtures` (it reads every heartbeat fixture). `wc -l crates/openvibes-core/src/health.rs` < 500; if not, move its `mod tests` to `crates/openvibes-core/src/health/tests.rs` as in Task 2 Step 2.

- [ ] **Step 6: Docs and commit**

`docs/components/openvibes-core.md`, in the line listing `RuleSetHealth`: add `` with an optional `state` (P20: `RuleSetState::NotAssigned`; absent while in use, a later value reads as `Other`) ``.

```bash
set -e
git add protocol crates/openvibes-core crates/openvibes-agent/src/health.rs crates/openvibes-agent/src/scan.rs docs/components/openvibes-core.md
git commit -m "Core: rule-set health state not_assigned (P20), protocol pin

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 4: Storage — `RuleStore::withdraw` / `is_withdrawn` (floor kept)

**Files:**
- Modify: `crates/openvibes-storage/src/rules.rs` (schema ~:8-18, `open` ~:48, `accept` ~:96-139, new methods after `accept`)
- Test: `crates/openvibes-storage/tests/rules.rs`
- Modify: `docs/components/openvibes-storage.md` (~:45)

**Interfaces:**
- Produces:
  - `RuleStore::withdraw(&mut self, rule_set_id: &Identifier) -> Result<(), StorageError>`: marks the set's row withdrawn; the row (version, digest, envelope) and so the rollback floor stay. An absent set records nothing and is `Ok(())`.
  - `RuleStore::is_withdrawn(&self, rule_set_id: &Identifier) -> Result<bool, StorageError>`: `false` for an absent set; a mark other than 0/1 is `StorageError::Corrupt`.
  - `RuleStore::accept` clears the mark, also on the identical-version no-op path (same version and digest = re-enabled). `get` is unchanged (it still returns a withdrawn set's row; the caller checks `is_withdrawn`).
  - Schema `user_version` 2: `rule_bundles.withdrawn INTEGER NOT NULL DEFAULT 0`, added by an upgrade step passed to `open_database`'s `upgrades` argument (as `identity.rs` and `queue.rs` do; a new database runs `SCHEMA_V1` then the upgrade).

- [ ] **Step 1: Write the failing tests** (append to `tests/rules.rs`)

```rust
#[test]
fn withdrawing_keeps_the_floor_and_accept_clears_the_mark() {
    let path = path("withdraw");
    let mut store = open(&path);
    let l1 = id("hardening-linux-l1");
    store.accept(&l1, &bundle(3, 3)).unwrap();
    store.accept(&id("baseline"), &bundle(2, 2)).unwrap();

    store.withdraw(&l1).unwrap();
    store.withdraw(&id("never-stored")).unwrap();
    assert_eq!(store.is_withdrawn(&l1), Ok(true));
    assert_eq!(store.is_withdrawn(&id("never-stored")), Ok(false), "nothing recorded");
    assert_eq!(store.is_withdrawn(&id("baseline")), Ok(false), "others untouched");
    drop(store);

    let mut store = open(&path);
    assert_eq!(store.is_withdrawn(&l1), Ok(true), "the mark survives a restart");
    assert_eq!(store.get(&l1), Ok(Some(bundle(3, 3))), "the row is kept");
    assert_eq!(store.get(&id("baseline")), Ok(Some(bundle(2, 2))));
    // The floor holds while withdrawn.
    assert_eq!(store.accept(&l1, &bundle(2, 2)), Err(StorageError::Rollback));
    assert_eq!(store.accept(&l1, &bundle(3, 9)), Err(StorageError::VersionConflict));
    assert_eq!(store.is_withdrawn(&l1), Ok(true), "a refused bundle re-enables nothing");
    // The identical version re-accepts and clears the mark.
    store.accept(&l1, &bundle(3, 3)).unwrap();
    assert_eq!(store.is_withdrawn(&l1), Ok(false));
    // So does a newer one, after another withdrawal.
    store.withdraw(&l1).unwrap();
    store.accept(&l1, &bundle(4, 4)).unwrap();
    assert_eq!(store.is_withdrawn(&l1), Ok(false));
}

#[test]
fn a_version_1_store_opens_and_migrates() {
    let path = path("migrate-v1");
    let connection = Connection::open(&path).unwrap();
    // The schema before P20; application_id is "OVR1" (0x4F565231).
    connection
        .execute_batch(
            "PRAGMA application_id = 1331057201;
             CREATE TABLE rule_bundles (
                 rule_set_id TEXT PRIMARY KEY,
                 version INTEGER NOT NULL,
                 preimage_sha256 BLOB NOT NULL,
                 envelope BLOB NOT NULL
             ) STRICT, WITHOUT ROWID;
             PRAGMA user_version = 1;",
        )
        .unwrap();
    let stored = bundle(2, 2);
    connection
        .execute(
            "INSERT INTO rule_bundles VALUES ('baseline', 2, ?1, ?2)",
            rusqlite::params![stored.preimage_sha256.to_vec(), stored.envelope],
        )
        .unwrap();
    drop(connection);

    let mut store = open(&path);
    assert_eq!(store.get(&id("baseline")), Ok(Some(bundle(2, 2))));
    assert_eq!(store.is_withdrawn(&id("baseline")), Ok(false));
    store.withdraw(&id("baseline")).unwrap();
    assert_eq!(store.is_withdrawn(&id("baseline")), Ok(true));
    drop(store);
    let version: i64 = Connection::open(&path)
        .unwrap()
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap();
    assert_eq!(version, 2);
}
```

- [ ] **Step 2: Run, see them fail**

Run: `$C test --locked -p openvibes-storage --test rules`
Expected: compile errors `no method named withdraw` / `is_withdrawn`.

- [ ] **Step 3: Implement**

After `SCHEMA_V1`:

```rust
/// Version 2 (P20): a set the platform no longer assigns to this host is
/// marked withdrawn. Its row stays, so the rollback floor holds.
const UPGRADE_V2: &str = "
    ALTER TABLE rule_bundles ADD COLUMN withdrawn INTEGER NOT NULL DEFAULT 0;
    PRAGMA user_version = 2;
";
```

`open`: `let connection = open_database(path, APPLICATION_ID, SCHEMA_V1, &[UPGRADE_V2])?;`

`accept`: the identical-version arm clears the mark and commits, and the insert names its columns (the table now has five):

```rust
        match current {
            Some((floor, _)) if version < floor => return Err(StorageError::Rollback),
            Some((floor, digest)) if version == floor => {
                if digest != bundle.preimage_sha256 {
                    return Err(StorageError::VersionConflict);
                }
                // The same bundle again: re-enabled if it was withdrawn.
                transaction.execute(
                    "UPDATE rule_bundles SET withdrawn = 0 WHERE rule_set_id = ?1",
                    [rule_set_id.as_str()],
                )?;
                return Ok(transaction.commit()?);
            }
            _ => {}
        }
        transaction.execute(
            "INSERT OR REPLACE INTO rule_bundles
             (rule_set_id, version, preimage_sha256, envelope, withdrawn)
             VALUES (?1, ?2, ?3, ?4, 0)",
            params![
                rule_set_id.as_str(),
                version,
                bundle.preimage_sha256,
                bundle.envelope
            ],
        )?;
        Ok(transaction.commit()?)
```

Also update `accept`'s doc: `` Accepting clears a withdrawal (P20), including the identical-version no-op. ``

After `accept`:

```rust
    /// Marks `rule_set_id` withdrawn (P20: the platform no longer assigns
    /// it to this host). Its bundle is no longer used, but the row and so
    /// the rollback floor stay; [`Self::accept`] clears the mark. A set
    /// never stored records nothing.
    pub fn withdraw(&mut self, rule_set_id: &Identifier) -> Result<(), StorageError> {
        self.connection.execute(
            "UPDATE rule_bundles SET withdrawn = 1 WHERE rule_set_id = ?1",
            [rule_set_id.as_str()],
        )?;
        Ok(())
    }

    /// Whether `rule_set_id` is withdrawn; `false` when never stored.
    pub fn is_withdrawn(&self, rule_set_id: &Identifier) -> Result<bool, StorageError> {
        let mark = self
            .connection
            .query_row(
                "SELECT withdrawn FROM rule_bundles WHERE rule_set_id = ?1",
                [rule_set_id.as_str()],
                |row| row.get::<_, i64>(0),
            )
            .optional()?;
        match mark {
            None | Some(0) => Ok(false),
            Some(1) => Ok(true),
            Some(_) => Err(StorageError::Corrupt),
        }
    }
```

- [ ] **Step 4: Run, see them pass**

Run: `$C test --locked -p openvibes-storage`
Expected: PASS (all storage tests, including the existing `rules` ones). `wc -l crates/openvibes-storage/src/rules.rs` < 500.

- [ ] **Step 5: Docs and commit**

`docs/components/openvibes-storage.md`, the `RuleStore` bullet becomes: ``- **`RuleStore` (`rules.sqlite`, schema 2):** the last accepted bundle and rollback floor for each rule set. `withdraw` marks a set the platform no longer assigns (P20): its bundle is no longer used, but the row and so the floor stay, and `accept` (even of the identical version) clears the mark; withdrawing a set never stored records nothing. Schema 1 databases are upgraded in place.``

```bash
set -e
git add crates/openvibes-storage docs/components/openvibes-storage.md
git commit -m "Storage: withdraw a rule set, keeping its floor (P20)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 5: Agent — the project-set table, added at config load

**Files:**
- Create: `crates/openvibes-agent/src/project_sets.rs`
- Modify: `crates/openvibes-agent/src/config.rs` (`RuleSetConfig` ~:72-85, `BASELINE_ALARMS` ~:61, `load_config` after the `let distribution = …;` match ~:279, `scan_config` push ~:311)
- Modify: `crates/openvibes-agent/src/lib.rs` (`mod project_sets;`, `pub use config::{…, RuleSetSource, …}`)
- Create: `crates/openvibes-agent/tests/project_sets.rs` (config part)
- Modify: `crates/openvibes-agent/tests/distribution.rs` (`configured()` helper, ~:126-160)
- Modify: `docs/components/openvibes-agent.md` (Configuration)

**Interfaces:**
- Consumes: `protocol/vectors/project-rule-sets.json` (Task 1).
- Produces: `pub enum RuleSetSource { Configured, Project { assignable: bool } }` (`Clone, Copy, Debug, Eq, PartialEq`), `RuleSetConfig.source: RuleSetSource`; `pub(crate) fn project_sets::add(scan: &mut ScanConfig, linux: bool) -> Result<(), AgentError>`; `pub(crate) const config::BASELINE_ALARMS`; `project_sets::SETS: [(&str, bool, bool); 4]` (id, Linux only, assignable).

- [ ] **Step 1: Write the failing integration test** — `crates/openvibes-agent/tests/project_sets.rs`:

```rust
//! The project's own rule sets (protocol P20): which ones an agent adds,
//! a quiet 404 for an added set, and 410 for an assignable one.

use std::{fs, path::PathBuf};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::SigningKey;
use openvibes_agent::{AgentConfig, RuleSetSource, load_config};

// Test-only seed. No signing credentials are provisioned to the scanner.
fn organization_key() -> SigningKey {
    SigningKey::from_bytes(&[7; 32])
}

fn trusted_keys() -> String {
    let public = URL_SAFE_NO_PAD.encode(organization_key().verifying_key().to_bytes());
    format!("trusted_keys = [{{ issuer_key_id = \"org.rules\", public_key = \"{public}\" }}]")
}

fn dir(test: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("agent-project-sets")
        .join(test);
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// Loads `top` (top-level keys; `CA` names a CA file) and `sets`
/// (`[[rule_sets]]` tables; `BUNDLE` names a bundle file).
fn load(test: &str, top: &str, sets: &str) -> AgentConfig {
    let dir = dir(test);
    fs::write(dir.join("ca.pem"), "read, not parsed, at load\n").unwrap();
    let top = top.replace("CA", &format!("{:?}", dir.join("ca.pem")));
    let sets = sets.replace("BUNDLE", &format!("{:?}", dir.join("baseline.json")));
    let path = dir.join("agent.toml");
    fs::write(
        &path,
        format!("state_dir = {:?}\n{top}\n{sets}", dir.join("state")),
    )
    .unwrap();
    load_config(&path).unwrap()
}

fn listed(config: &AgentConfig) -> Vec<(String, RuleSetSource)> {
    config
        .scan
        .rule_sets
        .iter()
        .map(|set| (set.id.as_str().to_owned(), set.source))
        .collect()
}

const PLATFORM: &str = "platform_url = \"https://p.example\"\nplatform_ca_file = CA";
const ONLINE: &str = "platform_url = \"https://p.example\"\nplatform_ca_file = CA\n\
                      distribution_url = \"https://p.example\"";

#[test]
fn project_sets_are_added_only_with_a_distribution_service() {
    let baseline = format!(
        "[[rule_sets]]\nid = \"baseline\"\nbundle_file = BUNDLE\n{}\n",
        trusted_keys()
    );
    let configured = RuleSetSource::Configured;
    let fixed = RuleSetSource::Project { assignable: false };
    let switched = RuleSetSource::Project { assignable: true };
    let only_baseline = vec![("baseline".to_owned(), configured)];
    assert_eq!(listed(&load("local", "", &baseline)), only_baseline, "local-only");
    assert_eq!(
        listed(&load("platform", PLATFORM, &baseline)),
        only_baseline,
        "no distribution_url: nothing added"
    );

    let linux = [
        ("baseline-alarms".to_owned(), fixed),
        ("hardening-linux-l1".to_owned(), switched),
        ("hardening-linux-l2".to_owned(), switched),
    ];
    let mut expected = only_baseline.clone();
    if cfg!(target_os = "linux") {
        expected.extend(linux.clone());
    }
    assert_eq!(listed(&load("online", ONLINE, &baseline)), expected);

    // Nothing configured: Windows and macOS get only the baseline.
    let mut expected = vec![("baseline".to_owned(), fixed)];
    if cfg!(target_os = "linux") {
        expected.extend(linux);
    }
    assert_eq!(listed(&load("online-empty", ONLINE, "")), expected);
}

#[test]
fn a_configured_project_set_keeps_its_own_keys_and_restricted() {
    let l1 = format!(
        "[[rule_sets]]\nid = \"hardening-linux-l1\"\n{}\nrestricted = false\n",
        trusted_keys()
    );
    let config = load("configured-l1", ONLINE, &l1);
    let l1: Vec<_> = config
        .scan
        .rule_sets
        .iter()
        .filter(|set| set.id.as_str() == "hardening-linux-l1")
        .collect();
    assert_eq!(l1.len(), 1, "never merged with the project's entry");
    assert_eq!(
        (l1[0].source, l1[0].restricted),
        (RuleSetSource::Configured, false)
    );
}
```

- [ ] **Step 2: Run, see it fail**

Run: `$C test --locked -p openvibes-agent --test project_sets`
Expected: compile error `no RuleSetSource in the root`.

- [ ] **Step 3: Implement `config.rs`**

`const BASELINE_ALARMS` becomes `pub(crate) const BASELINE_ALARMS`. Add before `RuleSetConfig`:

```rust
/// Where a rule set's entry came from (rule-set assignment, P20).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuleSetSource {
    /// A `[[rule_sets]]` entry in the configuration file. A 404 or 410
    /// for it is a refused answer.
    Configured,
    /// Added from the agent's own table of project sets
    /// (`project_sets.rs`). `assignable`: the platform may switch it off
    /// for this host with a 410.
    Project {
        /// Hardening sets are; the baseline and the alarms are not.
        assignable: bool,
    },
}
```

`RuleSetConfig`, after `restricted`:

```rust
    /// The configuration file, or the project-set table.
    pub source: RuleSetSource,
```

`scan_config`: the `sets.push(RuleSetConfig { … })` gains `source: RuleSetSource::Configured,`.

`load_config`, after the `let distribution = match … ;` statement and before `Ok(AgentConfig {`:

```rust
    // The project's own sets reach every agent that has a distribution
    // service, with no line here (P20); local-only agents keep exactly
    // their configuration.
    if distribution.is_some() {
        crate::project_sets::add(&mut scan, cfg!(target_os = "linux"))?;
    }
```

`lib.rs`: `mod project_sets;` (after `mod matches;`), and `RuleSetSource` in `pub use config::{ AgentConfig, Collectors, RuleSetConfig, RuleSetSource, ScanConfig, load_config, read_enrollment_token, };`.

- [ ] **Step 4: Create `project_sets.rs` with its unit tests**

```rust
//! The project's own rule sets (rule-set assignment spec, 2026-10-14 §3;
//! protocol P20): compiled in with their public key, so a host gets them
//! with no `agent.toml` line, and the platform decides per host which of
//! the assignable ones run.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use openvibes_core::Identifier;
use openvibes_rules::TrustedRuleKey;

use crate::{AgentError, RuleSetConfig, RuleSetSource, ScanConfig, config::BASELINE_ALARMS};

/// The project's offline rule key, as in the rules repository's `*.key`
/// files (`baseline/baseline.key`, `alarms/alarms.key`,
/// `hardening/linux-l1/hardening-linux-l1.key`). A rotation ships in an
/// agent release, which is how rule keys reach hosts out of band.
const ISSUER: &str = "openvibes-1";
const PUBLIC_KEY: &str = "pKYklRzoYShX_heLdRF9-2opdn36L-L1__T_ZdfvW3I";

/// Id, Linux only, assignable. Keep in step with
/// `protocol/vectors/project-rule-sets.json` (a test checks).
const SETS: [(&str, bool, bool); 4] = [
    ("baseline", false, false),
    ("baseline-alarms", true, false),
    ("hardening-linux-l1", true, true),
    ("hardening-linux-l2", true, true),
];

/// Adds every project set of this OS family (`linux`) that `scan` does not
/// name, fetched from the distribution service only. An entry with the
/// same id wins whole: its keys and `restricted`, never merged. Added sets
/// are restricted except `baseline-alarms`, as for configured ones.
pub(crate) fn add(scan: &mut ScanConfig, linux: bool) -> Result<(), AgentError> {
    let key: [u8; 32] = URL_SAFE_NO_PAD
        .decode(PUBLIC_KEY)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(AgentError::Config)?;
    for (id, linux_only, assignable) in SETS {
        if (linux_only && !linux) || scan.rule_sets.iter().any(|set| set.id.as_str() == id) {
            continue;
        }
        let id = Identifier::new(id).map_err(|_| AgentError::Config)?;
        let issuer = Identifier::new(ISSUER).map_err(|_| AgentError::Config)?;
        scan.trusted_keys.push(
            TrustedRuleKey::new(id.clone(), issuer, key).map_err(|_| AgentError::Config)?,
        );
        scan.rule_sets.push(RuleSetConfig {
            restricted: id.as_str() != BASELINE_ALARMS,
            id,
            bundle_file: None,
            source: RuleSetSource::Project { assignable },
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use openvibes_core::Identifier;

    use super::{SETS, add};
    use crate::{Collectors, RuleSetConfig, RuleSetSource, ScanConfig};

    const FIXED: RuleSetSource = RuleSetSource::Project { assignable: false };
    const SWITCHED: RuleSetSource = RuleSetSource::Project { assignable: true };

    fn empty() -> ScanConfig {
        ScanConfig {
            interval_ms: 3_600_000,
            rule_sets: Vec::new(),
            trusted_keys: Vec::new(),
            collectors: Collectors::default(),
        }
    }

    fn listed(scan: &ScanConfig) -> Vec<(&str, bool, RuleSetSource)> {
        scan.rule_sets
            .iter()
            .map(|set| (set.id.as_str(), set.restricted, set.source))
            .collect()
    }

    #[test]
    fn linux_gets_every_project_set() {
        let mut scan = empty();
        add(&mut scan, true).unwrap();
        assert_eq!(
            listed(&scan),
            [
                ("baseline", true, FIXED),
                ("baseline-alarms", false, FIXED),
                ("hardening-linux-l1", true, SWITCHED),
                ("hardening-linux-l2", true, SWITCHED),
            ]
        );
        assert_eq!(scan.trusted_keys.len(), 4);
    }

    #[test]
    fn other_systems_get_only_the_baseline() {
        let mut scan = empty();
        add(&mut scan, false).unwrap();
        assert_eq!(listed(&scan), [("baseline", true, FIXED)]);
    }

    #[test]
    fn a_configured_entry_wins_whole() {
        let mut scan = empty();
        scan.rule_sets.push(RuleSetConfig {
            id: Identifier::new("hardening-linux-l1").unwrap(),
            bundle_file: None,
            restricted: false,
            source: RuleSetSource::Configured,
        });
        add(&mut scan, true).unwrap();
        assert_eq!(
            listed(&scan)[0],
            ("hardening-linux-l1", false, RuleSetSource::Configured)
        );
        assert_eq!(
            listed(&scan).iter().filter(|(id, ..)| *id == "hardening-linux-l1").count(),
            1
        );
        assert_eq!(scan.trusted_keys.len(), 3, "no project key for the configured set");
    }

    #[test]
    fn the_table_follows_the_protocol_vector() {
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../../../protocol/vectors/project-rule-sets.json"
        ))
        .unwrap();
        let expected: Vec<(String, bool, bool)> = vector["sets"]
            .as_array()
            .unwrap()
            .iter()
            .map(|set| {
                (
                    set["id"].as_str().unwrap().to_owned(),
                    set["os_family"] == "linux",
                    set["assignable"].as_bool().unwrap(),
                )
            })
            .collect();
        let table: Vec<(String, bool, bool)> = SETS
            .iter()
            .map(|&(id, linux, assignable)| (id.to_owned(), linux, assignable))
            .collect();
        assert_eq!(table, expected);
    }
}
```

(`RuleSetSource` and `Collectors` are re-exported at the crate root by `lib.rs`; if the compiler wants `crate::config::…`, use that path.)

- [ ] **Step 5: Keep the distribution tests about configured sets**

In `crates/openvibes-agent/tests/distribution.rs`, add `AgentConfig` and `RuleSetSource` to the `use openvibes_agent::{…}` line, add:

```rust
/// These tests are about configured sets; the project's own sets, which
/// an agent with a distribution service adds (P20), have their own tests
/// in `project_sets.rs`.
fn configured_only(mut config: AgentConfig) -> AgentConfig {
    config
        .scan
        .rule_sets
        .retain(|set| set.source == RuleSetSource::Configured);
    config
}
```

and in `configured()` replace `Service::open(load_config(&config).unwrap()).unwrap()` with `Service::open(configured_only(load_config(&config).unwrap())).unwrap()`. Without this, the mock's one-handler-per-request list is consumed by the added sets' requests on Linux.

- [ ] **Step 6: Run, see it pass**

Run: `$C test --locked -p openvibes-agent --lib project_sets && $C test --locked -p openvibes-agent --test project_sets --test distribution`
Expected: PASS.

- [ ] **Step 7: Docs and commit**

`docs/components/openvibes-agent.md`, "Configuration", after the `process_events_source` paragraph:

```markdown
**The project's rule sets (P20).** The agent carries a table of the
project's own rule sets and their public key (issuer `openvibes-1`, the
key the rules repository signs every set with; `src/project_sets.rs`):

| Set | OS | Assignable |
|---|---|---|
| `baseline` | any | no |
| `baseline-alarms` | Linux | no |
| `hardening-linux-l1` | Linux | yes |
| `hardening-linux-l2` | Linux | yes |

With a `distribution_url`, the agent adds every set of its own OS that the
configuration does not name, fetched from the distribution service only.
A `[[rule_sets]]` entry with the same id wins whole: its keys and
`restricted` are used, never merged with the project's. Added sets are
restricted except `baseline-alarms`, as configured ones are. Without a
`distribution_url` nothing is added. A key rotation ships in an agent
release. What a 404 or 410 means for each set: see Failure behaviour.
```

```bash
set -e
git add crates/openvibes-agent docs/components/openvibes-agent.md
git commit -m "Agent: the project's rule sets, added with a distribution service (P20)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 6: Agent — quiet 404, 410 "not assigned", health, matches

**Files:**
- Modify: `crates/openvibes-agent/src/project_sets.rs` (add `Withdrawn`, `withdrawn`, vector test)
- Modify: `crates/openvibes-agent/src/scan.rs` (imports, `ScanReport` impl, `scan` loop ~:96-120, `current_bundle` ~:316-391, test module ~:393-460)
- Create: `crates/openvibes-agent/src/scan/tests.rs`
- Modify: `crates/openvibes-agent/src/service.rs` (`scan_if_due`, the `EvaluatedScan { configured: … }` ~:328-337)
- Modify: `crates/openvibes-agent/tests/project_sets.rs` (add `mod scans`)
- Modify: `docs/components/openvibes-agent.md` (health bullet ~:113, Failure behaviour ~:333), `AGENTS.md` (openvibes-agent architecture bullet)

**Interfaces:**
- Consumes: `TransportError::{NotFound, NotAssigned}` (Task 2), `RuleSetState`, `RuleSetHealth.state` (Task 3), `RuleStore::{withdraw, is_withdrawn}` (Task 4), `RuleSetSource`, `SETS` (Task 5).
- Produces: `pub(crate) enum project_sets::Withdrawn { NotOffered, NotAssigned }`; `pub(crate) fn project_sets::withdrawn(source: RuleSetSource, error: TransportError) -> Option<Withdrawn>`; `pub(crate) fn ScanReport::running_sets(&self) -> BTreeSet<Identifier>`.

- [ ] **Step 1: Move `scan.rs`'s unit tests out (460 lines)**

Create `crates/openvibes-agent/src/scan/tests.rs` with exactly the body of `mod tests { … }` at the end of `scan.rs` (its `use` lines, `finding`, `load_errors_map_to_refusal_codes`, `a_full_queue_keeps_the_newest_findings`), and replace that block with `#[cfg(test)]\nmod tests;`. In the moved file, the path `env!("CARGO_MANIFEST_DIR")` joins stay the same.

Run: `$C test --locked -p openvibes-agent --lib scan`
Expected: PASS (2 tests).

- [ ] **Step 2: Write the failing unit tests**

Append to `crates/openvibes-agent/src/scan/tests.rs`:

```rust
#[test]
fn a_set_no_longer_assigned_is_not_running() {
    use openvibes_core::{RuleSetHealth, RuleSetState};
    let set = |name: &str, state| RuleSetHealth {
        id: Identifier::new(name).unwrap(),
        version: None,
        expires_at_unix_ms: None,
        refused: None,
        state,
    };
    let report = ScanReport {
        rule_sets: vec![
            set("baseline", None),
            set("hardening-linux-l1", Some(RuleSetState::NotAssigned)),
        ],
        ..ScanReport::default()
    };
    // Its matches end (P13), so switching it back on starts them again.
    let running: Vec<String> = report
        .running_sets()
        .into_iter()
        .map(|id| id.as_str().to_owned())
        .collect();
    assert_eq!(running, ["baseline"]);
}
```

Append to `project_sets.rs`'s `mod tests` (and add `withdrawn, Withdrawn` to its `use super::{…}`, plus `use openvibes_transport::TransportError;`):

```rust
    #[test]
    fn the_answers_follow_the_protocol_vector() {
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../../../protocol/vectors/project-rule-sets.json"
        ))
        .unwrap();
        for case in vector["cases"].as_array().unwrap() {
            let id = case["rule_set_id"].as_str().unwrap();
            let source = if case["configured"].as_bool().unwrap() {
                RuleSetSource::Configured
            } else {
                let &(_, _, assignable) = SETS.iter().find(|(set, ..)| *set == id).unwrap();
                RuleSetSource::Project { assignable }
            };
            let error = match case["status"].as_u64().unwrap() {
                404 => TransportError::NotFound,
                410 => TransportError::NotAssigned,
                other => panic!("status {other}"),
            };
            let agent = match withdrawn(source, error) {
                None => "refused",
                Some(Withdrawn::NotOffered) => "not_offered",
                Some(Withdrawn::NotAssigned) => "not_assigned",
            };
            assert_eq!(agent, case["agent"].as_str().unwrap(), "{}", case["name"]);
        }
    }
```

- [ ] **Step 3: Write the failing service tests**

Append to `crates/openvibes-agent/tests/project_sets.rs`:

```rust
/// Scans against a mock distribution service. Linux only: elsewhere the
/// only project set is the baseline, configured here.
#[cfg(target_os = "linux")]
mod scans {
    use std::{
        fs,
        sync::{Arc, mpsc},
    };

    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use ed25519_dalek::Signer;
    use openvibes_agent::{AgentError, ScanReport, Service, load_config};
    use openvibes_core::{
        Confidence, EnrollmentResponse, Identifier, PayloadEncoding, ResourceLimits, Rule,
        RuleBundleRequest, RuleSet, RuleSetState, SchemaVersion, Severity, SignedRuleEnvelope,
    };
    use openvibes_rules::{TrustedRuleKey, signing_preimage};
    use openvibes_testkit::{Handler, Pki, Reply, Seen, json, serve, status};
    use openvibes_transport::TransportError;
    use sha2::{Digest, Sha256};

    use super::{dir, organization_key, trusted_keys};

    const NOW: i64 = 1_800_000_000_000;
    const HOUR: i64 = 3_600_000;
    const L1: &str = "hardening-linux-l1";

    fn id(value: &str) -> Identifier {
        Identifier::new(value).unwrap()
    }

    /// A `set` bundle signed with the test key; its one rule always matches.
    fn bundle(set: &str, version: u64) -> Vec<u8> {
        let payload = serde_json::to_string(&RuleSet {
            schema_version: SchemaVersion::V1,
            rules: vec![Rule {
                id: id("host.has.processes"),
                version: 1,
                title: "Processes are running".into(),
                severity: Severity::Info,
                confidence: Confidence::new(100).unwrap(),
                expression: "facts['process.count'] >= 1".into(),
                finding_message: "The host runs processes".into(),
                kind: openvibes_core::RuleKind::Snapshot,
                programs: None,
                attack: None,
            }],
        })
        .unwrap();
        let mut envelope = SignedRuleEnvelope {
            schema_version: SchemaVersion::V1,
            rule_set_id: id(set),
            rule_set_version: version,
            issuer_key_id: id("org.rules"),
            created_at_unix_ms: NOW - HOUR,
            expires_at_unix_ms: NOW + 100 * HOUR,
            payload_encoding: PayloadEncoding::Json,
            payload_sha256_hex: Sha256::digest(payload.as_bytes())
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
            payload,
            signature_base64url: String::new(),
        };
        let preimage = signing_preimage(&envelope, ResourceLimits::V1).unwrap();
        envelope.signature_base64url =
            URL_SAFE_NO_PAD.encode(organization_key().sign(&preimage).to_bytes());
        serde_json::to_vec(&envelope).unwrap()
    }

    fn raw(status: u16, body: Vec<u8>) -> Handler {
        Box::new(move |_: &Seen| Reply {
            status,
            headers: "",
            body,
            stall: false,
        })
    }

    fn not_found() -> Handler {
        raw(404, Vec::new())
    }

    fn gone() -> Handler {
        raw(410, Vec::new())
    }

    fn unchanged() -> Handler {
        raw(204, Vec::new())
    }

    /// Per scan, in request order: baseline (configured), then the added
    /// baseline-alarms, hardening-linux-l1, hardening-linux-l2.
    fn scans(answers: Vec<[Handler; 4]>) -> Vec<Handler> {
        answers.into_iter().flatten().collect()
    }

    /// Enrollment, then one heartbeat.
    fn ingest(pki: &Arc<Pki>) -> Vec<Handler> {
        let issuer = pki.clone();
        vec![
            Box::new(move |seen: &Seen| {
                let request: serde_json::Value = serde_json::from_slice(&seen.body).unwrap();
                json(&EnrollmentResponse {
                    schema_version: SchemaVersion::V1,
                    agent_id: id("agent.1"),
                    certificate_chain_pem: vec![
                        issuer.issue_client(request["csr_pem"].as_str().unwrap()),
                    ],
                    expires_at_unix_ms: NOW + 1_000 * HOUR,
                })
            }),
            Box::new(|_: &Seen| status(204)),
        ]
    }

    /// An enrolled agent: `baseline` configured with the test key, the
    /// project sets added. The project key's private half is offline, so
    /// L1 also trusts the test key, under its own issuer id.
    fn enrolled(test: &str, pki: &Arc<Pki>, distribution_url: &str) -> Service {
        let dir = dir(test);
        fs::write(dir.join("ca.pem"), pki.roots_pem()).unwrap();
        fs::write(dir.join("token"), "one-time\n").unwrap();
        fs::set_permissions(
            dir.join("token"),
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        )
        .unwrap();
        let (ingest_url, _) = serve(pki.server_config(false, false), ingest(pki));
        let path = dir.join("agent.toml");
        fs::write(
            &path,
            format!(
                "platform_url = {ingest_url:?}\nplatform_ca_file = {:?}\nstate_dir = {:?}\n\
                 enrollment_token_file = {:?}\ndistribution_url = {distribution_url:?}\n\
                 [[rule_sets]]\nid = \"baseline\"\n{}\n",
                dir.join("ca.pem"),
                dir.join("state"),
                dir.join("token"),
                trusted_keys(),
            ),
        )
        .unwrap();
        let mut config = load_config(&path).unwrap();
        let public = organization_key().verifying_key().to_bytes();
        config
            .scan
            .trusted_keys
            .push(TrustedRuleKey::new(id(L1), id("org.rules"), public).unwrap());
        let mut service = Service::open(config).unwrap();
        service.tick(NOW).unwrap();
        service
    }

    /// Each fetch: the set asked for and the version the agent held.
    fn asked(seen: &mpsc::Receiver<Seen>) -> Vec<(String, Option<u64>)> {
        seen.try_iter()
            .map(|seen| {
                let request: RuleBundleRequest = serde_json::from_slice(&seen.body).unwrap();
                (request.rule_set_id.as_str().to_owned(), request.current_version)
            })
            .collect()
    }

    fn versions(asked: &[(String, Option<u64>)], set: &str) -> Vec<Option<u64>> {
        asked
            .iter()
            .filter(|(name, _)| name == set)
            .map(|(_, version)| *version)
            .collect()
    }

    /// A set's health: (version, state); `None` when not listed.
    fn health(report: &ScanReport, set: &str) -> Option<(Option<u64>, Option<RuleSetState>)> {
        report
            .rule_sets
            .iter()
            .find(|health| health.id.as_str() == set)
            .map(|health| (health.version, health.state))
    }

    #[test]
    fn an_older_platform_without_the_project_sets_sees_no_change() {
        let pki = Arc::new(Pki::new());
        let (url, seen) = serve(
            pki.server_config(true, false),
            scans(vec![[
                raw(200, bundle("baseline", 1)),
                not_found(),
                not_found(),
                not_found(),
            ]]),
        );
        let mut service = enrolled("older-platform", &pki, &url);
        let report = service.scan_if_due(NOW).unwrap().unwrap();
        assert_eq!(report.matched, 1);
        assert!(report.rule_set_errors.is_empty(), "{:?}", report.rule_set_errors);
        assert_eq!(report.rules_retry_in_s, None, "nothing to fetch again early");
        let listed: Vec<&str> = report.rule_sets.iter().map(|set| set.id.as_str()).collect();
        assert_eq!(listed, ["baseline"], "a set not offered is not in health");
        let sets: Vec<String> = asked(&seen).into_iter().map(|(set, _)| set).collect();
        assert_eq!(sets, ["baseline", "baseline-alarms", L1, "hardening-linux-l2"]);
    }

    #[test]
    fn an_unassigned_set_stops_and_comes_back() {
        let pki = Arc::new(Pki::new());
        let (url, seen) = serve(
            pki.server_config(true, false),
            scans(vec![
                [raw(200, bundle("baseline", 1)), not_found(), raw(200, bundle(L1, 1)), not_found()],
                [unchanged(), not_found(), gone(), not_found()],
                [unchanged(), not_found(), raw(200, bundle(L1, 1)), not_found()],
            ]),
        );
        let mut service = enrolled("not-assigned", &pki, &url);
        let first = service.scan_if_due(NOW).unwrap().unwrap();
        assert_eq!(first.matched, 2, "baseline and L1");
        assert_eq!(health(&first, L1), Some((Some(1), None)));

        let off = service.scan_if_due(NOW + HOUR).unwrap().unwrap();
        assert_eq!(off.matched, 1, "L1 no longer runs");
        assert!(off.rule_set_errors.is_empty(), "{:?}", off.rule_set_errors);
        assert_eq!(health(&off, L1), Some((None, Some(RuleSetState::NotAssigned))));

        let on = service.scan_if_due(NOW + 2 * HOUR).unwrap().unwrap();
        assert_eq!(on.matched, 2, "switched back on: the next scan runs it");
        assert_eq!(health(&on, L1), Some((Some(1), None)));
        assert_eq!(
            versions(&asked(&seen), L1),
            [None, Some(1), None],
            "withdrawn: asked without current_version, so the same v1 comes back as 200"
        );
    }

    #[test]
    fn a_reassigned_set_keeps_its_rollback_floor() {
        let pki = Arc::new(Pki::new());
        let (url, _) = serve(
            pki.server_config(true, false),
            scans(vec![
                [raw(200, bundle("baseline", 1)), not_found(), raw(200, bundle(L1, 2)), not_found()],
                [unchanged(), not_found(), gone(), not_found()],
                [unchanged(), not_found(), raw(503, Vec::new()), not_found()],
                [unchanged(), not_found(), raw(200, bundle(L1, 1)), not_found()],
                [unchanged(), not_found(), raw(200, bundle(L1, 2)), not_found()],
            ]),
        );
        let mut service = enrolled("reassigned-floor", &pki, &url);
        assert_eq!(service.scan_if_due(NOW).unwrap().unwrap().matched, 2);
        assert_eq!(service.scan_if_due(NOW + HOUR).unwrap().unwrap().matched, 1);

        // Platform unreachable: a withdrawn set never falls back to its
        // stored bundle.
        let outage = service.scan_if_due(NOW + 2 * HOUR).unwrap().unwrap();
        assert_eq!(outage.matched, 1, "L1 stays off");
        assert_eq!(health(&outage, L1), Some((None, None)));

        // Switched on again with an older bundle: refused against the kept
        // floor, and still nothing runs.
        let older = service.scan_if_due(NOW + 3 * HOUR).unwrap().unwrap();
        assert_eq!(older.matched, 1, "a switch-off/on cannot roll L1 back");
        assert!(
            older
                .rule_set_errors
                .contains(&(id(L1), AgentError::Rules(openvibes_rules::LoadError::Rollback))),
            "{:?}",
            older.rule_set_errors
        );

        // The version it had (or newer) is accepted and runs again.
        let back = service.scan_if_due(NOW + 4 * HOUR).unwrap().unwrap();
        assert_eq!(back.matched, 2);
        assert_eq!(health(&back, L1), Some((Some(2), None)));
    }

    #[test]
    fn a_410_for_a_set_that_is_not_assignable_is_refused() {
        let pki = Arc::new(Pki::new());
        let (url, seen) = serve(
            pki.server_config(true, false),
            scans(vec![
                [raw(200, bundle("baseline", 1)), not_found(), not_found(), not_found()],
                [gone(), gone(), not_found(), not_found()],
                [unchanged(), not_found(), not_found(), not_found()],
            ]),
        );
        let mut service = enrolled("not-assignable", &pki, &url);
        service.scan_if_due(NOW).unwrap().unwrap();

        let refused = service.scan_if_due(NOW + HOUR).unwrap().unwrap();
        assert_eq!(refused.matched, 1, "the stored baseline keeps running");
        assert_eq!(
            refused.rule_set_errors,
            [
                (id("baseline"), AgentError::Transport(TransportError::Rejected)),
                (id("baseline-alarms"), AgentError::Transport(TransportError::Rejected)),
            ]
        );
        assert_eq!(health(&refused, "baseline"), Some((Some(1), None)));

        service.scan_if_due(NOW + 2 * HOUR).unwrap().unwrap();
        assert_eq!(
            versions(&asked(&seen), "baseline"),
            [None, Some(1), Some(1)],
            "its bundle and floor were kept"
        );
    }
}
```

(`sha2`, `base64`, `serde_json`, `openvibes_rules`, `openvibes_core`, `openvibes_transport` are already used by `tests/distribution.rs`, so they resolve in this test crate.)

- [ ] **Step 4: Run, see them fail**

Run: `$C test --locked -p openvibes-agent --lib && $C test --locked -p openvibes-agent --test project_sets`
Expected: compile errors (`running_sets`, `withdrawn`, `Withdrawn` missing); after stubbing, `scans::*` fail (404 reported as `Rejected`, 410 not honoured).

- [ ] **Step 5: Implement `withdrawn`** (in `project_sets.rs`, after `add`; add `use openvibes_transport::TransportError;`)

```rust
/// What a 404 or 410 from the distribution service means for one set (P20).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Withdrawn {
    /// 404 for an added set: not published here. Nothing runs and nothing
    /// is reported; asked again next scan.
    NotOffered,
    /// 410 for an assignable added set: not assigned to this host. The
    /// set stops, its stored bundle is withdrawn (floor kept), health says so.
    NotAssigned,
}

/// `None`: a refused answer, like any other 4xx. A platform can never
/// withdraw the baseline, the alarms, a site set or a configured entry.
pub(crate) fn withdrawn(source: RuleSetSource, error: TransportError) -> Option<Withdrawn> {
    match (source, error) {
        (RuleSetSource::Project { .. }, TransportError::NotFound) => Some(Withdrawn::NotOffered),
        (RuleSetSource::Project { assignable: true }, TransportError::NotAssigned) => {
            Some(Withdrawn::NotAssigned)
        }
        _ => None,
    }
}
```

- [ ] **Step 6: Implement in `scan.rs`**

Imports: `collections::{BTreeMap, BTreeSet}`; add `RuleSetState` to the `openvibes_core::{…}` list; `use openvibes_transport::{PlatformClient, TransportError};`; `use crate::project_sets::{Withdrawn, withdrawn};`.

After the `ScanReport` struct:

```rust
impl ScanReport {
    /// The rule sets running on this host after this scan: every listed
    /// set except one the platform no longer assigns (P20). The others'
    /// matches end (P13), so switching a set back on starts them again.
    pub(crate) fn running_sets(&self) -> BTreeSet<Identifier> {
        self.rule_sets
            .iter()
            .filter(|set| set.state != Some(RuleSetState::NotAssigned))
            .map(|set| set.id.clone())
            .collect()
    }
}
```

In `scan`, the head of the `for set in &config.rule_sets` loop becomes:

```rust
    for set in &config.rule_sets {
        let (bundle, errors) = match current_bundle(set, client, loader, store, now_unix_ms) {
            Ok(current) => current,
            // Not published here (an older platform, or no rules package):
            // nothing runs, nothing is reported.
            Err(Withdrawn::NotOffered) => continue,
            Err(Withdrawn::NotAssigned) => {
                // Stop using the stored bundle, so neither its expiry nor
                // a platform outage keeps it running; its row stays, so
                // the rollback floor holds when the set is switched back on.
                if let Err(error) = store.withdraw(&set.id) {
                    report
                        .rule_set_errors
                        .push((set.id.clone(), AgentError::Storage(error)));
                }
                report.rule_sets.push(RuleSetHealth {
                    id: set.id.clone(),
                    version: None,
                    expires_at_unix_ms: None,
                    refused: None,
                    state: Some(RuleSetState::NotAssigned),
                });
                continue;
            }
        };
        report.rule_sets.push(RuleSetHealth {
```

(the rest of the loop body is unchanged).

`current_bundle`: change the doc's last sentence to add `` `Err` when the platform withdrew a project set (P20). `` and the signature and body as follows (only the marked lines change):

```rust
fn current_bundle(
    set: &RuleSetConfig,
    client: Option<&PlatformClient>,
    loader: &RuleLoader,
    store: &mut RuleStore,
    now_unix_ms: i64,
) -> Result<(Option<VerifiedRuleSet>, Vec<AgentError>), Withdrawn> {
    let stored = match store.get(&set.id) {
        Ok(stored) => stored,
        Err(error) => return Ok((None, vec![AgentError::Storage(error)])),
    };
    let mut floor = match &stored {
        Some(stored) => {
            match AcceptedVersion::restore(set.id.clone(), stored.version, stored.preimage_sha256) {
                Ok(floor) => Some(floor),
                Err(_) => return Ok((None, vec![AgentError::Storage(StorageError::Corrupt)])),
            }
        }
        None => None,
    };
    // Withdrawn (P20): ask without current_version, so a platform holding
    // the same version answers 200 rather than 204; the floor still
    // applies to whatever comes back (the loader's and `accept`'s checks).
    let was_withdrawn = match store.is_withdrawn(&set.id) {
        Ok(withdrawn) => withdrawn,
        Err(error) => return Ok((None, vec![AgentError::Storage(error)])),
    };
    let mut errors = Vec::new();
    let mut accepted = None;
    let current_version = if was_withdrawn {
        None
    } else {
        floor.as_ref().map(AcceptedVersion::version)
    };
    for (from_file, candidate) in candidates(set, client, current_version) {
        let bytes = match candidate {
            Ok(Some(bytes)) => bytes,
            Ok(None) => continue,
            Err(AgentError::Transport(
                error @ (TransportError::NotFound | TransportError::NotAssigned),
            )) => {
                if let Some(withdrawn) = withdrawn(set.source, error) {
                    return Err(withdrawn);
                }
                // Refused like any other 4xx: the last accepted bundle
                // keeps running.
                errors.push(AgentError::Transport(TransportError::Rejected));
                continue;
            }
            Err(error) => {
                errors.push(error);
                continue;
            }
        };
        // … unchanged: LoadContext, load_json, store.accept …
    }
    // A withdrawn set never falls back to its stored bundle: it runs again
    // only once a fetched (or provisioned) bundle is accepted, which
    // clears the mark.
    if accepted.is_none() && !was_withdrawn {
        // … unchanged: re-verify the stored envelope …
    }
    Ok((accepted, errors))
}
```

- [ ] **Step 7: Implement in `service.rs`**

In `scan_if_due`, the `if self.changes_mode() { … }` block becomes:

```rust
        if self.changes_mode() {
            // A set the platform no longer assigns (P20), or does not
            // publish, is not running: its matches end, so switching it
            // back on starts them again.
            let running = report.running_sets();
            self.matches.observe(&EvaluatedScan {
                scanned_at_unix_ms: now_unix_ms,
                configured: running,
                evaluated: std::mem::take(&mut report.evaluated),
            });
            self.save_matches();
        }
```

- [ ] **Step 8: Run, see them pass**

Run: `$C test --locked -p openvibes-agent`
Expected: PASS, all test files (`distribution`, `project_sets`, `service`, `vertical_slice`, …). `wc -l crates/openvibes-agent/src/scan.rs crates/openvibes-agent/src/project_sets.rs` both < 500.

- [ ] **Step 9: Docs and commit**

`docs/components/openvibes-agent.md`:
- Health bullet becomes: ``- each rule set's version and expiry in use, why its last bundle was refused, and `state: not_assigned` for a set the platform no longer assigns (P20);``
- "Failure behaviour", after the paragraph that starts "Scanning with the distribution service":

```markdown
Project sets (P20): for a set the agent added, a 404 from the
distribution service means the platform does not publish it (an older
platform, or one without the rules package): the set runs nothing, is
left out of health, raises no error and no early retry, and is asked for
again at the next scan. A 410 for an assignable added set
(`hardening-linux-l1`, `-l2`) means the platform no longer assigns it to
this host: the agent stops evaluating it and marks its stored bundle
withdrawn (`RuleStore::withdraw`), so neither its expiry nor a platform
outage keeps it running; the rollback floor is kept. Its matches end
(P13), and health lists it with `state: not_assigned`. It asks again at
every scan, without `current_version`, so a 200 on a later scan brings it
back; that bundle must still be at or above the kept floor, so a
switch-off and on cannot roll the set back. For
every other set (the baseline, the alarms, a site set, or any set the
configuration names) a 404 or 410 is reported as `Rejected` like any
other refusal and the last accepted bundle keeps running: a platform
cannot remove the baseline.
```

`AGENTS.md`, in the `openvibes-agent` bullet, `it resolves each configured `[[rule_sets]]` bundle` becomes `it resolves each configured `[[rule_sets]]` bundle and, with a distribution service, each project set it adds (`project_sets.rs`, P20: a quiet 404, 410 "not assigned" for assignable sets)`.

```bash
set -e
git add crates/openvibes-agent docs/components/openvibes-agent.md AGENTS.md
git commit -m "Agent: quiet 404 for project sets, 410 not assigned (P20)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 7: Gate, final protocol pin, pull requests

**Files:**
- Modify: `protocol` submodule pin (agent)

- [ ] **Step 1: Protocol PR first**

```bash
set -e
cd /home/lime/Projects/OpenVIBES/openvibes-protocol-p20
git fetch -q origin && git rebase origin/main
.venv/bin/python tools/validate.py
git push -u origin p20-not-assigned
gh pr create --title "P20: 410 not assigned, health state, project rule sets" --body "$(cat <<'EOF'
Rule-set assignment (openvibes-platform docs/specs/2026-10-14-rule-set-assignment-design.md §4):
`410 Gone` on `/v1/rule-bundle` for an assignable project set, health `rule_sets[].state` `not_assigned`, and `vectors/project-rule-sets.json` (the project's sets and the 404/410 cases).

Validation: `tools/validate.py` 0 failures; agent tests with the submodule on this branch: green.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

Wait for its CI and merge (the user merges).

- [ ] **Step 2: Re-pin the agent to protocol `main` and rebase**

```bash
set -e
cd /home/lime/Projects/OpenVIBES/openvibes-agent-p20
git fetch -q origin && git rebase origin/main      # after #71, #72, #73
cd protocol && git fetch -q origin main && git checkout -q origin/main && cd ..
git -C protocol log --oneline -1                   # the P20 merge
git add protocol
git commit -m "Pin protocol: P20 merged

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

- [ ] **Step 3: Full agent gate**

```bash
set -e
C="env CARGO_TARGET_DIR=$HOME/.cache/openvibes-scratch/target nice -n 19 cargo"
$C fmt --all --check
$C clippy --locked --workspace --all-targets --all-features -- -D warnings -F unsafe-code
$C test --locked --workspace --all-features
RUSTDOCFLAGS="-D warnings" $C doc --locked --workspace --all-features --no-deps
$C audit --deny warnings
```

Expected: all green. A Windows/macOS-only failure cannot be seen here: `tests/project_sets.rs`'s `scans` module is Linux-only and the config test expects only `baseline` elsewhere; watch those CI jobs.

- [ ] **Step 4: Agent PR**

```bash
set -e
git push -u origin p20-project-sets
gh pr create --title "Project rule sets and 410 not assigned (P20)" --body "$(cat <<'EOF'
Rule-set assignment, agent side (spec §3, §4):
- the project's rule sets (baseline, baseline-alarms, hardening-linux-l1/-l2) and their key are compiled in; with a distribution_url the agent adds the ones of its OS that agent.toml does not name (a configured entry wins whole);
- 404 for an added set is quiet (older platforms see no change);
- 410 for an assignable added set stops it, marks its stored bundle withdrawn (rollback floor kept: re-assignment asks without current_version and accepts only at or above the floor), ends its matches and reports health `state: not_assigned`; asked again every scan;
- 410 for anything else is refused like other 4xx: the platform cannot remove the baseline.

Validation: fmt, clippy -D warnings -F unsafe-code, test --workspace --all-features, doc, audit: green locally (Linux).

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
gh pr checks --watch
```

---

## Self-review notes (rulings on the spec)

- Health `state` is a new optional field on each `rule_sets` entry, not a `refused` code: older readers treat an unknown `refused` as `invalid` (a health problem), and they ignore unknown fields.
- A set answered 404 is left out of health and out of the running sets (its matches end); its stored bundle is kept and not marked (only a 410 withdraws).
- The 410 "fixtures" are cases in `vectors/project-rule-sets.json` (a 410 has no body to fixture), checked by `validate.py` and run by the agent's unit test; the heartbeat gets valid/invalid `state` fixtures.
- "A configured entry" (§4) is read as any set `agent.toml` names, including an assignable id: its 410 is refused.
- OS family is the build target (`cfg!(target_os = "linux")`), not a runtime os-release read.
- Ruling (controller): withdrawal keeps the rollback floor; re-assignment requests with no current_version and accepts only at or above the floor — a platform cannot use a switch-off/on to roll a set back. Storage: schema 2 adds `rule_bundles.withdrawn`; `accept` (even the identical-version no-op) clears it; a withdrawn set never falls back to its stored bundle.
- The project key is not copied into the protocol: it lives in the agent (and the rules repository's `*.key` files).
