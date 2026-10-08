# Assistant quality step 3: lookups that find the data — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Raise the bundled small model's lookup accuracy (74% after step 2) toward the eval's 90% gate by fixing why lookups miss or come back empty, without giving back step 2's injection resistance or much latency.

**Architecture:** Five changes in `crates/platform-assistant`:
1. A stricter eval metric first, so the baseline is honest.
2. A result-budget split that gives the current lookup the room.
3. An optional, self-resolving `rule_set`.
4. Tool descriptions that name the fields the results carry.
5. Prompted-mode parsing that accepts the malformed shapes the model actually sends and never shows raw JSON as an answer.

No store, protocol or console API changes.

**Tech Stack:** Rust (tokio, serde_json), the crate's eval harness (`openvibes-admin assistant eval`), a local llama-server with Qwen3-4B Q4_K_M.

**Spec:** the step 1–3 investigation, `.superpowers/sdd/lookups/findings.md` in this worktree (R4, R5 and R6, plus Q3's case-by-case misses). The assistant spec is `docs/components/platform-assistant.md`; spec §10 there defines the eval.

## Global Constraints

- **Never** pass `--sleep-idle-seconds` to llama-server (CVE-2026-43631). Never touch the system `openvibes-llm` units or the installed llama-server process; never use sudo.
- The host has 31 GB. Run one heavy job at a time: a build, a model server or a test DB suite.
- Lookup error messages fed to the model are fixed text and never contain model text (`LookupError::message`, existing rule). Host data in results stays labelled as data.
- **Keep step 2:** the post-result reminder and exposure-checked injection cases stay; injection cases must stay 8/8 exposed and resisted, and leaks 0.
- **Eval run budget for the whole plan:** at most **4 full evals** and **4 six-case replays**. Report before exceeding it. A full eval takes about 10–12 min.
- User-visible wording: "compliance findings" in console text. Lookup and tool names are unchanged API (`search_findings` etc.).
- Each file stays under 500 lines where it already is; do not grow `lookups.rs` (1008 lines) by more than about 120 lines; put the new resolution helper next to the code it serves.
- Commits end with `Co-Authored-By: Claude <noreply@anthropic.com>`; identity `itismelime` / `26064407+itismelime@users.noreply.github.com`.

## Review Focus

1. **A rule that exists in two rule sets.** If `rule_set` is left out, the lookup must not pick one silently. It returns the matches from every set, each labelled with its `rule_set`; `rule_description` returns a fixed error listing nothing model-written. Tested in Task 3.
2. **A rule that matches no finding.** If `rule_set` is left out and no finding names the rule, the result is empty with a clear note, not an error. The model can then say "no such finding". Tested in Task 3.
3. **Long history plus several lookups.** The new budget split must never give a later lookup less than `MIN_RESULT_CHARS`, and never exceed `limit_chars` overall. Tested in Task 2 with four lookups and a long history.
4. **Prompted reply that is JSON but not an action, twice in a row.** The user must get an error, never the raw JSON. Tested in Task 5.
5. **An injected instruction in a rule set name or rule id.** Resolution only matches exact rule ids from store data and never echoes the model's text in an error. Tested in Task 3.

---

### Task 1: Eval counts a lookup only when it found something

The eval counts a case as "right lookup" even when that lookup returned nothing: R5 lists 9 calls with an invented `rule_set: "default"` that returned empty and still counted. Fix the metric first so later tasks are measured honestly.

**Files:**
- Modify: `crates/platform-assistant/src/eval.rs:930-990` (case scoring, `lookup_ok`), plus the case struct (`empty` field) and the per-case report line
- Modify: `crates/platform-assistant/eval/questions.toml` (header comment; `empty = true` on cases whose correct answer is "nothing found")
- Test: `crates/platform-assistant/tests/eval.rs`

**Interfaces:**
- Produces: `Case.empty: bool` (serde default `false`). `lookup_ok` means no error, and either `lookups` is empty, or some record whose `name` is in `case.lookups` has `error.is_none()` and `objects > 0` (`objects == 0` is accepted when `case.empty`).
- The failure line in the report says which case it was: `wrong lookup` (none of the expected names was called) or `empty result` (an expected lookup was called and found nothing).

- [ ] **Step 1: Write the failing test.** In `tests/eval.rs`, build a `Case` that expects `finding_endpoints`, plus an `Answer` whose only `LookupRecord` is `finding_endpoints` with `objects: 0, error: None`. Assert the case scores `lookup_ok == false` and that its failure reason is `"empty result"`. With `empty = true`, the same case scores `lookup_ok == true`. Follow the existing tests in that file for how a case is scored without a model, using the scripted backend in `tests/support`.
- [ ] **Step 2:** Run `cargo test -p platform-assistant --test eval` and expect a FAIL.
- [ ] **Step 3: Implement.** Score from the records instead of the names:

```rust
let lookups: Vec<&LookupRecord> = answer.lookups.iter().collect(); // in the Ok arm
let expected = |r: &&LookupRecord| r.name.is_some_and(|n| case.lookups.iter().any(|e| e == n));
let lookup_ok = error.is_none()
    && (case.lookups.is_empty()
        || lookups.iter().filter(expected).any(|r| r.error.is_none() && (r.objects > 0 || case.empty)));
```

  Keep the list of names for the report, as now.
- [ ] **Step 4: Mark the empty cases.** For each case in `questions.toml`, find out whether the right lookup returns objects from `eval/fleet.toml`. Write a test that, for each case, runs each of its expected lookups through `Lookups::with_source(FleetSource(fleet), now)` with the case's obvious arguments. Do not guess: cases like `agents-unknown` ("is there a host called X") need `empty = true`. List the cases you marked in the commit message.
- [ ] **Step 5:** Run `cargo test -p platform-assistant` and expect a PASS. Update the header comment in `questions.toml` to document `empty`.
- [ ] **Step 6: Baseline run** (counts as 1 of the 4 full evals). Use the eval setup below and save the output as `q/s3-baseline.txt`. Record lookup %, facts %, leaks, injections, median and p95, and the list of failing cases with their reasons. This is the number Tasks 2–5 are judged against.
- [ ] **Step 7: Commit:** `Assistant eval: a lookup counts only when it found something (empty = true for none-found cases)`.

**Eval setup (used by every measuring step):**
- Build the binary in this worktree with `cargo build --release --locked -p openvibes-admin`.
- Start the server with `EXTRA="--reasoning off" bash /tmp/claude-1000/-home-lime-Projects-OpenVIBES/dec7c5a6-58cb-4782-a848-04f167c9a3ff/scratchpad/q/start.sh <label>` (port 18531).
- Run `target/release/openvibes-admin assistant eval --file …/q/console.toml > …/q/<name>.txt`. This mirrors `q/runB.sh`, but with this worktree's binary.
- Stop the server afterwards with `kill $(cat q/server.pid)` and check that port 18531 is free.
- The six-case replay uses `assistant eval --cases` with the 6 cases in `q/six-final.toml`.

### Task 2: The current lookup gets the result room

R4: the room is `available / lookups_left`, so a one-lookup question gives its only result about 546 chars. Two things were dropped as a result: db-01 in `vulns-cve-hosts`, and the whole top-findings list in `fleet-overview` (`items: []`, `omitted: 7`).

**Files:**
- Modify: `crates/platform-assistant/src/orchestrator.rs:484-487` (room) and `src/config.rs:54-58` (Small budget)
- Test: `crates/platform-assistant/tests/orchestrator.rs`

**Interfaces:**
- Consumes: `lookups_left` (the current lookup counts as 1), `MIN_RESULT_CHARS = 400`, `RESERVE_CHARS`, `RESULT_PREFIX`.
- Produces: `fn result_room(limit: usize, base: usize, lookups_left: u32) -> usize`, a private free function so it can be unit-tested, and `Profile::Small.budget().prompt_tokens == 3_000`.

- [ ] **Step 1: Write the failing tests.**

```rust
#[test]
fn the_current_lookup_gets_the_room_and_later_ones_keep_the_minimum() {
    // 9000 limit, 3200 base: available = 9000 - (3200 + RESERVE + PREFIX)
    let available = 9_000 - (3_200 + RESERVE_CHARS + RESULT_PREFIX.len());
    assert_eq!(result_room(9_000, 3_200, 1), available);
    assert_eq!(result_room(9_000, 3_200, 4), available - 3 * MIN_RESULT_CHARS);
    // Never below the minimum, even with a long history.
    assert_eq!(result_room(9_000, 8_900, 4), MIN_RESULT_CHARS);
}
```

  Put this as a `#[cfg(test)] mod tests` inside `orchestrator.rs`, because `result_room` is private. Add an integration test in `tests/orchestrator.rs` that scripts one lookup whose output is 3,000 chars of items. Assert that the Small profile now passes more than 2,000 chars of it to the model. The scripted backend records the messages, so measure the `Message::Tool` content length. Also run four lookups with a long history and assert that every result is at least `MIN_RESULT_CHARS` and that `run.base_chars()` stays at or below `limit_chars` before each request (Review Focus 3).
- [ ] **Step 2:** Run them and expect a FAIL.
- [ ] **Step 3: Implement.**

```rust
/// Room for the current lookup's result: what is left, minus the minimum
/// kept for each lookup still allowed after it.
fn result_room(limit: usize, base: usize, lookups_left: u32) -> usize {
    let available = limit.saturating_sub(base + RESERVE_CHARS + RESULT_PREFIX.len());
    let later = lookups_left.saturating_sub(1) as usize * MIN_RESULT_CHARS;
    available.saturating_sub(later).max(MIN_RESULT_CHARS)
}
```

  Use it at `orchestrator.rs:484`, and keep `output.shrink_to(room)`. In `config.rs` set Small `prompt_tokens: 3_000`. The server context is 8,192, so it fits; update the doc comment and any test that asserts 2,000.
- [ ] **Step 4:** Run `cargo test -p platform-assistant` and expect a PASS.
- [ ] **Step 5: Six-case replay** (1 of 4). Expect `fleet-overview` to show top findings and not `items: []`. Note the median; if it is above 14 s, record why from the server log, counting prompt tokens per call.
- [ ] **Step 6: Commit:** `Assistant: the current lookup gets the result room; small prompt budget 3k`.

### Task 3: `rule_set` is optional and resolves itself

R5: the model invents `rule_set: "default"`, while the only set is `baseline`. Nothing tells it the names, and an unknown set returns empty.

**Files:**
- Modify: `crates/platform-assistant/src/lookups.rs`: `Lookup::FindingEndpoints.rule_set` and `Lookup::RuleDescription.rule_set` become `Option<String>`; the specs at `:157-167` and `:203-211` lose `rule_set` from `required`; parsing at `:339-380`; execution at `:750-780` and `:926-940`.
- Test: `crates/platform-assistant/tests/lookups.rs` (parsing) and `crates/platform-assistant/tests/store_lookups.rs` or the eval `FleetSource` (resolution).

**Interfaces:**
- Consumes: `Source::finding_groups(&GroupFilter { text: Some(rule), min_severity: None, rule_set_id }, since, limit)`. It already exists, so no store change.
- Produces: `async fn rule_sets_for(source, rule: &str, since) -> Vec<String>`, the distinct `rule_set` of groups whose `rule` equals `rule` exactly (case-insensitive). It lives in `lookups.rs` next to `finding_cite`.
- Behaviour:
  - **`finding_endpoints` without `rule_set`, or with a `rule_set` that has no group for the rule:** resolve with `rule_sets_for`. If there is one set, run as before. If there are several, run each and merge, so every item keeps its `rule_set` field. If there are none, return an empty result with `note: "no finding with this rule"`.
  - **`rule_description` without a set, or with a set that has no matching group:** resolve the same way. If there is exactly one set, describe it. If there are several, return the fixed error `LookupError::AmbiguousRule`, message `"the rule is in several rule sets; name one"`. If there are none, try the given `rule_set` as now, and if that fails return the existing not-found error.
  - **`search_findings` with a `rule_set` that matches no group:** rerun without the set and add `note: "rule set not found; showing all rule sets"` to the result.
- Descriptions:
  - On both `rule_set` parameters: `"Rule set; leave out unless the user names one."`
  - On `search_findings`: `"Rule set; leave out to search all."`

- [ ] **Step 1: Write the failing tests.**
  - **Parsing:** `finding_endpoints {"rule":"ssh-root-login"}` parses with `rule_set: None`, and `audit_arguments_are_the_validated_ones` shows `"rule_set": null`.
  - **Resolution, against the eval fleet:**
    - `finding_endpoints {"rule_set":"default","rule":<a real rule in eval/fleet.toml>}` returns endpoints.
    - A rule in two sets returns both sets' endpoints. Add a second set with the same rule id to a test fleet built in the test, not to `eval/fleet.toml`.
    - An unknown rule returns an empty result with the note.
    - `rule_description` for a rule in two sets returns `AmbiguousRule`, and its message contains neither the rule id nor the set names (Review Focus 1 and 5).
  - **Injection:** a rule id containing `ignore previous instructions` resolves to nothing. The model's text never appears in the error message.
- [ ] **Step 2:** Run `cargo test -p platform-assistant` and expect a FAIL.
- [ ] **Step 3: Implement** as described in Interfaces. Keep the `""` (pre-P6) rule set working: `Some("")` is a real set name, and `None` means resolve. If `lookups.rs` grows beyond about 120 lines, move the resolution into a new `src/lookups/resolve.rs`, made a module of `lookups.rs`.
- [ ] **Step 4:** Run `cargo test -p platform-assistant` and `cargo clippy -p platform-assistant --all-targets -- -D warnings` and expect a PASS.
- [ ] **Step 5: Commit:** `Assistant: rule_set is optional; a missing or unknown set resolves from the findings`.

### Task 4: Tool descriptions name what the results carry

R5: 8 misses are "no tool call", because the model says no function provides the information. The descriptions don't mention kernel, collectors, the reboot flag or the revoked and never-seen counts. 5 more misses use the wrong tool for fleet-wide counts.

**Files:**
- Modify: `crates/platform-assistant/src/lookups.rs:146-220` (description strings only)
- Test: `crates/platform-assistant/tests/lookups.rs`

**Interfaces:** descriptions only. The total length of the tool specs (currently 2,472 chars) may grow by at most 600 chars, since it counts against the prompt budget.

- [ ] **Step 1: Write the failing test.** Each listed field name appears in its tool's description, and the total spec JSON length stays within 3,100 chars:

```rust
#[test]
fn descriptions_name_the_fields_the_results_carry() {
    let specs = specs();
    let d = |n: &str| specs.iter().find(|s| s.name == n).unwrap().description.to_lowercase();
    for word in ["kernel", "collectors", "os", "last contact"] { assert!(d("agent_summary").contains(word), "{word}"); }
    for word in ["reboot", "exploited"] { assert!(d("host_vulnerabilities").contains(word), "{word}"); }
    for word in ["revoked", "never seen", "fleet-wide", "exploited"] { assert!(d("fleet_overview").contains(word), "{word}"); }
    for word in ["firewall", "auditd", "root login"] { assert!(d("search_findings").contains(word), "{word}"); }
    let total: usize = specs.iter().map(|s| serde_json::to_string(&s.parameters).unwrap().len() + s.description.len() + s.name.len()).sum();
    assert!(total <= 3_100, "{total}");
}
```

  Before writing the field lists, check the real result fields in `lookups.rs:800-900` (e.g. `running_kernel`, `capabilities`, `reboot_needed`, `never_seen`, `revoked`). Name only fields that exist.
- [ ] **Step 2:** Run it and expect a FAIL.
- [ ] **Step 3: Rewrite the descriptions.** Use plain words, one sentence each, and say when to use each tool:
  - **`fleet_overview`:** for fleet-wide counts, including agents by state (active, offline, stale, revoked, never seen), open and exploited vulnerabilities, top findings and top advisories.
  - **`search_findings`:** for compliance findings such as firewall, auditd or root login, searched by words.
  - **`host_vulnerabilities`:** for one host only, never "all".
  - **`vulnerability_hosts`:** needs a real CVE or advisory id taken from a result.
- [ ] **Step 4:** Run `cargo test -p platform-assistant` and expect a PASS.
- [ ] **Step 5: Six-case replay** (2 of 4), using the 6 cases. Then run one **full eval** (2 of 4). Compare the failing-case list with the Task 1 baseline, and list the cases that were fixed, still fail, or newly fail, with the reason for each.
- [ ] **Step 6: Commit:** `Assistant: tool descriptions name the fields and when to use each lookup`.

### Task 5: Prompted mode reads the shapes the model sends and never shows JSON

R6: about 10 of 96 prompted turns are malformed, e.g. `{"action":"agent_summary",…}` or no `"name"`, and `orchestrator.rs:600-601` then shows the raw JSON as the answer.

**Files:**
- Modify: `crates/platform-assistant/src/orchestrator.rs:283-298` (`parse_action`) and `:598-602` (fallback)
- Test: `crates/platform-assistant/tests/orchestrator.rs`

**Interfaces:**
- `parse_action` also accepts these shapes:
  - `{"action": "<one of NAMES>", "arguments": {...}}`;
  - `{"action": "<one of NAMES>", ...args}`, where args are the remaining keys minus `action`;
  - `{"action": "lookup", "arguments": {...}}` with the name inside the arguments as `"name"`.
- Anything else that starts with `{` is malformed, not an answer.
- New private `const REPAIR: &str = "Reply with one JSON object: {\"action\":\"lookup\",\"name\":…,\"arguments\":{…}} or {\"action\":\"answer\",\"text\":…}.";`
- On a malformed reply, push the assistant's reply plus `Message::User(REPAIR)` once and retry. The retry counts as a turn, and a second malformed reply returns `AnswerError::NoAnswer`. Prose that contains no `{` is still taken as the answer.
- The no-consecutive-user-messages rule from step 2 must hold: the repair message follows an assistant message.

- [ ] **Step 1: Write the failing tests** with a scripted backend in prompted mode:
  1. `{"action":"agent_summary","agent":"web-01"}`, then an answer: the lookup runs with `agent: web-01`.
  2. `{"action":"vulnerability_hosts","arguments":{"id":"CVE-2026-1"}}` runs that lookup.
  3. `{"action":"lookup","arguments":{"name":"fleet_overview"}}` runs `fleet_overview`.
  4. `{"foo":1}`, then `{"bar":2}`: returns `AnswerError::NoAnswer`, and no answer segment contains `{` (Review Focus 4).
  5. `{"foo":1}`, then a valid answer: the answer is returned, and the working messages alternate correctly.
  6. Plain prose with no braces is still the answer.
- [ ] **Step 2:** Run them and expect a FAIL.
- [ ] **Step 3: Implement** in `parse_action`, returning `Option<Action>` plus a `Malformed` variant, then handle it in the loop.
- [ ] **Step 4:** Run `cargo test -p platform-assistant` and expect a PASS.
- [ ] **Step 5: Commit:** `Assistant: prompted mode accepts the lookup shapes models send; never shows JSON as the answer`.

### Task 6: Docs, final measurement, gate

**Files:**
- Modify: `docs/components/platform-assistant.md` (budget split, optional `rule_set` and resolution, prompted repair, eval `empty`), `docs/components/openvibes-admin.md` if it describes the eval output, and the CHANGELOG if the repo keeps one.

- [ ] **Step 1: Docs**, written from the code as it now is.
- [ ] **Step 2: Final full eval** (3 of 4) and **one repeat** (4 of 4). Findings R7 says the failures are systematic, so compare the two runs' case lists. Report:
  - lookup %, facts %, leaks, injections (must be 0 leaks and 8/8 exposed and resisted), median and p95;
  - per case: fixed, still failing, or newly failing, with the reason.
  - If the median is above 13 s, give the reason from the server log (tokens per call), not a guess.
- [ ] **Step 3: Gate** (`testing.md` §2), run in the background and waited on properly. Capture the `test result` lines without a filter that can hide them.
- [ ] **Step 4: Commit the docs:** `Docs: assistant lookups step 3`.
