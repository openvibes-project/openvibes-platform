# Settings › General and suppressions with approval: implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship step 3 of the roles spec:
- a typed Settings › General page (screen 11);
- alarm suppressions that cover a host, a host group or all hosts, for 7 days, 30 days or until removed, and that wait for a second person's approval when the setting asks for it (screens 12 and 14).

**Architecture:**
- **Settings** are rows in a new `console_settings` table. Each key's type, range and default are declared once in the console (`settings/definitions.rs`). The store reads and writes raw JSON and audits every change with the old and new values.
- **Suppressions** gain a state machine: `waiting → active | rejected | withdrawn`, then `active → removed`. `expired` is derived from `expires_at` when read.
- **New columns:** a "where" (`agent_id`, `host_group_id`, or neither for all hosts), a duration, and the source alarm.
- **Matching** stays at alarm insert in ingest. Its SQL now loads only active, unexpired suppressions whose where covers the agent. Group membership goes through `console_host_in_group`, the one membership function from step 2.
- **Approval** is checked in the console against the approver's `alarms.suppressions.approve` reach, and the requester can never approve their own request.

**Tech Stack:**
- Rust: axum, utoipa, tokio-postgres, `platform-store` migrations;
- React and TypeScript web, with the in-browser demo server;
- vitest and Playwright.

**Spec:** `docs/specs/2026-10-16-roles-permissions-design.md` §7, §8, §12 item 5, §13, §15 and §16 step 3. Approved screens: `docs/specs/rbac-ui/approved.md` screens 11, 12 and 14, and the shared layout.

**Base:** `origin/main` a408d47, with steps 1 and 2 merged. Branch `settings-approval`, worktree `openvibes-platform-settings`.

## Global Constraints

**Settings**
- Settings live in `console_settings (key text PRIMARY KEY, value jsonb, changed_at, changed_by)`. Each key has a typed definition in code (type, range, default).
- `GET /v1/settings` and `PATCH /v1/settings/{key}` both need `settings.manage`. A value out of range is refused with 422. Every change is audited with the old and new values.
- Keys now:
  - `suppressions.require_approval` (bool, default false);
  - `sso.remove_inactive_days` (int, 1–3650, default 90).

**Suppressions**
- **What:** this program, or this exact command. Old `host` rows stay valid, but the form no longer offers `host`.
- **Where:**
  - this host (`agent_id`);
  - a group (`host_group_id`);
  - all hosts (neither). All hosts is offered only to a person whose `alarms.suppress` reaches all hosts.

  The form offers only the hosts and groups the person's `alarms.suppress` reaches.
- **For:** 7 days, 30 days, or until removed. `expires_at` is counted from activation.
- **Reason:** required, 1–4000 characters.
- **States:**
  - `waiting → active | rejected | withdrawn`;
  - `active → removed | expired`.
  - With `suppressions.require_approval` off, a new suppression is active at once.
- **Approve or reject:**
  - Needs `alarms.suppressions.approve` on the suppression's where:
    - a host the approver's role reaches;
    - a group in the approver's role, or the role reaches all hosts;
    - for all hosts, a role reaching all hosts.
  - The approver is never the requester; this is checked server-side.
  - Rejecting needs a reason (1–4000 characters).
  - Approving starts the For period.
- **Withdraw:** the requester can withdraw their own waiting request.
- **Turning the setting off** leaves waiting requests waiting.
- **Matching:** only active, unexpired suppressions are applied. Expiry is checked when matching runs; there is no job.
- **"Would have closed N alarms in the last 7 days"** is counted when the list is read, with the same matcher.

**Upgrade (§12.5)**
- Every existing row becomes `active`.
- Program and command rows mean all hosts.
- Host rows keep their host.
- `expires_at` stays empty.
- Already removed rows become `removed`.

**Audit**
- Every transition is audited with who and why:
  - `alarm.suppression.requested`, `.created` (active at once), `.approved`, `.rejected`, `.withdrawn`, `.removed`;
  - `settings.changed`.

**UI**
- Use the shared layout of `approved.md`: a header, a narrow left column of cards, and a wide right column of cards.
- Settings are rows (name and explanation left, control right) that save on change. Each row says "Saved · recorded in the audit log". There is no Save bar. Everything is full width.

**Project rules**
- Files under 500 lines.
- Every code folder has a README naming its files (`scripts/check-folder-readmes.sh`).
- `docs/components/` pages are updated in the same change.
- The OpenAPI snapshot and the web client are regenerated on any API change.
- The demo server mirrors every route.

**Environment (binding for every task)**
- This host is the user's production host and desktop. Never touch its own openvibes services or database. Tests use only `eval "$(scripts/test-db.sh)"`, and stop it afterwards.
- Every cargo command runs as `export CARGO_TARGET_DIR=~/.cache/openvibes-scratch/target CARGO_BUILD_JOBS=6 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0` under `nice -n 19 ionice -c3`. Run one heavy command at a time.
- Playwright: demo `--workers=4`, live `--workers=2`.
- The web build deletes `web/dist/.gitkeep`. Restore it with `git checkout -- crates/openvibes-console/web/dist/.gitkeep` before committing.
- Commits end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. Never push.

## Rulings in this plan (spec amendments, 2026-10-20)

These fill gaps in §7 and §8. Task 1 writes them into the spec.

1. **`GET /v1/settings` needs `settings.manage`.** The suppress form learns whether approval is on from `GET /v1/alarm-suppressions/options` (Task 5), so no one else needs the settings list.
2. **A suppression remembers its source alarm** (`alarm_id`, the platform row id). The alarm panel finds a waiting request through it, screen 14's "Open alarm" uses it, and "Ask again…" sends it again. Rows made before this step have none, so they show no "Open alarm" and no "Ask again…".
3. **Activation closes the source alarm.** This happens at create-when-active and at approval: if the source alarm is still open or investigating, it becomes `false_positive` with `suppressed_by` set. This is the close the web used to do itself before quieting. A waiting request closes nothing, so "these alarms keep arriving".
4. **Deleting a host group ends its suppressions.** Its waiting requests become `withdrawn` and its active ones `removed`. The delete preview counts them ("Ends N alarm suppressions"). There is no foreign key: a suppression whose group is gone matches nothing, because `console_host_in_group` needs the group row.
5. **Who sees which suppression** (with `alarms.suppressions.read`):
   - a host row, if the host is in reach;
   - a group row, if the group is in the viewer's role, or the viewer reaches all hosts;
   - an all-hosts row, for every reader, because it closes alarms on their hosts too.

   Before this step, program and command rows were global-only.
6. **Remove needs `alarms.suppress` on the row's where**, with the same rule as creating it.
7. **The list returns** waiting, active (including expired, shown with an Expired badge) and rejected rows. Withdrawn and removed rows live in the audit log.
8. **Bulk "suppress"** (compliance bulk, program and all hosts, global callers only) goes through the same store function, so it waits when approval is on. Its result says "requested" for waiting ones.
9. **Device and signature suppressions** (made by `openvibes-admin`) are always active, and netlog's matcher is unchanged. `removed_at` stays in step with `state = 'removed'`.

## Review Focus

1. **A suppression for a group, with a host that joins the group later.** Alarms from that host are closed from the moment it joins, and stop being closed when it leaves, with no restart. Pinned in Task 4 by `a_group_suppression_follows_membership`.
2. **An expired suppression keeps closing alarms because nothing runs a job.** Matching must compare `expires_at` with the batch's `now`. Pinned in Task 4 by `an_expired_suppression_closes_nothing`.
3. **The requester approves their own request through a second session or a bearer token.** The server compares the requester with the session's user id, and bearer tokens are refused on every write. Pinned in Task 5 by `requester_cannot_approve_even_holding_approve_everywhere`.
4. **A team lead approves a request for a host outside their reach by guessing its id.** The answer must be the same 404 as for a missing id. Pinned in Task 5 by `approving_outside_reach_is_not_found`.
5. **Turning approval off while requests wait.** They stay waiting and can still be decided or withdrawn. New requests are active at once. Pinned in Task 3 by `turning_approval_off_leaves_waiting_requests`.

---

### Task 1: General settings, store and API

**Files:**
- Create: `migrations/0054_console_settings.sql`.
- Modify: `crates/platform-store/src/migrate.rs` (add 54, `SCHEMA_VERSION = 54`).
- Create: `crates/platform-store/src/console_settings.rs`; register it in `lib.rs`.
- Create: `crates/openvibes-console/src/settings/{mod.rs,definitions.rs,README.md}`; mount the routes where the other areas are mounted (`routes()` per area).
- Modify: `crates/openvibes-console/src/http/openapi.rs`, `docs/api/console-v1.openapi.json` (regenerated), and the web client (`npm --prefix crates/openvibes-console/web run generate:api`).
- Modify: the spec §7 and §8 (paste the plan's "Rulings in this plan" as "Plan rulings, 2026-10-20").
- Docs: `docs/components/platform-store.md`, `docs/components/openvibes-console.md`, and a new `docs/components/console-settings.md` (indexed in `docs/components/README.md`).
- Tests: `crates/platform-store/tests/console_settings.rs` and `crates/openvibes-console/tests/settings_http.rs`.

**Interfaces:**
- Produces, in the store:
  - `console_settings::all(client) -> Vec<StoredSetting { key, value: serde_json::Value, changed_at, changed_by }>`;
  - `console_settings::set(client: &mut Client, key: &str, value: &Value, actor: &str, now) -> Result<Option<Value> /*old*/, StoreError>`, which also audits `settings.changed`;
  - `console_settings::recent(client, limit) -> Vec<AuditLine>`;
  - `console_settings::require_approval(tx: &impl GenericClient) -> Result<bool, StoreError>`, which is false when the row is absent or not a bool.
- Produces, in the console:
  - `GET /api/v1/settings` → `SettingsView { items: [SettingView { key, section, label, help, kind: "bool"|"int", min?, max?, default, value, changed_at?, changed_by? }], recent: [SettingChangeView { at, actor, key, old, new }] }`;
  - `PATCH /api/v1/settings/{key}` with `{ "value": … }` → `SettingView`.

- [ ] **Step 1: Write the failing tests.** In `crates/platform-store/tests/console_settings.rs`, using `common::migrated()`:

```rust
#[tokio::test]
async fn a_change_is_stored_and_audited_with_old_and_new() {
    let Some((_db, mut client)) = common::migrated().await else { return };
    let now = chrono::Utc::now();
    let old = console_settings::set(&mut client, "suppressions.require_approval",
        &serde_json::json!(true), "admin-1", now).await.unwrap();
    assert_eq!(old, None);
    let old = console_settings::set(&mut client, "suppressions.require_approval",
        &serde_json::json!(false), "admin-1", now).await.unwrap();
    assert_eq!(old, Some(serde_json::json!(true)));
    let row = client.query_one(
        "SELECT detail FROM audit_log WHERE action = 'settings.changed' ORDER BY id DESC LIMIT 1",
        &[]).await.unwrap();
    let detail: serde_json::Value = row.get(0);
    assert_eq!(detail, serde_json::json!({
        "key": "suppressions.require_approval", "old": true, "new": false }));
}

#[tokio::test]
async fn require_approval_is_false_until_set() {
    let Some((_db, client)) = common::migrated().await else { return };
    assert!(!console_settings::require_approval(&client).await.unwrap());
}
```

In `crates/openvibes-console/tests/settings_http.rs`, use the `common::people::Fx` fixture: an admin session, plus a `viewer` role without `settings.manage`.

```rust
// GET as admin → 200, two items, suppressions.require_approval value false (default), sso.remove_inactive_days 90.
// GET as viewer → 403 permission_denied.
// PATCH sso.remove_inactive_days {"value": 0} → 422 invalid_setting, {"value": 3651} → 422, {"value": "90"} → 422, {"value": 30} → 200 value 30.
// PATCH suppressions.require_approval {"value": 1} → 422; {"value": true} → 200.
// PATCH unknown.key → 404 setting_not_found.
// PATCH without the CSRF header → 403 (as other writes).
// After the two changes, GET recent has 2 lines, newest first, with key, old and new.
```

Write each comment line as a real assertion with `fx.call(&session, Method::PATCH, "/api/v1/settings/sso.remove_inactive_days", Some(json!({"value": 0})))`. Model it on `host_groups_http.rs`.

- [ ] **Step 2: Run them to see them fail.**

```bash
eval "$(scripts/test-db.sh)"
nice -n 19 ionice -c3 cargo test --locked -p platform-store --test console_settings
nice -n 19 ionice -c3 cargo test --locked -p openvibes-console --test settings_http
```

Expected: a compile error (module `console_settings` not found).

- [ ] **Step 3: Write the migration** `migrations/0054_console_settings.sql`:

```sql
-- General settings (roles spec §7): one row per changed key; a key with no
-- row has its default, which lives in the console's definitions.
CREATE TABLE console_settings (
    key text PRIMARY KEY CHECK (key ~ '^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$'),
    value jsonb NOT NULL,
    changed_at timestamptz NOT NULL,
    changed_by text NOT NULL
);
GRANT SELECT, INSERT, UPDATE ON console_settings TO "openvibes-console";
```

Add `(54, include_str!("../../../migrations/0054_console_settings.sql"))` and set `SCHEMA_VERSION = 54`.

- [ ] **Step 4: Write the store module.** `set` runs in one transaction:
  1. `SELECT value … FOR UPDATE`;
  2. upsert with `INSERT … ON CONFLICT (key) DO UPDATE`;
  3. insert the audit row, in the shape `host_group_writes.rs` uses: `actor_kind 'user'`, `target_kind 'setting'`, `target_id = key`, detail `{key, old, new}` with `old` null when there was no row.

  `require_approval` is `SELECT value FROM console_settings WHERE key = 'suppressions.require_approval'` → `value.as_bool().unwrap_or(false)`. It takes `&impl GenericClient`, so Task 3 can call it inside its transaction.

- [ ] **Step 5: Write the definitions and the routes.**

```rust
// settings/definitions.rs
pub enum Kind { Bool { default: bool }, Int { min: i64, max: i64, default: i64 } }
pub struct Definition { pub key: &'static str, pub section: &'static str,
    pub label: &'static str, pub help: &'static str, pub kind: Kind }
pub static DEFINITIONS: [Definition; 2] = [
    Definition { key: "suppressions.require_approval", section: "Alarm suppressions",
        label: "Suppressions need approval",
        help: "A new suppression waits until someone else who can approve on those hosts accepts it. Matching alarms keep arriving while it waits.",
        kind: Kind::Bool { default: false } },
    Definition { key: "sso.remove_inactive_days", section: "Single sign-on",
        label: "Remove inactive single sign-on users",
        help: "Days without a sign-in before a single sign-on user is removed. Takes effect once single sign-on is set up.",
        kind: Kind::Int { min: 1, max: 3650, default: 90 } },
];
pub fn check(def: &Definition, value: &serde_json::Value) -> Result<(), String>
// Bool: value.is_boolean(). Int: value.as_i64() in [min, max], and is_i64 (no floats, no strings).
// On failure: "Use true or false" / "Use a whole number from 1 to 3650".
```

Handlers use `access::editor::caller(state, headers, csrf)` and `editor.denied(Permission::SettingsManage)`. Responses:
- an unknown key → 404 `setting_not_found`;
- a failed check → 422 `invalid_setting`, with the message as the field error on `value`;
- a store error → `unavailable_auth()`.

`recent` holds the last five changes.

- [ ] **Step 6: Run the tests until they pass.** Then regenerate the OpenAPI document and the client (testing.md), and run `cargo test -p openvibes-console --test api_contract`.

- [ ] **Step 7: Commit:** `settings: typed general settings with audited changes (GET/PATCH /v1/settings)`.

---

### Task 2: Settings › General screen (11), with the demo

**Files:**
- Create: `crates/openvibes-console/web/src/views/admin/settings/General.tsx` and `General.test.tsx`. Update the folder README.
- Modify: `web/src/views/admin/settings/Settings.tsx`. Add a first tab `general`, labelled "General", with `access: [{ permission: "settings.manage" }]` (match the existing `Access` shape).
- Modify: `web/src/ui/auditActions.ts` (`settings.changed: "Changed a setting"`), and its test.
- Create: `web/src/demo/routes/settings.ts` (GET and PATCH, with the same checks, codes and audit). Register it with the demo router and add a vitest in `web/src/demo/server.test.ts` style.
- Create: `web/e2e/demo/general-settings.spec.ts`.
- Docs: `docs/components/console-web.md`.

**Interfaces:**
- Consumes `GET/PATCH /api/v1/settings` from Task 1, through the generated types `SettingsView` and `SettingView`.

- [ ] **Step 1: Write the failing tests.**
  - **`General.test.tsx`** renders with a fixture `SettingsView` and asserts:
    - the "On this page" card lists "Alarm suppressions 1" and "Single sign-on 1";
    - the toggle's accessible name is "Suppressions need approval";
    - the number input's accessible name is "Remove inactive single sign-on users" with `min=1 max=3650`;
    - the help text is shown;
    - the Recent changes card shows "Changed a setting" lines and "Audit log" links to `/audit?q=settings.changed`.
  - **`saveValue` (pure)** turns a 422 `ApiError` into the server's field message, and turns success into "Saved · recorded in the audit log".
  - **`general-settings.spec.ts`** (demo, as an admin persona):
    - open Settings › General and switch "Suppressions need approval" on;
    - see "Saved · recorded in the audit log", then reload and see it still on;
    - type 0 in the days field and see "Use a whole number from 1 to 3650";
    - run axe on the page.

- [ ] **Step 2: Run them to see them fail:** `npm --prefix crates/openvibes-console/web run test -- General` and the spec with `--workers=4`.

- [ ] **Step 3: Build the screen** in the shared layout. Reuse the step-1/2 markup and `Card` from `views/admin/people/PersonPage.tsx`, as `GroupPage.tsx` does.
  - **Header:** "General", summary "Settings that apply to the whole console."
  - **Left column:** "On this page" (anchor links to each section, with its count) and Recent changes.
  - **Right column:** one card per section, with a row per setting: label and help on the left, control on the right.
  - **Saving:**
    - A bool saves on change; an int saves on blur or Enter when it changed.
    - While saving, the control is disabled.
    - On success the row shows "Saved · recorded in the audit log" and the resource is invalidated.
    - On 422 the row shows the message (`role="alert"`) and keeps the typed text.
  - **"Suppressions need approval", when on,** names who can approve: "Approvers: people whose role holds Approve suppressions on those hosts — " followed by the names of the roles from `GET /api/v1/roles` that hold `alarms.suppressions.approve`, or "no role holds it yet".

- [ ] **Step 4: Write the demo route**, mirroring Task 1 exactly: same keys, defaults, 403/404/422 codes, `recent`, and an audit line in the demo audit log.

- [ ] **Step 5: Run vitest, tsc, eslint and build, then the new demo spec** (`--workers=4`). Restore `web/dist/.gitkeep`.

- [ ] **Step 6: Commit:** `console web: Settings › General (screen 11) with demo`.

---

### Task 3: Suppression states, where and duration: migration and store

**Files:**
- Create: `migrations/0055_suppression_approval.sql`. Set `SCHEMA_VERSION = 55`.
- Modify: `crates/platform-store/src/alarm_suppressions.rs`. Split it so each file stays under 500 lines: `alarm_suppressions.rs` (types, list, audit), `alarm_suppression_writes.rs` (request, decide, withdraw, remove). Keep `create_for_device` where it lives.
- Modify: `crates/openvibes-console/src/alarms/suppressions.rs` and `compliance/bulk.rs`, only enough to compile against the new store signatures. Task 5 builds the real API. Keep the old request body working in this task by mapping the old `scope` to the new `What` and `Where`: `host` becomes program on this host.
- Tests: `crates/platform-store/tests/alarm_suppressions.rs` (extend it) and `crates/platform-store/tests/suppression_upgrade.rs` (new).
- Docs: `docs/components/platform-store.md`.

**Interfaces:**
- Produces:

```rust
pub enum What { Program, Command }
pub enum Where { Host, Group(String /*uuid*/), All }        // Host = the source alarm's agent
pub enum State { Waiting, Active, Rejected, Withdrawn, Removed }   // Expired is derived
pub struct Request<'a> { pub alarm_row_id: i64, pub what: What, pub place: Where,
    pub for_days: Option<i32> /*7|30|None*/, pub reason: &'a str }
pub struct Suppression { /* existing fields */ pub state: State, pub expired: bool,
    pub host_group_id: Option<String>, pub host_group_name: Option<String>,
    pub for_days: Option<i32>, pub activated_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>, pub decided_by: Option<String>,
    pub decided_at: Option<DateTime<Utc>>, pub decision_reason: Option<String>,
    pub alarm_id: Option<i64> }
pub enum Change { Done(Suppression), NotFound, NeedsGlobalScope, NotInReach, Invalid(String),
    WrongState, OwnRequest }
pub async fn request(client: &mut Client, suppress: &AgentScope, req: &Request<'_>, actor: &str, now) -> Result<Change, StoreError>;
pub async fn decide(client: &mut Client, approve: &AgentScope, id: i64, approve_it: bool, reason: Option<&str>, actor: &str, now) -> Result<Change, StoreError>;
pub async fn withdraw(client: &mut Client, id: i64, actor: &str, now) -> Result<Change, StoreError>;
pub async fn remove(client: &mut Client, suppress: &AgentScope, id: i64, actor: &str, now) -> Result<Change, StoreError>;
pub async fn list(client: &Client, read: &AgentScope, filter: &ListFilter, now) -> Result<Vec<Suppression>, StoreError>;
pub struct ListFilter { pub state: Option<State> /*Active includes expired*/, pub alarm_id: Option<i64> }
pub fn in_reach(scope: &AgentScope, s: &Suppression) -> /* SQL predicate builder, see Step 4 */
```

- [ ] **Step 1: Write the failing tests**, in `tests/alarm_suppressions.rs`. Reuse its `setup()`, which gives an agent and an alarm. Add a rule group and a manual group with `common::manual_group` / `common::rule_group`.

```rust
// request_is_active_at_once_without_approval: Request{Program, All, Some(7), "noisy"} as Global
//   → Done, state Active, activated_at == now, expires_at == now + 7 days, source alarm now
//   state 'false_positive' with suppressed_by = id; audit 'alarm.suppression.created'.
// request_waits_with_approval_on: console_settings::set(require_approval=true) first
//   → state Waiting, activated_at/expires_at None, source alarm still 'open';
//   audit 'alarm.suppression.requested'.
// approving_starts_the_period: waiting request by "alice", decide(.., true, None, "bob", later)
//   → Active, activated_at == later, expires_at == later + 30d (for_days 30), alarm closed;
//   audit 'alarm.suppression.approved'.
// requester_cannot_decide_own: decide(.., actor "alice") → OwnRequest, row unchanged.
// rejecting_needs_a_reason: decide(false, None) → Invalid("reason"); decide(false, Some(" ")) → Invalid;
//   decide(false, Some("not this host")) → Rejected with decision_reason; audit 'alarm.suppression.rejected'.
// only_waiting_can_be_decided_or_withdrawn: decide on Active → WrongState; withdraw on Active → WrongState.
// withdraw_is_the_requesters_own: withdraw by "bob" → OwnRequest-style refusal (NotFound — another
//   person's request is not theirs to withdraw); by "alice" → Withdrawn; audit '.withdrawn'.
// turning_approval_off_leaves_waiting_requests: approval on, request (Waiting), approval off,
//   row still Waiting, decide works; a new request is Active at once.
// where_must_be_in_reach: scope AssetGroups([g1]) asking Group(g2) → NotInReach; asking All → NeedsGlobalScope;
//   asking Host for an alarm on a host outside g1 → NotFound.
// a_removed_suppression_keeps_removed_at_in_step: remove → state Removed, removed_at/by set.
// list_shows_expired_as_expired: active row with expires_at < now → expired == true, state Active.
```

In `tests/suppression_upgrade.rs`, use `common::at_version(db, 54)`. Seed the old shapes:
- a host row;
- a program row;
- a command row;
- a removed program row;
- a device row.

Then `step_to(client, 55)` and assert:
- states active, active, active, removed, active;
- `host_group_id` null on all of them;
- `agent_id` kept on the host row;
- `expires_at` null;
- `activated_at = created_at`;
- the device row unchanged.

- [ ] **Step 2: Run them to see them fail** (compile errors on the new types).

- [ ] **Step 3: Write the migration** `migrations/0055_suppression_approval.sql`:

```sql
-- openvibes: needs-backup
-- Suppressions with approval (roles spec §8): a state, a where (host,
-- group or all hosts), a duration and the source alarm.
ALTER TABLE alarm_suppressions
    ADD COLUMN state text NOT NULL DEFAULT 'active'
        CHECK (state IN ('waiting', 'active', 'rejected', 'withdrawn', 'removed')),
    ADD COLUMN host_group_id uuid,
    ADD COLUMN for_days integer CHECK (for_days IN (7, 30)),
    ADD COLUMN activated_at timestamptz,
    ADD COLUMN expires_at timestamptz,
    ADD COLUMN decided_by text,
    ADD COLUMN decided_at timestamptz,
    ADD COLUMN decision_reason text CHECK (length(decision_reason) BETWEEN 1 AND 4000),
    ADD COLUMN alarm_id bigint;

UPDATE alarm_suppressions SET state = 'removed' WHERE removed_at IS NOT NULL;
UPDATE alarm_suppressions SET activated_at = created_at;
ALTER TABLE alarm_suppressions ALTER COLUMN state DROP DEFAULT;

ALTER TABLE alarm_suppressions
    ADD CONSTRAINT alarm_suppressions_removed_state_check
        CHECK ((state = 'removed') = (removed_at IS NOT NULL)),
    ADD CONSTRAINT alarm_suppressions_active_check
        CHECK (state NOT IN ('active', 'removed') OR activated_at IS NOT NULL),
    ADD CONSTRAINT alarm_suppressions_rejected_check
        CHECK (state <> 'rejected' OR decision_reason IS NOT NULL);

-- program/command may now be for one host or one group (never both);
-- host/device/signature keep their old shapes.
ALTER TABLE alarm_suppressions DROP CONSTRAINT alarm_suppressions_scope_fields_check;
ALTER TABLE alarm_suppressions ADD CONSTRAINT alarm_suppressions_scope_fields_check CHECK (
    (scope = 'host' AND agent_id IS NOT NULL AND host_group_id IS NULL AND exe IS NULL
        AND args_sha256 IS NULL AND device_id IS NULL)
 OR (scope = 'program' AND exe IS NOT NULL AND args_sha256 IS NULL AND device_id IS NULL
        AND NOT (agent_id IS NOT NULL AND host_group_id IS NOT NULL))
 OR (scope = 'command' AND exe IS NOT NULL AND args_sha256 IS NOT NULL AND device_id IS NULL
        AND NOT (agent_id IS NOT NULL AND host_group_id IS NOT NULL))
 OR (scope = 'device' AND device_id IS NOT NULL AND agent_id IS NULL AND host_group_id IS NULL
        AND exe IS NULL AND args_sha256 IS NULL AND rule_set_id LIKE 'device-%')
 OR (scope = 'signature' AND device_id IS NULL AND agent_id IS NULL AND host_group_id IS NULL
        AND exe IS NULL AND args_sha256 IS NULL AND rule_set_id LIKE 'device-%'));

DROP INDEX alarm_suppressions_active_idx;
CREATE INDEX alarm_suppressions_active_idx ON alarm_suppressions (rule_set_id, rule_id)
    WHERE state = 'active';
CREATE INDEX alarm_suppressions_waiting_idx ON alarm_suppressions (created_at)
    WHERE state = 'waiting';
```

Before writing the new constraint, read the current text of `alarm_suppressions_scope_fields_check` in 0046 and keep every old branch's meaning. The SQL above restates it, with `host_group_id IS NULL` added to the old shapes.

- [ ] **Step 4: Write the store.**
  - **`request`**, in one transaction:
    1. Validate the reason (trimmed, 1–4000) and `for_days` (7, 30 or none), else `Invalid("reason")` / `Invalid("for")`.
    2. Check the where:
       - `All` with a non-global scope → `NeedsGlobalScope`;
       - `Group(g)` that is not global and not in `scope.group_ids()` → `NotInReach`;
       - `Group(g)` where `g` names no group → `Invalid("group")`.
    3. Load the alarm through the suppress-scope visibility predicate, as today.
    4. Hash the args for `Command`.
    5. Read `console_settings::require_approval(&tx)` to pick the state, Waiting or Active.
    6. Insert with `scope = 'program'|'command'`, `agent_id` only for `Host`, `host_group_id` only for `Group`, and `alarm_id`.
    7. If Active, set `activated_at`/`expires_at` and close the source alarm with `close_source(&tx, id, alarm_row_id, actor, now)`. It sets `state='false_positive'`, `suppressed_by`, `note='suppressed by #id'`, `triage_updated_at/by`, bumps `triage_version`, and writes an `alarm_triage_history` row the way `alarms.rs` does for ingest. It only does this when the alarm's state is `open` or `investigating`.
    8. Audit `.requested` or `.created` with the detail `{rule_set_id, rule_id, what, where, host_group_id, agent_id, exe, for_days, reason, state}`.
  - **`decide`:**
    1. `SELECT … FOR UPDATE`, filtered by the approver's reach (Step 5) → `NotFound` if outside.
    2. Not waiting → `WrongState`.
    3. `created_by == actor` → `OwnRequest`.
    4. Reject without a valid reason → `Invalid("reason")`.
    5. Approve: Active, `activated_at = now`, `expires_at = now + for_days`, then `close_source`.
    6. Reject: Rejected with `decision_reason`.
    7. Set `decided_by/at` and audit.
  - **`withdraw`:** only the requester's own waiting row (another person's id → `NotFound`). Set Withdrawn and `decided_by/at`, and audit.
  - **`remove`:** an active row in the suppress reach. Set Removed and `removed_at/by`, and audit.
  - **`list`:**
    - States are waiting, active and rejected, with `expired = state = 'active' AND expires_at IS NOT NULL AND expires_at <= now`.
    - It joins `console_asset_groups` for `host_group_name`.
    - Order: waiting first by `created_at`, then active newest first, then rejected newest first.
    - At most 500 rows of each state.

- [ ] **Step 5: Write the reach predicate**, one SQL builder used by `list` (read scope), `decide` (approve scope) and `remove` (suppress scope). `$1` is global and `$2` the group ids, as `agent_visibility`:

```sql
( $1::boolean
  OR (s.agent_id IS NOT NULL AND EXISTS (SELECT 1 FROM agents a WHERE a.agent_id = s.agent_id
        AND {agent_visibility("a.agent_id", "$1", "$2")}))
  OR (s.host_group_id IS NOT NULL AND s.host_group_id::text = ANY($2::text[]))
  OR (s.agent_id IS NULL AND s.host_group_id IS NULL AND s.device_id IS NULL AND {all_rows_ok}) )
```

`{all_rows_ok}` is `true` for `list` (ruling 5) and `$1::boolean` for `decide` and `remove`.

- [ ] **Step 6: Make the console compile.**
  - Point `alarms/suppressions.rs` at `request`, mapping the old body: `scope` `program`/`command` become What with Where All, and `host` becomes Program with Where Host (this mapping is gone in Task 5).
  - Point `compliance/bulk.rs` at `request(Program, All, None, note)`.

  Run the platform-store suite and `cargo test -p openvibes-console` once.

- [ ] **Step 7: Commit:** `store: suppressions get states, a where (host, group or all) and a duration; migration 55`.

---

### Task 4: Matching follows state, expiry and groups; group delete ends suppressions

**Files:**
- Modify: `crates/platform-store/src/alarms.rs` (the suppression load in `insert_batch`, and a shared matcher).
- Modify: `crates/platform-store/src/alarm_suppressions.rs` (`would_close(client, s, now) -> i64`, used by `list` for waiting rows).
- Modify: `crates/platform-store/src/host_group_writes.rs` (`delete`) and `host_group_preview.rs` (`suppressions_ended`).
- Modify: `migrations/0055_suppression_approval.sql`: add `GRANT SELECT ON console_host_group_members TO "openvibes-ingest";`. `console_host_in_group` runs with the caller's rights and reads the members table for manual groups. 55 is not released, so it may be edited.
- Modify: `crates/openvibes-console/src/hosts/groups_types.rs` and `groups.rs` (the preview view carries `suppressions_ended`), and the web delete dialog line in `views/admin/groups/DeleteGroup.tsx` ("Ends N alarm suppressions").
- Tests: `crates/platform-store/tests/alarms.rs` (or a new `suppression_matching.rs`), `host_group_writes.rs`, and `alarm_suppressions.rs`.
- Docs: `docs/components/openvibes-ingest.md` and `platform-store.md`.

**Interfaces:**
- Produces:
  - `pub(crate) fn suppression_matches(scope: &str, exe: Option<&str>, args_sha256: Option<&str>, agent_id: Option<&str>, alarm_agent: &str, alarm: (&str /*exe*/, &str /*args_sha256*/)) -> bool`, used by ingest and by `would_close`;
  - `Suppression.would_close: Option<i64>` (Some only for waiting rows);
  - `Preview.suppressions_ended: i64`.

- [ ] **Step 1: Write the failing tests.** Run them as the ingest path does, through `alarms::insert_batch`.

```rust
// a_group_suppression_follows_membership: manual group G with host A; active suppression
//   Program/Group(G) for exe "/usr/bin/noisy"; insert an alarm from A with that exe → suppressed;
//   from host B (not in G) → open; add B to G (direct insert into console_host_group_members);
//   next alarm from B → suppressed; remove A from G → next alarm from A → open.
// an_expired_suppression_closes_nothing: active, expires_at = now - 1s → alarm open;
//   expires_at = now + 1h → suppressed.
// a_waiting_or_rejected_suppression_closes_nothing.
// a_host_where_only_covers_that_host: Program/Host on A → alarm from B stays open.
// ingest_role_can_match_groups: run insert_batch on a client connected as "openvibes-ingest"
//   (see how tests/alarms.rs or ingest tests switch role; else SET ROLE "openvibes-ingest")
//   with a manual-group suppression → no permission error, alarm suppressed.
// would_close_counts_the_last_7_days: waiting Command/All suppression; seed 3 matching alarms
//   (last_seen now-1d, now-6d, now-8d) and 1 with other args → would_close == Some(2).
// deleting_a_group_ends_its_suppressions: group G with one waiting and one active suppression;
//   preview(delete) suppressions_ended == 2; delete → waiting row Withdrawn, active row Removed
//   (removed_by = deleter), host_group.deleted detail has "suppressions_ended": 2.
```

- [ ] **Step 2: Run them to see them fail.**

- [ ] **Step 3: Change the load in `insert_batch`.** `$2` is the batch's agent and `$3` the batch's `now`:

```sql
SELECT id, rule_set_id, rule_id, scope, agent_id, exe, args_sha256
FROM alarm_suppressions
WHERE state = 'active'
  AND (expires_at IS NULL OR expires_at > $3)
  AND rule_set_id = ANY($1)
  AND (agent_id IS NULL OR agent_id = $2)
  AND (host_group_id IS NULL OR console_host_in_group($2, host_group_id))
ORDER BY id
```

Replace the old `matches` method with `suppression_matches`, which keeps the same rules, and keep the first-match semantics (`ORDER BY id` makes it stable). Leave netlog's `device_alarms.rs` alone, since device rows are always active.

- [ ] **Step 4: Write `would_close`:** `SELECT al.agent_id, al.process->>'exe', al.process->'args' FROM alarms al WHERE al.rule_set_id = $1 AND al.rule_id = $2 AND al.last_seen > $now - interval '7 days' AND ($agent::text IS NULL OR al.agent_id = $agent) AND ($group::uuid IS NULL OR console_host_in_group(al.agent_id, $group))`. Hash the args in Rust with `alarms::args_sha256`, then count the rows where `suppression_matches` holds. Cap the scan at 10,000 rows and mark it with a `ponytail:` comment naming the cap.

- [ ] **Step 5: Change the group delete**, inside its transaction:
  - `UPDATE alarm_suppressions SET state='withdrawn', decided_by=$actor, decided_at=$now WHERE host_group_id=$g AND state='waiting'`;
  - `UPDATE … SET state='removed', removed_by=$actor, removed_at=$now WHERE host_group_id=$g AND state='active'`;
  - add the total to the audit detail.

  The preview counts the same rows.

- [ ] **Step 6: Run the tests until they pass,** then run the platform-store suite and `-p openvibes-ingest` once.

- [ ] **Step 7: Commit:** `ingest: suppressions match by state, expiry and group; deleting a group ends its suppressions`.

---

### Task 5: Suppression API with approval

**Files:**
- Modify: `crates/openvibes-console/src/alarms/suppressions.rs`. Split it into `suppressions.rs` (list, options, create) and `suppression_decisions.rs` (approve, reject, withdraw, remove), plus `suppression_types.rs` if needed. Update `alarms/mod.rs` routes and the README.
- Modify: `compliance/bulk.rs` (the result wording for waiting ones).
- Modify: `http/openapi.rs`, the snapshot and the client. Keep the web compiling with minimal edits; Tasks 6 and 7 build the screens.
- Tests: `crates/openvibes-console/tests/suppressions_http.rs` (new; leave the old suppression part of `alarms_http.rs` updated or moved there).
- Docs: `docs/components/openvibes-console.md` and `console-rbac.md` (who may approve).

**Routes:**

| Method and path | Needs | Answer |
|---|---|---|
| `GET /api/v1/alarm-suppressions?state=waiting\|active\|rejected&alarm_id=` | `alarms.suppressions.read` | `{ items: AlarmSuppressionView[] }` |
| `GET /api/v1/alarm-suppressions/options` | `alarms.suppress` | `{ require_approval, all_hosts: bool, groups: [{id, name}] }`. The groups are those the suppress scope reaches: all groups when global, else the scope's groups. |
| `POST /api/v1/alarm-suppressions` | `alarms.suppress` + CSRF | 201 with the view. Body `{ alarm_id, what: "program"\|"command", where: {"kind":"host"}\|{"kind":"group","group_id"}\|{"kind":"all"}, for_days: 7\|30\|null, reason }`, `deny_unknown_fields` |
| `POST …/{id}/approve` | `alarms.suppressions.approve` + CSRF | 200 view |
| `POST …/{id}/reject` with `{ reason }` | `alarms.suppressions.approve` + CSRF | 200 view |
| `POST …/{id}/withdraw` | `alarms.suppress` + CSRF | 200 view |
| `DELETE …/{id}` | `alarms.suppress` + CSRF | 204 |

`AlarmSuppressionView` has:
- `id`, `rule_set_id`, `rule_id`;
- `what` (`program`, `command`, or the legacy `host`, `device` or `signature`);
- `where` (`{kind, agent_id?, hostname?, group_id?, group_name?}`);
- `exe`, `args_sha256`;
- `for_days`;
- `status` (`waiting`, `active`, `expired`, `rejected`);
- `reason`;
- `requested_by`, `requested_at`;
- `decided_by`, `decided_at`, `decision_reason`;
- `activated_at`, `expires_at`;
- `alarm_id`;
- `would_close`;
- `can_decide`, `can_withdraw`, `can_remove`.

The display names come from `COALESCE(display_name, username)` of `console_users` where the id is a user, falling back to the stored text.

**Refusals:**

| Status | Code | When |
|---|---|---|
| 404 | `alarm_not_found` | the alarm is missing or out of reach |
| 404 | `suppression_not_found` | the suppression is missing or out of reach, including approving outside reach |
| 403 | `global_scope_required` | where = all hosts without global suppress |
| 403 | `permission_denied` | not holding the permission; a group outside reach |
| 409 | `own_request` | "You can't approve or reject your own request" |
| 409 | `suppression_not_waiting` | |
| 422 | `invalid_suppression` | names the field: `reason`, `for` or `group` |

- [ ] **Step 1: Write the failing tests** with the `Fx` fixture. Set up two leads (team lead template) with the same rule group "linux", a Windows lead on "windows", an analyst on "linux", and an admin.

```rust
// options_follow_the_suppress_reach: analyst → all_hosts false, groups [linux]; admin → all_hosts true, all groups.
// analyst_request_waits_when_approval_is_on: admin PATCH setting on; analyst POST {program, group linux, 7, reason}
//   → 201 status "waiting", can_withdraw true for analyst; alarm still open (GET alarm state "open").
// lead_approves_and_it_becomes_active: linux lead POST approve → 200 status "active", expires_at ≈ now+7d;
//   alarm closed "false_positive".
// requester_cannot_approve_even_holding_approve_everywhere: admin requests (approval on), admin approves own → 409 own_request.
// approving_outside_reach_is_not_found: windows lead approve linux request → 404 suppression_not_found;
//   same body as approving id 999999.
// reject_needs_reason: reject {} → 422 invalid_suppression field reason; reject {"reason":"no"} → 200 rejected,
//   GET as the analyst shows decision_reason "no".
// withdraw_only_own: linux lead withdraw analyst's → 404; analyst → 200 withdrawn; then it is gone from the list.
// all_hosts_needs_global: analyst where all → 403 global_scope_required.
// group_outside_reach: analyst where group windows → 403 permission_denied.
// list_visibility: windows lead sees all-hosts rows and windows rows, not linux-group rows.
// can_decide_flags: linux lead sees can_decide true on the analyst's waiting row, false on own; analyst false.
// bearer_token_cannot_approve: a service-account token with approve → 403 (CSRF/bearer refusal as other writes).
// remove_active: analyst DELETE an active linux-group row → 204; on an all-hosts row → 404 (not in suppress reach).
```

- [ ] **Step 2: Run them to see them fail.**

- [ ] **Step 3: Write the handlers.**
  - Each one gets the scope for its own permission through `authenticated_permission` (it already refuses bearer tokens when `csrf_required`), then calls the Task 3 store functions.
  - Each `Change` variant maps to the table above; there is no wildcard arm.
  - The `can_*` flags are computed per row:
    - `can_decide` = status waiting, not own, and the row in the caller's approve reach (the approve scope from the caller's capabilities, through `scope_of`);
    - `can_withdraw` = waiting and own;
    - `can_remove` = active and in the suppress reach.
  - Give the store `list` an optional second and third scope, or call a small store `reach_flags(client, ids, approve, suppress)` that returns the two booleans per id with the Task 3 predicate. Choose whichever keeps the files under 500 lines, and record the choice in the report.

- [ ] **Step 4: Change bulk.** A waiting result counts as "requested" in the per-row message: "Suppression requested, waiting for approval".

- [ ] **Step 5: Regenerate the OpenAPI document and the client.** Make the minimal web edits to compile: `QuietMenu` sends the new body with Where All for program/command and Where Host for "On this host". Tasks 6 and 7 replace them. Run `cargo test -p openvibes-console` and the web typecheck, vitest and build.

- [ ] **Step 6: Commit:** `console: approve, reject and withdraw suppressions; options for the suppress form`.

---

### Task 6: The suppress form and a waiting request on the alarm (screen 12), with the demo

**Files:**
- Create: `web/src/panels/alarms/SuppressForm.tsx` and `SuppressForm.test.tsx`. Update the panels README.
- Modify: `web/src/views/investigate/Alarms.tsx`. `QuietMenu` becomes a single "Suppress…" button that opens the form. Keep the export name, or update both callers.
- Modify: `web/src/panels/alarms/AlarmPanel.tsx`. Show the waiting request and Withdraw.
- Modify: `web/src/demo/routes/alarms.ts`, `context.ts` and `data.ts`. Mirror Task 5's routes, states, refusals, flags, options and close-on-activation. Add a `require_approval` read from the demo settings (Task 2). Group membership comes from the step-2 demo evaluator (`web/src/demo/hostGroups.ts`). Expiry uses the demo's `now`.
- Modify: `web/src/ui/auditActions.ts` (the five transitions), and `web/src/demo/server.test.ts`.
- Modify: `web/e2e/demo/alarms.spec.ts` (the old Quiet tests).
- Docs: `docs/components/console-web.md`.

- [ ] **Step 1: Write the failing tests.** In `SuppressForm.test.tsx`, with `options` fixtures:
  - **What:** "This program" (shows the exe) and "This exact command" (shows exe and args).
  - **Where:** "This host" (hostname), then each group from options, then "All hosts" only when `all_hosts`.
  - **For:** 7 days, 30 days, until removed.
  - **Reason:** required; Request stays disabled until filled.
  - **With `require_approval`:** the note reads "Someone who can approve on those hosts must accept it. Until then these alarms keep arriving." and the button says "Request". Without it, the button says "Suppress".
  - **`bodyOf(form)`** (pure) gives the exact POST body.

  `AlarmPanel` test (markup): a waiting request for the alarm shows "Suppression requested, waiting for approval… these alarms keep arriving" and a "Withdraw request" button when `can_withdraw`.

  Demo e2e in `alarms.spec.ts`:
  - **Suppress with approval off:** the alarm closes and the row appears under Alarm suppressions → Active.
  - **With approval on:**
    - the panel shows the waiting text;
    - Withdraw works;
    - the request is made again;
    - an approver persona sees it under Waiting and approves;
    - the alarm closes.

  Pick personas the demo already has: one with suppress, one with approve on the same hosts. Add a persona if none fits, and update the persona list in the tests.

- [ ] **Step 2: Run them to see them fail.**

- [ ] **Step 3: Build the form**, inline in the panel or as a dialog that matches the approved screen 12. Load options from `GET /api/v1/alarm-suppressions/options`. Submit, then show the result:
  - when active, toast "Suppressed · recorded in the audit log" and invalidate the alarm and the list;
  - when waiting, the panel state.

  Errors appear in `role="alert"`. Disable controls while sending. The panel fetches `GET /api/v1/alarm-suppressions?alarm_id=<id>&state=waiting`.

- [ ] **Step 4: Write the demo routes** with the same semantics as Task 5. Add vitests for each refusal code.

- [ ] **Step 5: Run vitest, tsc, eslint and build, then the changed demo specs.** Then run the full demo e2e (`--workers=4`). Restore `.gitkeep`.

- [ ] **Step 6: Commit:** `console web: suppress form with where and duration; waiting request on the alarm (screen 12)`.

---

### Task 7: Alarm suppressions page with approvals (screen 14) and the menu count

**Files:**
- Rewrite: `web/src/views/operate/AlarmSuppressions.tsx` in the shared layout. Add `SuppressionRow.tsx` and `AlarmSuppressions.test.tsx`, and update the README.
- Modify: `web/src/shell/Chrome.tsx` `useMenuCounts()`. Add `/alarm-suppressions` with the count of `can_decide` waiting rows, fetched only when `can("alarms.suppressions.approve")`.
- Modify: the demo, if anything is missing for the page.
- Create: `web/e2e/demo/alarm-suppressions.spec.ts`.
- Docs: `docs/components/console-web.md`.

- [ ] **Step 1: Write the failing tests.** `AlarmSuppressions.test.tsx`, with a fixture list:
  - **Left column:** "By status" with Waiting 2, Active 3, Rejected 1, each linking to its card, then Recent changes.
  - **Right column:** one card per status, in that order.
  - **Each row:**
    - the command or program;
    - the What, Where and For chips;
    - the quoted reason;
    - "asked by Alice · 2 h ago";
    - for waiting rows, "Would have closed 12 alarms in the last 7 days";
    - the status badge (Waiting, Active, Expired, Rejected with the reason);
    - "Open alarm" when `alarm_id`;
    - the actions by flag: Approve and Reject… (`can_decide`), Withdraw (`can_withdraw`), Remove… (`can_remove`), and Ask again… on rejected rows that have an `alarm_id` and when the viewer holds `alarms.suppress`.
  - **Reject…** opens an inline required reason, and Reject stays disabled until it is filled.
  - **The menu count** is "2" for two `can_decide` rows, and nothing for 0.

  Demo e2e `alarm-suppressions.spec.ts`:
  - approve one, and see it move to Active;
  - reject one with a reason, and see the reason;
  - withdraw own;
  - remove an active one;
  - the menu count decreases;
  - run axe on the page.

- [ ] **Step 2: Run them to see them fail.**

- [ ] **Step 3: Build the page.**
  - **Header:** "Alarm suppressions", summary "Alarms that are closed as they arrive, and requests waiting for approval."
  - **Left column:** "By status" and Recent changes. Recent changes are the newest audit lines with actions `alarm.suppression.*`, from `GET /api/v1/audit-events` filtered by action when the viewer holds `audit.read`. Otherwise hide the card.
  - **"Ask again…"** opens `SuppressForm` (Task 6) prefilled from the row, with `alarm_id` from the row.
  - **After each action,** invalidate the list and the menu count, and show the toast "Saved · recorded in the audit log".

- [ ] **Step 4: Run vitest, tsc, eslint and build, then the new spec and the full demo e2e** (`--workers=4`). Restore `.gitkeep`.

- [ ] **Step 5: Commit:** `console web: Alarm suppressions with approvals (screen 14) and the waiting count`.

---

### Task 8: Live e2e, docs and the gate

**Files:**
- Modify: `web/e2e/live/teams.spec.ts`, or add `web/e2e/live/suppressions.spec.ts`, plus `scripts/console-e2e-server.sh` if the seed needs a second Linux lead and an alarm.
- Docs: one pass over every page these tasks touched. Add an "Upgrading" note in `docs/components/console-rbac.md`: existing suppressions stay active and program and command ones cover all hosts, and new ones can wait for approval when Settings › General says so.

- [ ] **Step 1: Write the live journey** (spec §15, "a suppression approved by the other team lead"):
  1. The admin turns "Suppressions need approval" on in Settings › General.
  2. Linux lead A suppresses an alarm on a Linux host for the Linux group. It waits.
  3. A's own Approve is not offered, and the API answers 409 for it.
  4. The Windows lead does not see the request.
  5. Linux lead B approves it, and the alarm is closed.
  6. The admin sees the five audit lines.

  Run it with `--workers=2` on chromium and firefox.

- [ ] **Step 2: Run the full local gate** (`~/Projects/OpenVIBES/testing.md` §2, including the browser items) once. Expected: all green. WebKit can't launch on this host, which is a known limitation.

- [ ] **Step 3: Commit.** No push and no PR; the controller opens it.

---

## Self-review notes

- **Spec coverage:**
  - §7 → Tasks 1 and 2;
  - §8.1 what, where, for and reason → Tasks 3, 5 and 6;
  - §8.2 states, approval, self-approval, withdraw, setting off, matching, expiry and the 7-day count → Tasks 3, 4 and 5;
  - §8.3 the page, menu badge, panel and audit → Tasks 6 and 7;
  - §12.5 upgrade → Task 3 (`suppression_upgrade.rs`);
  - §13 routes → Tasks 1 and 5;
  - §15 unit, store, demo e2e and live e2e items → each task, with the live part in Task 8.
- **Not here:**
  - Hosts pages (step 4);
  - distinct commands on the Alarms page (step 5);
  - SSO and the purge job (the setting is stored only).
- **Interfaces across tasks:**
  - `require_approval(&impl GenericClient)` (Task 1) is used by Task 3.
  - `suppression_matches` (Task 4) is used by `would_close` (Task 4).
  - The `Change` variants (Task 3) are mapped in Task 5.
  - `SuppressForm` (Task 6) is reused by "Ask again…" (Task 7).
  - The demo settings (Task 2) are read by the demo suppressions (Task 6).
- **Interim state:** after Task 3, the old Quiet body still works through a mapping, and Task 5 replaces it. The web compiles after every task. The full demo e2e is green after Tasks 2, 6 and 7. The live e2e is not touched before Task 8.
