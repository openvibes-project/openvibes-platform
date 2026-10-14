# Rule-set assignment, part 2: rules RPM and platform backend Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The project's hardening L1 set ships in the rules RPM, Setup publishes it, and the platform decides per host (default plus asset-group overrides, on wins) whether an assignable set runs: distribution answers `410` for a set that is off, ingest ends the host's open matches of the set once the agent reports it `not_assigned` (triage untouched), and the console API exposes the switches for the later screens.

**Architecture:** One migration adds `rule_set_assignment` (default per assignable set) and `rule_set_group_assignment` (overrides, cascading with the group). A new store module `platform_store::rule_assignment` holds the console reads and audited writes and one SQL resolution (`HOST_STATE`) shared by distribution (`assigned`) and the console host view (`for_agent`). Ingest gets `finding_changes::end_unassigned`, called from the heartbeat handler. Setup's rules step loops over the optional stems present in `/usr/share/openvibes/rules`.

**Tech Stack:** Rust (axum, tokio-postgres, utoipa), PostgreSQL migrations, RPM spec (rules repo), bash (lab).

**Spec:** `docs/specs/2026-10-14-rule-set-assignment-design.md` (§5, §7 steps 3–5), completing `docs/specs/2026-10-09-hardening-rules-design.md` step 5. The console screens (§6) are a separate plan, made after the companion mockups.

## Global Constraints

- TDD: every task writes the failing test first. Database tests need `eval "$(scripts/test-db.sh)"` first; without `OPENVIBES_TEST_DATABASE_URL` they are skipped, and a green run proves nothing (check the variable is set).
- New files stay under 500 lines; `fleet.rs` and `router.rs` already exceed it, so do not grow them beyond the lines shown here.
- Every component change updates its `docs/components/` page in the same commit (new page: `docs/components/rule-set-assignment.md`, indexed in `docs/components/README.md`).
- Commits end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. Git identity in every repo: `itismelime` / `26064407+itismelime@users.noreply.github.com`.
- Protocol first: P20 (`410 Gone`, health per-set state `not_assigned`) is plan 1's Task 1, not this plan's. Task 6 consumes it and waits until it is merged into agent `main`.
- The platform gate (`testing.md` §2) passes locally before any PR; the Fedora job (`testing.md` §3) runs because migrations change grants the installed services use. Rules RPM changes are checked with `bash scripts/build-rpm.sh dist` in `registry.fedoraproject.org/fedora:44`.
- Scratch builds: `CARGO_TARGET_DIR=~/.cache/openvibes-scratch/target`, `nice -n 19`, never `/tmp` (RAM here). One heavy job at a time.
- This host runs the user's production platform: never touch its `openvibes-*` services or database, no `sudo`.
- Least privilege for database roles: table or column `SELECT` only where a query needs it; new tables `REVOKE ALL ... FROM PUBLIC`.
- Migration number: `0049` is the next free one on `origin/main` (schema 48). The user's `feat/netlog` branch also has a `0049`; whichever merges second renumbers at rebase (`SCHEMA_VERSION`, the `MIGRATIONS` entry, the file name, the doc headings).
- The spec's fixed strings, verbatim: audit action `rules.assignment.change`; history note `rule set no longer assigned to this host` (by `system`); set ids `hardening-linux-l1` (default on), `hardening-linux-l2` (default off).
- Lab ssh, when not through `./lab ssh`: `-o IdentitiesOnly=yes -o IdentityAgent=none`.

## Review Focus

1. **A host in no group gets the set's default**, and a group with no selectors matches no host (as for access). Test: Task 3 `a_host_in_no_group_gets_the_default`.
2. **A host in two groups, one on and one off, runs the set** (on wins), and deleting the "on" group drops it back to the other group's off. Tests: Task 3 `on_wins_and_a_deleted_group_falls_back`, Task 4 `on_wins_across_groups`.
3. **An unknown, retired or unpublished set still answers 404, never 410**, even when it is switched off. Test: Task 4 `unpublished_or_retired_sets_stay_not_found`.
4. **Ending matches is idempotent across repeated heartbeats** and never ends another set's, another host's, or a non-assignable set's matches, and never changes triage (no state, note or version change; user decision 2026-10-14). Tests: Task 6 `ends_only_this_hosts_open_matches_of_the_set`, `repeated_reports_end_nothing_more`, `a_non_assignable_set_ends_nothing`, `triage_is_never_touched`.
5. **An agent from before P20 sees no change**: it never asks for hardening, its baseline and alarm sets answer as before with both assignable sets switched off, and a heartbeat without a per-set state ends nothing. Tests: Task 4 `other_sets_are_unchanged`, Task 6 `a_heartbeat_without_state_ends_nothing`.

---

## File structure

| File | Responsibility |
|---|---|
| `openvibes-rules/openvibes-rules-baseline.spec`, `scripts/build-rpm.sh` | Ship `hardening-linux-l1.{json,key}` |
| `openvibes-rules/docs/components/hardening-linux-l1.md` | Says the set is signed and shipped |
| `migrations/0049_rule_set_assignment.sql` | Tables, defaults, grants (console, distribution, ingest) |
| `crates/platform-store/src/migrate.rs` | `SCHEMA_VERSION = 49`, migration entry |
| `crates/platform-store/src/rule_assignment.rs` (new) | Overview, audited writes, host resolution |
| `crates/platform-store/src/finding_changes.rs` | `end_unassigned` |
| `crates/platform-store/src/console_read.rs` | `AgentRuleSet.state` |
| `crates/openvibes-distribution/src/lib.rs` | `410` for an off set |
| `crates/openvibes-console/src/rule_assignment.rs` (new) | `/api/v1/rule-set-assignments…`, host view |
| `crates/openvibes-console/src/{lib,router,openapi,api}.rs` | Module, routes, OpenAPI, `AgentRuleSetView.state` |
| `crates/openvibes-ingest/src/delivery.rs` | Heartbeat calls `end_unassigned` |
| `crates/openvibes-admin/src/setup/fleet.rs` | Optional stems loop (alarms, hardening L1, L2) |
| `docs/components/rule-set-assignment.md` (new) + existing pages | Docs |

---

### Task 1: The rules RPM ships hardening L1 (openvibes-rules)

**Files:**
- Modify: `/home/lime/Projects/OpenVIBES/openvibes-rules/scripts/build-rpm.sh` (header comment, `rpmbuild` defines, `want` list)
- Modify: `/home/lime/Projects/OpenVIBES/openvibes-rules/openvibes-rules-baseline.spec` (`%description`, `%install`, `%files`)
- Modify: `/home/lime/Projects/OpenVIBES/openvibes-rules/docs/components/hardening-linux-l1.md` (Interfaces "Signing" bullet, "How to test")

**Interfaces:**
- Produces: `/usr/share/openvibes/rules/hardening-linux-l1.json` and `.key` (key line `hardening-linux-l1 openvibes-1 <PUBLIC_KEY>`), read by Task 7. Stem = set id.

- [ ] **Step 1: Branch**

```bash
cd /home/lime/Projects/OpenVIBES/openvibes-rules
git fetch origin && git switch -c claude/rpm-hardening-l1 origin/main
git config user.name itismelime
git config user.email 26064407+itismelime@users.noreply.github.com
```

- [ ] **Step 2: Write the failing test (the RPM's expected file list)**

In `scripts/build-rpm.sh`, replace the header's second line and the `want` list:

```bash
# checks it: rpmlint without errors, exactly the six rule files (baseline,
# alarm and hardening L1 rule sets, with their keys), the licence and NOTICE,
# and two directories. The version is the signed envelope's rule set version.
```

```bash
want='/usr/share/licenses/openvibes-rules-baseline/LICENSE
/usr/share/licenses/openvibes-rules-baseline/NOTICE
/usr/share/openvibes
/usr/share/openvibes/rules
/usr/share/openvibes/rules/alarms.json
/usr/share/openvibes/rules/alarms.key
/usr/share/openvibes/rules/baseline.json
/usr/share/openvibes/rules/baseline.key
/usr/share/openvibes/rules/hardening-linux-l1.json
/usr/share/openvibes/rules/hardening-linux-l1.key'
```

and add the define after `--define "alarms_dir $root/alarms" \`:

```bash
    --define "hardening_dir $root/hardening" \
```

- [ ] **Step 3: Run it to verify it fails**

```bash
cd /home/lime/Projects/OpenVIBES/openvibes-rules
podman run --rm -v "$PWD":/src:Z -w /src registry.fedoraproject.org/fedora:44 \
  bash -c 'dnf -q -y install rpm-build rpmlint jq && bash scripts/build-rpm.sh dist'
```

Expected: FAIL with `build-rpm: unexpected files:` (the spec does not install the hardening files yet).

- [ ] **Step 4: Ship the files**

In `openvibes-rules-baseline.spec`, replace the `%description` body with:

```text
The OpenVIBES project's signed baseline rule set, the threat-alarm rule
set (baseline-alarms, for agents 0.2 and later), the Linux hardening
level 1 rule set (hardening-linux-l1), and their public keys.
openvibes-admin Setup trusts the keys and publishes the rule sets; the
platform decides per host whether hardening runs.
```

after the two `alarms` install lines add:

```text
# The project's hardening sets live in hardening/ (build-rpm.sh passes it);
# level 2 joins here once it is signed.
install -D -m 0644 %{hardening_dir}/linux-l1/hardening-linux-l1.json %{buildroot}%{_datadir}/openvibes/rules/hardening-linux-l1.json
install -D -m 0644 %{hardening_dir}/linux-l1/hardening-linux-l1.key %{buildroot}%{_datadir}/openvibes/rules/hardening-linux-l1.key
```

and after `%{_datadir}/openvibes/rules/alarms.key` in `%files`:

```text
%{_datadir}/openvibes/rules/hardening-linux-l1.json
%{_datadir}/openvibes/rules/hardening-linux-l1.key
```

- [ ] **Step 5: Run it to verify it passes**

Same `podman run` as Step 3. Expected: `build-rpm: openvibes-rules-baseline-4-1.fc44.noarch.rpm`, no rpmlint error.

- [ ] **Step 6: Fix the component page**

In `docs/components/hardening-linux-l1.md` replace the "Signing" bullet with:

```markdown
- Signed: `hardening/linux-l1/hardening-linux-l1.json` (Ed25519, issuer
  `openvibes-1`, version 4 from release v4) and its key line
  `hardening/linux-l1/hardening-linux-l1.key`. The RPM
  `openvibes-rules-baseline` installs both to `/usr/share/openvibes/rules/`
  (0644); platform Setup and `helper rules-apply` trust and publish them, and
  the platform switches the set per asset group (platform spec
  `2026-10-14-rule-set-assignment-design.md`).
```

and replace the "How to test" block and its last sentence with:

```text
cargo run -p hardening-check -- --dir hardening/linux-l1 \
  --cases tests/hardening-l1-cases.json --allowlist hardening.allowlist \
  --set hardening-linux-l1
```

```markdown
prints `ok: 43 rules, 149 cases` and verifies the envelope against the key.
`bash scripts/build-rpm.sh dist` in `fedora:44` checks the RPM ships both files.
```

- [ ] **Step 7: Rules gate, commit**

```bash
cd /home/lime/Projects/OpenVIBES/openvibes-rules
nice -n 19 cargo run --locked -p hardening-check -- --dir hardening/linux-l1 \
  --cases tests/hardening-l1-cases.json --allowlist hardening.allowlist --set hardening-linux-l1
cargo fmt --check && nice -n 19 cargo clippy --locked --all-targets -- -D warnings && nice -n 19 cargo test --locked
git add scripts/build-rpm.sh openvibes-rules-baseline.spec docs/components/hardening-linux-l1.md
git commit -m "RPM: ship hardening-linux-l1 beside the baseline and alarms

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

Expected: `ok: 43 rules, 149 cases`, all green. Open the PR (body: what, the commands above with results, the AI disclosure CONTRIBUTING.md asks for). Note in the PR body: hosts get the file only with the next rules release (v5), which the maintainer signs; the RPM version stays the baseline envelope's.

---

### Task 2: Migration and store, assignment configuration with audit

**Files:**
- Create: `migrations/0049_rule_set_assignment.sql`
- Modify: `crates/platform-store/src/migrate.rs:6` (`SCHEMA_VERSION`), `:170-174` (entry)
- Create: `crates/platform-store/src/rule_assignment.rs`
- Modify: `crates/platform-store/src/lib.rs` (`pub mod rule_assignment;` after `pub mod rule_drafts;`)
- Test: `crates/platform-store/tests/rule_assignment.rs` (new)
- Docs: create `docs/components/rule-set-assignment.md`; add a row to `docs/components/README.md`; add a section to `docs/components/platform-store.md`

**Interfaces:**
- Produces (`platform_store::rule_assignment`):
  - `pub struct GroupOverride { pub asset_group_id: String, pub name: String, pub enabled: bool }`
  - `pub struct Assignment { pub rule_set_id: String, pub default_enabled: bool, pub published: bool, pub groups: Vec<GroupOverride> }`
  - `pub struct GroupName { pub asset_group_id: String, pub name: String }`
  - `pub struct Overview { pub sets: Vec<Assignment>, pub groups: Vec<GroupName> }`
  - `pub enum Change { Done(Assignment), UnknownSet, UnknownGroup }`
  - `pub async fn overview(client: &Client) -> Result<Overview, StoreError>`
  - `pub async fn set_default(client: &mut Client, actor: &str, set: &str, enabled: bool) -> Result<Change, StoreError>`
  - `pub async fn set_group(client: &mut Client, actor: &str, set: &str, group: &str, enabled: Option<bool>) -> Result<Change, StoreError>` (`None` removes the override)
- Tables: `rule_set_assignment(rule_set_id text PK, default_enabled bool)`, `rule_set_group_assignment(rule_set_id, asset_group_id uuid, enabled bool)`.

- [ ] **Step 1: Write the failing tests**

Create `crates/platform-store/tests/rule_assignment.rs`:

```rust
//! Rule-set assignment (spec 2026-10-14): defaults, group overrides, audit,
//! run as the roles that use them.

mod common;

use common::TestDb;
use platform_store::{
    Client,
    rule_assignment::{self, Change, GroupOverride},
};

const L1: &str = "hardening-linux-l1";
const L2: &str = "hardening-linux-l2";

/// The migrated database and an admin client (kept for the whole test, so
/// pooled connections with a role set are never handed back as admin).
async fn setup() -> (TestDb, Client) {
    let db = TestDb::create().await;
    let mut admin = db.pool.get().await.unwrap();
    platform_store::migrate(&mut admin).await.unwrap();
    (db, admin)
}

async fn as_role(db: &TestDb, role: &str) -> Client {
    let client = db.pool.get().await.unwrap();
    client
        .batch_execute(&format!("SET ROLE \"{role}\""))
        .await
        .unwrap();
    client
}

/// An asset group whose hosts carry every `selectors` tag; its id.
async fn group(admin: &Client, name: &str, selectors: &[(&str, &str)]) -> String {
    let id: String = admin
        .query_one(
            "INSERT INTO console_asset_groups (asset_group_id, name, created_at, created_by)
             VALUES (gen_random_uuid(), $1, now(), 'test') RETURNING asset_group_id::text",
            &[&name],
        )
        .await
        .unwrap()
        .get(0);
    for (key, value) in selectors {
        admin
            .execute(
                "INSERT INTO console_asset_group_selectors (asset_group_id, tag_key, tag_value, created_at)
                 VALUES ($1::text::uuid, $2, $3, now())",
                &[&id, key, value],
            )
            .await
            .unwrap();
    }
    id
}

async fn audits(admin: &Client) -> Vec<serde_json::Value> {
    admin
        .query(
            "SELECT detail FROM audit_log WHERE action = 'rules.assignment.change' ORDER BY id",
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|row| row.get(0))
        .collect()
}

fn done(change: Change) -> rule_assignment::Assignment {
    match change {
        Change::Done(assignment) => assignment,
        other => panic!("expected Done, got {other:?}"),
    }
}

#[tokio::test]
async fn the_defaults_are_l1_on_and_l2_off() {
    let (db, admin) = setup().await;
    let web = group(&admin, "web", &[("env", "web")]).await;
    let console = as_role(&db, "openvibes-console").await;
    let overview = rule_assignment::overview(&console).await.unwrap();
    let sets: Vec<_> = overview
        .sets
        .iter()
        .map(|s| (s.rule_set_id.as_str(), s.default_enabled, s.published, s.groups.len()))
        .collect();
    assert_eq!(sets, [(L1, true, false, 0), (L2, false, false, 0)]);
    assert_eq!(overview.groups.len(), 1);
    assert_eq!(overview.groups[0].asset_group_id, web);
    // A live bundle makes the set published; retiring it unpublishes it.
    let mut admin = admin;
    platform_store::rules::add_trust_key(&mut admin, L1, "openvibes-1", [9; 32])
        .await
        .unwrap();
    platform_store::rules::publish(
        &mut admin,
        &platform_store::rules::NewBundle {
            rule_set_id: L1,
            version: 1,
            envelope: b"{}",
            envelope_sha256: [0; 32],
            issuer_key_id: "openvibes-1",
            created_at_ms: 0,
            expires_at_ms: i64::MAX,
            published_by: "test",
        },
    )
    .await
    .unwrap();
    let published = |o: &rule_assignment::Overview| o.sets[0].published;
    assert!(published(&rule_assignment::overview(&console).await.unwrap()));
    platform_store::rules::retire(&admin, L1).await.unwrap();
    assert!(!published(&rule_assignment::overview(&console).await.unwrap()));
    drop((console, admin));
    db.drop().await;
}

#[tokio::test]
async fn a_default_change_is_audited_with_old_and_new() {
    let (db, admin) = setup().await;
    let mut console = as_role(&db, "openvibes-console").await;
    let l2 = done(rule_assignment::set_default(&mut console, "alice", L2, true).await.unwrap());
    assert!(l2.default_enabled);
    // The same value again changes nothing and is not audited.
    done(rule_assignment::set_default(&mut console, "alice", L2, true).await.unwrap());
    assert_eq!(
        rule_assignment::set_default(&mut console, "alice", "baseline", false)
            .await
            .unwrap(),
        Change::UnknownSet
    );
    let rows = audits(&admin).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0],
        serde_json::json!({"rule_set_id": L2, "asset_group_id": null,
            "asset_group_name": null, "old": false, "new": true})
    );
    let actor: String = admin
        .query_one(
            "SELECT actor FROM audit_log WHERE action = 'rules.assignment.change'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(actor, "alice");
    drop((console, admin));
    db.drop().await;
}

#[tokio::test]
async fn group_overrides_are_set_changed_removed_and_audited() {
    let (db, admin) = setup().await;
    let web = group(&admin, "web", &[("env", "web")]).await;
    let mut console = as_role(&db, "openvibes-console").await;
    let c = &mut console;
    let l1 = done(rule_assignment::set_group(c, "alice", L1, &web, Some(false)).await.unwrap());
    assert_eq!(
        l1.groups,
        [GroupOverride {
            asset_group_id: web.clone(),
            name: "web".into(),
            enabled: false
        }]
    );
    let l1 = done(rule_assignment::set_group(c, "alice", L1, &web, Some(true)).await.unwrap());
    assert!(l1.groups[0].enabled);
    let l1 = done(rule_assignment::set_group(c, "alice", L1, &web, None).await.unwrap());
    assert!(l1.groups.is_empty());
    // Removing what is not there changes nothing.
    let l1 = done(rule_assignment::set_group(c, "alice", L1, &web, None).await.unwrap());
    assert!(l1.groups.is_empty());
    assert_eq!(
        rule_assignment::set_group(&mut console, "alice", L1, "00000000-0000-4000-8000-000000000000", Some(true))
            .await
            .unwrap(),
        Change::UnknownGroup
    );
    assert_eq!(
        rule_assignment::set_group(&mut console, "alice", L1, "not-a-uuid", Some(true))
            .await
            .unwrap(),
        Change::UnknownGroup
    );
    assert_eq!(
        rule_assignment::set_group(&mut console, "alice", "baseline", &web, Some(true))
            .await
            .unwrap(),
        Change::UnknownSet
    );
    let olds_news: Vec<_> = audits(&admin)
        .await
        .iter()
        .map(|d| (d["old"].clone(), d["new"].clone(), d["asset_group_name"].clone()))
        .collect();
    assert_eq!(
        olds_news,
        [
            (serde_json::Value::Null, false.into(), "web".into()),
            (false.into(), true.into(), "web".into()),
            (true.into(), serde_json::Value::Null, "web".into()),
        ]
    );
    drop((console, admin));
    db.drop().await;
}

#[tokio::test]
async fn deleting_a_group_deletes_its_overrides() {
    let (db, admin) = setup().await;
    let web = group(&admin, "web", &[("env", "web")]).await;
    let mut console = as_role(&db, "openvibes-console").await;
    done(rule_assignment::set_group(&mut console, "alice", L1, &web, Some(false)).await.unwrap());
    admin
        .execute(
            "DELETE FROM console_asset_groups WHERE asset_group_id::text = $1",
            &[&web],
        )
        .await
        .unwrap();
    let overview = rule_assignment::overview(&console).await.unwrap();
    assert!(overview.sets[0].groups.is_empty() && overview.groups.is_empty());
    drop((console, admin));
    db.drop().await;
}
```

- [ ] **Step 2: Run them to verify they fail**

```bash
cd /home/lime/Projects/OpenVIBES/openvibes-platform-assign
eval "$(scripts/test-db.sh)"; echo "${OPENVIBES_TEST_DATABASE_URL:?not set}"
export CARGO_TARGET_DIR=~/.cache/openvibes-scratch/target
nice -n 19 cargo test --locked -p platform-store --test rule_assignment
```

Expected: FAIL to compile, `could not find rule_assignment in platform_store`.

- [ ] **Step 3: The migration**

Create `migrations/0049_rule_set_assignment.sql`:

```sql
-- OpenVIBES platform schema version 49: rule-set assignment (spec
-- 2026-10-14-rule-set-assignment-design.md). The project's assignable rule
-- sets with their default, and on/off overrides per asset group. On a host,
-- any matching group that says on wins, else any that says off, else the
-- default. No foreign key to rule_sets: a set is assignable before its
-- rules are published (L2 shows "not available yet").
CREATE TABLE rule_set_assignment (
    rule_set_id text PRIMARY KEY CHECK (length(rule_set_id) BETWEEN 1 AND 128),
    default_enabled boolean NOT NULL
);
CREATE TABLE rule_set_group_assignment (
    rule_set_id text NOT NULL REFERENCES rule_set_assignment ON DELETE CASCADE,
    asset_group_id uuid NOT NULL REFERENCES console_asset_groups ON DELETE CASCADE,
    enabled boolean NOT NULL,
    PRIMARY KEY (rule_set_id, asset_group_id)
);
INSERT INTO rule_set_assignment (rule_set_id, default_enabled) VALUES
    ('hardening-linux-l1', true), ('hardening-linux-l2', false);
REVOKE ALL ON rule_set_assignment, rule_set_group_assignment FROM PUBLIC;
-- The console switches defaults and overrides (rules.upload).
GRANT SELECT, UPDATE ON rule_set_assignment TO "openvibes-console";
GRANT SELECT, INSERT, UPDATE, DELETE ON rule_set_group_assignment TO "openvibes-console";
```

In `crates/platform-store/src/migrate.rs` set `pub const SCHEMA_VERSION: i32 = 49;` and append after the `48` entry:

```rust
    (
        49,
        include_str!("../../../migrations/0049_rule_set_assignment.sql"),
    ),
```

- [ ] **Step 4: The store module**

Create `crates/platform-store/src/rule_assignment.rs`:

```rust
//! Rule-set assignment (spec 2026-10-14-rule-set-assignment-design.md): which
//! of the project's assignable sets run on which hosts. A default per set and
//! on/off overrides per asset group; console writes are audited
//! (`rules.assignment.change`) with the old and new value.

use crate::{Client, StoreError};

/// One asset group's override for a set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupOverride {
    /// The group.
    pub asset_group_id: String,
    /// Its name.
    pub name: String,
    /// On or off for the group's hosts.
    pub enabled: bool,
}

/// An assignable set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Assignment {
    /// Rule set id.
    pub rule_set_id: String,
    /// On or off for hosts no override covers.
    pub default_enabled: bool,
    /// A live (not retired) bundle is published, so agents can get it.
    pub published: bool,
    /// Overrides, by group name.
    pub groups: Vec<GroupOverride>,
}

/// An asset group an override can name.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupName {
    /// The group.
    pub asset_group_id: String,
    /// Its name.
    pub name: String,
}

/// Every assignable set, and every asset group.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Overview {
    /// The sets, by id.
    pub sets: Vec<Assignment>,
    /// The groups, by name.
    pub groups: Vec<GroupName>,
}

/// Outcome of a change.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Change {
    /// Applied (or already so); the set as it now is.
    Done(Assignment),
    /// Not an assignable set.
    UnknownSet,
    /// No such asset group.
    UnknownGroup,
}

/// Every assignable set with its overrides, and every asset group.
pub async fn overview(client: &Client) -> Result<Overview, StoreError> {
    let sets = client
        .query(
            "SELECT a.rule_set_id, a.default_enabled,
                    EXISTS (SELECT 1 FROM rule_bundles b JOIN rule_sets s USING (rule_set_id)
                            WHERE b.rule_set_id = a.rule_set_id AND s.retired_at IS NULL)
             FROM rule_set_assignment a ORDER BY a.rule_set_id",
            &[],
        )
        .await?;
    let overrides = client
        .query(
            "SELECT o.rule_set_id, o.asset_group_id::text, g.name, o.enabled
             FROM rule_set_group_assignment o JOIN console_asset_groups g USING (asset_group_id)
             ORDER BY g.name",
            &[],
        )
        .await?;
    let groups = client
        .query(
            "SELECT asset_group_id::text, name FROM console_asset_groups ORDER BY name",
            &[],
        )
        .await?;
    Ok(Overview {
        sets: sets
            .iter()
            .map(|row| {
                let rule_set_id: String = row.get(0);
                Assignment {
                    groups: overrides
                        .iter()
                        .filter(|o| o.get::<_, &str>(0) == rule_set_id)
                        .map(|o| GroupOverride {
                            asset_group_id: o.get(1),
                            name: o.get(2),
                            enabled: o.get(3),
                        })
                        .collect(),
                    rule_set_id,
                    default_enabled: row.get(1),
                    published: row.get(2),
                }
            })
            .collect(),
        groups: groups
            .iter()
            .map(|row| GroupName {
                asset_group_id: row.get(0),
                name: row.get(1),
            })
            .collect(),
    })
}

async fn current(client: &Client, set: &str) -> Result<Change, StoreError> {
    Ok(overview(client)
        .await?
        .sets
        .into_iter()
        .find(|a| a.rule_set_id == set)
        .map_or(Change::UnknownSet, Change::Done))
}

/// One `rules.assignment.change` row: `group` is (id, name), `None` for the
/// default; `None` as old or new means "no override".
async fn audit(
    transaction: &tokio_postgres::Transaction<'_>,
    actor: &str,
    set: &str,
    group: Option<(&str, &str)>,
    old: Option<bool>,
    new: Option<bool>,
) -> Result<(), StoreError> {
    transaction
        .execute(
            "INSERT INTO audit_log (actor, action, target, result, detail, actor_kind, actor_id,
                 actor_display, target_kind, target_id)
             VALUES ($1, 'rules.assignment.change', 'rule_set', 'success',
                 jsonb_build_object('rule_set_id', $2::text, 'asset_group_id', $3::text,
                     'asset_group_name', $4::text, 'old', $5::boolean, 'new', $6::boolean),
                 'user', $1, $1, 'rule_set', $2)",
            &[&actor, &set, &group.map(|g| g.0), &group.map(|g| g.1), &old, &new],
        )
        .await?;
    Ok(())
}

/// Switches a set's default. Setting the value it has is a no-op (no audit).
pub async fn set_default(
    client: &mut Client,
    actor: &str,
    set: &str,
    enabled: bool,
) -> Result<Change, StoreError> {
    let transaction = client.transaction().await?;
    let Some(row) = transaction
        .query_opt(
            "SELECT default_enabled FROM rule_set_assignment WHERE rule_set_id = $1 FOR UPDATE",
            &[&set],
        )
        .await?
    else {
        return Ok(Change::UnknownSet);
    };
    let old: bool = row.get(0);
    if old != enabled {
        transaction
            .execute(
                "UPDATE rule_set_assignment SET default_enabled = $2 WHERE rule_set_id = $1",
                &[&set, &enabled],
            )
            .await?;
        audit(&transaction, actor, set, None, Some(old), Some(enabled)).await?;
    }
    transaction.commit().await?;
    current(client, set).await
}

/// Sets (`Some`) or removes (`None`) a group's override. `group` is compared
/// as text, so a malformed id is simply unknown.
pub async fn set_group(
    client: &mut Client,
    actor: &str,
    set: &str,
    group: &str,
    enabled: Option<bool>,
) -> Result<Change, StoreError> {
    let transaction = client.transaction().await?;
    if transaction
        .query_opt(
            "SELECT 1 FROM rule_set_assignment WHERE rule_set_id = $1 FOR UPDATE",
            &[&set],
        )
        .await?
        .is_none()
    {
        return Ok(Change::UnknownSet);
    }
    let Some(row) = transaction
        .query_opt(
            "SELECT asset_group_id::text, name FROM console_asset_groups
             WHERE asset_group_id::text = $1",
            &[&group],
        )
        .await?
    else {
        return Ok(Change::UnknownGroup);
    };
    let (group_id, name): (String, String) = (row.get(0), row.get(1));
    let old: Option<bool> = transaction
        .query_opt(
            "SELECT enabled FROM rule_set_group_assignment
             WHERE rule_set_id = $1 AND asset_group_id::text = $2",
            &[&set, &group_id],
        )
        .await?
        .map(|row| row.get(0));
    if old != enabled {
        match enabled {
            Some(on) => {
                transaction
                    .execute(
                        "INSERT INTO rule_set_group_assignment (rule_set_id, asset_group_id, enabled)
                         VALUES ($1, $2::text::uuid, $3)
                         ON CONFLICT (rule_set_id, asset_group_id) DO UPDATE SET enabled = EXCLUDED.enabled",
                        &[&set, &group_id, &on],
                    )
                    .await?
            }
            None => {
                transaction
                    .execute(
                        "DELETE FROM rule_set_group_assignment
                         WHERE rule_set_id = $1 AND asset_group_id::text = $2",
                        &[&set, &group_id],
                    )
                    .await?
            }
        };
        audit(&transaction, actor, set, Some((&group_id, &name)), old, enabled).await?;
    }
    transaction.commit().await?;
    current(client, set).await
}
```

Add `pub mod rule_assignment;` to `crates/platform-store/src/lib.rs` after `pub mod rule_drafts;` (keep the doc-comment style of the neighbours: one `///` line above it, "Rule-set assignment: defaults, group overrides, per-host state.").

- [ ] **Step 5: Run them to verify they pass**

```bash
nice -n 19 cargo test --locked -p platform-store --test rule_assignment
nice -n 19 cargo test --locked -p platform-store --test migrate
```

Expected: PASS (4 tests; migrate still green with schema 49).

- [ ] **Step 6: Docs**

Create `docs/components/rule-set-assignment.md`:

```markdown
# Rule-set assignment

Which of the project's assignable rule sets run on which hosts, switched per
asset group in the console with no host-side step. Spec:
[`../specs/2026-10-14-rule-set-assignment-design.md`](../specs/2026-10-14-rule-set-assignment-design.md).

## Purpose

Agents know the project's sets and ask for every one of their OS family
(protocol P20). The platform answers per host: a set that is off for the host
gets `410 Gone`, the agent stops running it and reports `not_assigned`, and
ingest ends its open matches there (triage untouched, one history entry
saying why).

## Interfaces

**Tables (schema 49).** `rule_set_assignment` has one row per assignable set
with its default: `hardening-linux-l1` on, `hardening-linux-l2` off (the row
exists before the rules are published). `rule_set_group_assignment` holds
on/off overrides per asset group; deleting a group deletes its rows.

**A host's state for a set:** on if any group the host matches says on (on
wins); else off if any of its groups says off; else the default. A host
matches a group when it carries every selector tag; a group without
selectors matches no host (as for access).

**Store (`platform_store::rule_assignment`).** `overview` (sets, overrides,
whether a live bundle is published, every group), `set_default` and
`set_group` (`None` removes an override). A change writes one audit row
`rules.assignment.change` (actor, `rule_set_id`, `asset_group_id`,
`asset_group_name`, `old`, `new`; `null` for "default" or "no override");
setting the current value writes nothing.

## Configuration

None: defaults come from the migration and are changed in the console.

## Failure behaviour

A database error is a 503 for the console caller; nothing is half written
(each change is one transaction).

## How to test

`eval "$(scripts/test-db.sh)"; cargo test -p platform-store --test rule_assignment`.
```

In `docs/components/README.md` add after the `console-rbac` row:

```markdown
| `rule-set-assignment` | store module, console API, distribution and ingest behaviour | per-group switches for the project's assignable rule sets (hardening L1/L2): defaults, overrides, on wins, `410` answers, matches ended when a host stops running a set (schema 49) | [rule-set-assignment.md](rule-set-assignment.md) |
```

and change the `platform-store` row's "schema 47," to "schema 49, rule-set assignment,". Append to the end of `docs/components/platform-store.md`:

```markdown
## Rule-set assignment (`rule_assignment::…`, schema 49)

`rule_set_assignment` (default per assignable set) and
`rule_set_group_assignment` (overrides per asset group, cascading with the
group); the console role reads and writes them. Behaviour, grants and tests:
[rule-set-assignment.md](rule-set-assignment.md).
```

- [ ] **Step 7: Commit**

```bash
cargo fmt --all
git add migrations/0049_rule_set_assignment.sql crates/platform-store/src/migrate.rs \
  crates/platform-store/src/lib.rs crates/platform-store/src/rule_assignment.rs \
  crates/platform-store/tests/rule_assignment.rs docs/components/rule-set-assignment.md \
  docs/components/README.md docs/components/platform-store.md
git commit -m "Store: rule-set assignment defaults and group overrides, audited

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 3: A host's state for a set (on wins), readable by distribution

**Files:**
- Modify: `crates/platform-store/src/rule_assignment.rs` (append `Source`, `HostAssignment`, `HOST_STATE`, `assigned`, `for_agent`)
- Modify: `migrations/0049_rule_set_assignment.sql` (append distribution grants)
- Test: `crates/platform-store/tests/rule_assignment.rs` (append)
- Docs: `docs/components/rule-set-assignment.md` (Interfaces), `docs/components/openvibes-distribution.md` (role sentence in Configuration)

**Interfaces:**
- Consumes: Task 2 tables and module.
- Produces:
  - `pub enum Source { Default, Group }`
  - `pub struct HostAssignment { pub rule_set_id: String, pub enabled: bool, pub source: Source }`
  - `pub async fn assigned(client: &Client, agent_id: &str, set: &str) -> Result<bool, StoreError>` (true for any set that is not assignable)
  - `pub async fn for_agent(client: &Client, scope: &crate::console_read::AgentScope, agent_id: &str) -> Result<Option<Vec<HostAssignment>>, StoreError>` (`None`: unknown or not visible)

- [ ] **Step 1: Write the failing tests**

Append to `crates/platform-store/tests/rule_assignment.rs`:

```rust
use platform_store::{
    console_read::AgentScope,
    rule_assignment::{HostAssignment, Source},
};

async fn agent(admin: &Client, id: &str, tags: &[(&str, &str)]) {
    admin
        .execute(
            "INSERT INTO agents (agent_id, status, enrolled_at) VALUES ($1, 'active', now())",
            &[&id],
        )
        .await
        .unwrap();
    for (key, value) in tags {
        admin
            .execute(
                "INSERT INTO console_agent_tags (agent_id, tag_key, tag_value, changed_at, changed_by)
                 VALUES ($1, $2, $3, now(), 'test')",
                &[&id, key, value],
            )
            .await
            .unwrap();
    }
}

async fn assigned(dist: &Client, agent: &str, set: &str) -> bool {
    rule_assignment::assigned(dist, agent, set).await.unwrap()
}

#[tokio::test]
async fn a_host_in_no_group_gets_the_default() {
    let (db, admin) = setup().await;
    agent(&admin, "agent.a", &[("env", "web")]).await;
    // A group without selectors matches nobody, so its "off" does not apply.
    let empty = group(&admin, "empty", &[]).await;
    let mut console = as_role(&db, "openvibes-console").await;
    done(rule_assignment::set_group(&mut console, "t", L1, &empty, Some(false)).await.unwrap());
    let dist = as_role(&db, "openvibes-distribution").await;
    assert!(assigned(&dist, "agent.a", L1).await);
    assert!(!assigned(&dist, "agent.a", L2).await);
    // Not assignable: always served as before.
    assert!(assigned(&dist, "agent.a", "baseline").await);
    let host = rule_assignment::for_agent(&console, &AgentScope::Global, "agent.a")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        host,
        [
            HostAssignment { rule_set_id: L1.into(), enabled: true, source: Source::Default },
            HostAssignment { rule_set_id: L2.into(), enabled: false, source: Source::Default },
        ]
    );
    drop((console, dist, admin));
    db.drop().await;
}

#[tokio::test]
async fn on_wins_and_a_deleted_group_falls_back() {
    let (db, admin) = setup().await;
    agent(&admin, "agent.a", &[("env", "web"), ("tier", "db")]).await;
    agent(&admin, "agent.b", &[("env", "web")]).await;
    let web = group(&admin, "web", &[("env", "web")]).await;
    // Needs both tags: agent.b is not a member.
    let web_db = group(&admin, "web-db", &[("env", "web"), ("tier", "db")]).await;
    let mut console = as_role(&db, "openvibes-console").await;
    done(rule_assignment::set_group(&mut console, "t", L2, &web, Some(false)).await.unwrap());
    done(rule_assignment::set_group(&mut console, "t", L2, &web_db, Some(true)).await.unwrap());
    done(rule_assignment::set_group(&mut console, "t", L1, &web, Some(false)).await.unwrap());
    let dist = as_role(&db, "openvibes-distribution").await;
    assert!(assigned(&dist, "agent.a", L2).await, "one group on, one off: on");
    assert!(!assigned(&dist, "agent.b", L2).await, "only the off group");
    assert!(!assigned(&dist, "agent.a", L1).await, "an off group beats the on default");
    let source = |host: Vec<HostAssignment>| host.into_iter().map(|h| (h.enabled, h.source)).collect::<Vec<_>>();
    assert_eq!(
        source(rule_assignment::for_agent(&console, &AgentScope::Global, "agent.a").await.unwrap().unwrap()),
        [(false, Source::Group), (true, Source::Group)]
    );
    admin
        .execute("DELETE FROM console_asset_groups WHERE asset_group_id::text = $1", &[&web_db])
        .await
        .unwrap();
    assert!(!assigned(&dist, "agent.a", L2).await, "back to web's off");
    drop((console, dist, admin));
    db.drop().await;
}

#[tokio::test]
async fn the_host_view_is_scoped_and_distribution_reads_no_more_than_it_needs() {
    let (db, admin) = setup().await;
    agent(&admin, "agent.a", &[("env", "web")]).await;
    let other = group(&admin, "other", &[("env", "db")]).await;
    let console = as_role(&db, "openvibes-console").await;
    let scoped = AgentScope::AssetGroups(vec![other]);
    assert_eq!(
        rule_assignment::for_agent(&console, &scoped, "agent.a").await.unwrap(),
        None
    );
    assert_eq!(
        rule_assignment::for_agent(&console, &AgentScope::Global, "agent.nobody").await.unwrap(),
        None
    );
    let privileges: Vec<bool> = admin
        .query_one(
            "SELECT ARRAY[
                has_column_privilege('openvibes-distribution', 'console_agent_tags', 'tag_value', 'SELECT'),
                has_column_privilege('openvibes-distribution', 'console_agent_tags', 'changed_by', 'SELECT'),
                has_table_privilege('openvibes-distribution', 'rule_set_group_assignment', 'UPDATE')]",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(privileges, [true, false, false]);
    drop((console, admin));
    db.drop().await;
}
```

Merge the new `use` items into the file's existing `use platform_store::{...}` block when formatting.

- [ ] **Step 2: Run them to verify they fail**

```bash
nice -n 19 cargo test --locked -p platform-store --test rule_assignment
```

Expected: FAIL to compile, `cannot find function assigned` / `Source` not found.

- [ ] **Step 3: Implement**

Append to `crates/platform-store/src/rule_assignment.rs`:

```rust
/// Where a host's state for a set comes from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Source {
    /// No group of the host overrides the set.
    Default,
    /// A group of the host decided it.
    Group,
}

/// One assignable set's state on one host.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostAssignment {
    /// Rule set id.
    pub rule_set_id: String,
    /// Whether the host runs it.
    pub enabled: bool,
    /// Default or a group.
    pub source: Source,
}

/// Per assignable set for agent `$1`: (set, enabled, decided by a group).
/// `bool_or` over the overrides of the host's groups is true when any says
/// on, false when all say off, NULL when none applies (then the default). A
/// group matches when it has selectors and the host carries every one, as
/// for access (`console_read::agent_visibility`).
const HOST_STATE: &str = "
    SELECT a.rule_set_id, COALESCE(bool_or(o.enabled), a.default_enabled),
           bool_or(o.enabled) IS NOT NULL
    FROM rule_set_assignment a
    LEFT JOIN rule_set_group_assignment o ON o.rule_set_id = a.rule_set_id
     AND EXISTS (SELECT 1 FROM console_asset_group_selectors s
                 WHERE s.asset_group_id = o.asset_group_id)
     AND NOT EXISTS (
         SELECT 1 FROM console_asset_group_selectors r
         WHERE r.asset_group_id = o.asset_group_id
           AND NOT EXISTS (SELECT 1 FROM console_agent_tags t
                           WHERE t.agent_id = $1 AND t.tag_key = r.tag_key
                             AND t.tag_value = r.tag_value))
    GROUP BY a.rule_set_id, a.default_enabled";

/// Whether `agent_id` runs `set`. A set that is not assignable is always
/// assigned, so distribution answers it exactly as before.
pub async fn assigned(client: &Client, agent_id: &str, set: &str) -> Result<bool, StoreError> {
    let row = client
        .query_opt(
            &format!(
                "SELECT enabled FROM ({HOST_STATE}) AS h (rule_set_id, enabled, from_group)
                 WHERE rule_set_id = $2"
            ),
            &[&agent_id, &set],
        )
        .await?;
    Ok(row.is_none_or(|row| row.get(0)))
}

/// Every assignable set's state on `agent_id`, or `None` when the agent is
/// unknown or outside `scope`.
pub async fn for_agent(
    client: &Client,
    scope: &crate::console_read::AgentScope,
    agent_id: &str,
) -> Result<Option<Vec<HostAssignment>>, StoreError> {
    let visible = crate::console_read::agent_visibility("a.agent_id", "$2", "$3");
    if client
        .query_opt(
            &format!("SELECT 1 FROM agents a WHERE a.agent_id = $1 AND {visible}"),
            &[&agent_id, &scope.is_global(), &scope.group_ids()],
        )
        .await?
        .is_none()
    {
        return Ok(None);
    }
    let rows = client
        .query(&format!("{HOST_STATE} ORDER BY a.rule_set_id"), &[&agent_id])
        .await?;
    Ok(Some(
        rows.iter()
            .map(|row| HostAssignment {
                rule_set_id: row.get(0),
                enabled: row.get(1),
                source: if row.get(2) { Source::Group } else { Source::Default },
            })
            .collect(),
    ))
}
```

Append to `migrations/0049_rule_set_assignment.sql`:

```sql
-- Distribution answers 410 for a set that is off on the asking host: it
-- reads the switches and only the tag and selector columns membership needs.
GRANT SELECT ON rule_set_assignment, rule_set_group_assignment TO "openvibes-distribution";
GRANT SELECT (agent_id, tag_key, tag_value) ON console_agent_tags TO "openvibes-distribution";
GRANT SELECT (asset_group_id, tag_key, tag_value) ON console_asset_group_selectors
    TO "openvibes-distribution";
```

- [ ] **Step 4: Run them to verify they pass**

```bash
nice -n 19 cargo test --locked -p platform-store --test rule_assignment
```

Expected: PASS (7 tests).

- [ ] **Step 5: Docs**

In `docs/components/rule-set-assignment.md` add to Interfaces, after the store paragraph:

```markdown
`assigned(agent, set)` (distribution) and `for_agent(scope, agent)` (the
console's host view, `None` outside the caller's scope) share one SQL
resolution (`HOST_STATE`). A set that is not assignable is always
assigned. Grants: `openvibes-distribution` may read the two tables and only
`console_agent_tags (agent_id, tag_key, tag_value)` and
`console_asset_group_selectors (asset_group_id, tag_key, tag_value)`.
```

In `docs/components/openvibes-distribution.md`, replace the sentence starting "The database role `openvibes-distribution` may only read" with:

```markdown
The database role `openvibes-distribution` may only read `agents`,
`certificates`, `rule_sets`, `rule_bundles`, `schema_version`, the
rule-set assignment tables, and the tag and selector columns that decide
group membership ([rule-set-assignment.md](rule-set-assignment.md)).
```

- [ ] **Step 6: Commit**

```bash
cargo fmt --all
git add crates/platform-store/src/rule_assignment.rs crates/platform-store/tests/rule_assignment.rs \
  migrations/0049_rule_set_assignment.sql docs/components/rule-set-assignment.md \
  docs/components/openvibes-distribution.md
git commit -m "Store: a host's state for an assignable set, on wins

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 4: Distribution answers 410 for a set that is off on the host

**Files:**
- Modify: `crates/openvibes-distribution/src/lib.rs:74-97`
- Test: `crates/openvibes-distribution/tests/assignment.rs` (new)
- Docs: `docs/components/openvibes-distribution.md` (Interface table, query sentence, Failure behaviour, Test), `docs/components/rule-set-assignment.md`

**Interfaces:**
- Consumes: `platform_store::rule_assignment::assigned(&Client, &str, &str) -> Result<bool, StoreError>` (Task 3).
- Produces: `POST /v1/rule-bundle` → `410`, empty body, for an assignable set that is off on the authenticated agent's host; every other answer unchanged.

- [ ] **Step 1: Write the failing tests**

Create `crates/openvibes-distribution/tests/assignment.rs`:

```rust
//! Protocol P20: `410 Gone` for an assignable set switched off on the
//! asking host; every other answer unchanged.

mod support;

use support::{Agent, World, request};

const L1: &str = "hardening-linux-l1";
const L2: &str = "hardening-linux-l2";
const BUNDLE: &[u8] = b"{\"version\":1}";

async fn status(world: &World, agent: &Agent, set: &str, current: Option<u64>) -> u16 {
    world.raw(&request(set, current), Some(agent)).await.unwrap().0
}

async fn set_default(world: &World, set: &str, enabled: bool) {
    world
        .db()
        .await
        .execute(
            "UPDATE rule_set_assignment SET default_enabled = $2 WHERE rule_set_id = $1",
            &[&set, &enabled],
        )
        .await
        .unwrap();
}

async fn tag(world: &World, agent: &Agent, key: &str, value: &str) {
    world
        .db()
        .await
        .execute(
            "INSERT INTO console_agent_tags (agent_id, tag_key, tag_value, changed_at, changed_by)
             VALUES ($1, $2, $3, now(), 'test')",
            &[&agent.id, &key, &value],
        )
        .await
        .unwrap();
}

/// A group of hosts tagged `key=value` with `set` switched to `enabled`.
async fn group(world: &World, name: &str, key: &str, value: &str, set: &str, enabled: bool) -> String {
    let db = world.db().await;
    let id: String = db
        .query_one(
            "INSERT INTO console_asset_groups (asset_group_id, name, created_at, created_by)
             VALUES (gen_random_uuid(), $1, now(), 'test') RETURNING asset_group_id::text",
            &[&name],
        )
        .await
        .unwrap()
        .get(0);
    db.execute(
        "INSERT INTO console_asset_group_selectors (asset_group_id, tag_key, tag_value, created_at)
         VALUES ($1::text::uuid, $2, $3, now())",
        &[&id, &key, &value],
    )
    .await
    .unwrap();
    db.execute(
        "INSERT INTO rule_set_group_assignment (rule_set_id, asset_group_id, enabled)
         VALUES ($1, $2::text::uuid, $3)",
        &[&set, &id, &enabled],
    )
    .await
    .unwrap();
    id
}

#[tokio::test]
async fn a_set_switched_off_for_the_host_is_gone() {
    let world = World::start().await;
    world.publish(L1, 1, BUNDLE).await;
    let agent = world.agent(1).await;
    assert_eq!(status(&world, &agent, L1, None).await, 200, "L1 is on by default");
    set_default(&world, L1, false).await;
    let (code, _, body) = world.raw(&request(L1, None), Some(&agent)).await.unwrap();
    assert_eq!((code, body.len()), (410, 0));
    assert_eq!(status(&world, &agent, L1, Some(1)).await, 410, "even when current");
    set_default(&world, L1, true).await;
    assert_eq!(status(&world, &agent, L1, Some(1)).await, 204, "back on");
    world.stop().await;
}

#[tokio::test]
async fn on_wins_across_groups() {
    let world = World::start().await;
    world.publish(L2, 1, BUNDLE).await;
    let agent = world.agent(1).await;
    let other = world.agent(2).await;
    tag(&world, &agent, "env", "web").await;
    tag(&world, &agent, "tier", "db").await;
    tag(&world, &other, "env", "web").await;
    group(&world, "web", "env", "web", L2, false).await;
    let db_group = group(&world, "db", "tier", "db", L2, true).await;
    assert_eq!(status(&world, &agent, L2, None).await, 200, "one group on wins");
    assert_eq!(status(&world, &other, L2, None).await, 410);
    world
        .db()
        .await
        .execute(
            "DELETE FROM console_asset_groups WHERE asset_group_id::text = $1",
            &[&db_group],
        )
        .await
        .unwrap();
    assert_eq!(status(&world, &agent, L2, None).await, 410, "falls back to web's off");
    world.stop().await;
}

#[tokio::test]
async fn unpublished_or_retired_sets_stay_not_found() {
    let world = World::start().await;
    let agent = world.agent(1).await;
    // L2: assignable, off by default, nothing published.
    assert_eq!(status(&world, &agent, L2, None).await, 404);
    world.publish(L1, 1, BUNDLE).await;
    set_default(&world, L1, false).await;
    assert!(
        platform_store::rules::retire(&world.db().await, L1)
            .await
            .unwrap()
    );
    assert_eq!(status(&world, &agent, L1, None).await, 404);
    world.stop().await;
}

#[tokio::test]
async fn other_sets_are_unchanged() {
    let world = World::start().await;
    world.publish("baseline", 1, BUNDLE).await;
    world.publish("baseline-alarms", 1, BUNDLE).await;
    set_default(&world, L1, false).await;
    set_default(&world, L2, false).await;
    let agent = world.agent(1).await;
    assert_eq!(status(&world, &agent, "baseline", None).await, 200);
    assert_eq!(status(&world, &agent, "baseline", Some(1)).await, 204);
    assert_eq!(status(&world, &agent, "baseline-alarms", None).await, 200);
    assert_eq!(status(&world, &agent, "site-rules", None).await, 404);
    world.stop().await;
}
```

- [ ] **Step 2: Run them to verify they fail**

```bash
nice -n 19 cargo test --locked -p openvibes-distribution --test assignment
```

Expected: `a_set_switched_off_for_the_host_is_gone` and `on_wins_across_groups` FAIL (`left: 200, right: 410`); the other two pass already (they pin today's behaviour).

- [ ] **Step 3: Implement**

In `crates/openvibes-distribution/src/lib.rs` replace the handler (doc comment through the closing brace, lines 74-97):

```rust
/// `POST /v1/rule-bundle`: the set's current envelope, byte for byte, when
/// the agent's version is older; 204 when it is current; 404 when the set
/// is unknown, retired, or has nothing published; 410 (P20, no body) when
/// it is an assignable set switched off on this agent's host. Authentication
/// runs first, so an unauthenticated client never learns how bodies are
/// parsed.
async fn rule_bundle(
    AuthenticatedAgent(agent_id): AuthenticatedAgent,
    State(state): State<AppState>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let request: RuleBundleRequest = platform_agent_server::parse(&body)?;
    let current = request
        .current_version
        .map(|version| i64::try_from(version).unwrap_or(i64::MAX));
    let set = request.rule_set_id.as_str();
    let client = state.pool.get().await.map_err(|_| ApiError::Unavailable)?;
    let served = platform_store::rules::serve(&client, set, current).await?;
    // 404 first: an unknown, retired or unpublished set never reads as
    // "not assigned".
    if !matches!(served, Served::Unknown)
        && !platform_store::rule_assignment::assigned(&client, &agent_id, set).await?
    {
        return Ok(StatusCode::GONE.into_response());
    }
    Ok(match served {
        Served::Unknown => ApiError::NotFound.into_response(),
        Served::UpToDate => StatusCode::NO_CONTENT.into_response(),
        Served::Envelope(bytes) => {
            ([(header::CONTENT_TYPE, "application/json")], bytes).into_response()
        }
    })
}
```

- [ ] **Step 4: Run them to verify they pass**

```bash
nice -n 19 cargo test --locked -p openvibes-distribution
```

Expected: PASS (the new file and the existing `bundle.rs`, `auth.rs`, `limits.rs`, `logging.rs`, `protocol_fixtures.rs`).

- [ ] **Step 5: Docs**

In `docs/components/openvibes-distribution.md`, add a row after the 404 row:

```markdown
| An assignable set (`hardening-linux-l1`, `-l2`) switched off on this agent's host (P20; [rule-set-assignment.md](rule-set-assignment.md)) | 410, no body |
```

replace "Every request is one primary-key query ([platform-store.md](platform-store.md), `rules::serve`);" with "Every request is one primary-key query ([platform-store.md](platform-store.md), `rules::serve`), plus one indexed assignment lookup for a set that is served (`rule_assignment::assigned`);", add to Failure behaviour:

```markdown
- Switching a set off answers 410 from the next request; the agent stops
  running it and deletes its bundle (P20). Switching it on serves it again.
```

and to Test: ``- `assignment.rs`: 410 when off (also when current), on wins across groups, group deletion falls back, unpublished or retired stays 404, other sets unchanged;``. In `docs/components/rule-set-assignment.md` add under Interfaces: "**Distribution.** `POST /v1/rule-bundle` answers `410 Gone` with no body for an assignable set that is off on the asking host, checked after the 404 cases; every other answer is unchanged."

- [ ] **Step 6: Commit**

```bash
cargo fmt --all
git add crates/openvibes-distribution docs/components/openvibes-distribution.md docs/components/rule-set-assignment.md
git commit -m "Distribution: 410 for an assignable set that is off on the host (P20)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 5: Console API for the switches, the host view and the per-set state

**Files:**
- Create: `crates/openvibes-console/src/rule_assignment.rs`
- Modify: `crates/openvibes-console/src/lib.rs` (`mod rule_assignment;` in alphabetical place)
- Modify: `crates/openvibes-console/src/router.rs:621-624` (routes), `:3695-3700` (`state`)
- Modify: `crates/openvibes-console/src/openapi.rs` (paths, schemas)
- Modify: `crates/openvibes-console/src/api.rs:1037-1046` (`AgentRuleSetView.state`)
- Modify: `crates/platform-store/src/console_read.rs:156-165`, `:1366-1376` (`AgentRuleSet.state`)
- Modify (struct literals gain `state`): `crates/openvibes-console/src/site_fleet.rs:207`, `crates/openvibes-console/src/seeded.rs:281`, `crates/platform-store/tests/console_read.rs:172,178`
- Regenerate: `docs/api/console-v1.openapi.json`, `crates/openvibes-console/web/src/api/generated.ts`
- Test: `crates/openvibes-console/tests/rule_assignment_http.rs` (new), `crates/platform-store/tests/console_read.rs` (extend)
- Docs: `docs/components/rule-set-assignment.md` (Console API section)

**Interfaces:**
- Consumes: Task 2 `overview`, `set_default`, `set_group`, `Change`; Task 3 `for_agent`, `Source`.
- Produces (HTTP, all `Cache-Control: no-store`; errors are `application/problem+json`):

| Method and path | Permission | Body | 200 response |
|---|---|---|---|
| `GET /api/v1/rule-set-assignments` | `rules.read` (global) | none | `RuleSetAssignmentsView` |
| `PUT /api/v1/rule-set-assignments/{rule_set_id}` | `rules.upload` (global), CSRF | `{"default_enabled": bool}` | `RuleSetAssignmentView` |
| `PUT /api/v1/rule-set-assignments/{rule_set_id}/groups/{asset_group_id}` | `rules.upload`, CSRF | `{"enabled": bool}` | `RuleSetAssignmentView` |
| `DELETE /api/v1/rule-set-assignments/{rule_set_id}/groups/{asset_group_id}` | `rules.upload`, CSRF | none | `RuleSetAssignmentView` (idempotent) |
| `GET /api/v1/agents/{agent_id}/rule-set-assignments` | `agents.read` (scoped) | none | `HostRuleSetAssignmentsView` |

  Shapes: `RuleSetAssignmentsView { items: [RuleSetAssignmentView], asset_groups: [{asset_group_id, name}] }`; `RuleSetAssignmentView { rule_set_id, default_enabled, published, groups: [{asset_group_id, name, enabled}] }`; `HostRuleSetAssignmentsView { items: [{rule_set_id, enabled, source: "default"|"group"}] }`. Errors: 400 `invalid_request` (bad body), 403 `permission_denied`, 404 `rule_set_not_assignable`, `asset_group_not_found`, `agent_not_found`, 503.
  `AgentRuleSetView` (host detail, existing `GET /api/v1/agents/{agent_id}`) gains `state: Option<String>` (`"not_assigned"` from P20 health; `null` otherwise).

- [ ] **Step 1: Write the failing store test for `state`**

In `crates/platform-store/tests/console_read.rs`, change the health JSON at line 158 so the second set carries a state, and the expected literals:

```rust
            "UPDATE agents SET health_at = $2,
                health = '{\"rule_sets\":[{\"id\":\"baseline\",\"version\":2,\"expires_at_unix_ms\":1853910427825},
                    {\"id\":\"site\",\"refused\":\"signature\"},
                    {\"id\":\"hardening-linux-l2\",\"state\":\"not_assigned\"}]}'::jsonb
             WHERE agent_id = $1",
```

```rust
        vec![
            platform_store::console_read::AgentRuleSet {
                id: "baseline".to_owned(),
                version: Some(2),
                expires_at_ms: Some(1_853_910_427_825),
                refused: None,
                state: None,
            },
            platform_store::console_read::AgentRuleSet {
                id: "site".to_owned(),
                version: None,
                expires_at_ms: None,
                refused: Some("signature".to_owned()),
                state: None,
            },
            platform_store::console_read::AgentRuleSet {
                id: "hardening-linux-l2".to_owned(),
                version: None,
                expires_at_ms: None,
                refused: None,
                state: Some("not_assigned".to_owned()),
            },
        ]
```

- [ ] **Step 2: Write the failing HTTP tests**

Create `crates/openvibes-console/tests/rule_assignment_http.rs`. First copy, verbatim, everything in `crates/openvibes-console/tests/assistant_internet_http.rs` above its first `#[tokio::test]` (imports, `TestDb`, `database_url`, `cookie_pair`, `new_preauth`, `PASSWORD`, `user`, `login`, `call`, `setup`, `setup_with`), then change the file's first doc line to `//! Rule-set assignment over HTTP: permissions, switches, audit, host view.`, drop `authenticated_router_with_fetch` from the import, and replace `setup_with` and `setup` with:

```rust
async fn setup() -> (TestDb, axum::Router) {
    let db = TestDb::create().await;
    let mut client = db.pool.get().await.unwrap();
    platform_store::migrate(&mut client).await.unwrap();
    user(&mut client, "11111111-1111-4111-8111-111111111111",
        "22222222-2222-4222-8222-222222222222", "alice", "admin").await;
    user(&mut client, "33333333-3333-4333-8333-333333333333",
        "44444444-4444-4444-8444-444444444444", "bob", "analyst").await;
    client
        .batch_execute(
            "INSERT INTO agents (agent_id, status, enrolled_at) VALUES ('agent.web', 'active', now());
             INSERT INTO console_agent_tags VALUES ('agent.web', 'env', 'web', now(), 'test');
             INSERT INTO console_asset_groups VALUES
                 ('55555555-5555-4555-8555-555555555555', 'web', now(), 'test');
             INSERT INTO console_asset_group_selectors VALUES
                 ('55555555-5555-4555-8555-555555555555', 'env', 'web', now());",
        )
        .await
        .unwrap();
    drop(client);
    let router = authenticated_router(db.pool.clone(), "https://console.example");
    (db, router)
}
```

Then the tests:

```rust
const WEB: &str = "55555555-5555-4555-8555-555555555555";
const LIST: &str = "/api/v1/rule-set-assignments";
const L1: &str = "/api/v1/rule-set-assignments/hardening-linux-l1";

#[tokio::test]
async fn readers_see_the_switches_and_only_rule_publishers_change_them() {
    let (db, router) = setup().await;
    let (cookie, csrf) = login(&router, "bob").await;
    let (status, body, _) = call(&router, "GET", LIST, &cookie, &csrf, None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body,
        serde_json::json!({
            "items": [
                {"rule_set_id": "hardening-linux-l1", "default_enabled": true, "published": false, "groups": []},
                {"rule_set_id": "hardening-linux-l2", "default_enabled": false, "published": false, "groups": []}
            ],
            "asset_groups": [{"asset_group_id": WEB, "name": "web"}]
        })
    );
    let off = serde_json::json!({"default_enabled": false});
    let (status, ..) = call(&router, "PUT", L1, &cookie, &csrf, Some(off.clone()), None).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "an analyst has no rules.upload");

    let (cookie, csrf) = login(&router, "alice").await;
    let (status, body, _) = call(&router, "PUT", L1, &cookie, &csrf, Some(off), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["default_enabled"], false);
    let bad = serde_json::json!({"default_enabled": "no"});
    let (status, body, _) = call(&router, "PUT", L1, &cookie, &csrf, Some(bad), None).await;
    assert_eq!((status, body["code"].as_str()), (StatusCode::BAD_REQUEST, Some("invalid_request")));
    let (status, body, _) = call(&router, "PUT", "/api/v1/rule-set-assignments/baseline",
        &cookie, &csrf, Some(serde_json::json!({"default_enabled": false})), None).await;
    assert_eq!((status, body["code"].as_str()), (StatusCode::NOT_FOUND, Some("rule_set_not_assignable")));
    let audited: i64 = db.pool.get().await.unwrap()
        .query_one("SELECT count(*) FROM audit_log WHERE action = 'rules.assignment.change'
                    AND actor = '11111111-1111-4111-8111-111111111111'", &[])
        .await.unwrap().get(0);
    assert_eq!(audited, 1);
    db.drop().await;
}

#[tokio::test]
async fn group_overrides_and_the_host_view() {
    let (db, router) = setup().await;
    let (cookie, csrf) = login(&router, "alice").await;
    let group = format!("{L1}/groups/{WEB}");
    let host = "/api/v1/agents/agent.web/rule-set-assignments";
    let (_, body, _) = call(&router, "GET", host, &cookie, &csrf, None, None).await;
    assert_eq!(body["items"][0], serde_json::json!(
        {"rule_set_id": "hardening-linux-l1", "enabled": true, "source": "default"}));
    let (status, body, _) = call(&router, "PUT", &group, &cookie, &csrf,
        Some(serde_json::json!({"enabled": false})), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["groups"], serde_json::json!([{"asset_group_id": WEB, "name": "web", "enabled": false}]));
    let (_, body, _) = call(&router, "GET", host, &cookie, &csrf, None, None).await;
    assert_eq!(body["items"][0], serde_json::json!(
        {"rule_set_id": "hardening-linux-l1", "enabled": false, "source": "group"}));
    for _ in 0..2 {
        let (status, body, _) = call(&router, "DELETE", &group, &cookie, &csrf, None, None).await;
        assert_eq!((status, body["groups"].clone()), (StatusCode::OK, serde_json::json!([])));
    }
    let unknown = format!("{L1}/groups/66666666-6666-4666-8666-666666666666");
    let (status, body, _) = call(&router, "PUT", &unknown, &cookie, &csrf,
        Some(serde_json::json!({"enabled": true})), None).await;
    assert_eq!((status, body["code"].as_str()), (StatusCode::NOT_FOUND, Some("asset_group_not_found")));
    let (status, body, _) = call(&router, "GET", "/api/v1/agents/agent.nobody/rule-set-assignments",
        &cookie, &csrf, None, None).await;
    assert_eq!((status, body["code"].as_str()), (StatusCode::NOT_FOUND, Some("agent_not_found")));
    db.drop().await;
}
```

The `actor` in `audit_log` is the console user id (`authenticated_permission` returns it): the test pins that.

- [ ] **Step 3: Run them to verify they fail**

```bash
nice -n 19 cargo test --locked -p platform-store --test console_read
nice -n 19 cargo test --locked -p openvibes-console --test rule_assignment_http
```

Expected: both FAIL to compile (`no field state`; routes absent would 404 once compiled).

- [ ] **Step 4: Implement the per-set state**

`crates/platform-store/src/console_read.rs`: add to `AgentRuleSet`

```rust
    /// The agent's state for the set (P20: `not_assigned`), if it sent one.
    pub state: Option<String>,
```

and in `agent_rule_sets`, after the `refused:` field:

```rust
                state: set
                    .get("state")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned),
```

`crates/openvibes-console/src/api.rs` `AgentRuleSetView`, after `refused`:

```rust
    /// The agent's state for the set: `not_assigned` when the platform
    /// switched it off for this host (P20); absent otherwise.
    pub state: Option<String>,
```

`router.rs:3695` map adds `state: set.state,`; `site_fleet.rs:207` and `seeded.rs:281` literals add `state: None,`.

- [ ] **Step 5: Implement the endpoints**

Create `crates/openvibes-console/src/rule_assignment.rs`:

```rust
//! `/api/v1/rule-set-assignments`: the per-group switches of the project's
//! assignable rule sets (spec 2026-10-14). Reading needs `rules.read`,
//! changing `rules.upload`, both global; one host's state needs
//! `agents.read` within the caller's scope.

use axum::{
    Json,
    extract::{Path, State, rejection::JsonRejection},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use platform_store::{console_read::AgentScope, rule_assignment as store};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{
    Permission, ProblemDetails,
    problem::problem_response,
    router::{AuthHttpState, authenticated_permission, no_store, unavailable_auth},
};

/// One asset group's override.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct RuleSetGroupOverrideView {
    /// The group.
    pub asset_group_id: String,
    /// Its name.
    pub name: String,
    /// On or off for its hosts.
    pub enabled: bool,
}

/// One assignable rule set.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct RuleSetAssignmentView {
    /// Rule set id.
    pub rule_set_id: String,
    /// On or off for hosts no override covers.
    pub default_enabled: bool,
    /// False until a live bundle is published ("not available yet").
    pub published: bool,
    /// Overrides, by group name.
    pub groups: Vec<RuleSetGroupOverrideView>,
}

/// An asset group an override can name.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct AssignableGroupView {
    /// The group.
    pub asset_group_id: String,
    /// Its name.
    pub name: String,
}

/// Every assignable set, and the groups an override can name.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct RuleSetAssignmentsView {
    /// The sets.
    pub items: Vec<RuleSetAssignmentView>,
    /// Every asset group, by name.
    pub asset_groups: Vec<AssignableGroupView>,
}

/// A set's new default.
#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SetRuleSetDefaultRequest {
    /// On or off for hosts no override covers.
    pub default_enabled: bool,
}

/// A group's override.
#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SetRuleSetGroupRequest {
    /// On or off for the group's hosts.
    pub enabled: bool,
}

/// One assignable set's state on a host, as the platform decides it.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct HostRuleSetAssignmentView {
    /// Rule set id.
    pub rule_set_id: String,
    /// Whether the host runs it.
    pub enabled: bool,
    /// `default` or `group`.
    pub source: String,
}

/// Every assignable set's state on one host.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct HostRuleSetAssignmentsView {
    /// The sets, by id.
    pub items: Vec<HostRuleSetAssignmentView>,
}

fn forbidden() -> Response {
    problem_response(ProblemDetails::new(
        StatusCode::FORBIDDEN,
        "permission_denied",
        "Access is not available",
    ))
}

fn view(assignment: store::Assignment) -> RuleSetAssignmentView {
    RuleSetAssignmentView {
        rule_set_id: assignment.rule_set_id,
        default_enabled: assignment.default_enabled,
        published: assignment.published,
        groups: assignment
            .groups
            .into_iter()
            .map(|g| RuleSetGroupOverrideView {
                asset_group_id: g.asset_group_id,
                name: g.name,
                enabled: g.enabled,
            })
            .collect(),
    }
}

/// The caller's user id when they may change switches.
async fn writer(state: &AuthHttpState, headers: &HeaderMap) -> Result<String, Response> {
    match authenticated_permission(state, headers, Permission::RulesUpload, true).await {
        Ok((AgentScope::Global, actor)) => Ok(actor),
        Ok(_) => Err(forbidden()),
        Err(response) => Err(response),
    }
}

fn change_response(result: Result<store::Change, platform_store::StoreError>) -> Response {
    match result {
        Ok(store::Change::Done(assignment)) => no_store(Json(view(assignment)).into_response()),
        Ok(store::Change::UnknownSet) => problem_response(ProblemDetails::not_found(
            "rule_set_not_assignable",
            "Rule set is not assignable",
        )),
        Ok(store::Change::UnknownGroup) => problem_response(ProblemDetails::not_found(
            "asset_group_not_found",
            "Asset group not found",
        )),
        Err(_) => unavailable_auth(),
    }
}

fn invalid() -> Response {
    problem_response(ProblemDetails::new(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        "The request body is not valid",
    ))
}

#[utoipa::path(get, path = "/api/v1/rule-set-assignments", tag = "rules",
    responses(
        (status = 200, description = "Assignable rule sets and asset groups", body = RuleSetAssignmentsView),
        (status = 401, description = "Authentication required", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Permission denied", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Read unavailable", body = crate::ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn list_assignments(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
) -> Response {
    match authenticated_permission(&state, &headers, Permission::RulesRead, false).await {
        Ok((AgentScope::Global, _)) => {}
        Ok(_) => return forbidden(),
        Err(response) => return response,
    }
    let Ok(client) = state.pool.get().await else {
        return unavailable_auth();
    };
    match store::overview(&client).await {
        Ok(overview) => no_store(
            Json(RuleSetAssignmentsView {
                items: overview.sets.into_iter().map(view).collect(),
                asset_groups: overview
                    .groups
                    .into_iter()
                    .map(|g| AssignableGroupView {
                        asset_group_id: g.asset_group_id,
                        name: g.name,
                    })
                    .collect(),
            })
            .into_response(),
        ),
        Err(_) => unavailable_auth(),
    }
}

#[utoipa::path(put, path = "/api/v1/rule-set-assignments/{rule_set_id}", tag = "rules",
    params(("rule_set_id" = String, Path),
        ("Origin" = String, Header, description = "Must exactly match configured origin"),
        ("X-CSRF-Token" = String, Header, description = "Session synchronizer token")),
    request_body = SetRuleSetDefaultRequest,
    responses(
        (status = 200, description = "The set after the change", body = RuleSetAssignmentView),
        (status = 400, description = "Invalid body", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Origin, CSRF, or permission check failed", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "Not an assignable set", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Update unavailable", body = crate::ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn set_default(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path(rule_set_id): Path<String>,
    payload: Result<Json<SetRuleSetDefaultRequest>, JsonRejection>,
) -> Response {
    let actor = match writer(&state, &headers).await {
        Ok(actor) => actor,
        Err(response) => return response,
    };
    let Ok(Json(request)) = payload else {
        return invalid();
    };
    let Ok(mut client) = state.pool.get().await else {
        return unavailable_auth();
    };
    change_response(
        store::set_default(&mut client, &actor, &rule_set_id, request.default_enabled).await,
    )
}

#[utoipa::path(put, path = "/api/v1/rule-set-assignments/{rule_set_id}/groups/{asset_group_id}", tag = "rules",
    params(("rule_set_id" = String, Path), ("asset_group_id" = String, Path),
        ("Origin" = String, Header, description = "Must exactly match configured origin"),
        ("X-CSRF-Token" = String, Header, description = "Session synchronizer token")),
    request_body = SetRuleSetGroupRequest,
    responses(
        (status = 200, description = "The set after the change", body = RuleSetAssignmentView),
        (status = 400, description = "Invalid body", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Origin, CSRF, or permission check failed", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "Not an assignable set, or no such group", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Update unavailable", body = crate::ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn set_group(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path((rule_set_id, asset_group_id)): Path<(String, String)>,
    payload: Result<Json<SetRuleSetGroupRequest>, JsonRejection>,
) -> Response {
    let actor = match writer(&state, &headers).await {
        Ok(actor) => actor,
        Err(response) => return response,
    };
    let Ok(Json(request)) = payload else {
        return invalid();
    };
    let Ok(mut client) = state.pool.get().await else {
        return unavailable_auth();
    };
    change_response(
        store::set_group(&mut client, &actor, &rule_set_id, &asset_group_id, Some(request.enabled))
            .await,
    )
}

#[utoipa::path(delete, path = "/api/v1/rule-set-assignments/{rule_set_id}/groups/{asset_group_id}", tag = "rules",
    params(("rule_set_id" = String, Path), ("asset_group_id" = String, Path),
        ("Origin" = String, Header, description = "Must exactly match configured origin"),
        ("X-CSRF-Token" = String, Header, description = "Session synchronizer token")),
    responses(
        (status = 200, description = "The set without that override (also when it had none)", body = RuleSetAssignmentView),
        (status = 403, description = "Origin, CSRF, or permission check failed", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "Not an assignable set, or no such group", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Update unavailable", body = crate::ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn clear_group(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path((rule_set_id, asset_group_id)): Path<(String, String)>,
) -> Response {
    let actor = match writer(&state, &headers).await {
        Ok(actor) => actor,
        Err(response) => return response,
    };
    let Ok(mut client) = state.pool.get().await else {
        return unavailable_auth();
    };
    change_response(
        store::set_group(&mut client, &actor, &rule_set_id, &asset_group_id, None).await,
    )
}

#[utoipa::path(get, path = "/api/v1/agents/{agent_id}/rule-set-assignments", tag = "agents",
    params(("agent_id" = String, Path)),
    responses(
        (status = 200, description = "Each assignable set's state on the host", body = HostRuleSetAssignmentsView),
        (status = 401, description = "Authentication required", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "Agent not found", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Read unavailable", body = crate::ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn host_assignments(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path(agent_id): Path<String>,
) -> Response {
    let (scope, _) =
        match authenticated_permission(&state, &headers, Permission::AgentsRead, false).await {
            Ok(context) => context,
            Err(response) => return response,
        };
    let Ok(client) = state.pool.get().await else {
        return unavailable_auth();
    };
    match store::for_agent(&client, &scope, &agent_id).await {
        Ok(Some(sets)) => no_store(
            Json(HostRuleSetAssignmentsView {
                items: sets
                    .into_iter()
                    .map(|set| HostRuleSetAssignmentView {
                        rule_set_id: set.rule_set_id,
                        enabled: set.enabled,
                        source: match set.source {
                            store::Source::Default => "default",
                            store::Source::Group => "group",
                        }
                        .to_owned(),
                    })
                    .collect(),
            })
            .into_response(),
        ),
        Ok(None) => problem_response(ProblemDetails::not_found("agent_not_found", "Agent not found")),
        Err(_) => unavailable_auth(),
    }
}
```

`router.rs`, after the `/v1/rule-sets/{rule_set_id}/bundles` route:

```rust
        .route(
            "/v1/rule-set-assignments",
            get(crate::rule_assignment::list_assignments),
        )
        .route(
            "/v1/rule-set-assignments/{rule_set_id}",
            axum::routing::put(crate::rule_assignment::set_default),
        )
        .route(
            "/v1/rule-set-assignments/{rule_set_id}/groups/{asset_group_id}",
            axum::routing::put(crate::rule_assignment::set_group)
                .delete(crate::rule_assignment::clear_group),
        )
        .route(
            "/v1/agents/{agent_id}/rule-set-assignments",
            get(crate::rule_assignment::host_assignments),
        )
```

`openapi.rs`: add to `paths(...)` after `crate::router::publish_authenticated_rule_bundle,`:

```rust
        crate::rule_assignment::list_assignments,
        crate::rule_assignment::set_default,
        crate::rule_assignment::set_group,
        crate::rule_assignment::clear_group,
        crate::rule_assignment::host_assignments,
```

and to `components(schemas(...))` after `crate::ports::UnitView,`:

```rust
        crate::rule_assignment::RuleSetAssignmentsView,
        crate::rule_assignment::RuleSetAssignmentView,
        crate::rule_assignment::RuleSetGroupOverrideView,
        crate::rule_assignment::AssignableGroupView,
        crate::rule_assignment::SetRuleSetDefaultRequest,
        crate::rule_assignment::SetRuleSetGroupRequest,
        crate::rule_assignment::HostRuleSetAssignmentsView,
        crate::rule_assignment::HostRuleSetAssignmentView,
```

`lib.rs`: `mod rule_assignment;` between `mod rbac;`/`mod router;` neighbours in alphabetical order.

- [ ] **Step 6: Run the tests, regenerate the contract**

```bash
nice -n 19 cargo test --locked -p platform-store --test console_read
nice -n 19 cargo test --locked -p openvibes-console --test rule_assignment_http
nice -n 19 cargo run --locked -p openvibes-console --bin export_openapi > docs/api/console-v1.openapi.json
npm --prefix crates/openvibes-console/web run generate:api
bash scripts/build-console.sh
```

Expected: tests PASS; `build-console.sh` green (no snapshot drift after regeneration). If `site_fleet.rs` or `seeded.rs` tests fail to compile, the `state: None` literal is missing there.

- [ ] **Step 7: Docs**

Append to `docs/components/rule-set-assignment.md` a section `## Console API` containing the endpoint table and shapes from this task's Interfaces block, plus: "Reading needs `rules.read`, changing `rules.upload` (operator, admin), both global. The list carries every asset group so an operator without `rbac.read` can add an override. Writes are absolute values (no `If-Match`): a repeated write changes nothing and is not audited. The host detail's `rule_sets[].state` is the agent's own report (`not_assigned`); the host view above is the platform's decision. A test: `cargo test -p openvibes-console --test rule_assignment_http`."

- [ ] **Step 8: Commit**

```bash
cargo fmt --all
git add crates/openvibes-console crates/platform-store/src/console_read.rs \
  crates/platform-store/tests/console_read.rs docs/api/console-v1.openapi.json \
  docs/components/rule-set-assignment.md
git commit -m "Console: rule-set assignment API, host view, per-set state

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 6: Ingest ends a host's matches of a set it no longer runs

Blocked until plan 1's P20 work (protocol P20 and the agent's `openvibes-core` health type) is merged into agent `main` and protocol `main`.

**Files:**
- Modify: `Cargo.toml:14,36,37` (agent rev), `Cargo.lock`, `protocol` (submodule)
- Modify: `crates/platform-store/src/health.rs:189` (test literal gains `state: None`)
- Modify: `crates/platform-store/src/finding_changes.rs` (append `NOT_ASSIGNED_NOTE`, `end_unassigned`)
- Modify: `migrations/0049_rule_set_assignment.sql` (append ingest grants)
- Modify: `crates/openvibes-ingest/src/delivery.rs:21-71` (heartbeat)
- Test: `crates/platform-store/tests/end_unassigned.rs` (new), `crates/openvibes-ingest/tests/assignment.rs` (new)
- Docs: `docs/components/openvibes-ingest.md` (Heartbeats section), `docs/components/rule-set-assignment.md`

**Interfaces:**
- Consumes (plan 1, P20, fixed by the coordinator): the wire field is a new optional `state` on each heartbeat `health.rule_sets[]` entry, value `"not_assigned"` (not a `refused` code); the trigger is exactly `rule_sets[].state == "not_assigned"`. Rust names (plan 1 Task 3): `RuleSetHealth.state: Option<RuleSetState>`, `RuleSetState { NotAssigned, Other }` (a later value reads as `Other`, which ends nothing); Step 1 checks them on the pinned rev. The assignable sets and the 404/410 cases are listed in the protocol vector `vectors/project-rule-sets.json`; Step 1b pins the migration's hard-coded sets against it. Contract also relied on: after a `410` the agent drops the set's matches from its P13 match set (sends them `ended` or leaves them out of its next digest), else the digest resync would reopen them.
- Produces: `pub const NOT_ASSIGNED_NOTE: &str = "rule set no longer assigned to this host";` and `pub async fn end_unassigned(client: &mut Client, agent_id: &str, sets: &[String], now: DateTime<Utc>) -> Result<u64, StoreError>` in `platform_store::finding_changes`.

- [ ] **Step 1: Bump the agent and protocol pins, check the consumed names**

```bash
cd /home/lime/Projects/OpenVIBES/openvibes-platform-assign
rev=$(git ls-remote https://github.com/openvibes-project/openvibes-agent.git refs/heads/main | cut -f1)
[[ $rev =~ ^[0-9a-f]{40}$ ]] || { echo "no agent main rev"; exit 1; }
sed -i "s/b186685afc85024433e87671d35fb28e4f7fd061/$rev/g" Cargo.toml
nice -n 19 cargo update -p openvibes-core -p openvibes-transport -p openvibes-rules
git -C protocol fetch origin && git -C protocol checkout origin/main
git -C ../openvibes-agent fetch origin
git -C ../openvibes-agent grep -n "NotAssigned\|not_assigned\|pub state" "$rev" -- crates/openvibes-core/src/health.rs
```

Expected: the grep shows `pub state: Option<RuleSetState>` in `RuleSetHealth` and `NotAssigned` in `RuleSetState`. If plan 1 chose other names, use them in Steps 4–5 below (only `not_assigned_sets` and the tests' JSON change). Then add `state: None,` to the `RuleSetHealth` literal in `crates/platform-store/src/health.rs:189` and run `nice -n 19 cargo check --locked --workspace --all-targets --all-features`; fix any other compile error the newer agent crates cause before going on.

- [ ] **Step 1b: Pin the hard-coded assignable sets to the protocol vector**

Look at the vector's shape first:

```bash
jq . protocol/vectors/project-rule-sets.json | head -40
```

Append to `crates/platform-store/tests/rule_assignment.rs` (written for a vector listing sets as objects with `id` and `assignable`; if `jq` showed other key names, use those, nothing else changes):

```rust
/// The migration's assignable sets are exactly the protocol's (P20 vector).
#[tokio::test]
async fn the_assignable_sets_match_the_protocol_vector() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../protocol/vectors/project-rule-sets.json");
    let vector: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let sets = vector.get("sets").unwrap_or(&vector);
    let mut want: Vec<&str> = sets
        .as_array()
        .unwrap()
        .iter()
        .filter(|set| set["assignable"] == true)
        .map(|set| set["id"].as_str().unwrap())
        .collect();
    want.sort_unstable();
    let (db, admin) = setup().await;
    let got: Vec<String> = admin
        .query("SELECT rule_set_id FROM rule_set_assignment ORDER BY 1", &[])
        .await
        .unwrap()
        .iter()
        .map(|row| row.get(0))
        .collect();
    assert_eq!(got, want);
    drop(admin);
    db.drop().await;
}
```

Run `nice -n 19 cargo test --locked -p platform-store --test rule_assignment the_assignable_sets_match_the_protocol_vector`. Expected: PASS (`hardening-linux-l1`, `hardening-linux-l2`). It fails the day the protocol adds an assignable set without a migration row, which is the point.

- [ ] **Step 2: Write the failing store tests**

Create `crates/platform-store/tests/end_unassigned.rs`:

```rust
//! The agent reports a set `not_assigned` (spec 2026-10-14 §5, user decision
//! 2026-10-14): its open matches end, triage is never touched, and a history
//! entry says why. Run as the `openvibes-ingest` role.

mod common;

use chrono::{Duration, Utc};
use common::TestDb;
use platform_store::{
    Client,
    finding_changes::{NOT_ASSIGNED_NOTE, end_unassigned},
};

const L1: &str = "hardening-linux-l1";

async fn setup() -> (TestDb, Client, Client) {
    let db = TestDb::create().await;
    let mut admin = db.pool.get().await.unwrap();
    platform_store::migrate(&mut admin).await.unwrap();
    for agent in ["agent.a", "agent.b"] {
        admin
            .execute(
                "INSERT INTO agents (agent_id, status, enrolled_at) VALUES ($1, 'active', now())",
                &[&agent],
            )
            .await
            .unwrap();
    }
    let ingest = db.pool.get().await.unwrap();
    ingest
        .batch_execute("SET ROLE \"openvibes-ingest\"")
        .await
        .unwrap();
    (db, admin, ingest)
}

/// An open P13 match of `set`/`rule` on `agent`.
async fn open(admin: &Client, agent: &str, set: &str, rule: &str) {
    admin
        .execute(
            "INSERT INTO current_findings (agent_id, rule_set_id, rule_id, last_finding_id,
                 rule_version, severity, first_observed_at, last_observed_at, last_observed_day,
                 scan_id, confidence, message, evidence, received_at, origin, authenticated, source)
             VALUES ($1, $2, $3, 'finding.seed', 1, 'low', now() - interval '1 hour',
                 now() - interval '1 hour', current_date, 'scan.1', 100, 'm', '{}', now(),
                 'online', true, 'changes')",
            &[&agent, &set, &rule],
        )
        .await
        .unwrap();
}

/// (match ended, triage state or "none", history notes) of one finding.
async fn state(admin: &Client, agent: &str, set: &str, rule: &str) -> (bool, String, Vec<String>) {
    let row = admin
        .query_one(
            "SELECT c.ended_at IS NOT NULL, COALESCE(t.state, 'none'),
                    ARRAY(SELECT h.from_state || '>' || h.to_state || ' ' || h.changed_by || ': ' || h.note
                          FROM console_finding_triage_history h
                          WHERE (h.agent_id, h.rule_set_id, h.rule_id) = (c.agent_id, c.rule_set_id, c.rule_id)
                          ORDER BY h.event_id)
             FROM current_findings c
             LEFT JOIN console_finding_triage t USING (agent_id, rule_set_id, rule_id)
             WHERE c.agent_id = $1 AND c.rule_set_id = $2 AND c.rule_id = $3",
            &[&agent, &set, &rule],
        )
        .await
        .unwrap();
    (row.get(0), row.get(1), row.get(2))
}

fn note(state: &str) -> Vec<String> {
    vec![format!("{state}>{state} system: {NOT_ASSIGNED_NOTE}")]
}

fn untouched() -> (bool, String, Vec<String>) {
    (false, "none".into(), Vec::new())
}

#[tokio::test]
async fn ends_only_this_hosts_open_matches_of_the_set() {
    let (db, admin, mut ingest) = setup().await;
    open(&admin, "agent.a", L1, "harden.ssh.x").await;
    open(&admin, "agent.a", L1, "harden.ssh.y").await;
    open(&admin, "agent.a", "hardening-linux-l2", "harden.audit.z").await;
    open(&admin, "agent.a", "baseline", "base.rule").await;
    open(&admin, "agent.b", L1, "harden.ssh.x").await;
    let n = end_unassigned(&mut ingest, "agent.a", &[L1.to_owned()], Utc::now())
        .await
        .unwrap();
    assert_eq!(n, 2);
    // Ended, no triage row created, one history entry by the system.
    for rule in ["harden.ssh.x", "harden.ssh.y"] {
        assert_eq!(state(&admin, "agent.a", L1, rule).await, (true, "none".into(), note("open")));
    }
    assert_eq!(state(&admin, "agent.a", "hardening-linux-l2", "harden.audit.z").await, untouched());
    assert_eq!(state(&admin, "agent.a", "baseline", "base.rule").await, untouched());
    assert_eq!(state(&admin, "agent.b", L1, "harden.ssh.x").await, untouched());
    let audits: i64 = admin
        .query_one("SELECT count(*) FROM audit_log", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(audits, 0, "a match ending writes no audit row, as for any match end");
    drop((admin, ingest));
    db.drop().await;
}

#[tokio::test]
async fn repeated_reports_end_nothing_more() {
    let (db, admin, mut ingest) = setup().await;
    open(&admin, "agent.a", L1, "harden.ssh.x").await;
    let sets = [L1.to_owned()];
    assert_eq!(end_unassigned(&mut ingest, "agent.a", &sets, Utc::now()).await.unwrap(), 1);
    for _ in 0..3 {
        assert_eq!(end_unassigned(&mut ingest, "agent.a", &sets, Utc::now()).await.unwrap(), 0);
    }
    assert_eq!(state(&admin, "agent.a", L1, "harden.ssh.x").await.2, note("open"));
    drop((admin, ingest));
    db.drop().await;
}

#[tokio::test]
async fn a_match_the_agent_already_ended_is_left_alone() {
    // The agent's own P13 `ended` often arrives first: nothing more to do.
    let (db, admin, mut ingest) = setup().await;
    open(&admin, "agent.a", L1, "harden.ssh.x").await;
    admin
        .execute("UPDATE current_findings SET ended_at = now() - interval '1 minute'", &[])
        .await
        .unwrap();
    assert_eq!(end_unassigned(&mut ingest, "agent.a", &[L1.to_owned()], Utc::now()).await.unwrap(), 0);
    assert_eq!(state(&admin, "agent.a", L1, "harden.ssh.x").await, (true, "none".into(), Vec::new()));
    drop((admin, ingest));
    db.drop().await;
}

#[tokio::test]
async fn a_non_assignable_set_ends_nothing() {
    let (db, admin, mut ingest) = setup().await;
    open(&admin, "agent.a", "baseline", "base.rule").await;
    assert_eq!(
        end_unassigned(&mut ingest, "agent.a", &["baseline".to_owned()], Utc::now()).await.unwrap(),
        0
    );
    assert_eq!(state(&admin, "agent.a", "baseline", "base.rule").await, untouched());
    drop((admin, ingest));
    db.drop().await;
}

#[tokio::test]
async fn triage_is_never_touched() {
    let (db, admin, mut ingest) = setup().await;
    open(&admin, "agent.a", L1, "harden.ssh.x").await;
    admin
        .execute(
            "INSERT INTO console_finding_triage (agent_id, rule_set_id, rule_id, state, rule_version,
                 note, accepted_until, version, updated_at, updated_by)
             VALUES ('agent.a', $1, 'harden.ssh.x', 'accepted_risk', 1, 'known',
                 now() + interval '30 days', 3, now() - interval '1 day', 'analyst')",
            &[&L1],
        )
        .await
        .unwrap();
    end_unassigned(&mut ingest, "agent.a", &[L1.to_owned()], Utc::now() + Duration::seconds(1))
        .await
        .unwrap();
    let row = admin
        .query_one(
            "SELECT state, note, version, updated_by FROM console_finding_triage", &[])
        .await
        .unwrap();
    let triage: (String, String, i64, String) = (row.get(0), row.get(1), row.get(2), row.get(3));
    assert_eq!(triage, ("accepted_risk".into(), "known".into(), 3, "analyst".into()));
    assert_eq!(state(&admin, "agent.a", L1, "harden.ssh.x").await.2, note("accepted_risk"));
    drop((admin, ingest));
    db.drop().await;
}
```

- [ ] **Step 3: Run them to verify they fail**

```bash
nice -n 19 cargo test --locked -p platform-store --test end_unassigned
```

Expected: FAIL to compile, `cannot find function end_unassigned`.

- [ ] **Step 4: Implement the match end**

Append to `crates/platform-store/src/finding_changes.rs`:

```rust
/// History note when a match ends because its set is off for the host
/// (spec 2026-10-14 §5).
pub const NOT_ASSIGNED_NOTE: &str = "rule set no longer assigned to this host";

/// The agent reported `sets` as `not_assigned` (P20). For each of them that
/// is assignable (`rule_set_assignment`), this host's still-open matches end,
/// as when the host stops matching (user decision 2026-10-14). Triage is
/// never touched; each ended match gets one triage-history entry by
/// `system` with [`NOT_ASSIGNED_NOTE`], its state unchanged (from = to), so
/// the finding's history says why it ended. No audit row: no match end
/// writes one. Switching the set back on, the next observation starts the
/// match again through the usual rules. Returns how many matches ended; a
/// repeated report ends nothing more.
///
/// ponytail: runs on every heartbeat that names a `not_assigned` set (an
/// index probe that finds nothing after the first time); gate it on
/// `ingest::heartbeat`'s changed-rule-sets result if load tests show it.
///
/// # Errors
///
/// A database error.
pub async fn end_unassigned(
    client: &mut Client,
    agent_id: &str,
    sets: &[String],
    now: DateTime<Utc>,
) -> Result<u64, StoreError> {
    let transaction = client.transaction().await?;
    let ended = transaction
        .query(
            "UPDATE current_findings SET ended_at = $3, end_approximate = true
             WHERE agent_id = $1 AND rule_set_id = ANY($2) AND ended_at IS NULL
               AND rule_set_id IN (SELECT rule_set_id FROM rule_set_assignment)
             RETURNING rule_set_id, rule_id, rule_version",
            &[&agent_id, &sets, &now],
        )
        .await?;
    for row in &ended {
        let (set, rule, rule_version): (String, String, i64) = (row.get(0), row.get(1), row.get(2));
        transaction
            .execute(
                "INSERT INTO console_finding_triage_history (agent_id, rule_set_id, rule_id,
                     from_state, to_state, note, changed_at, changed_by, rule_version)
                 SELECT $1, $2, $3, s.state, s.state, $4, $5, 'system', $6
                 FROM (SELECT COALESCE((SELECT state FROM console_finding_triage
                                        WHERE agent_id = $1 AND rule_set_id = $2 AND rule_id = $3),
                                       'open') AS state) s",
                &[&agent_id, &set, &rule, &NOT_ASSIGNED_NOTE, &now, &rule_version],
            )
            .await?;
    }
    transaction.commit().await?;
    Ok(ended.len() as u64)
}
```

Append to `migrations/0049_rule_set_assignment.sql`:

```sql
-- Ingest ends a host's matches of a set the agent reports not_assigned: it
-- checks the set is assignable (it already updates current_findings and
-- writes triage history).
GRANT SELECT ON rule_set_assignment TO "openvibes-ingest";
```

- [ ] **Step 5: Run them to verify they pass**

```bash
nice -n 19 cargo test --locked -p platform-store --test end_unassigned
```

Expected: PASS (5 tests).

- [ ] **Step 6: Write the failing ingest test**

Create `crates/openvibes-ingest/tests/assignment.rs`:

```rust
//! P20: a heartbeat whose health reports an assignable set `not_assigned`
//! ends the host's open matches of that set; one without a state ends none.

mod support;

use chrono::{Duration, Utc};
use openvibes_core::{EnrollmentToken, Heartbeat, Identifier};
use openvibes_transport::{ClientIdentity, HostKey, PlatformClient};
use support::World;

async fn blocking<T: Send + 'static>(work: impl FnOnce() -> T + Send + 'static) -> T {
    tokio::task::spawn_blocking(work).await.unwrap()
}

async fn enrolled(world: &World) -> (String, Vec<String>, String) {
    let transport = world.transport();
    let token = EnrollmentToken::new(world.token(1, Duration::days(1)).await).unwrap();
    blocking(move || {
        let key = HostKey::generate().unwrap();
        let response = PlatformClient::new(&transport, None)
            .unwrap()
            .enroll(&token, &key)
            .unwrap();
        (
            response.agent_id.as_str().to_owned(),
            response.certificate_chain_pem,
            key.expose_key_pem().to_owned(),
        )
    })
    .await
}

/// A valid heartbeat (the protocol fixture) whose health lists `rule_sets`.
fn beat(agent_id: &str, rule_sets: serde_json::Value) -> Heartbeat {
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../protocol/fixtures/v1/heartbeat/valid-alarms-fallback.json");
    let mut beat: Heartbeat =
        serde_json::from_str(&std::fs::read_to_string(fixture).unwrap()).unwrap();
    beat.agent_id = Identifier::new(agent_id).unwrap();
    beat.observed_at_unix_ms = Utc::now().timestamp_millis();
    beat.match_sha256 = None;
    beat.health.as_mut().unwrap().rule_sets = serde_json::from_value(rule_sets).unwrap();
    beat
}

async fn send(world: &World, chain: &[String], key: &str, beat: Heartbeat) {
    let (transport, chain, key) = (world.transport(), chain.to_vec(), key.to_owned());
    blocking(move || {
        let identity = ClientIdentity::from_pem(&chain, &key).unwrap();
        PlatformClient::new(&transport, Some(&identity))
            .unwrap()
            .heartbeat(&beat)
            .unwrap();
    })
    .await;
}

async fn seed(world: &World, agent_id: &str) {
    world
        .db()
        .await
        .execute(
            "INSERT INTO current_findings (agent_id, rule_set_id, rule_id, last_finding_id,
                 rule_version, severity, first_observed_at, last_observed_at, last_observed_day,
                 scan_id, confidence, message, evidence, received_at, origin, authenticated, source)
             VALUES ($1, 'hardening-linux-l1', 'harden.ssh.x', 'finding.seed', 1, 'low', now(),
                 now(), current_date, 'scan.1', 100, 'm', '{}', now(), 'online', true, 'changes')",
            &[&agent_id],
        )
        .await
        .unwrap();
}

/// (match ended, history entries, triage rows).
async fn observed(world: &World) -> (bool, i64, i64) {
    let row = world
        .db()
        .await
        .query_one(
            "SELECT (SELECT ended_at IS NOT NULL FROM current_findings),
                    (SELECT count(*) FROM console_finding_triage_history),
                    (SELECT count(*) FROM console_finding_triage)",
            &[],
        )
        .await
        .unwrap();
    (row.get(0), row.get(1), row.get(2))
}

#[tokio::test]
async fn a_heartbeat_without_state_ends_nothing() {
    let world = World::start().await;
    let (agent_id, chain, key) = enrolled(&world).await;
    seed(&world, &agent_id).await;
    let sets = serde_json::json!([{"id": "hardening-linux-l1", "version": null}]);
    send(&world, &chain, &key, beat(&agent_id, sets)).await;
    assert_eq!(observed(&world).await, (false, 0, 0));
    world.stop().await;
}

#[tokio::test]
async fn a_not_assigned_report_ends_the_sets_matches() {
    let world = World::start().await;
    let (agent_id, chain, key) = enrolled(&world).await;
    seed(&world, &agent_id).await;
    let sets = serde_json::json!([{"id": "hardening-linux-l1", "state": "not_assigned"}]);
    send(&world, &chain, &key, beat(&agent_id, sets.clone())).await;
    assert_eq!(observed(&world).await, (true, 1, 0));
    send(&world, &chain, &key, beat(&agent_id, sets)).await;
    assert_eq!(observed(&world).await, (true, 1, 0), "the second report ends nothing more");
    world.stop().await;
}
```

- [ ] **Step 7: Run it to verify it fails**

```bash
nice -n 19 cargo test --locked -p openvibes-ingest --test assignment
```

Expected: `a_not_assigned_report_ends_the_sets_matches` FAILS (`left: (false, 0, 0), right: (true, 1, 0)`); the other passes.

- [ ] **Step 8: Wire the heartbeat**

In `crates/openvibes-ingest/src/delivery.rs`, add above `heartbeat`:

```rust
/// The rule sets the agent reports as not assigned to its host (P20).
fn not_assigned_sets(heartbeat: &Heartbeat) -> Vec<String> {
    heartbeat
        .health
        .iter()
        .flat_map(|health| &health.rule_sets)
        .filter(|set| matches!(set.state, Some(openvibes_core::RuleSetState::NotAssigned)))
        .map(|set| set.id.as_str().to_owned())
        .collect()
}
```

and in `heartbeat`, right after the `ingest::heartbeat(...).await?;` statement:

```rust
    // P20: a set the platform switched off for this host ends its open matches
    // here once the agent says it stopped running it.
    let not_assigned = not_assigned_sets(&heartbeat);
    if !not_assigned.is_empty() {
        finding_changes::end_unassigned(&mut client, &agent_id, &not_assigned, now).await?;
    }
```

- [ ] **Step 9: Run them to verify they pass**

```bash
nice -n 19 cargo test --locked -p openvibes-ingest
nice -n 19 cargo test --locked -p platform-store
```

Expected: PASS, including `protocol_fixtures` with the bumped protocol's new fixtures.

- [ ] **Step 10: Docs**

In `docs/components/openvibes-ingest.md`, after "An invalid `health` makes the heartbeat invalid (400)." add:

```markdown
  A rule set the report marks `state: not_assigned` (P20) ends this host's
  still-open matches of that set when it is an assignable one, as when the
  host stops matching. Triage is not touched; each ended match gets one
  triage-history entry by `system` with the note "rule set no longer
  assigned to this host" (state unchanged). No audit row, as for any match
  end. Repeated reports end nothing more
  ([rule-set-assignment.md](rule-set-assignment.md)).
```

In `docs/components/rule-set-assignment.md` add an `**Ingest.**` paragraph with the same rule plus: "Triage (state, note, assignee, version) never changes here (user decision 2026-10-14). A match the agent already ended through P13 is left as it is. Switching the set back on: the agent's next scan starts the match again through the usual rules, as for any finding that comes back. Grants: `openvibes-ingest` may read `rule_set_assignment` (it already updates `current_findings` and writes triage history)." and the tests `end_unassigned.rs` (store) and `openvibes-ingest/tests/assignment.rs` under How to test.

- [ ] **Step 11: Commit**

```bash
cargo fmt --all
git add Cargo.toml Cargo.lock protocol crates/platform-store crates/openvibes-ingest \
  migrations/0049_rule_set_assignment.sql docs/components/openvibes-ingest.md \
  docs/components/rule-set-assignment.md
git commit -m "Ingest: end a host's matches of a set it reports not_assigned (P20)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 7: Setup and `helper rules-apply` publish the hardening stems present

**Files:**
- Modify: `crates/openvibes-admin/src/setup/fleet.rs:17-21` (consts), `:79-88` (`alarms_key` → `optional_key`), `:136-143` (`rules_check`), `:169-175` (`rules_apply`), `:207` (`agent_toml`)
- Test: `crates/openvibes-admin/src/setup/fleet.rs` (tests module, after `the_alarm_rule_set_is_published_beside_the_baseline`)
- Docs: `docs/components/openvibes-admin.md:577-581` (Setup `rules` step), `:768` (`helper rules-apply`)

**Interfaces:**
- Consumes: Task 1's files `/usr/share/openvibes/rules/hardening-linux-l1.{json,key}` (and later `hardening-linux-l2.*`).
- Produces: `const OPTIONAL: [&str; 3] = ["alarms", "hardening-linux-l1", "hardening-linux-l2"]`, `fn optional_key<R: Runner>(ctx: &Ctx<R>, stem: &str) -> Result<Option<[String; 3]>, String>`.

- [ ] **Step 1: Write the failing test**

In the tests module of `fleet.rs`, after the alarm publishing test:

```rust
    const L1_KEY: &str =
        "hardening-linux-l1 openvibes-1 CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC";

    /// Rules v5 carries hardening L1 (L2 later): every stem present is
    /// trusted and published after the alarms, an absent one is skipped,
    /// and the step stays Todo until each present set is published.
    #[test]
    fn the_hardening_sets_are_published_when_present() {
        let fake = Fake::new("rules-hardening");
        fake.answer(
            &admin(&["rules", "list"]),
            0,
            "baseline v1 keys 1\nbaseline-alarms v1 keys 1\n",
        );
        let rules = "/usr/share/openvibes/rules";
        for (stem, key) in [("baseline", KEY), ("alarms", ALARMS_KEY), ("hardening-linux-l1", L1_KEY)] {
            fake.file(&format!("{rules}/{stem}.key"), &format!("{key}\n"));
            fake.file(&format!("{rules}/{stem}.json"), "{\"rule_set_version\":1}");
        }
        let plan = plan(&[Ingest, Distribution, Rules]);
        assert_eq!(rules_check(&fake.ctx(&plan)).unwrap(), StepState::Todo);
        fake.answer(&["/usr/bin/rpm", "-q", "--quiet", "openvibes-rules-baseline"], 0, "");
        fake.answer(&admin(&["rules", "trust", "add"]), 0, "trusted\n");
        fake.answer(&admin(&["rules", "publish"]), 0, "published\n");
        let state = run_step(&fake.ctx(&plan), Step::Rules);
        assert!(
            state.detail().ends_with("baseline-alarms published, hardening-linux-l1 published"),
            "{state:?}"
        );
        let calls = fake.calls.borrow();
        let trusted: Vec<&str> = calls
            .iter()
            .filter(|call| call.get(6).is_some_and(|word| word == "trust"))
            .map(|call| call[8].as_str())
            .collect();
        assert_eq!(trusted, ["baseline", "baseline-alarms", "hardening-linux-l1"]);
        let published: Vec<&str> = calls
            .iter()
            .filter(|call| call.get(6).is_some_and(|word| word == "publish"))
            .map(|call| call[7].as_str())
            .collect();
        assert_eq!(
            published,
            [
                "/usr/share/openvibes/rules/baseline.json",
                "/usr/share/openvibes/rules/alarms.json",
                "/usr/share/openvibes/rules/hardening-linux-l1.json"
            ]
        );
    }
```

(`KEY`, `ALARMS_KEY`, `admin`, `plan`, `run_step`, `Fake` are already in scope there.)

- [ ] **Step 2: Run it to verify it fails**

```bash
nice -n 19 cargo test --locked -p openvibes-admin --bin openvibes-admin the_hardening_sets_are_published_when_present
```

Expected: FAIL: `rules_check` returns `Done(...)` instead of `Todo` (hardening is ignored).

- [ ] **Step 3: Implement**

Replace the `ALARMS` const doc and add the list (lines 17-21):

```rust
/// The rule sets the rules package may carry, as `STEM.json` and
/// `STEM.key`: the baseline findings rules, always; then, when present, the
/// threat-alarm rules (rules v2, only a P14 agent runs them) and the
/// project's hardening sets (L1 from rules v5, L2 once signed), which the
/// platform switches per asset group.
const BASELINE: &str = "baseline";
const ALARMS: &str = "alarms";
const OPTIONAL: [&str; 3] = [ALARMS, "hardening-linux-l1", "hardening-linux-l2"];
```

Replace `alarms_key` (lines 79-88):

```rust
/// The trust line of an optional set when the package carries it; an
/// unreadable or malformed key next to `STEM.json` is an error, as for the
/// baseline, so the rules are never silently left unpublished.
fn optional_key<R: Runner>(ctx: &Ctx<R>, stem: &str) -> Result<Option<[String; 3]>, String> {
    if ctx.exists(&format!("{RULES}/{stem}.json")) {
        set_key(ctx, stem).map(Some)
    } else {
        Ok(None)
    }
}
```

In `rules_check` replace the `if let Some([alarms, _, _]) = alarms_key(ctx)? ... }` block with:

```rust
    for stem in OPTIONAL {
        if let Some([set, _, _]) = optional_key(ctx, stem)?
            && !retired(ctx, &set)?
        {
            match current(&set, stem)? {
                Some(version) => done.push_str(&format!(", {set} v{version}")),
                None => return Ok(StepState::Todo),
            }
        }
    }
```

In `rules_apply` replace the alarms block with:

```rust
    for stem in OPTIONAL {
        if let Some([set, issuer, key]) = optional_key(ctx, stem)?
            && !retired(ctx, &set)?
        {
            ctx.as_admin(&["rules", "trust", "add", &set, &issuer, "--", &key])?;
            ctx.as_admin(&["rules", "publish", &format!("{RULES}/{stem}.json")])?;
            done.push_str(&format!(", {set} published"));
        }
    }
```

and in `agent_toml` change `alarms_key(ctx).ok().flatten()` to `optional_key(ctx, ALARMS).ok().flatten()`. The local agent's `agent.toml` does not name the hardening sets: the agent adds the project's sets itself (plan 1).

- [ ] **Step 4: Run them to verify they pass**

```bash
nice -n 19 cargo test --locked -p openvibes-admin
```

Expected: PASS, including the existing alarm and `auto_rules` tests.

- [ ] **Step 5: Docs**

In `docs/components/openvibes-admin.md` replace "when the package also carries `alarms.json`/`alarms.key` (rules v2), the threat-alarm set is trusted and published the same way)," with "when the package also carries `alarms.json`/`alarms.key` (rules v2) or a hardening set (`hardening-linux-l1.*` from rules v5, `hardening-linux-l2.*` once signed), each is trusted and published the same way, in that order, and a missing one is skipped; the platform then switches the hardening sets per asset group ([rule-set-assignment.md](rule-set-assignment.md)))," and at line 768 replace "It runs the sets Update knows (`baseline`, and `alarms` when the package carries it)." with "It runs the sets Update knows (`baseline`, then `alarms`, `hardening-linux-l1` and `hardening-linux-l2` when the package carries them)."

- [ ] **Step 6: Commit**

```bash
cargo fmt --all
git add crates/openvibes-admin/src/setup/fleet.rs docs/components/openvibes-admin.md
git commit -m "Setup: trust and publish the hardening sets the rules package carries

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 8: Platform gate, Fedora job, pull request

**Files:** none new (fixes only where the gate fails).

- [ ] **Step 1: Rebase and renumber if needed**

```bash
cd /home/lime/Projects/OpenVIBES/openvibes-platform-assign
git fetch origin && git rebase origin/main
git ls-tree --name-only origin/main migrations/ | tail -1
```

If `origin/main` now has a `0049_*`, rename ours to the next number and update `SCHEMA_VERSION`, the `MIGRATIONS` entry, the SQL header line, and "schema 49" in the docs pages of this plan; rerun Task 2–6 tests.

- [ ] **Step 2: The local gate (testing.md §2), in order, stop at the first failure**

```bash
eval "$(scripts/test-db.sh)"; echo "${OPENVIBES_TEST_DATABASE_URL:?not set}"
export CARGO_TARGET_DIR=~/.cache/openvibes-scratch/target
bash scripts/build-console.sh
cargo fmt --all --check
bash scripts/check-names.sh
nice -n 19 cargo clippy --locked --workspace --all-targets --all-features -- -D warnings -F unsafe-code
RUSTDOCFLAGS="-D warnings" nice -n 19 cargo doc --locked --workspace --all-features --no-deps
nice -n 19 cargo test --locked --workspace --all-features
cargo audit --deny warnings
bash scripts/test-console-e2e.sh
scripts/test-db.sh stop
```

Expected: all green. `cargo audit` is red on `main` until platform #280 (rustls) merges; if it is still red, say so in the PR body and rebase once #280 is in. The regenerated `generated.ts` counts as browser code: `test-console-e2e.sh` runs for it.

- [ ] **Step 3: The Fedora job (testing.md §3: migration grants used by installed services)**

```bash
podman run --rm -it -v "$PWD":/src:Z -w /src registry.fedoraproject.org/fedora:44 bash
# inside: the "fedora" job's steps from .github/workflows/ci.yml, then the
# "integration" job's (real agent against ingest and distribution).
```

Expected: both green. If it cannot run, say which step and why in the PR body and watch that CI job.

- [ ] **Step 4: Push and open the PR**

```bash
git push -u origin HEAD:feat/rule-set-assignment
gh pr create --repo openvibes-project/openvibes-platform --base main --head feat/rule-set-assignment \
  --title "Rule-set assignment: per-group hardening switches, 410, matches end" --body-file - <<'EOF'
Spec: docs/specs/2026-10-14-rule-set-assignment-design.md (§5, §7 step 4 without the console screens).

- Migration 49: assignable sets with defaults (L1 on, L2 off) and per-group overrides (on wins).
- Distribution answers 410 for an assignable set off on the host (P20); 404 cases unchanged.
- Ingest ends a host's open matches of a set the agent reports `not_assigned` (triage untouched, one history entry).
- Console API: /api/v1/rule-set-assignments (list, default, group override), host view, `rule_sets[].state`.
- Setup and `helper rules-apply` publish the hardening sets the rules package carries.

Validation: <each gate command from testing.md §2 and §3 with its result; anything not run, with why>

AI disclosure: written with Claude Code (CONTRIBUTING.md).

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
gh pr checks --watch
```

Replace the Validation line with the real commands and results before sending (no placeholder left in the PR body). On a red check: `gh run view <run-id> --log-failed | grep -E 'FAILED|panicked|error'`, reproduce locally, fix, rerun the gate, push.

---

### Task 9: Lab check (openvibes-lab): Fedora and Debian hosts with the new agent

Runs after Tasks 1–8 have CI builds and plan 1's agent has CI builds (RPM and .deb). One heavy job at a time: no sweep or other lab run in parallel. Lab ssh goes through `./lab ssh` (it already uses `-o IdentitiesOnly=yes -o IdentityAgent=none`).

**Files:** none (results go into the PR and `status.md`).

- [ ] **Step 1: Collect the packages**

```bash
set -euo pipefail
dir=~/.cache/openvibes-lab-assign && rm -rf "$dir" && mkdir -p "$dir"
gh run download -R openvibes-project/openvibes-platform --name <platform RPM artifact of the PR's CI run> -D "$dir"
gh run download -R openvibes-project/openvibes-agent --name <agent RPM and deb artifacts of main's CI run> -D "$dir"
gh run download -R openvibes-project/openvibes-rules --name rules-rpms -D "$dir"
ls "$dir"
```

Take the artifact names from `gh run view <run-id>` of each repository's CI run (platform: the PR head; agent: `main` after plan 1; rules: Task 1's PR). Expected: platform RPMs, `openvibes-agent-*.rpm`, `openvibes-agent_*.deb`, `openvibes-rules-baseline-4-1.fc44.noarch.rpm`.

- [ ] **Step 2: Bring up the lab**

```bash
cd /home/lime/Projects/OpenVIBES/openvibes-lab
./lab up --from ~/.cache/openvibes-lab-assign platform fedora debian
./lab status
```

Expected: three machines, both agents checked in.

- [ ] **Step 3: L1 findings appear**

```bash
./lab ssh platform 'sudo runuser -u openvibes-admin -- openvibes-admin rules list'
./lab ssh platform "sudo -u postgres psql -d openvibes -Atc \"SELECT a.hostname, count(*) FROM current_findings c JOIN agents a USING (agent_id) WHERE c.rule_set_id = 'hardening-linux-l1' AND c.ended_at IS NULL GROUP BY 1\""
```

Expected: `hardening-linux-l1 v4` published; after the agents' next scan (up to one scan interval), both hosts list L1 findings. If none appear, check the hosts' health `rule_sets` in the console before going on.

- [ ] **Step 4: Switch L1 off for the Fedora host's group**

```bash
set -euo pipefail
cd /home/lime/Projects/OpenVIBES/openvibes-lab
LAB_ROOT=$PWD; for f in lib/*.sh; do source "$f"; done
jar=$(mktemp -p ~/.cache); console_login "$jar"
csrf=$(_console_curl -b "$jar" https://platform.lab/api/v1/session | jq -er .csrf_token)
api() { _console_curl -b "$jar" -H 'Content-Type: application/json' -H 'Origin: https://platform.lab' -H "X-CSRF-Token: $csrf" "$@"; }
fid=$(alarms_agent fedora "$jar" | jq -er .id)
tags='{"tags":[{"key":"lab","value":"no-l1"}]}'
token=$(api -X POST --data "$tags" "https://platform.lab/api/v1/agents/$fid/tags/preview" | jq -er .preview_token)
api -X PUT --data "{\"tags\":[{\"key\":\"lab\",\"value\":\"no-l1\"}],\"preview_token\":\"$token\"}" "https://platform.lab/api/v1/agents/$fid/tags" >/dev/null
gid=$(api -X POST --data '{"name":"lab-no-l1","selectors":[{"key":"lab","value":"no-l1"}]}' https://platform.lab/api/v1/access-control/asset-groups | jq -er .asset_group_id)
api -X PUT --data '{"enabled":false}' "https://platform.lab/api/v1/rule-set-assignments/hardening-linux-l1/groups/$gid" | jq .
api "https://platform.lab/api/v1/agents/$fid/rule-set-assignments" | jq .
```

Expected: the set shows the `lab-no-l1` override `enabled: false`; the host view says L1 `enabled: false, source: "group"`. Debian keeps L1 on.

- [ ] **Step 5: 410, `not_assigned`, matches ended**

```bash
./lab ssh fedora 'sudo journalctl -u openvibes-agent --since "-15 min" | grep -i "hardening-linux-l1" | tail -5'
api "https://platform.lab/api/v1/agents/$fid" | jq '.rule_sets'
./lab ssh platform "sudo -u postgres psql -d openvibes -Atc \"SELECT c.ended_at IS NOT NULL, COALESCE(t.state,'open'), (SELECT h.note FROM console_finding_triage_history h WHERE (h.agent_id, h.rule_set_id, h.rule_id) = (c.agent_id, c.rule_set_id, c.rule_id) ORDER BY h.event_id DESC LIMIT 1), count(*) FROM current_findings c LEFT JOIN console_finding_triage t USING (agent_id, rule_set_id, rule_id) WHERE c.agent_id = '$fid' AND c.rule_set_id = 'hardening-linux-l1' GROUP BY 1, 2, 3\""
```

Expected, within one scan interval plus one heartbeat: the agent logged the 410 for `hardening-linux-l1`; its `rule_sets` entry has `"state": "not_assigned"`; every Fedora L1 match is ended (`t`), its triage state is what it was (`open` unless an analyst changed it), and its latest history note is `rule set no longer assigned to this host`; Debian's L1 matches stay open (`f`).

- [ ] **Step 6: Switching it back on brings them back**

```bash
api -X DELETE "https://platform.lab/api/v1/rule-set-assignments/hardening-linux-l1/groups/$gid" | jq .groups
```

Then rerun the Step 5 queries after the next scan. Expected: the agent fetches L1 again (200), the state is gone from its health, and the matches it still finds are open again (`ended_at` cleared by the agent's new `started`), their triage as it was.

- [ ] **Step 7: An old agent is unaffected**

```bash
old=$(gh release view -R openvibes-project/openvibes-agent --json tagName --jq .tagName | sed 's/^v//')
./lab up --version "$old" ubuntu
./lab ssh ubuntu 'sudo journalctl -u openvibes-agent --since "-15 min" | grep -ci hardening || true'
```

Expected: the released agent enrolls, gets baseline (and alarms) as before, never asks for hardening (count 0), and its health shows no problem. If `up` refuses a different source than the running lab, run `./lab up --bare ubuntu` then `./lab install ubuntu --version "$old"`.

- [ ] **Step 8: Record and tear down**

Write the results (each check, pass or fail, times) into the platform PR as a comment and into `/home/lime/Projects/OpenVIBES/status.md` (commit there right after the edit, subject `[claude] lab check: rule-set assignment`), then:

```bash
rm -f "$jar"
./lab down
```
