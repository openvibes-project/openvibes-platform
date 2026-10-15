# Rule-set assignment, part 3: console screens Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The approved console screens for rule-set assignment: Settings › Rule sets lists the hardening sets with a **Runs on** column, a set's panel gets **Where it runs** (default switch, group overrides, inline add row), and the host panel gets the **Hardening** line, the **Not assigned** badge and the **Hardening facts unavailable** warning.

**Architecture:** The #283 API lacks some figures the screens show, so Tasks 1–3 add them: in the existing store module and console handlers, Linux host counts per set and per group, each group's selectors, the group that decides a host's state, `published` per host set, and the hardening collector's outcome from the host's stored health report; one column (migration `0050`, set by ingest) records when a host's report last had usable hardening facts, for "has not reported for N days". Task 3 also lets `rules.upload` read the rule-set list, bundle history and coverage (user, 2026-10-15). No new route. The web app gets one module of pure helpers (`panels/ruleAssignment.ts`), one panel section component (`panels/WhereItRuns.tsx`) and one host component file (`panels/HostHardening.tsx`); `Admin.tsx`, `OpsPanels.tsx`, `AgentPanel.tsx` and `Settings.tsx` only wire them in. The demo gets a matching in-memory store (`demo/assignments.ts`). The check count in the panel's Source row comes from the existing `GET /api/v1/rules/coverage`.

**Tech Stack:** Rust (axum, tokio-postgres, utoipa), React 19 + TypeScript, vitest (node, `renderToStaticMarkup`), Playwright (live and demo).

**Spec:** `docs/specs/2026-10-14-rule-set-assignment-design.md` §6, and the approved screens `docs/specs/rule-set-assignment-ui/approved.md` (generator `gen.py` in the same folder; `python3 gen.py base OUT_DIR` renders them). The approved screens bind every visible text, order and control. Backend: `docs/components/rule-set-assignment.md`, PR #283.

## Rulings (user and controller, 2026-10-15)

- **G1, root-facts freshness → platform-side record (user).** Neither the protocol nor the agent (`origin/main`: `spec/contracts-v1.md` P12/P19; agent `root_facts.rs`, `scan.rs`) reports when the root-facts helper last wrote: the agent sends only `health.last_scan.collectors.hardening` (`ok`; `not_found` when the helper's file is stale or malformed; `invalid_data` when its facts fail validation), and a **missing file sends no outcome** (same as a host with no helper). So ingest records `agents.hardening_facts_ok_at`, the time of the last stored report whose hardening outcome was `ok` (migration `0050`, Task 2), and the console counts N days from it. Texts (Task 4 `factsNote`): known time: the approved sentence, "has not reported for N days"; never `ok` since enrollment: "has not reported since enrollment"; `invalid_data`: "sent invalid hardening facts". Ceilings: N counts from the platform's last good report (the heartbeat write is throttled to 5 minutes), not the helper's own write, and is at least 1; the migration backfills hosts whose stored report is `ok` now, so a host that was broken at upgrade time reads "since enrollment" even if it once worked; a helper whose file is missing stays invisible (needs a protocol change, not planned).
- **G2, operators read the rule list → yes (user).** `rules.upload` also reads `GET /api/v1/rule-sets`, `GET /api/v1/rule-sets/{id}/bundles`, `GET /api/v1/rules/coverage` (and `GET /api/v1/attack`, which shares that check), globally, like the assignment list (Task 3). Analysts and viewers still get 403. The UI's read gate everywhere in this feature is `readsRules(can)` = `rules.read` or `rules.upload`, so operators see version, signer, expiry, Published versions and the check count like admins.
- **G3, "pending" (controller: accepted).** "pending" = the agent's latest report disagrees with the platform's decision (on but not running, or off but still running). No switch time is stored. An agent too old to know the project sets never lists L1, so an on L1 shows "pending" on it until the agent is updated; documented in `rule-set-assignment.md` (Task 7) and marked `ponytail:` in `hardeningParts`.
- **G4, copy the screens do not show (controller).** Toasts: "hardening-linux-l1 is now on by default" / "… off by default"; "hardening-linux-l1 is now on for <group>" / "… off for <group>"; "<group> follows the default again". Disabled Add-group reasons: "No asset groups yet: create one under Settings › Access." and "Every asset group is listed.". A Not assigned row switched off by the default reads "off by default" (by a group: "off for <group>"). For `invalid_data` the facts sentence says "sent invalid hardening facts".
- **Coverage menu entry (controller).** G2 lets `rules.upload` read coverage, so the Coverage navigation entry (registry/rail) follows the same `readsRules(can)` check: operators get the Coverage page too. Task 6 changes the entry's permission and its test asserts an operator sees it. Cost if wrong: one menu entry.
- **G5, group names (user).** The host view always returns the deciding group's name, also to callers scoped to other groups. No masking.
- **"N checks".** Counted from `GET /api/v1/rules/coverage` (verified current rules, test rules left out). The demo has no hardening rules in its coverage, so it shows "(Level 1)" without a count.

## Global Constraints

- The approved screens (`docs/specs/rule-set-assignment-ui/approved.md`) bind texts, order and controls; copy each string verbatim from there or from this plan.
- The interface comes first: fast, uncluttered, clear. No new visual patterns: reuse `Switch`, `Segmented`, `Select`, `Section`, `.table--compact`, `.tag`, `.badge`, `toast`.
- No commands in the product: no typed-command hints in anything this plan adds.
- Permissions: reading the switches, the rule-set list, bundle history and coverage needs `rules.read` OR `rules.upload` (global; the list, history and coverage change in Task 3); changing needs global `rules.upload` + CSRF (already enforced server-side). The UI hides the Rule sets tab without either, and disables the switches and hides Add/remove without `rules.upload`. Use `readsRules(can)` and `useSession().can("rules.upload", true)`.
- TDD: every task writes the failing test first and runs it red before the code.
- Migration number: `0050` is the next free one on `origin/main` (schema 49); if another branch takes it first, renumber at rebase (`SCHEMA_VERSION`, the `MIGRATIONS` entry, the file name, the doc headings).
- Files under 500 lines. `AgentPanel.tsx` (314), `OpsPanels.tsx` (288), `Admin.tsx` (264) only get wiring; new components go in their own files. `demo/server.ts` (1220) only gets the route lines shown; `crates/platform-store/tests/rule_assignment.rs` (497) and `crates/openvibes-console/tests/rule_assignment_http.rs` (466) only get the edits shown (new store tests go in a new file).
- `docs/components/` pages updated in the same change: `rule-set-assignment.md` (API in Task 3, console in Tasks 6–7), `platform-store.md` (Task 2), `console-rbac.md` (Task 3) and a pointer in `console-web.md` (Task 6).
- Console API changes: regenerate and commit the snapshot and client (testing.md §2): `cargo run --locked -p openvibes-console --bin export_openapi > docs/api/console-v1.openapi.json` and `npm --prefix crates/openvibes-console/web run generate:api`.
- The demo data layer gets matching data so the demo build shows every approved screen (Task 5).
- Playwright e2e, live and demo, for the flows (Task 8).
- Never symlink `node_modules` from another checkout; this worktree has its own (`npm --prefix crates/openvibes-console/web ci` if it is missing).
- Commits end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. Git identity: `itismelime` / `26064407+itismelime@users.noreply.github.com`.
- Scratch builds: `CARGO_TARGET_DIR=~/.cache/openvibes-scratch/target`, `nice -n 19`, never `/tmp` (RAM here). One heavy job at a time.
- This host runs the user's production platform: no `sudo`, never touch its `openvibes-*` services or database.
- Database tests need `eval "$(scripts/test-db.sh)"` first; check `OPENVIBES_TEST_DATABASE_URL` is set before trusting a green run.
- Before the PR: the local gate, testing.md §2, plus `bash scripts/test-console-e2e.sh` and `npm --prefix crates/openvibes-console/web run test:e2e:demo`. WebKit cannot launch on this host (known): say so in the PR and watch that CI job.

## Review Focus

1. **A user without `rules.read`/`rules.upload` never sees the switches or the rule list; a reader without `rules.upload` sees the switches read-only; an operator reads everything and changes the switches.** Tests: Task 3 `rule_readers_and_publishers…` (operator reads the list, history and coverage; analyst 403), Task 6 `without rules.upload the switches are read-only…`, Task 8 demo `a viewer has no Rule sets tab, an operator changes switches`.
2. **A failed change leaves the switch in its old state and shows the error.** Test: Task 8 live `a failed change keeps the switch and says why`.
3. **A group deleted elsewhere while the panel is open:** the change answers 404 `asset_group_not_found`, the toast says "Asset group not found", the list refetches. Tests: Task 5 `an unknown group answers 404`, Task 8 live (route answers 404).
4. **No asset groups at all, or every group already listed:** "+ Add group" is disabled with a visible reason. Test: Task 6 `with no asset groups, Add group is disabled and says why`; Task 4 `addGroupBlocked`.
5. **A host in two groups (on wins) names the right deciding group:** the first group by name among those that say on; among those that say off when none says on. Tests: Task 1 `the_host_view_names_the_deciding_group…`, Task 4 `hardeningParts`.

Also covered: very long group names (Task 6 `a very long group name…`), keyboard-only use with Esc to cancel (Task 8 demo `L2 is switched on for Lab…`), and missing root facts for N days, since enrollment, or invalid (Task 2 `ingest_records_when_hardening_facts_were_last_usable`, Task 4 `factsNote`, Task 7).

---

### Task 1: Store: host counts, group selectors, the deciding group, published

**Files:**
- Modify: `crates/platform-store/src/rule_assignment.rs` (structs, `overview`, `HOST_STATE`, `assigned`, `for_agent`)
- Modify: `crates/platform-store/tests/rule_assignment.rs:381-392` (the one `HostAssignment` literal)
- Create: `crates/platform-store/tests/rule_assignment_fleet.rs`

**Interfaces:**
- Produces (Task 3 relies on these exact names):
  - `Assignment { rule_set_id, default_enabled, published, hosts_on: i64, hosts_off: i64, groups }`
  - `GroupName { asset_group_id, name, selectors: Vec<String> /* "key=value", sorted */, hosts: i64 }`
  - `HostAssignment { rule_set_id, enabled, source, group: Option<String>, published: bool }`
- A **Linux host** is an agent with `status = 'active'` (stale hosts included; revoked and imported not) whose inventory reported os-release (`os_id IS NOT NULL`). Membership is the access rule: a group with selectors whose every tag the host carries.

- [ ] **Step 1: Write the failing tests**

Create `crates/platform-store/tests/rule_assignment_fleet.rs`:

```rust
//! Rule-set assignment, the console's figures (plan 2026-10-15, part 3):
//! Linux host counts per set and per group, group selectors, the group that
//! decides a host's state, whether the set is published, and (Task 2) when
//! hardening facts were last usable.

mod common;

use common::TestDb;
use platform_store::{
    Client,
    console_read::AgentScope,
    rule_assignment::{self, Change, HostAssignment, Source},
};

const L1: &str = "hardening-linux-l1";
const L2: &str = "hardening-linux-l2";
const ALICE: &str = "00000000-0000-4000-8000-000000000001";
const A: &str = "agent.00000000-0000-4000-8000-000000000001";
const B: &str = "agent.00000000-0000-4000-8000-000000000002";
const C: &str = "agent.00000000-0000-4000-8000-000000000003";
const D: &str = "agent.00000000-0000-4000-8000-000000000004";
const E: &str = "import.lab-9";

async fn setup() -> (TestDb, Client) {
    let db = TestDb::create().await;
    let mut admin = db.pool.get().await.unwrap();
    platform_store::migrate(&mut admin).await.unwrap();
    admin
        .execute(
            "INSERT INTO console_users (user_id, username, display_name, created_at)
             VALUES ($1::text::uuid, 'alice', 'Alice', now())",
            &[&ALICE],
        )
        .await
        .unwrap();
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

/// An agent; `linux` sets `os_id` as an inventory from os-release does.
async fn agent(admin: &Client, id: &str, status: &str, linux: bool, tags: &[(&str, &str)]) {
    admin
        .execute(
            "INSERT INTO agents (agent_id, status, enrolled_at, os_id) VALUES ($1, $2, now(), $3)",
            &[&id, &status, &linux.then_some("fedora")],
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

async fn switch(console: &mut Client, set: &str, group: &str, on: bool) {
    let change = rule_assignment::set_group(console, ALICE, set, group, Some(on))
        .await
        .unwrap();
    assert!(matches!(change, Change::Done(_)), "{change:?}");
}

#[tokio::test]
async fn hosts_are_counted_per_set_and_per_group_on_linux_hosts_only() {
    let (db, admin) = setup().await;
    agent(&admin, A, "active", true, &[("env", "prod")]).await;
    agent(&admin, B, "active", true, &[("env", "lab")]).await;
    // Not counted: no os-release reported yet, revoked, imported.
    agent(&admin, C, "active", false, &[("env", "prod")]).await;
    agent(&admin, D, "revoked", true, &[("env", "prod")]).await;
    agent(&admin, E, "imported", true, &[("env", "prod")]).await;
    let prod = group(&admin, "prod", &[("env", "prod")]).await;
    let lab = group(&admin, "lab", &[("env", "lab")]).await;
    group(&admin, "empty", &[]).await;
    let mut console = as_role(&db, "openvibes-console").await;
    switch(&mut console, L1, &prod, false).await;
    switch(&mut console, L2, &lab, true).await;
    let overview = rule_assignment::overview(&console).await.unwrap();
    let sets: Vec<_> = overview
        .sets
        .iter()
        .map(|s| (s.rule_set_id.as_str(), s.hosts_on, s.hosts_off))
        .collect();
    assert_eq!(sets, [(L1, 1, 1), (L2, 1, 1)]);
    let groups: Vec<_> = overview
        .groups
        .iter()
        .map(|g| (g.name.as_str(), g.selectors.clone(), g.hosts))
        .collect();
    assert_eq!(
        groups,
        [
            ("empty", vec![], 0),
            ("lab", vec!["env=lab".to_owned()], 1),
            ("prod", vec!["env=prod".to_owned()], 1),
        ]
    );
    drop((console, admin));
    db.drop().await;
}

#[tokio::test]
async fn no_linux_host_counts_zero() {
    let (db, admin) = setup().await;
    let console = as_role(&db, "openvibes-console").await;
    let overview = rule_assignment::overview(&console).await.unwrap();
    assert!(overview.sets.iter().all(|s| (s.hosts_on, s.hosts_off) == (0, 0)));
    drop((console, admin));
    db.drop().await;
}

#[tokio::test]
async fn the_host_view_names_the_deciding_group_and_says_whether_the_set_is_published() {
    let (db, admin) = setup().await;
    agent(&admin, A, "active", true, &[("env", "web"), ("tier", "db")]).await;
    let zeta = group(&admin, "zeta", &[("env", "web")]).await;
    let alpha = group(&admin, "alpha", &[("tier", "db")]).await;
    let mid = group(&admin, "mid", &[("env", "web"), ("tier", "db")]).await;
    let mut console = as_role(&db, "openvibes-console").await;
    // L2: two groups say on, one says off. On wins; the first on group by name decides.
    switch(&mut console, L2, &zeta, true).await;
    switch(&mut console, L2, &alpha, true).await;
    switch(&mut console, L2, &mid, false).await;
    // L1: only an off group.
    switch(&mut console, L1, &mid, false).await;
    let host = rule_assignment::for_agent(&console, &AgentScope::Global, A)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        host,
        [
            HostAssignment {
                rule_set_id: L1.into(),
                enabled: false,
                source: Source::Group,
                group: Some("mid".into()),
                published: false,
            },
            HostAssignment {
                rule_set_id: L2.into(),
                enabled: true,
                source: Source::Group,
                group: Some("alpha".into()),
                published: false,
            },
        ]
    );
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
    let host = rule_assignment::for_agent(&console, &AgentScope::Global, A)
        .await
        .unwrap()
        .unwrap();
    assert_eq!((host[0].published, host[1].published), (true, false));
    // Distribution reads no group names: the shared resolution still works for it.
    let dist = as_role(&db, "openvibes-distribution").await;
    assert!(!rule_assignment::assigned(&dist, A, L1).await.unwrap());
    assert!(rule_assignment::assigned(&dist, A, L2).await.unwrap());
    drop((console, dist, admin));
    db.drop().await;
}
```

In `crates/platform-store/tests/rule_assignment.rs`, the literal in `a_host_in_no_group_gets_the_default` (lines 381–392) becomes:

```rust
            HostAssignment {
                rule_set_id: L1.into(),
                enabled: true,
                source: Source::Default,
                group: None,
                published: false,
            },
            HostAssignment {
                rule_set_id: L2.into(),
                enabled: false,
                source: Source::Default,
                group: None,
                published: false,
            },
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd /home/lime/Projects/OpenVIBES/openvibes-platform-console-assign && eval "$(scripts/test-db.sh)" && echo "$OPENVIBES_TEST_DATABASE_URL" && CARGO_TARGET_DIR=~/.cache/openvibes-scratch/target nice -n 19 cargo test --locked -p platform-store --test rule_assignment_fleet --test rule_assignment`
Expected: FAIL to compile: no field `hosts_on` on `Assignment`, no field `group` on `HostAssignment`.

- [ ] **Step 3: Implement**

In `crates/platform-store/src/rule_assignment.rs`:

Add to `Assignment` (after `published`):

```rust
    /// Linux hosts that run it now.
    pub hosts_on: i64,
    /// Linux hosts that do not.
    pub hosts_off: i64,
```

Add to `GroupName` (after `name`):

```rust
    /// Its selectors, `key=value`, sorted.
    pub selectors: Vec<String>,
    /// Linux hosts it matches.
    pub hosts: i64,
```

Add to `HostAssignment` (after `source`):

```rust
    /// The group that decided it (the first by name when several agree);
    /// `None` when the default did.
    pub group: Option<String>,
    /// A live bundle is published, so the agent can get it.
    pub published: bool,
```

Above `overview`, add:

```rust
/// Linux hosts and their group memberships, as a CTE prefix for the
/// console's counts. A Linux host is an active agent (stale included;
/// revoked and imported not) whose inventory reported os-release (`os_id`).
/// A host is a member of a group with selectors whose every tag it carries,
/// as for access.
// ponytail: agents × groups per overview call; precompute if a fleet of many thousand hosts makes the panel slow.
const FLEET: &str = "
    WITH linux AS (SELECT agent_id FROM agents WHERE status = 'active' AND os_id IS NOT NULL),
    member AS (
        SELECT l.agent_id, g.asset_group_id FROM linux l CROSS JOIN console_asset_groups g
        WHERE EXISTS (SELECT 1 FROM console_asset_group_selectors s
                      WHERE s.asset_group_id = g.asset_group_id)
          AND NOT EXISTS (
              SELECT 1 FROM console_asset_group_selectors r
              WHERE r.asset_group_id = g.asset_group_id
                AND NOT EXISTS (SELECT 1 FROM console_agent_tags t
                                WHERE t.agent_id = l.agent_id AND t.tag_key = r.tag_key
                                  AND t.tag_value = r.tag_value)))";
```

In `overview`, after the `groups` query, add the three queries:

```rust
    let counts = client
        .query(
            &format!(
                "{FLEET}
                 SELECT a.rule_set_id,
                        count(*) FILTER (WHERE COALESCE(o.on_any, a.default_enabled)),
                        count(*) FILTER (WHERE NOT COALESCE(o.on_any, a.default_enabled))
                 FROM rule_set_assignment a CROSS JOIN linux l
                 LEFT JOIN LATERAL (
                     SELECT bool_or(x.enabled) AS on_any FROM rule_set_group_assignment x
                     JOIN member m ON m.asset_group_id = x.asset_group_id AND m.agent_id = l.agent_id
                     WHERE x.rule_set_id = a.rule_set_id) o ON true
                 GROUP BY a.rule_set_id"
            ),
            &[],
        )
        .await?;
    let group_hosts = client
        .query(
            &format!("{FLEET} SELECT asset_group_id::text, count(*) FROM member GROUP BY 1"),
            &[],
        )
        .await?;
    let selectors = client
        .query(
            "SELECT asset_group_id::text, tag_key || '=' || tag_value
             FROM console_asset_group_selectors ORDER BY 2",
            &[],
        )
        .await?;
```

and build the structs with them (replace the `Ok(Overview { ... })` body):

```rust
    Ok(Overview {
        sets: sets
            .iter()
            .map(|row| {
                let rule_set_id: String = row.get(0);
                let (hosts_on, hosts_off) = counts
                    .iter()
                    .find(|c| c.get::<_, &str>(0) == rule_set_id)
                    .map_or((0, 0), |c| (c.get(1), c.get(2)));
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
                    hosts_on,
                    hosts_off,
                }
            })
            .collect(),
        groups: groups
            .iter()
            .map(|row| {
                let asset_group_id: String = row.get(0);
                GroupName {
                    selectors: selectors
                        .iter()
                        .filter(|s| s.get::<_, &str>(0) == asset_group_id)
                        .map(|s| s.get(1))
                        .collect(),
                    hosts: group_hosts
                        .iter()
                        .find(|h| h.get::<_, &str>(0) == asset_group_id)
                        .map_or(0, |h| h.get(1)),
                    asset_group_id,
                    name: row.get(1),
                }
            })
            .collect(),
    })
```

`HOST_STATE` gains two columns, the ids of the host's groups that say on and that say off (distribution may read `rule_set_group_assignment`, not group names, so names are looked up only in `for_agent`). Replace its `SELECT` lines:

```rust
const HOST_STATE: &str = "
    SELECT a.rule_set_id, COALESCE(bool_or(o.enabled), a.default_enabled),
           bool_or(o.enabled) IS NOT NULL,
           array_agg(o.asset_group_id::text) FILTER (WHERE o.enabled),
           array_agg(o.asset_group_id::text) FILTER (WHERE NOT o.enabled)
    FROM rule_set_assignment a
```

(the rest of the constant is unchanged), update its doc comment's first line to `/// Per assignable set for agent `$1`: (set, enabled, decided by a group, ids of the host's groups saying on, saying off).`, and in `assigned` change the alias list to `AS h (rule_set_id, enabled, from_group, on_groups, off_groups)`.

In `for_agent`, replace the second query and the mapping:

```rust
    let rows = client
        .query(
            &format!(
                "SELECT h.rule_set_id, h.enabled, h.from_group,
                        (SELECT min(g.name) FROM console_asset_groups g
                         WHERE g.asset_group_id::text = ANY(
                             CASE WHEN h.enabled THEN h.on_groups ELSE h.off_groups END)),
                        EXISTS (SELECT 1 FROM rule_bundles b JOIN rule_sets s USING (rule_set_id)
                                WHERE b.rule_set_id = h.rule_set_id AND s.retired_at IS NULL)
                 FROM ({HOST_STATE}) AS h (rule_set_id, enabled, from_group, on_groups, off_groups)
                 ORDER BY h.rule_set_id"
            ),
            &[&agent_id],
        )
        .await?;
    Ok(Some(
        rows.iter()
            .map(|row| HostAssignment {
                rule_set_id: row.get(0),
                enabled: row.get(1),
                source: if row.get(2) {
                    Source::Group
                } else {
                    Source::Default
                },
                group: row.get(3),
                published: row.get(4),
            })
            .collect(),
    ))
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `CARGO_TARGET_DIR=~/.cache/openvibes-scratch/target nice -n 19 cargo test --locked -p platform-store --test rule_assignment_fleet --test rule_assignment --test rule_assignment_grants --test end_unassigned`
Expected: PASS (all four files; `rule_assignment` and `end_unassigned` prove the shared resolution and distribution are unchanged).

- [ ] **Step 5: Commit**

```bash
git add crates/platform-store/src/rule_assignment.rs crates/platform-store/tests/rule_assignment.rs crates/platform-store/tests/rule_assignment_fleet.rs
git commit -m "rule-set assignment: host counts, selectors and the deciding group in the store

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2: When hardening facts were last usable (migration 0050, ingest, store)

**Files:**
- Create: `migrations/0050_hardening_facts_ok_at.sql`
- Modify: `crates/platform-store/src/migrate.rs` (`SCHEMA_VERSION = 50`, one `MIGRATIONS` entry)
- Modify: `crates/platform-store/src/ingest.rs:325-333` (the `heartbeat` UPDATE)
- Modify: `crates/platform-store/src/rule_assignment.rs` (new `hardening_facts`)
- Modify: `crates/platform-store/tests/rule_assignment_fleet.rs` (two tests)
- Modify: `docs/components/platform-store.md` (P12 paragraph and the rule-set assignment section)

**Interfaces:**
- Consumes: Task 1's test helpers in `rule_assignment_fleet.rs` (`setup`, `as_role`, `agent`, `A`).
- Produces (Task 3 relies on it): `pub async fn hardening_facts(client: &Client, agent_id: &str) -> Result<(Option<String>, Option<DateTime<Utc>>), StoreError>`: the hardening collector's outcome in the latest stored report, and when a stored report last had it `ok` (`agents.hardening_facts_ok_at`); `(None, None)` for an unknown agent.
- Ruling G1: the time is the platform's, set by ingest; it is never the helper's own write time.

- [ ] **Step 1: Write the failing tests**

Append to `crates/platform-store/tests/rule_assignment_fleet.rs`:

```rust
#[tokio::test]
async fn the_hardening_facts_outcome_comes_from_the_latest_report() {
    let (db, admin) = setup().await;
    agent(&admin, A, "active", true, &[]).await;
    let console = as_role(&db, "openvibes-console").await;
    assert_eq!(
        rule_assignment::hardening_facts(&console, A).await.unwrap(),
        (None, None),
        "no report yet"
    );
    admin
        .execute(
            "UPDATE agents SET health = $2 WHERE agent_id = $1",
            &[
                &A,
                &serde_json::json!({"last_scan": {"collectors": {"hardening": "not_found", "packages": "ok"}}}),
            ],
        )
        .await
        .unwrap();
    let (outcome, ok_at) = rule_assignment::hardening_facts(&console, A).await.unwrap();
    assert_eq!((outcome.as_deref(), ok_at), (Some("not_found"), None), "never ok: since enrollment");
    drop((console, admin));
    db.drop().await;
}

#[tokio::test]
async fn ingest_records_when_hardening_facts_were_last_usable() {
    let (db, admin) = setup().await;
    agent(&admin, A, "active", true, &[]).await;
    let ingest = as_role(&db, "openvibes-ingest").await;
    let t0 = chrono::Utc::now();
    // Ten minutes apart: past the five-minute heartbeat write throttle.
    for (outcome, at) in [("ok", t0), ("not_found", t0 + chrono::Duration::minutes(10))] {
        let health = serde_json::json!({"last_scan": {"collectors": {"hardening": outcome}}});
        platform_store::ingest::heartbeat(&ingest, A, "0.5.0", None, &[], Some(&health), at)
            .await
            .unwrap();
    }
    let console = as_role(&db, "openvibes-console").await;
    let (outcome, ok_at) = rule_assignment::hardening_facts(&console, A).await.unwrap();
    assert_eq!(outcome.as_deref(), Some("not_found"));
    assert_eq!(
        ok_at.map(|t| t.timestamp_millis()),
        Some(t0.timestamp_millis()),
        "the last stored report with usable facts"
    );
    drop((ingest, console, admin));
    db.drop().await;
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `CARGO_TARGET_DIR=~/.cache/openvibes-scratch/target nice -n 19 cargo test --locked -p platform-store --test rule_assignment_fleet`
Expected: FAIL to compile: no function `hardening_facts`.

- [ ] **Step 3: Implement**

Create `migrations/0050_hardening_facts_ok_at.sql`:

```sql
-- OpenVIBES platform schema version 50: when a host's stored health report
-- last had usable hardening facts (the root-facts helper, P19), so the
-- console can say for how long they have been missing (rule-set assignment
-- console plan, ruling G1). Set by ingest; the agent reports no such time.
-- The console reads and ingest updates `agents` through their table grants.
ALTER TABLE agents ADD COLUMN hardening_facts_ok_at timestamptz;
UPDATE agents SET hardening_facts_ok_at = health_at
 WHERE health -> 'last_scan' -> 'collectors' ->> 'hardening' = 'ok';
```

In `crates/platform-store/src/migrate.rs`: `pub const SCHEMA_VERSION: i32 = 50;` and append to `MIGRATIONS`:

```rust
    (
        50,
        include_str!("../../../migrations/0050_hardening_facts_ok_at.sql"),
    ),
```

In `ingest::heartbeat`'s UPDATE, after the `health_at = …` line, add:

```sql
                 hardening_facts_ok_at = CASE
                     WHEN $7::jsonb -> 'last_scan' -> 'collectors' ->> 'hardening' = 'ok' THEN $2
                     ELSE hardening_facts_ok_at END,
```

(keep the commas valid: `health_at = …` gains a trailing comma and the new assignment ends without one, before `WHERE`). Add one sentence to the function's doc comment: "A report whose hardening outcome is `ok` also sets `hardening_facts_ok_at`."

Append to `crates/platform-store/src/rule_assignment.rs`:

```rust
/// The hardening collector's outcome (the root-facts helper, P19) in
/// `agent_id`'s latest stored health report (`ok`; `not_found`: the
/// helper's file is stale or malformed; `invalid_data`: its facts failed
/// validation; `None`: no report, or no helper file at all, which the agent
/// does not report), and when a stored report last had it `ok` (`None`:
/// never since enrollment, or since schema 50). Callers check visibility
/// first (`for_agent`); an unknown agent gives `(None, None)`.
pub async fn hardening_facts(
    client: &Client,
    agent_id: &str,
) -> Result<(Option<String>, Option<DateTime<Utc>>), StoreError> {
    Ok(client
        .query_opt(
            "SELECT health -> 'last_scan' -> 'collectors' ->> 'hardening', hardening_facts_ok_at
             FROM agents WHERE agent_id = $1",
            &[&agent_id],
        )
        .await?
        .map_or((None, None), |row| (row.get(0), row.get(1))))
}
```

with `use chrono::{DateTime, Utc};` at the top.

Docs, `docs/components/platform-store.md`: at the end of the P12 paragraph (the one starting "Protocol P12. `agents` gains `health`…") add "Schema 50 adds `hardening_facts_ok_at`: the heartbeat write sets it to the report's time when `last_scan.collectors.hardening` is `ok` (backfilled from `health_at` for reports that were `ok` at migration)."; in "Rule-set assignment (`rule_assignment::…`, schema 49)" add "`hardening_facts(agent)` returns the hardening outcome of the latest report and `hardening_facts_ok_at`, for the host panel's facts warning."

- [ ] **Step 4: Run the tests to verify they pass**

Run: `CARGO_TARGET_DIR=~/.cache/openvibes-scratch/target nice -n 19 cargo test --locked -p platform-store --test rule_assignment_fleet --test ingest --test migrate`
Expected: PASS (`ingest` proves the heartbeat write is otherwise unchanged).

- [ ] **Step 5: Commit**

```bash
git add migrations/0050_hardening_facts_ok_at.sql crates/platform-store/src/migrate.rs crates/platform-store/src/ingest.rs crates/platform-store/src/rule_assignment.rs crates/platform-store/tests/rule_assignment_fleet.rs docs/components/platform-store.md
git commit -m "store: record when a host's hardening facts were last usable (schema 50)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 3: Console API: the new fields, `rules.upload` reads the rule list, OpenAPI snapshot, generated client, docs

**Files:**
- Modify: `crates/openvibes-console/src/rule_assignment.rs` (four views, `view`, `list_assignments`, `host_assignments`; `reader` becomes `rules_reader`)
- Modify: `crates/openvibes-console/src/router.rs` (`authenticated_rule_sets`, `authenticated_rule_bundles`: the permission check only)
- Modify: `crates/openvibes-console/src/coverage.rs` (`global_rules_read`)
- Modify: `crates/openvibes-console/tests/rule_assignment_http.rs` (setup agent row, three exact-JSON assertions, the rule-read loop)
- Regenerate: `docs/api/console-v1.openapi.json`, `crates/openvibes-console/web/src/api/generated.ts`
- Modify: `docs/components/rule-set-assignment.md` (Console API), `docs/components/console-rbac.md` (`rules.upload`)

**Interfaces:**
- Consumes: Task 1's `Assignment.hosts_on/hosts_off`, `GroupName.selectors/hosts`, `HostAssignment.group/published`; Task 2's `rule_assignment::hardening_facts` (outcome, ok time).
- Produces (JSON; the web types in Task 4 are generated from these):
  - `RuleSetAssignmentView { rule_set_id, default_enabled, published, hosts_on: i64, hosts_off: i64, groups: [{asset_group_id, name, enabled}] }`
  - `AssignableGroupView { asset_group_id, name, selectors: [string], hosts: i64 }`
  - `HostRuleSetAssignmentView { rule_set_id, enabled, source, group: string|null, published: bool }`
  - `HostRuleSetAssignmentsView { items, hardening_facts: string|null, hardening_facts_ok_at: string|null /* RFC 3339 */ }`
  - `pub(crate) async fn rules_reader(state: &AuthHttpState, headers: &HeaderMap) -> Result<String, Response>`: the caller's user id when they hold `rules.read` or `rules.upload` globally; 401/403/503 otherwise.
  - Permission change (ruling G2): `GET /api/v1/rule-sets`, `GET /api/v1/rule-sets/{id}/bundles`, `GET /api/v1/rules/coverage` and `GET /api/v1/attack` accept `rules.upload` as well as `rules.read`, globally.

- [ ] **Step 1: Write the failing test changes**

In `crates/openvibes-console/tests/rule_assignment_http.rs` `setup()`, the agent becomes a Linux host whose helper's facts are stale:

```rust
            "INSERT INTO agents (agent_id, status, enrolled_at, os_id, health)
                 VALUES ('{AGENT}', 'active', now(), 'fedora',
                         '{{\"last_scan\": {{\"collectors\": {{\"hardening\": \"not_found\"}}}}}}');
             UPDATE agents SET hardening_facts_ok_at = now() - interval '3 days' WHERE agent_id = '{AGENT}';
```

(replacing `INSERT INTO agents (agent_id, status, enrolled_at) VALUES ('{AGENT}', 'active', now());`; the doubled braces are `format!` escapes).

Add below the constants:

```rust
/// Rule reads that `rules.upload` grants as well as `rules.read` (user, 2026-10-15).
const RULE_READS: [&str; 4] = [
    "/api/v1/rule-sets",
    "/api/v1/rule-sets/baseline/bundles",
    "/api/v1/rules/coverage",
    "/api/v1/attack",
];
```

In `rule_readers_and_publishers_see_the_switches_and_only_publishers_change_them`, after the analyst's two `FORBIDDEN` checks add:

```rust
    for path in RULE_READS {
        let (status, ..) = call(&router, "GET", path, &cookie, &csrf, None, None).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "analyst {path}");
    }
```

after the operator's list assertion add (no bundle is published in this test, so the history answers 404, not 403):

```rust
    for path in RULE_READS {
        let (status, ..) = call(&router, "GET", path, &cookie, &csrf, None, None).await;
        assert!(
            matches!(status, StatusCode::OK | StatusCode::NOT_FOUND),
            "operator {path}: {status}"
        );
    }
```

and the operator's list becomes:

```rust
        serde_json::json!({
            "items": [
                {"rule_set_id": "hardening-linux-l1", "default_enabled": true, "published": false,
                 "hosts_on": 1, "hosts_off": 0, "groups": []},
                {"rule_set_id": "hardening-linux-l2", "default_enabled": false, "published": false,
                 "hosts_on": 0, "hosts_off": 1, "groups": []}
            ],
            "asset_groups": [{"asset_group_id": WEB, "name": "web", "selectors": ["env=web"], "hosts": 1}]
        })
```

In `group_overrides_and_the_host_view`, the first host view:

```rust
    assert_eq!(
        body["items"][0],
        serde_json::json!(
        {"rule_set_id": "hardening-linux-l1", "enabled": true, "source": "default",
         "group": null, "published": false})
    );
    assert_eq!(body["hardening_facts"], "not_found");
    assert!(body["hardening_facts_ok_at"].is_string(), "{body}");
```

and the host view after the group switch:

```rust
        serde_json::json!(
        {"rule_set_id": "hardening-linux-l1", "enabled": false, "source": "group",
         "group": "web", "published": false})
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `CARGO_TARGET_DIR=~/.cache/openvibes-scratch/target nice -n 19 cargo test --locked -p openvibes-console --test rule_assignment_http`
Expected: FAIL: the bodies lack `hosts_on`, `selectors`, `group`, `hardening_facts`; the operator's rule reads answer 403.

- [ ] **Step 3: Implement**

In `crates/openvibes-console/src/rule_assignment.rs`:

`RuleSetAssignmentView` gains, after `published`:

```rust
    /// Linux hosts that run it now (an active agent that reported
    /// os-release).
    pub hosts_on: i64,
    /// Linux hosts that do not.
    pub hosts_off: i64,
```

`AssignableGroupView` gains, after `name`:

```rust
    /// Its selectors, `key=value`.
    pub selectors: Vec<String>,
    /// Linux hosts it matches.
    pub hosts: i64,
```

`HostRuleSetAssignmentView` gains, after `source`:

```rust
    /// The group that decided it (the first by name when several agree);
    /// null when the default did.
    pub group: Option<String>,
    /// False until a live bundle is published ("waits until published").
    pub published: bool,
```

`HostRuleSetAssignmentsView` gains, after `items`:

```rust
    /// The hardening collector's outcome in the host's latest health report:
    /// `ok`, or an error code such as `not_found` (the root-facts helper's
    /// file is stale or malformed); null without one.
    pub hardening_facts: Option<String>,
    /// RFC 3339 time of the last stored report whose hardening outcome was
    /// `ok`; null when none was since enrollment.
    pub hardening_facts_ok_at: Option<String>,
```

In `view`, add `hosts_on: assignment.hosts_on, hosts_off: assignment.hosts_off,` after `published`. In `list_assignments`, the group mapping becomes:

```rust
                    .map(|g| AssignableGroupView {
                        asset_group_id: g.asset_group_id,
                        name: g.name,
                        selectors: g.selectors,
                        hosts: g.hosts,
                    })
```

Replace the `match store::for_agent(...)` in `host_assignments` with:

```rust
    let sets = match store::for_agent(&client, &scope, &agent_id).await {
        Ok(Some(sets)) => sets,
        Ok(None) => {
            return problem_response(ProblemDetails::not_found(
                "agent_not_found",
                "Agent not found",
            ));
        }
        Err(_) => return unavailable_auth(),
    };
    let Ok((hardening_facts, ok_at)) = store::hardening_facts(&client, &agent_id).await else {
        return unavailable_auth();
    };
    no_store(
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
                    group: set.group,
                    published: set.published,
                })
                .collect(),
            hardening_facts,
            hardening_facts_ok_at: ok_at
                .map(|at| at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)),
        })
        .into_response(),
    )
```

Replace `reader` with a crate-visible reader that returns the actor (the rule-set list audits `rule_sets.viewed` by it), and update the module comment's first sentence to say the rule list reads accept either permission too:

```rust
/// The caller's user id when they hold `rules.read` or `rules.upload`
/// globally: reading the switches, and (user, 2026-10-15) the rule-set list,
/// bundle history, coverage and the ATT&CK catalog, so operators see what
/// they publish and switch.
pub(crate) async fn rules_reader(
    state: &AuthHttpState,
    headers: &HeaderMap,
) -> Result<String, Response> {
    for permission in [Permission::RulesRead, Permission::RulesUpload] {
        match authenticated_permission(state, headers, permission, false).await {
            Ok((AgentScope::Global, actor)) => return Ok(actor),
            Ok(_) => {}
            Err(response) if response.status() == StatusCode::FORBIDDEN => {}
            Err(response) => return Err(response),
        }
    }
    Err(forbidden())
}
```

and in `list_assignments` call `rules_reader(&state, &headers)` where it called `reader`.

In `crates/openvibes-console/src/router.rs`, in both `authenticated_rule_sets` and `authenticated_rule_bundles`, replace the `let (scope, actor) = match authenticated_permission(&state, &headers, crate::Permission::RulesRead, false).await { … };` and the `if !matches!(scope, …Global) { return problem_response(…) }` block after it with:

```rust
    let actor = match crate::rule_assignment::rules_reader(&state, &headers).await {
        Ok(actor) => actor,
        Err(response) => return response,
    };
```

(the rest of each handler is unchanged; if `authenticated_rule_bundles` does not use `actor`, bind `_actor`). In `crates/openvibes-console/src/coverage.rs`, `global_rules_read` becomes:

```rust
async fn global_rules_read(
    state: &AuthHttpState,
    headers: &HeaderMap,
) -> Result<platform_store::Client, Response> {
    crate::rule_assignment::rules_reader(state, headers).await?;
    state.pool.get().await.map_err(|_| unavailable_auth())
}
```

(drop imports that become unused). The Rules capability flag the assistant reads (`router.rs` ~3123) and every write route keep `rules.read`/`rules.upload` exactly as they are.

- [ ] **Step 4: Run the test, then regenerate the snapshot and the client**

Run: `CARGO_TARGET_DIR=~/.cache/openvibes-scratch/target nice -n 19 cargo test --locked -p openvibes-console --test rule_assignment_http --test api_contract`
Expected: `rule_assignment_http` PASS; `api_contract` may FAIL on snapshot drift until the next command. Also run `CARGO_TARGET_DIR=~/.cache/openvibes-scratch/target nice -n 19 cargo test --locked -p openvibes-console --test auth_http` (it reads the rule list and history as an admin): PASS.

Run:
```bash
CARGO_TARGET_DIR=~/.cache/openvibes-scratch/target nice -n 19 cargo run --locked -p openvibes-console --bin export_openapi > docs/api/console-v1.openapi.json
npm --prefix crates/openvibes-console/web run generate:api
CARGO_TARGET_DIR=~/.cache/openvibes-scratch/target nice -n 19 cargo test --locked -p openvibes-console --test api_contract
npm --prefix crates/openvibes-console/web run typecheck
```
Expected: PASS; `git diff --stat` shows the snapshot and `src/api/generated.ts` changed only in the four schemas.

- [ ] **Step 5: Update the component doc**

In `docs/components/rule-set-assignment.md`, section "Console API", replace the "Shapes:" sentence with:

```markdown
Shapes: `RuleSetAssignmentsView { items: [RuleSetAssignmentView],
asset_groups: [{asset_group_id, name, selectors: ["key=value"], hosts}] }`;
`RuleSetAssignmentView { rule_set_id, default_enabled, published, hosts_on,
hosts_off, groups: [{asset_group_id, name, enabled}] }`;
`HostRuleSetAssignmentsView { items: [{rule_set_id, enabled, source:
"default"|"group", group, published}], hardening_facts,
hardening_facts_ok_at }`. Host counts are
**Linux hosts**: active agents (stale included; revoked and imported not)
whose inventory reported os-release (`os_id`); `hosts` is how many a group
matches, `hosts_on`/`hosts_off` how many run the set or not. `group` names
the group that decided the host's state (the first by name when several
agree; `null` for the default). `hardening_facts` is the hardening
collector's outcome in the host's latest health report (`ok`, `not_found`
when the root-facts helper's file is stale or malformed, `invalid_data`),
`null` without one; the agent reports nothing when the helper's file is
missing. `hardening_facts_ok_at` is when a stored report last had it `ok`
(schema 50, set by ingest), `null` when none did since enrollment. `group`
is returned to every caller who may see the host, also when the group is
outside their scope (user, 2026-10-15).
```

In the same section, replace the sentence "Reading needs `rules.read` (admin) or `rules.upload` (operator, admin), changing `rules.upload`, all global; an analyst or viewer holds neither and gets 403." with "Reading needs `rules.read` (admin) or `rules.upload` (operator, admin), changing `rules.upload`, all global; an analyst or viewer holds neither and gets 403. The same either-permission check (`rules_reader`) guards `GET /api/v1/rule-sets`, its bundle history, `GET /api/v1/rules/coverage` and `GET /api/v1/attack` (user, 2026-10-15)."

In `docs/components/console-rbac.md`, replace "`rules.read` stays Admin-only, so listing drafts needs `rules.write` too." with "`rules.read` stays Admin-only, so listing drafts needs `rules.write` too; but `rules.upload` also reads the rule-set list, bundle history, coverage and the ATT&CK catalog (user, 2026-10-15), so operators see what they publish and switch."

and in "Store", after the `overview` sentence, add: "`overview` also counts Linux hosts per set and per group (`FLEET`, one CTE), and lists each group's selectors. `for_agent` adds the deciding group's name and `published`; `HOST_STATE` returns the host's on and off group ids so distribution never reads group names. `hardening_facts(agent)` reads the outcome from `agents.health` and `agents.hardening_facts_ok_at` (schema 50)."

- [ ] **Step 6: Commit**

```bash
git add crates/openvibes-console/src/rule_assignment.rs crates/openvibes-console/src/router.rs crates/openvibes-console/src/coverage.rs crates/openvibes-console/tests/rule_assignment_http.rs docs/api/console-v1.openapi.json crates/openvibes-console/web/src/api/generated.ts docs/components/rule-set-assignment.md docs/components/console-rbac.md
git commit -m "console API: assignment figures and hardening facts; rules.upload reads the rule list, history and coverage

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 4: Web: types, pure helpers, a bare Switch

**Files:**
- Modify: `crates/openvibes-console/web/src/api/types.ts` (four aliases)
- Create: `crates/openvibes-console/web/src/panels/ruleAssignment.ts`
- Create: `crates/openvibes-console/web/src/panels/ruleAssignment.test.ts`
- Modify: `crates/openvibes-console/web/src/ui/Switch.tsx` (`bare` prop)
- Modify: `crates/openvibes-console/web/src/ui/controls.test.tsx` (one case)

**Interfaces:**
- Consumes: the generated schemas from Task 3.
- Produces:
  - types `RuleSetAssignments`, `RuleSetAssignment`, `AssignableGroup`, `HostRuleSetAssignments`
  - `type RuleSetRow = { rule_set_id: string; set: RuleSet | undefined; assignment: RuleSetAssignment | undefined }`
  - `ruleSetRows(sets: readonly RuleSet[], assignments: readonly RuleSetAssignment[]): RuleSetRow[]`
  - `runsOn(id: string, assignment: RuleSetAssignment | undefined): { text: string; more: string | null }`
  - `sourceDetail(id: string, checks: number | null): string`
  - `shortName(id: string): string`
  - `type HardeningPart = { name: string; on: boolean; group: string | null; note: "waits until published" | "pending" | null }`
  - `hardeningParts(host: HostRuleSetAssignments, agent: Pick<Agent, "rule_sets" | "rule_sets_at">): HardeningPart[]`
  - `factsUnavailable(outcome: string | null | undefined): boolean`
  - `factsNote(outcome: string, okAt: string | null | undefined, now?: number): string` (ruling G1/G4 texts)
  - `readsRules(can: (permission: Permission, global?: boolean) => boolean): boolean`: `rules.read` or `rules.upload`, globally (ruling G2)
  - `addGroupBlocked(groups: number, free: number): string | null`
  - `Switch` gains `bare?: boolean`: no visible label; `label` becomes the `aria-label`.

- [ ] **Step 1: Write the failing tests**

Create `src/panels/ruleAssignment.test.ts`:

```ts
import { describe, expect, it } from "vitest";

import type { HostRuleSetAssignments, RuleSet, RuleSetAssignment } from "../api/types";
import { addGroupBlocked, factsNote, factsUnavailable, hardeningParts, readsRules, ruleSetRows, runsOn, shortName, sourceDetail } from "./ruleAssignment";

const L1 = "hardening-linux-l1";
const L2 = "hardening-linux-l2";
const l1: RuleSetAssignment = { rule_set_id: L1, default_enabled: true, published: true, hosts_on: 162, hosts_off: 24, groups: [{ asset_group_id: "g-prod", name: "Production", enabled: false }] };
const l2: RuleSetAssignment = { rule_set_id: L2, default_enabled: false, published: false, hosts_on: 0, hosts_off: 186, groups: [] };
const baseline: RuleSet = { rule_set_id: "baseline", retired: false, trusted_keys: 1, current_signer_removed: false, current_version: 14, current_issuer_key_id: "ops-2026", current_expires_at_ms: 0 };

describe("the Rule sets list", () => {
  it("lists published sets and assignable ones, an unpublished set too", () => {
    expect(ruleSetRows([baseline], [l1, l2]).map((r) => [r.rule_set_id, Boolean(r.set), Boolean(r.assignment)])).toEqual([
      ["baseline", true, false], [L1, false, true], [L2, false, true],
    ]);
  });
  it("says where each set runs: the default, then how many groups differ", () => {
    expect(runsOn("baseline", undefined)).toEqual({ text: "All hosts", more: null });
    expect(runsOn("baseline-alarms", undefined)).toEqual({ text: "Linux", more: null });
    expect(runsOn("site", undefined)).toEqual({ text: "Hosts that trust its key", more: null });
    expect(runsOn(L1, l1)).toEqual({ text: "Linux", more: "· 1 group off" });
    expect(runsOn(L2, l2)).toEqual({ text: "Off", more: null });
    const three = [{ asset_group_id: "a", name: "Lab", enabled: true }, { asset_group_id: "b", name: "Web", enabled: true }, { asset_group_id: "c", name: "Db", enabled: false }];
    expect(runsOn(L2, { ...l2, groups: three })).toEqual({ text: "Off", more: "· 2 groups on" });
  });
  it("names the source with its checks and level", () => {
    expect(sourceDetail(L1, 43)).toBe("(43 checks, Level 1)");
    expect(sourceDetail(L2, null)).toBe("(Level 2: stricter, may affect services)");
    expect(sourceDetail(L1, 0)).toBe("(Level 1)");
    expect(sourceDetail("site", null)).toBe("");
  });
  it("explains why a group cannot be added", () => {
    expect(addGroupBlocked(0, 0)).toBe("No asset groups yet: create one under Settings › Access.");
    expect(addGroupBlocked(2, 0)).toBe("Every asset group is listed.");
    expect(addGroupBlocked(2, 1)).toBeNull();
  });
});

describe("the host's Hardening line", () => {
  const set = (rule_set_id: string, enabled: boolean, extra: Partial<HostRuleSetAssignments["items"][number]> = {}) =>
    ({ rule_set_id, enabled, source: "default", group: null, published: true, ...extra });
  const parts = (items: HostRuleSetAssignments["items"], rule_sets: { id: string; version?: number | null; state?: string | null }[], at: string | null = "2026-10-15T10:00:00Z") =>
    hardeningParts({ items, hardening_facts: null }, { rule_sets, rule_sets_at: at });

  it("names the group that switched a set off", () => {
    expect(parts([set(L1, false, { source: "group", group: "Production" }), set(L2, false, { published: false })], [{ id: L1, state: "not_assigned" }])).toEqual([
      { name: "L1", on: false, group: "Production", note: null },
      { name: "L2", on: false, group: null, note: null },
    ]);
  });
  it("an on set that is not published waits; a host in two on groups shows the one the platform names", () => {
    expect(parts([set(L2, true, { source: "group", group: "alpha", published: false })], [])[0]).toEqual({ name: "L2", on: true, group: "alpha", note: "waits until published" });
  });
  it("is pending until the agent's report agrees", () => {
    expect(parts([set(L1, false, { source: "group", group: "Lab" })], [{ id: L1, version: 4 }])[0]?.note).toBe("pending");
    expect(parts([set(L1, true)], [{ id: L1, state: "not_assigned" }])[0]?.note).toBe("pending");
    expect(parts([set(L1, true)], [])[0]?.note).toBe("pending");
    expect(parts([set(L1, true)], [{ id: L1, version: 4 }])[0]?.note).toBeNull();
    expect(parts([set(L1, false)], [])[0]?.note).toBeNull();
    expect(parts([set(L1, true)], [], null)[0]?.note).toBeNull();
  });
  it("short names and facts", () => {
    expect(shortName(L1)).toBe("L1");
    expect(shortName("site")).toBe("site");
    expect([null, undefined, "ok", "not_found", "invalid_data"].map(factsUnavailable)).toEqual([false, false, false, true, true]);
  });
  it("says for how long the root-facts helper has not reported, since enrollment, or that its facts were invalid", () => {
    const now = Date.parse("2026-10-15T12:00:00Z");
    const tail = " (openvibes-agent-facts.timer), so checks that read root-only files show as unavailable, not failed.";
    expect(factsNote("not_found", "2026-10-12T11:00:00Z", now)).toBe(`The agent's root-facts helper has not reported for 3 days${tail}`);
    expect(factsNote("not_found", "2026-10-15T09:00:00Z", now)).toBe(`The agent's root-facts helper has not reported for 1 day${tail}`);
    expect(factsNote("not_found", null, now)).toBe(`The agent's root-facts helper has not reported since enrollment${tail}`);
    expect(factsNote("invalid_data", "2026-10-12T11:00:00Z", now)).toBe(`The agent's root-facts helper sent invalid hardening facts${tail}`);
  });
});

describe("who reads the rule sets", () => {
  it("rules.read or rules.upload, globally", () => {
    const holding = (...held: string[]) => (p: string, global?: boolean) => global === true && held.includes(p);
    expect([readsRules(holding("rules.read")), readsRules(holding("rules.upload")), readsRules(holding("agents.read"))]).toEqual([true, true, false]);
  });
});
```

Add to the `describe("Switch", …)` block in `src/ui/controls.test.tsx`:

```tsx
  it("bare: no visible label, the label is the accessible name", () => {
    const html = renderToStaticMarkup(<Switch bare label="Runs for Lab" checked={false} onChange={noop} />);
    expect(html).toContain('aria-label="Runs for Lab"');
    expect(html).not.toContain("switch__label");
  });
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `npm --prefix crates/openvibes-console/web test -- src/panels/ruleAssignment.test.ts src/ui/controls.test.tsx`
Expected: FAIL: cannot resolve `./ruleAssignment`; the bare Switch still renders `switch__label`.

- [ ] **Step 3: Implement**

Append to `src/api/types.ts` (beside `RuleSet`):

```ts
export type RuleSetAssignments = S["RuleSetAssignmentsView"];
export type RuleSetAssignment = S["RuleSetAssignmentView"];
export type AssignableGroup = S["AssignableGroupView"];
export type HostRuleSetAssignments = S["HostRuleSetAssignmentsView"];
```

Create `src/panels/ruleAssignment.ts`:

```ts
// Rule-set assignment in the console (spec 2026-10-14 §6; approved screens in
// docs/specs/rule-set-assignment-ui/approved.md): the parts without React.
import type { Agent, HostRuleSetAssignments, Permission, RuleSet, RuleSetAssignment } from "../api/types";

/** Where the project's sets that are not assignable run. */
const FIXED: Record<string, string> = { baseline: "All hosts", "baseline-alarms": "Linux" };
/** The panel's Source detail per assignable set. */
const LEVEL: Record<string, string> = { "hardening-linux-l1": "Level 1", "hardening-linux-l2": "Level 2: stricter, may affect services" };

export type RuleSetRow = { rule_set_id: string; set: RuleSet | undefined; assignment: RuleSetAssignment | undefined };

/** Published sets and assignable ones: an assignable set is listed before it is published. */
export function ruleSetRows(sets: readonly RuleSet[], assignments: readonly RuleSetAssignment[]): RuleSetRow[] {
  const ids = [...new Set([...sets.map((s) => s.rule_set_id), ...assignments.map((a) => a.rule_set_id)])].sort();
  return ids.map((id) => ({ rule_set_id: id, set: sets.find((s) => s.rule_set_id === id), assignment: assignments.find((a) => a.rule_set_id === id) }));
}

/** The list's Runs on cell: the default (Linux, or Off), then how many groups differ from it. */
export function runsOn(id: string, assignment: RuleSetAssignment | undefined): { text: string; more: string | null } {
  if (!assignment) return { text: FIXED[id] ?? "Hosts that trust its key", more: null };
  const on = assignment.default_enabled;
  const differ = assignment.groups.filter((g) => g.enabled !== on).length;
  return { text: on ? "Linux" : "Off", more: differ ? `· ${differ} ${differ === 1 ? "group" : "groups"} ${on ? "off" : "on"}` : null };
}

/** The panel's Source detail, "(43 checks, Level 1)"; no count when unknown or zero. */
export function sourceDetail(id: string, checks: number | null): string {
  const parts = [checks ? `${checks} checks` : null, LEVEL[id] ?? null].filter(Boolean);
  return parts.length ? `(${parts.join(", ")})` : "";
}

/** hardening-linux-l1 → L1. */
export function shortName(id: string): string {
  const level = /-l(\d+)$/.exec(id)?.[1];
  return level ? `L${level}` : id;
}

export type HardeningPart = { name: string; on: boolean; group: string | null; note: "waits until published" | "pending" | null };

/** The host's Hardening line, one part per assignable set: the platform's
 * decision, the group that decided it, and whether the agent has caught up. */
export function hardeningParts(host: HostRuleSetAssignments, agent: Pick<Agent, "rule_sets" | "rule_sets_at">): HardeningPart[] {
  return host.items.map((set) => {
    const reported = agent.rule_sets.find((r) => r.id === set.rule_set_id);
    const running = reported !== undefined && reported.state !== "not_assigned";
    // ponytail: "pending" = the agent's latest report disagrees; no switch time is stored, so an agent too old to know the project sets stays "pending" for an on set until it is updated. Store the change time if that confuses.
    const note = set.enabled && !set.published ? "waits until published"
      : agent.rule_sets_at != null && set.enabled !== running ? "pending" : null;
    return { name: shortName(set.rule_set_id), on: set.enabled, group: set.group ?? null, note };
  });
}

/** The latest report says the root-facts helper's hardening facts could not be used. */
export const factsUnavailable = (outcome: string | null | undefined): boolean => outcome != null && outcome !== "ok";

const FACTS_TAIL = " (openvibes-agent-facts.timer), so checks that read root-only files show as unavailable, not failed.";

/** Why hardening checks show as unavailable (approved screen 8; rulings G1, G4): for
 * how many days (at least 1) since a stored report last had usable facts, "since
 * enrollment" when none did, or that the facts sent were invalid. */
export function factsNote(outcome: string, okAt: string | null | undefined, now = Date.now()): string {
  if (outcome === "invalid_data") return `The agent's root-facts helper sent invalid hardening facts${FACTS_TAIL}`;
  if (!okAt) return `The agent's root-facts helper has not reported since enrollment${FACTS_TAIL}`;
  const days = Math.max(1, Math.floor((now - Date.parse(okAt)) / 86_400_000));
  return `The agent's root-facts helper has not reported for ${days} ${days === 1 ? "day" : "days"}${FACTS_TAIL}`;
}

/** Who reads the rule sets, their switches, history and coverage: `rules.read` or `rules.upload`, globally. */
export const readsRules = (can: (permission: Permission, global?: boolean) => boolean): boolean =>
  can("rules.read", true) || can("rules.upload", true);

/** Why "+ Add group" is disabled, or null when a group can be added. */
export function addGroupBlocked(groups: number, free: number): string | null {
  if (groups === 0) return "No asset groups yet: create one under Settings › Access.";
  return free === 0 ? "Every asset group is listed." : null;
}
```

Replace `src/ui/Switch.tsx`:

```tsx
// On/off row: label left, switch right; the whole row is the button (Space/Enter toggle natively).
// `bare`: the track only (a table cell), with the label as its accessible name.
export function Switch(props: { label: string; checked: boolean; onChange: (checked: boolean) => void; disabled?: boolean; bare?: boolean }) {
  const { label, checked, onChange, disabled, bare } = props;
  return (
    <button type="button" role="switch" aria-checked={checked} aria-label={bare ? label : undefined} disabled={disabled} className="switch"
      style={bare ? { width: "auto" } : undefined} onClick={() => onChange(!checked)}>
      {!bare && <span className="switch__label">{label}</span>}
      <span className="switch__track" aria-hidden="true"><span className="switch__knob" /></span>
    </button>
  );
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `npm --prefix crates/openvibes-console/web test -- src/panels/ruleAssignment.test.ts src/ui/controls.test.tsx && npm --prefix crates/openvibes-console/web run typecheck && npm --prefix crates/openvibes-console/web run lint`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/openvibes-console/web/src/api/types.ts crates/openvibes-console/web/src/panels/ruleAssignment.ts crates/openvibes-console/web/src/panels/ruleAssignment.test.ts crates/openvibes-console/web/src/ui/Switch.tsx crates/openvibes-console/web/src/ui/controls.test.tsx
git commit -m "console-web: rule-set assignment helpers and a bare Switch

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 5: Demo data layer

**Files:**
- Modify: `crates/openvibes-console/web/src/demo/data.ts` (agents: `os_id`/`os_version`, L1 in their health; L1 in `ruleSets`)
- Create: `crates/openvibes-console/web/src/demo/assignments.ts`
- Create: `crates/openvibes-console/web/src/demo/assignments.test.ts`
- Modify: `crates/openvibes-console/web/src/demo/server.ts` (store creation and five routes, after `const send = …`, near the cases routes; the read check of three existing routes)

**Interfaces:**
- Consumes: Task 4's types.
- Produces: the demo answers the five routes with the real JSON shapes. Seed: L1 default on and off for Production (`grp-prod`), published v4 by `openvibes-1`; L2 default off, no overrides, not published. Prod hosts (`n % 3 === 0`) report L1 `not_assigned`; `agent-00040` (lab) does not list L1 yet ("pending"); every 17th host's hardening facts are `not_found` (last usable 3 days ago; `agent-00034` never since enrollment). The demo's rule-set list, bundle history and coverage answer `rules.upload` too (ruling G2). State persists in `localStorage` (`browserPersistence`) so a reload keeps the switches, like cases and dashboards.

- [ ] **Step 1: Write the failing test**

Create `src/demo/assignments.test.ts`:

```ts
import { describe, expect, it } from "vitest";

import type { HostRuleSetAssignments, RuleSetAssignments } from "../api/types";
import { createDemoServer } from "./server";

const get = async <T,>(server: ReturnType<typeof createDemoServer>, path: string) => (await (await server.handle("GET", path)).json()) as T;

describe("demo rule-set assignment", () => {
  it("starts with L1 on but off for Production, and L2 off and not published", async () => {
    const view = await get<RuleSetAssignments>(createDemoServer({ persona: "admin" }), "/api/v1/rule-set-assignments");
    const [l1, l2] = view.items;
    expect(l1).toMatchObject({ rule_set_id: "hardening-linux-l1", default_enabled: true, published: true, groups: [{ asset_group_id: "grp-prod", name: "Production", enabled: false }] });
    expect(l2).toMatchObject({ rule_set_id: "hardening-linux-l2", default_enabled: false, published: false, groups: [] });
    const prod = view.asset_groups.find((g) => g.name === "Production");
    expect(prod?.selectors).toEqual(["env=prod"]);
    expect(l1?.hosts_off).toBe(prod?.hosts);
    expect((l1?.hosts_on ?? 0) + (l1?.hosts_off ?? 0)).toBe(l2?.hosts_off);
  });

  it("a group switched on shows in the host view with its group; facts and pending come from the hosts", async () => {
    const server = createDemoServer({ persona: "admin" });
    expect((await server.handle("PUT", "/api/v1/rule-set-assignments/hardening-linux-l2/groups/grp-lab", { enabled: true })).status).toBe(200);
    const lab = await get<HostRuleSetAssignments>(server, "/api/v1/agents/agent-00004/rule-set-assignments");
    expect(lab.items).toEqual([
      { rule_set_id: "hardening-linux-l1", enabled: true, source: "default", group: null, published: true },
      { rule_set_id: "hardening-linux-l2", enabled: true, source: "group", group: "Lab", published: false },
    ]);
    expect(lab.hardening_facts).toBe("ok");
    const prod = await get<HostRuleSetAssignments>(server, "/api/v1/agents/agent-00003/rule-set-assignments");
    expect(prod.items[0]).toEqual({ rule_set_id: "hardening-linux-l1", enabled: false, source: "group", group: "Production", published: true });
    const stale = await get<HostRuleSetAssignments>(server, "/api/v1/agents/agent-00017/rule-set-assignments");
    expect(stale.hardening_facts).toBe("not_found");
    expect(Date.now() - Date.parse(stale.hardening_facts_ok_at ?? "")).toBeGreaterThan(3 * 86_400_000 - 60_000);
    const never = await get<HostRuleSetAssignments>(server, "/api/v1/agents/agent-00034/rule-set-assignments");
    expect([never.hardening_facts, never.hardening_facts_ok_at]).toEqual(["not_found", null]);
    expect((await server.handle("DELETE", "/api/v1/rule-set-assignments/hardening-linux-l2/groups/grp-lab")).status).toBe(200);
    expect((await get<RuleSetAssignments>(server, "/api/v1/rule-set-assignments")).items[1]?.groups).toEqual([]);
  });

  it("an unknown group answers 404, a set that is not assignable 404, a bad body 400", async () => {
    const server = createDemoServer({ persona: "admin" });
    const unknown = await server.handle("PUT", "/api/v1/rule-set-assignments/hardening-linux-l1/groups/grp-gone", { enabled: true });
    expect([unknown.status, ((await unknown.json()) as { code: string }).code]).toEqual([404, "asset_group_not_found"]);
    expect((await server.handle("PUT", "/api/v1/rule-set-assignments/baseline", { default_enabled: false })).status).toBe(404);
    expect((await server.handle("PUT", "/api/v1/rule-set-assignments/hardening-linux-l1", { default_enabled: "no" })).status).toBe(400);
  });

  it("an analyst cannot read the switches or the rule list, an operator reads both and changes switches, a viewer cannot change them", async () => {
    expect((await createDemoServer({ persona: "analyst" }).handle("GET", "/api/v1/rule-set-assignments")).status).toBe(403);
    const operator = createDemoServer({ persona: "operator" });
    expect((await operator.handle("GET", "/api/v1/rule-set-assignments")).status).toBe(200);
    expect((await operator.handle("PUT", "/api/v1/rule-set-assignments/hardening-linux-l1", { default_enabled: false })).status).toBe(200);
    for (const path of ["/api/v1/rule-sets", "/api/v1/rule-sets/hardening-linux-l1/bundles", "/api/v1/rules/coverage"]) {
      expect((await operator.handle("GET", path)).status, path).toBe(200);
      expect((await createDemoServer({ persona: "analyst" }).handle("GET", path)).status, path).toBe(403);
    }
    expect((await createDemoServer({ persona: "viewer" }).handle("PUT", "/api/v1/rule-set-assignments/hardening-linux-l1", { default_enabled: false })).status).toBe(403);
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npm --prefix crates/openvibes-console/web test -- src/demo/assignments.test.ts`
Expected: FAIL: the routes answer 404 (`not_found`).

- [ ] **Step 3: Implement**

In `src/demo/data.ts`, below `const ROLES = …`:

```ts
/** os-release IDs for demo hosts, so Linux host counts and the Hardening line show. */
const OS = [["fedora", "44"], ["debian", "13"], ["ubuntu", "24.04"], ["rhel", "10.1"]] as const;
```

In the agent loop's object literal, add after `capabilities` (no `random()` call, so the rest of the fleet is unchanged):

```ts
      ...(status === "imported" ? {} : { os_id: (OS[n % OS.length] as readonly [string, string])[0], os_version: (OS[n % OS.length] as readonly [string, string])[1] }),
```

and extend `rule_sets` with hardening L1 (after the `baseline-alarms` entry):

```ts
        // Hardening L1 (rule-set assignment): Production has it off, so its hosts report
        // not_assigned; agent-00040 has not caught up with the default yet ("pending").
        ...(n % 3 === 0 ? [{ id: "hardening-linux-l1", version: null, expires_at_ms: null, state: "not_assigned" }]
          : n === 40 ? [] : [{ id: "hardening-linux-l1", version: 4, expires_at_ms: now + 330 * DAY }]),
```

Right after `const ruleSets: RuleSet[] = …;` (before `bundles`):

```ts
  // The project's hardening L1, from the rules package; L2 is not published yet.
  ruleSets.push({ rule_set_id: "hardening-linux-l1", retired: false, trusted_keys: 1, current_signer_removed: false, current_version: 4, current_issuer_key_id: "openvibes-1", current_expires_at_ms: now + 330 * DAY });
```

Create `src/demo/assignments.ts`:

```ts
// The demo's rule-set assignment: the real API's routes, JSON and status codes
// (crates/openvibes-console/src/rule_assignment.rs,
// docs/components/rule-set-assignment.md), in memory and, in a browser, in
// localStorage. Hosts, tags and asset groups come from the rest of the demo,
// so the Access view's groups are the same ones.
import type { Agent, HostRuleSetAssignments, RuleSetAssignment, RuleSetAssignments } from "../api/types";
import type { DemoData } from "./data";

type Result = { status: number; body?: unknown };
type Saved = { defaults: Record<string, boolean>; overrides: Record<string, Record<string, boolean>> };
type Persistence = { load: () => unknown; save: (state: unknown) => void } | undefined;

const SEED: Saved = {
  defaults: { "hardening-linux-l1": true, "hardening-linux-l2": false },
  overrides: { "hardening-linux-l1": { "grp-prod": false }, "hardening-linux-l2": {} },
};
const problem = (status: number, code: string, title: string): Result => ({ status, body: { status, code, title } });
const byName = (a: { name: string }, b: { name: string }) => a.name.localeCompare(b.name);

export function createAssignmentStore(data: DemoData, audit: (setId: string) => void, persistence: Persistence) {
  const loaded = persistence?.load() as Saved | null | undefined;
  const state: Saved = loaded?.defaults && loaded.overrides ? loaded : structuredClone(SEED);
  const save = () => persistence?.save(state);
  const ids = () => Object.keys(state.defaults).sort();
  // A deleted group's overrides are gone, as the database's cascade does.
  const groups = () => data.access.asset_groups;
  const linux = () => data.agents.filter((a) => a.status !== "revoked" && a.status !== "imported" && a.os_id);
  const member = (agent: Agent, selectors: readonly string[]) =>
    selectors.length > 0 && selectors.every((s) => (data.tags.get(agent.id) ?? []).some((t) => `${t.key}=${t.value}` === s));
  const published = (id: string) => data.ruleSets.some((s) => s.rule_set_id === id && !s.retired);
  const overridden = (id: string) => groups().filter((g) => g.asset_group_id in (state.overrides[id] ?? {})).sort(byName);
  const decide = (id: string, agent: Agent) => {
    const mine = overridden(id).filter((g) => member(agent, g.selectors));
    const on = mine.filter((g) => state.overrides[id]?.[g.asset_group_id]);
    const deciding = on.length ? on : mine;
    return { enabled: mine.length ? on.length > 0 : state.defaults[id] ?? false, group: deciding[0]?.name ?? null };
  };
  const view = (id: string): RuleSetAssignment => {
    const hosts = linux();
    const on = hosts.filter((a) => decide(id, a).enabled).length;
    return {
      rule_set_id: id, default_enabled: state.defaults[id] ?? false, published: published(id), hosts_on: on, hosts_off: hosts.length - on,
      groups: overridden(id).map((g) => ({ asset_group_id: g.asset_group_id, name: g.name, enabled: state.overrides[id]?.[g.asset_group_id] ?? false })),
    };
  };
  const setGroup = (id: string, groupId: string, enabled: boolean | null): Result => {
    if (!(id in state.defaults)) return problem(404, "rule_set_not_assignable", "Rule set is not assignable");
    if (!groups().some((g) => g.asset_group_id === groupId)) return problem(404, "asset_group_not_found", "Asset group not found");
    const overrides = (state.overrides[id] ??= {});
    if ((overrides[groupId] ?? null) !== enabled) {
      if (enabled === null) delete overrides[groupId]; else overrides[groupId] = enabled;
      audit(id);
      save();
    }
    return { status: 200, body: view(id) };
  };
  return {
    list: (): RuleSetAssignments => ({
      items: ids().map(view),
      asset_groups: [...groups()].sort(byName).map((g) => ({ asset_group_id: g.asset_group_id, name: g.name, selectors: g.selectors, hosts: linux().filter((a) => member(a, g.selectors)).length })),
    }),
    setDefault(id: string, body: Record<string, unknown>): Result {
      if (!(id in state.defaults)) return problem(404, "rule_set_not_assignable", "Rule set is not assignable");
      if (typeof body.default_enabled !== "boolean") return problem(400, "invalid_request", "The request body is not valid");
      if (state.defaults[id] !== body.default_enabled) { state.defaults[id] = body.default_enabled; audit(id); save(); }
      return { status: 200, body: view(id) };
    },
    setGroup(id: string, groupId: string, body: Record<string, unknown>): Result {
      return typeof body.enabled === "boolean" ? setGroup(id, groupId, body.enabled) : problem(400, "invalid_request", "The request body is not valid");
    },
    clearGroup: (id: string, groupId: string): Result => setGroup(id, groupId, null),
    host(agent: Agent): HostRuleSetAssignments {
      const n = Number(agent.id.slice(-5));
      const facts = !agent.os_id || agent.status === "imported" ? null : n % 17 === 0 || n === 34 ? "not_found" : "ok";
      return {
        items: ids().map((id) => {
          const decided = decide(id, agent);
          const fromGroup = overridden(id).some((g) => member(agent, g.selectors));
          return { rule_set_id: id, enabled: decided.enabled, source: fromGroup ? "group" : "default", group: fromGroup ? decided.group : null, published: published(id) };
        }),
        hardening_facts: facts,
        // Missing facts: last usable 3 days ago, or never since enrollment (agent-00034).
        hardening_facts_ok_at: facts === "ok" ? agent.rule_sets_at ?? null : n === 34 ? null : new Date(Date.now() - 3 * 86_400_000 - 3_600_000).toISOString(),
      };
    },
  };
}
```

In `src/demo/server.ts`, import `createAssignmentStore` from `./assignments`. Right after `const capabilities = …` add:

```ts
  // Rule sets, their switches, history and coverage: rules.read or rules.upload, globally (the real API's rule).
  const readsRules = () => capabilities.some((c) => (c.permission === "rules.read" || c.permission === "rules.upload") && c.scope.kind === "global");
```

After the `const send = …` helper add:

```ts
  const assignments = createAssignmentStore(data, (setId) => audit("rules.assignment.change", setId, "rule_set"), browserPersistence("openvibes-demo-rule-assignment"));
  route("GET", "/api/v1/rule-set-assignments", null, () => (readsRules() ? json(assignments.list()) : problem(403, "permission_denied", "Access is not available")));
  route("PUT", "/api/v1/rule-set-assignments/{set}", "rules.upload", ({ set = "" }, _, body) => send(assignments.setDefault(set, body)));
  route("PUT", "/api/v1/rule-set-assignments/{set}/groups/{group}", "rules.upload", ({ set = "", group = "" }, _, body) => send(assignments.setGroup(set, group, body)));
  route("DELETE", "/api/v1/rule-set-assignments/{set}/groups/{group}", "rules.upload", ({ set = "", group = "" }) => send(assignments.clearGroup(set, group)));
  route("GET", "/api/v1/agents/{id}/rule-set-assignments", "agents.read", ({ id = "" }) => {
    const agent = agentById(id);
    return agent ? json(assignments.host(agent)) : problem(404, "agent_not_found", "Agent not found");
  });
```

The three existing read routes `GET /api/v1/rule-sets`, `GET /api/v1/rule-sets/{id}/bundles` (~line 754) and `GET /api/v1/rules/coverage` (~line 835) change their permission from `"rules.read"` to `null` and start their handler with the same check (ruling G2), e.g.:

```ts
  route("GET", "/api/v1/rule-sets", null, () => (readsRules() ? json({ items: data.ruleSets }) : problem(403, "permission_denied", "Access is not available")));
```

If `browserPersistence`'s other callers pass a differently shaped object, adapt only the `Persistence` type above to it (it returns `{ load, save } | undefined`).

- [ ] **Step 4: Run the tests to verify they pass**

Run: `npm --prefix crates/openvibes-console/web test && npm --prefix crates/openvibes-console/web run typecheck && npm --prefix crates/openvibes-console/web run lint`
Expected: PASS, the whole vitest suite included (the demo's third rule set and `os_id` must not break `server.test.ts`; if a count there changes, fix the expectation and say why in the commit body).

- [ ] **Step 5: Commit**

```bash
git add crates/openvibes-console/web/src/demo/data.ts crates/openvibes-console/web/src/demo/assignments.ts crates/openvibes-console/web/src/demo/assignments.test.ts crates/openvibes-console/web/src/demo/server.ts
git commit -m "demo: rule-set assignment store, hardening L1 and host OS data

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 6: Settings › Rule sets: tab access, the Runs on column, the panel's Where it runs

**Files:**
- Create: `crates/openvibes-console/web/src/panels/WhereItRuns.tsx`
- Create: `crates/openvibes-console/web/src/panels/WhereItRuns.test.tsx`
- Modify: `crates/openvibes-console/web/src/views/Settings.tsx` (tab gate)
- Modify: `crates/openvibes-console/web/src/views/Admin.tsx` (`RuleSets`)
- Modify: `crates/openvibes-console/web/src/panels/OpsPanels.tsx` (`RuleSetPanel`)
- Modify: `docs/components/rule-set-assignment.md`, `docs/components/console-web.md`

**Interfaces:**
- Consumes: Task 4 helpers and types; Task 5 demo routes.
- Produces: `WhereItRuns({ assignment: RuleSetAssignment; groups: readonly AssignableGroup[]; canChange: boolean })`. Accessible names Task 8 relies on: switch "On for Linux hosts by default"; table "Group overrides"; per-row switch "Runs for <group>", button "Remove <group>"; button "+ Add group"; add row combobox "Group", radiogroup "Runs" with radios "On"/"Off"; buttons "Add", "Cancel".

- [ ] **Step 1: Write the failing test**

Create `src/panels/WhereItRuns.test.tsx`:

```tsx
// Markup only (vitest runs in node); clicks, keys and toasts are in the e2e (Task 8).
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import type { AssignableGroup, RuleSetAssignment } from "../api/types";
import { WhereItRuns } from "./WhereItRuns";

const prod: AssignableGroup = { asset_group_id: "g-prod", name: "Production", selectors: ["env=prod"], hosts: 24 };
const lab: AssignableGroup = { asset_group_id: "g-lab", name: "Lab", selectors: ["env=lab"], hosts: 31 };
const l1: RuleSetAssignment = { rule_set_id: "hardening-linux-l1", default_enabled: true, published: true, hosts_on: 162, hosts_off: 24, groups: [{ asset_group_id: "g-prod", name: "Production", enabled: false }] };
const l2: RuleSetAssignment = { rule_set_id: "hardening-linux-l2", default_enabled: false, published: false, hosts_on: 0, hosts_off: 186, groups: [] };
const html = (assignment: RuleSetAssignment, groups: AssignableGroup[], canChange = true) =>
  renderToStaticMarkup(<WhereItRuns assignment={assignment} groups={groups} canChange={canChange} />);

describe("Where it runs", () => {
  it("a published set: the default, the counts, the overrides with tags and hosts, the explanation", () => {
    const out = html(l1, [prod, lab]);
    expect(out).toContain('<h3 class="section-title">Where it runs</h3>');
    expect(out).toContain("On for Linux hosts by default");
    expect(out).toContain("Runs on <b>162</b> Linux hosts · off on <b>24</b>.");
    expect(out).toContain('aria-label="Group overrides"');
    expect(out).toContain('<span class="tag">env=prod</span>');
    expect(out).toContain('aria-label="Runs for Production"');
    expect(out).toContain('aria-label="Remove Production"');
    expect(out).toContain("+ Add group");
    expect(out).toContain("A host runs it when any of its groups has it on; otherwise when the default is on. Hosts follow on their next scan.");
  });
  it("an unpublished set says it is not available yet, and that no group differs", () => {
    const out = html(l2, [prod, lab]);
    expect(out).toContain("<b>Not available yet.</b>");
    expect(out).toContain("This platform has no L2 set yet: it comes with a later rules package. Switches you set now are kept and apply when it is published.");
    expect(out).toContain("No group differs from the default.");
    expect(out).not.toContain("Runs on");
    expect(out).not.toContain("Group overrides");
  });
  it("without rules.upload the switches are read-only and nothing can be added or removed", () => {
    const out = html(l1, [prod, lab], false);
    expect(out.match(/role="switch"[^>]*disabled=""/g)).toHaveLength(2);
    expect(out).not.toContain("+ Add group");
    expect(out).not.toContain("Remove Production");
  });
  it("with no asset groups, Add group is disabled and says why", () => {
    const out = html(l2, []);
    expect(out).toMatch(/disabled="">\+ Add group/);
    expect(out).toContain("No asset groups yet: create one under Settings › Access.");
  });
  it("a very long group name stays on one line, with the full name on hover", () => {
    const long = "g".repeat(200);
    const out = html({ ...l1, groups: [{ asset_group_id: "g-long", name: long, enabled: false }] }, [{ ...prod, asset_group_id: "g-long", name: long }]);
    expect(out).toContain(`<div class="truncate" style="max-width:220px" title="${long}">${long}</div>`);
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npm --prefix crates/openvibes-console/web test -- src/panels/WhereItRuns.test.tsx`
Expected: FAIL: cannot resolve `./WhereItRuns`.

- [ ] **Step 3: Implement `WhereItRuns.tsx`**

```tsx
// Settings › Rule sets › a set's panel: "Where it runs" (approved screens 2–5,
// docs/specs/rule-set-assignment-ui/approved.md): the default switch, the
// groups that override it, and the inline row that adds one. The switches show
// the server's state: a failed change leaves them as they were.
import { useRef, useState } from "react";
import type { KeyboardEvent } from "react";

import { ApiError, invalidate, request } from "../api/client";
import type { AssignableGroup, RuleSetAssignment } from "../api/types";
import { Icon } from "../ui/Icon";
import { Section } from "../ui/panel";
import { Segmented } from "../ui/Segmented";
import { Select } from "../ui/Select";
import { Switch } from "../ui/Switch";
import { toast } from "../ui/toast";
import { addGroupBlocked, shortName } from "./ruleAssignment";

const EXPLAIN = "A host runs it when any of its groups has it on; otherwise when the default is on. Hosts follow on their next scan. Switching it off ends that host's findings from this set (their triage stays).";
const NOTE_BOX = { display: "block", border: "1px solid var(--line-strong)", borderRadius: 8, padding: "10px 12px" } as const;

const Tags = ({ selectors }: { selectors: readonly string[] }) => (
  <span className="row row--wrap">{selectors.map((s) => <span key={s} className="tag">{s}</span>)}</span>
);

export function WhereItRuns({ assignment, groups, canChange }: { assignment: RuleSetAssignment; groups: readonly AssignableGroup[]; canChange: boolean }) {
  const id = assignment.rule_set_id;
  const base = `/api/v1/rule-set-assignments/${encodeURIComponent(id)}`;
  const [busy, setBusy] = useState(false);
  const [adding, setAdding] = useState<{ group: string; on: boolean } | null>(null);
  const addButton = useRef<HTMLButtonElement>(null);
  const addRow = useRef<HTMLTableRowElement>(null);
  const byId = new Map(groups.map((g) => [g.asset_group_id, g]));
  const free = groups.filter((g) => !assignment.groups.some((o) => o.asset_group_id === g.asset_group_id));
  const blocked = addGroupBlocked(groups.length, free.length);

  const change = (method: "PUT" | "DELETE", path: string, body: unknown, done: string) => {
    setBusy(true);
    request(method, path, body)
      .then(() => toast(done), (error: unknown) => toast(error instanceof ApiError ? error.message : "The change failed", true))
      .finally(() => { setBusy(false); invalidate("/api/v1/rule-set-assignments"); invalidate("/api/v1/agents/"); });
  };
  const setGroup = (groupId: string, name: string, on: boolean) =>
    change("PUT", `${base}/groups/${encodeURIComponent(groupId)}`, { enabled: on }, `${id} is now ${on ? "on" : "off"} for ${name}`);
  const open = () => {
    const first = free[0];
    if (!first) return;
    setAdding({ group: first.asset_group_id, on: !assignment.default_enabled });
    requestAnimationFrame(() => addRow.current?.querySelector<HTMLElement>('[role="combobox"]')?.focus());
  };
  const cancel = () => { setAdding(null); requestAnimationFrame(() => addButton.current?.focus()); };
  const add = () => {
    if (!adding) return;
    setGroup(adding.group, byId.get(adding.group)?.name ?? adding.group, adding.on);
    setAdding(null);
  };
  // Esc cancels the add row, and does not close the panel.
  const onKey = (event: KeyboardEvent) => { if (event.key === "Escape") { event.stopPropagation(); cancel(); } };
  const chosen = adding ? byId.get(adding.group) : undefined;

  return (
    <Section title="Where it runs">
      <div className="stack" onKeyDown={adding ? onKey : undefined}>
        {!assignment.published && (
          <div style={NOTE_BOX}><b>Not available yet.</b> <span className="subtle">{`This platform has no ${shortName(id)} set yet: it comes with a later rules package. Switches you set now are kept and apply when it is published.`}</span></div>
        )}
        <Switch label="On for Linux hosts by default" checked={assignment.default_enabled} disabled={!canChange || busy}
          onChange={(on) => change("PUT", base, { default_enabled: on }, `${id} is now ${on ? "on" : "off"} by default`)} />
        {assignment.published && <p className="subtle">Runs on <b>{assignment.hosts_on}</b> Linux hosts · off on <b>{assignment.hosts_off}</b>.</p>}
        {assignment.groups.length === 0 && !adding ? <p className="subtle">No group differs from the default.</p> : (
          <table className="table table--compact" aria-label="Group overrides">
            <thead><tr><th>Group</th><th>Matches</th><th className="num">Hosts</th><th className="num">Runs</th></tr></thead>
            <tbody>
              {assignment.groups.map((o) => (
                <tr key={o.asset_group_id}>
                  <td><div className="truncate" style={{ maxWidth: 220 }} title={o.name}>{o.name}</div></td>
                  <td><Tags selectors={byId.get(o.asset_group_id)?.selectors ?? []} /></td>
                  <td className="num subtle">{byId.get(o.asset_group_id)?.hosts ?? "—"}</td>
                  <td className="num">
                    <span className="row" style={{ justifyContent: "flex-end", gap: 6 }}>
                      <Switch bare label={`Runs for ${o.name}`} checked={o.enabled} disabled={!canChange || busy} onChange={(on) => setGroup(o.asset_group_id, o.name, on)} />
                      {canChange && (
                        <button type="button" className="icon-button" aria-label={`Remove ${o.name}`} title={`Remove: ${o.name} follows the default again`} disabled={busy}
                          onClick={() => change("DELETE", `${base}/groups/${encodeURIComponent(o.asset_group_id)}`, undefined, `${o.name} follows the default again`)}>
                          <Icon name="close" size={14} />
                        </button>
                      )}
                    </span>
                  </td>
                </tr>
              ))}
              {adding && (
                <tr ref={addRow}>
                  <td><Select small label="Group" value={adding.group} onChange={(group) => setAdding({ ...adding, group })} options={free.map((g) => ({ value: g.asset_group_id, label: g.name }))} /></td>
                  <td><Tags selectors={chosen?.selectors ?? []} /></td>
                  <td className="num subtle">{chosen?.hosts ?? 0}</td>
                  <td className="num">
                    <Segmented label="Runs" value={adding.on ? "on" : "off"} onChange={(v) => setAdding({ ...adding, on: v === "on" })}
                      options={[{ value: "on", label: "On" }, { value: "off", label: "Off" }]} />
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        )}
        {canChange && (
          <div className="row">
            {adding ? (
              <>
                <button type="button" className="button button--small button--primary" disabled={busy} onClick={add}>Add</button>
                <button type="button" className="button button--small" onClick={cancel}>Cancel</button>
              </>
            ) : (
              <>
                <button ref={addButton} type="button" className="button button--small" disabled={blocked !== null || busy} onClick={open}>+ Add group</button>
                {blocked && <span className="subtle">{blocked}</span>}
              </>
            )}
          </div>
        )}
        <p className="subtle">{EXPLAIN}</p>
      </div>
    </Section>
  );
}
```

If the test's exact `style` string differs (React renders `max-width:220px`), keep the component and adjust only the string in the test after checking the real markup.

- [ ] **Step 4: Run the test to verify it passes**

Run: `npm --prefix crates/openvibes-console/web test -- src/panels/WhereItRuns.test.tsx src/ui/no-native-controls.test.ts`
Expected: PASS (no native `<select>`).

- [ ] **Step 5: Wire the tab, the list and the panel**

`src/views/Settings.tsx`: compute once `const rulesTab = readsRules(can);` (import from `../panels/ruleAssignment`) and use it for the tab's `allowed` and in the `active === "rule-sets"` branch.

`src/views/Admin.tsx`, `RuleSets` (imports: `RuleSetAssignments` type; `ruleSetRows`, `runsOn` from `../panels/ruleAssignment`). The tab only shows to `readsRules` holders, so both lists are always fetched:

```tsx
export function RuleSets() {
  const { can } = useSession();
  const sets = useResource<{ items: RuleSet[] }>("/api/v1/rule-sets");
  const assignments = useResource<RuleSetAssignments>("/api/v1/rule-set-assignments");
  const top = useTop();
  const rows = ruleSetRows(sets.data?.items ?? [], assignments.data?.items ?? []);
  const error = sets.error ?? assignments.error;
  const loaded = sets.data && assignments.data;
  return (
    <div className="view">
      <ViewHeader title="Rule sets" count={rows.length} refresh="/api/v1/rule-set"
        actions={can("rules.upload", true) && (
          <button type="button" className="button button--primary" onClick={() => nav.open({ kind: "rule-bundle", id: "new" }, true)}><Icon name="plus" size={15} /> Publish bundle</button>
        )} />
      {error ? <div className="view-pad"><ErrorBox error={error} /></div> : !loaded ? <Loading /> : rows.length === 0 ? (
        <Empty icon="rules" title="No rule sets">Publish a signed bundle with openvibes-admin to start.</Empty>
      ) : (
        <DataTable label="Rule sets" rows={rows} rowKey={(r) => r.rule_set_id}
          onOpen={(r) => nav.open({ kind: "rule-set", id: r.rule_set_id }, true)}
          isOpen={(r) => top?.kind === "rule-set" && top.id === r.rule_set_id}
          defaultSort={{ key: "id", direction: "asc" }}
          columns={[
            { key: "id", header: "Rule set", sort: (r) => r.rule_set_id, render: (r) => <span className="mono nowrap">{r.rule_set_id}</span> },
            { key: "version", header: "Version", numeric: true, width: "90px", sort: (r) => r.set?.current_version, render: (r) => r.set ? <span className="num">{r.set.current_version ?? "—"}</span> : <span className="subtle">—</span> },
            { key: "key", header: "Signed by", width: "130px", sort: (r) => r.set?.current_issuer_key_id, render: (r) => <span className={r.set ? "mono subtle" : "subtle"}>{r.set?.current_issuer_key_id ?? "—"}</span> },
            { key: "expires", header: "Expires", width: "130px", sort: (r) => r.set?.current_expires_at_ms, render: (r) => r.set ? <span className={within(r.set.current_expires_at_ms, 7 * 86_400_000) ? "warn-text" : "subtle"}><Ago value={r.set.current_expires_at_ms} /></span> : <span className="subtle">—</span> },
            { key: "runs", header: "Runs on", width: "170px", render: (r) => { const where = runsOn(r.rule_set_id, r.assignment); return <span className="nowrap">{where.text}{where.more && <span className="subtle"> {where.more}</span>}</span>; } },
            { key: "state", header: "State", width: "140px", render: (r) => r.set?.current_signer_removed ? <span className="badge badge--bad">Signer removed</span>
              : r.set?.retired ? <span className="badge">Retired</span>
              : r.assignment && !r.assignment.published ? <span className="badge badge--plain">Not published</span>
              : <span className="badge badge--ok">Active</span> },
          ]} />
      )}
    </div>
  );
}
```

(The Empty text is unchanged from `main`; with the assignment rows it no longer shows once migrated.)

`src/panels/OpsPanels.tsx`, `RuleSetPanel` (imports: `AttackCoverage`, `RuleSetAssignments` types; `readsRules`, `sourceDetail` from `./ruleAssignment`; `WhereItRuns` from `./WhereItRuns`; `useSession` is already imported):

```tsx
export function RuleSetPanel({ id }: { id: string }) {
  const { can } = useSession();
  const reads = readsRules(can);
  const sets = useResource<{ items: RuleSet[] }>(reads ? "/api/v1/rule-sets" : null);
  const set = sets.data?.items.find((item) => item.rule_set_id === id);
  const bundles = useResource<{ items: RuleBundle[] }>(set ? `/api/v1/rule-sets/${encodeURIComponent(id)}/bundles` : null);
  const assignments = useResource<RuleSetAssignments>(reads ? "/api/v1/rule-set-assignments" : null);
  const assignment = assignments.data?.items.find((item) => item.rule_set_id === id);
  const coverage = useResource<AttackCoverage>(reads && assignment?.published ? "/api/v1/rules/coverage" : null);
  const checks = coverage.data ? coverage.data.rules.filter((r) => r.rule_set_id === id && !r.draft).length : null;
  const error = sets.error ?? assignments.error;
  if (error) return <div className="panel-body"><ErrorBox error={error} /></div>;
  if (!set && !assignment) return sets.loading || assignments.loading ? <Loading /> : <div className="panel-body"><Empty title="Rule set not found" /></div>;
  return (
    <>
      <PanelHeader icon="rules" kind="Rule set" title={id}
        badges={<>
          {assignment && !assignment.published ? <span className="badge badge--plain">Not published</span>
            : set && <span className="badge badge--accent badge--plain">version {set.current_version ?? "—"}</span>}
          {set?.retired && <span className="badge badge--plain">Retired</span>}
          {set?.current_signer_removed && <span className="badge badge--bad">Signer key removed</span>}
        </>} />
      <div className="panel-body stack">
        <dl className="kv">
          {set && <>
            <dt>Signed by</dt><dd className="mono">{set.current_issuer_key_id ?? "—"}</dd>
            <dt>Expires</dt><dd>{set.current_expires_at_ms ? <><Ago value={set.current_expires_at_ms} /> · {date(set.current_expires_at_ms)}</> : "—"}</dd>
          </>}
          {assignment
            ? <><dt>Source</dt><dd>OpenVIBES rules package <span className="subtle">{sourceDetail(id, checks)}</span></dd></>
            : set && <><dt>Trusted keys</dt><dd className="num">{set.trusted_keys}</dd></>}
        </dl>
        {!assignment && <p className="subtle">Bundles are signed offline; publish a new version with <code>openvibes-admin rules publish</code> or the API. Agents fetch it on their next contact.</p>}
        {assignment && <WhereItRuns assignment={assignment} groups={assignments.data?.asset_groups ?? []} canChange={can("rules.upload", true)} />}
      </div>
      {set && (
        <Section title="Published versions" flush>
          {/* the existing bundles table, unchanged */}
        </Section>
      )}
    </>
  );
}
```

Keep the existing Published versions table body verbatim inside the `{set && …}` (replace only the comment line with it). The site-set paragraph keeps `main`'s text; it is outside this feature (the assignable panels never show it).

- [ ] **Step 6: Run the checks**

Run: `npm --prefix crates/openvibes-console/web test && npm --prefix crates/openvibes-console/web run typecheck && npm --prefix crates/openvibes-console/web run lint && wc -l crates/openvibes-console/web/src/panels/OpsPanels.tsx crates/openvibes-console/web/src/views/Admin.tsx`
Expected: PASS; both files under 500 lines.

Compare the demo with the approved screens 1–5 by eye (not a gate): run `VITE_DEMO=true npm --prefix crates/openvibes-console/web run dev`, open `/settings?tab=rule-sets`, then L1, then L2 › + Add group › Lab › Add, beside `python3 docs/specs/rule-set-assignment-ui/gen.py docs/specs/rule-set-assignment-ui/base ~/.cache/openvibes-scratch/mockups` output. Order, texts and controls must match.

- [ ] **Step 7: Docs**

Append to `docs/components/rule-set-assignment.md` a section:

```markdown
## Console screens

Approved 2026-10-15 (`../specs/rule-set-assignment-ui/approved.md`).
Settings › Rule sets shows the tab to holders of `rules.read` or
`rules.upload` (global). The list merges published sets with the assignable
ones, so L2 is listed before it is published ("—", **Not published**), and
its **Runs on** column reads the default (Linux, or Off) and how many groups
differ (`panels/ruleAssignment.ts`). Operators (`rules.upload` only) see
the same list and panels as admins (user, 2026-10-15). A set's panel adds **Where it runs** (`panels/WhereItRuns.tsx`):
the default switch, "Runs on N Linux hosts · off on M" once published, the
group overrides (Group, Matches, Hosts, Runs: a switch and ×), "+ Add
group" (an inline row: a group not listed yet, On | Off with the opposite of
the default preselected, Add or Cancel; Esc cancels), and the explanation.
Switches show the server's state: a change waits for the answer, a failure
shows its error in a toast and leaves the switch as it was, and the list
and host views are refetched either way. Without `rules.upload` the switches
are disabled and Add and × are hidden. The Source row's check count comes
from `GET /api/v1/rules/coverage`.
Toasts: "<set> is now on/off by default", "<set> is now on/off for
<group>", "<group> follows the default again"; errors show the API's title.
```

In `docs/components/console-web.md`, under **Views**, change "- rule sets, with signed-bundle preview and publish;" to "- rule sets, with signed-bundle preview and publish, and where each assignable set runs ([rule-set assignment](rule-set-assignment.md#console-screens));".

- [ ] **Step 8: Commit**

```bash
git add crates/openvibes-console/web/src/panels/WhereItRuns.tsx crates/openvibes-console/web/src/panels/WhereItRuns.test.tsx crates/openvibes-console/web/src/views/Settings.tsx crates/openvibes-console/web/src/views/Admin.tsx crates/openvibes-console/web/src/panels/OpsPanels.tsx docs/components/rule-set-assignment.md docs/components/console-web.md
git commit -m "console-web: Runs on column and Where it runs for the assignable rule sets

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 7: Host panel: the Hardening line, Not assigned, Hardening facts unavailable

**Files:**
- Create: `crates/openvibes-console/web/src/panels/HostHardening.tsx`
- Create: `crates/openvibes-console/web/src/panels/HostHardening.test.tsx`
- Modify: `crates/openvibes-console/web/src/panels/AgentPanel.tsx` (one row after Threat alarms; `HostRuleSets` ~:210-240)
- Modify: `docs/components/rule-set-assignment.md` (Console screens, one paragraph)

**Interfaces:**
- Consumes: `hardeningParts`, `factsUnavailable`, `factsNote`, `readsRules` (Task 4); the host view route with `hardening_facts_ok_at` (Task 3, demo Task 5).
- Produces: `hostAssignmentsPath(agent: Agent): string | null`; `HardeningLine({ parts: HardeningPart[]; facts: string | null | undefined; okAt: string | null | undefined })` (presentational, returns the `<dt>`/`<dd>` rows); `HardeningRows({ agent: Agent })` (fetches, renders `HardeningLine`); `NotAssigned({ text: string | null })` with `text` "off for <group>", "off by default" (ruling G4) or null.

- [ ] **Step 1: Write the failing test**

Create `src/panels/HostHardening.test.tsx`:

```tsx
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { HardeningLine, NotAssigned } from "./HostHardening";

const text = (html: string) => html.replace(/<[^>]+>/g, "").replaceAll("&#x27;", "'");

describe("the host's Hardening line", () => {
  it("names the deciding group (screen 6)", () => {
    const html = renderToStaticMarkup(<dl><HardeningLine parts={[{ name: "L1", on: false, group: "Production", note: null }, { name: "L2", on: false, group: null, note: null }]} facts="ok" okAt={null} /></dl>);
    expect(text(html)).toBe("HardeningL1 off (Production) · L2 off");
  });
  it("says a set waits until published, or is pending (screen 7)", () => {
    const html = renderToStaticMarkup(<dl><HardeningLine parts={[{ name: "L1", on: true, group: null, note: "pending" }, { name: "L2", on: true, group: "Lab", note: "waits until published" }]} facts={null} okAt={null} /></dl>);
    expect(text(html)).toBe("HardeningL1 on · pending · L2 on (Lab) · waits until published");
  });
  it("warns when the root-facts helper's facts are unavailable, for how long (screen 8)", () => {
    const threeDaysAgo = new Date(Date.now() - 3 * 86_400_000 - 3_600_000).toISOString();
    const html = renderToStaticMarkup(<dl><HardeningLine parts={[{ name: "L1", on: true, group: null, note: null }]} facts="not_found" okAt={threeDaysAgo} /></dl>);
    expect(html).toContain('<span class="badge badge--warn badge--plain">Hardening facts unavailable</span>');
    expect(text(html)).toContain("The agent's root-facts helper has not reported for 3 days (openvibes-agent-facts.timer), so checks that read root-only files show as unavailable, not failed.");
    expect(html).toContain('style="grid-column:1 / -1"');
    const never = renderToStaticMarkup(<dl><HardeningLine parts={[]} facts="not_found" okAt={null} /></dl>);
    expect(text(never)).toContain("has not reported since enrollment (");
    const ok = renderToStaticMarkup(<dl><HardeningLine parts={[]} facts="ok" okAt={threeDaysAgo} /></dl>);
    expect(ok).not.toContain("Hardening facts unavailable");
  });
  it("a set the host reports not assigned: the badge and the group (screen 6)", () => {
    expect(renderToStaticMarkup(<NotAssigned text="off for Production" />)).toBe('<span class="badge badge--plain" title="Switched off for Production">Not assigned</span><span class="subtle nowrap">off for Production</span>');
    expect(renderToStaticMarkup(<NotAssigned text="off by default" />)).toBe('<span class="badge badge--plain" title="Switched off by default">Not assigned</span><span class="subtle nowrap">off by default</span>');
    expect(renderToStaticMarkup(<NotAssigned text={null} />)).toBe('<span class="badge badge--plain">Not assigned</span>');
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npm --prefix crates/openvibes-console/web test -- src/panels/HostHardening.test.tsx`
Expected: FAIL: cannot resolve `./HostHardening`.

- [ ] **Step 3: Implement**

Create `src/panels/HostHardening.tsx`:

```tsx
// The host's Hardening line (approved screens 6–8): each assignable set as the
// platform decides it, the group that decided it, whether the agent has
// caught up, and why hardening checks may show as unavailable.
import { useResource } from "../api/client";
import type { Agent, HostRuleSetAssignments } from "../api/types";
import { factsNote, factsUnavailable, hardeningParts, type HardeningPart } from "./ruleAssignment";

/** Linux hosts only (os-release reported), never imported ones. */
export const hostAssignmentsPath = (agent: Agent): string | null =>
  agent.os_id && agent.status !== "imported" ? `/api/v1/agents/${encodeURIComponent(agent.id)}/rule-set-assignments` : null;

export function HardeningLine({ parts, facts, okAt }: { parts: HardeningPart[]; facts: string | null | undefined; okAt: string | null | undefined }) {
  return (
    <>
      <dt>Hardening</dt>
      <dd>
        {parts.map((part, i) => (
          <span key={part.name}>
            {i > 0 && " · "}{part.name} {part.on ? "on" : "off"}
            {(part.group || part.note) && <span className="subtle">{part.group && ` (${part.group})`}{part.note && ` · ${part.note}`}</span>}
          </span>
        ))}
      </dd>
      {factsUnavailable(facts) && (
        <dd style={{ gridColumn: "1 / -1" }}>
          <span className="badge badge--warn badge--plain">Hardening facts unavailable</span> <span className="subtle">{factsNote(facts ?? "", okAt)}</span>
        </dd>
      )}
    </>
  );
}

export function HardeningRows({ agent }: { agent: Agent }) {
  const host = useResource<HostRuleSetAssignments>(hostAssignmentsPath(agent));
  if (!host.data || host.data.items.length === 0) return null;
  return <HardeningLine parts={hardeningParts(host.data, agent)} facts={host.data.hardening_facts} okAt={host.data.hardening_facts_ok_at} />;
}

/** A set the host reports `not_assigned`; `text` says what switched it off ("off for
 * Production", "off by default"), null while the platform now says on (pending). */
export function NotAssigned({ text }: { text: string | null }) {
  return (
    <>
      <span className="badge badge--plain" title={text ? `Switched ${text}` : undefined}>Not assigned</span>
      {text && <span className="subtle nowrap">{text}</span>}
    </>
  );
}
```

In `src/panels/AgentPanel.tsx`:
- import `{ HardeningRows, NotAssigned, hostAssignmentsPath }` from `./HostHardening` and `HostRuleSetAssignments` from the types;
- after the Threat alarms line in the Identity `<dl>` add `{data.status !== "imported" && <HardeningRows agent={data} />}`;
- in `HostRuleSets`, the published list is read with `readsRules(can)` instead of `can("rules.read")` (ruling G2: operators see "behind" too), and after the `published` resource add

```tsx
  const host = useResource<HostRuleSetAssignments>(hostAssignmentsPath(agent));
  const decided = new Map((host.data?.items ?? []).map((item) => [item.rule_set_id, item]));
```

and make the row's badges conditional (the version/behind/refused/expires spans move into the `else` branch unchanged):

```tsx
                {set.state === "not_assigned" ? (() => {
                  const d = decided.get(set.id);
                  return <NotAssigned text={!d || d.enabled ? null : d.group ? `off for ${d.group}` : "off by default"} />;
                })() : <>
                  {/* the existing version, behind, refused and expires spans, unchanged */}
                </>}
```

(Replace the comment with the existing four spans. Both components request the same path, so `useResource`'s cache makes one request.)

Append to the "Console screens" section of `docs/components/rule-set-assignment.md`:

```markdown
The host panel's Details (`panels/HostHardening.tsx`, Linux hosts only) add
a **Hardening** row after Threat alarms: per assignable set "L1 on" or
"off", the deciding group in brackets, "waits until published" for an on
set not published yet, and "pending" while the agent's latest report
disagrees with the platform's decision. No switch time is stored, so an
agent too old to know the project sets shows "pending" for L1 until it is
updated (controller ruling, 2026-10-15). A hardening collector outcome other
than `ok` adds the warning **Hardening facts unavailable** with its cause:
"has not reported for N days" (N from `hardening_facts_ok_at`, at least 1),
"has not reported since enrollment" when no report was ever `ok`, or "sent
invalid hardening facts" for `invalid_data`. In the Rule sets section, a set
the agent reports `not_assigned` shows **Not assigned** and "off for
<group>", or "off by default" when the default switched it off.
```

- [ ] **Step 4: Run the checks**

Run: `npm --prefix crates/openvibes-console/web test && npm --prefix crates/openvibes-console/web run typecheck && npm --prefix crates/openvibes-console/web run lint && wc -l crates/openvibes-console/web/src/panels/AgentPanel.tsx`
Expected: PASS; AgentPanel under 500 lines. In the demo build, `/agents?open=agent%3Aagent-00003` matches screen 6, `agent-00017` shows screen 8 ("for 3 days"), and `agent-00034` "since enrollment".

- [ ] **Step 5: Commit**

```bash
git add crates/openvibes-console/web/src/panels/HostHardening.tsx crates/openvibes-console/web/src/panels/HostHardening.test.tsx crates/openvibes-console/web/src/panels/AgentPanel.tsx docs/components/rule-set-assignment.md
git commit -m "console-web: Hardening line, Not assigned and missing root facts on the host panel

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 8: Playwright e2e (demo and live), then the local gate

**Files:**
- Create: `crates/openvibes-console/web/e2e/demo/rule-set-assignment.spec.ts`
- Modify: `crates/openvibes-console/web/e2e/live/console.spec.ts` (one test appended)

**Interfaces:**
- Consumes: the accessible names from Task 6, the demo seed from Task 5, the texts from Task 7.

- [ ] **Step 1: Write the demo spec**

```ts
import AxeBuilder from "@axe-core/playwright";
import { type Page, expect, test } from "@playwright/test";

// Rule-set assignment on the demo: the approved screens
// (docs/specs/rule-set-assignment-ui/approved.md), by mouse and by keyboard.
test.beforeEach(async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { level: 1 })).toContainText("Alex");
});

const row = (page: Page, id: string) =>
  page.getByRole("table", { name: "Rule sets" }).locator("tbody tr").filter({ has: page.getByText(id, { exact: true }) });

test("the list says where each set runs, and L2 is not published", async ({ page }) => {
  await page.goto("/settings?tab=rule-sets");
  await expect(row(page, "baseline")).toContainText("All hosts");
  await expect(row(page, "baseline-alarms")).toContainText("Linux");
  await expect(row(page, "hardening-linux-l1")).toContainText("Linux · 1 group off");
  await expect(row(page, "hardening-linux-l2")).toContainText("Off");
  await expect(row(page, "hardening-linux-l2")).toContainText("Not published");
  await expect(row(page, "site")).toContainText("Hosts that trust its key");
});

test("L2 is switched on for Lab from the panel, by keyboard too", async ({ page }) => {
  await page.goto("/settings?tab=rule-sets&open=rule-set%3Ahardening-linux-l2");
  const inspector = page.locator(".inspector");
  await expect(inspector.getByText("Not available yet.")).toBeVisible();
  await expect(inspector.getByText("No group differs from the default.")).toBeVisible();
  await expect(inspector.getByText("Published versions")).toHaveCount(0);
  const addGroup = inspector.getByRole("button", { name: "+ Add group" });
  await addGroup.click();
  await expect(inspector.getByRole("combobox", { name: "Group" })).toBeFocused();
  // Esc cancels the row, keeps the panel open, and gives focus back.
  await page.keyboard.press("Escape");
  await expect(addGroup).toBeFocused();
  await expect(inspector.locator(".panel-header__title")).toHaveText("hardening-linux-l2");
  await page.keyboard.press("Enter");
  await inspector.getByRole("combobox", { name: "Group" }).click();
  await page.getByRole("option", { name: "Lab" }).click();
  await expect(inspector.getByRole("radio", { name: "On" })).toHaveAttribute("aria-checked", "true");
  expect((await new AxeBuilder({ page }).include(".inspector").analyze()).violations).toEqual([]);
  await inspector.getByRole("button", { name: "Add", exact: true }).click();
  await expect(page.locator(".toast").last()).toContainText("hardening-linux-l2 is now on for Lab");
  const lab = inspector.getByRole("table", { name: "Group overrides" }).locator("tbody tr").filter({ hasText: "Lab" });
  await expect(lab).toContainText("env=lab");
  const labSwitch = lab.getByRole("switch", { name: "Runs for Lab" });
  await expect(labSwitch).toHaveAttribute("aria-checked", "true");
  await expect(row(page, "hardening-linux-l2")).toContainText("Off · 1 group on");
  // The host follows: a Lab host waits until L2 is published.
  await page.goto("/agents?open=agent%3Aagent-00004");
  await expect(page.locator(".inspector dt", { hasText: "Hardening" }).locator("+ dd")).toHaveText("L1 on · L2 on (Lab) · waits until published");
  // Space on the focused switch turns it off again.
  await page.goto("/settings?tab=rule-sets&open=rule-set%3Ahardening-linux-l2");
  await labSwitch.focus();
  await page.keyboard.press("Space");
  await expect(page.locator(".toast").last()).toContainText("hardening-linux-l2 is now off for Lab");
  await expect(labSwitch).toHaveAttribute("aria-checked", "false");
  await page.goto("/audit");
  await expect(page.getByText("rules.assignment.change").first()).toBeVisible();
});

test("hosts: a group switched L1 off, one host pending, one without root facts", async ({ page }) => {
  await page.goto("/agents?open=agent%3Aagent-00003");
  const hardening = page.locator(".inspector dt", { hasText: "Hardening" }).locator("+ dd");
  await expect(hardening).toHaveText("L1 off (Production) · L2 off");
  const l1 = page.getByRole("list", { name: "Rule sets on this host" }).locator("li").filter({ hasText: "hardening-linux-l1" });
  await expect(l1).toContainText("Not assigned");
  await expect(l1).toContainText("off for Production");
  await page.goto("/agents?open=agent%3Aagent-00040");
  await expect(hardening).toHaveText("L1 on · pending · L2 off");
  await page.goto("/agents?open=agent%3Aagent-00017");
  await expect(page.locator(".inspector").getByText("Hardening facts unavailable")).toBeVisible();
  await expect(page.locator(".inspector")).toContainText("has not reported for 3 days (openvibes-agent-facts.timer)");
  await page.goto("/agents?open=agent%3Aagent-00034");
  await expect(page.locator(".inspector")).toContainText("has not reported since enrollment (openvibes-agent-facts.timer)");
});

test("a viewer has no Rule sets tab, an operator reads the rule list and changes switches", async ({ page }) => {
  await page.getByRole("button", { name: "Account" }).click();
  await page.getByRole("menuitemradio", { name: "viewer" }).click();
  await page.goto("/settings?tab=rule-sets");
  await expect(page.getByRole("tab", { name: "Rule sets" })).toHaveCount(0);
  await page.getByRole("button", { name: "Account" }).click();
  await page.getByRole("menuitemradio", { name: "operator" }).click();
  await page.goto("/settings?tab=rule-sets&open=rule-set%3Ahardening-linux-l1");
  // rules.upload reads the list, history and versions like an admin (user, 2026-10-15).
  await expect(row(page, "baseline")).toBeVisible();
  await expect(row(page, "hardening-linux-l1")).toContainText("openvibes-1");
  await expect(page.locator(".inspector").getByText("Published versions")).toBeVisible();
  const byDefault = page.locator(".inspector").getByRole("switch", { name: "On for Linux hosts by default" });
  await expect(byDefault).toBeEnabled();
  await byDefault.click();
  await expect(page.locator(".toast").last()).toContainText("hardening-linux-l1 is now off by default");
  await page.getByRole("button", { name: "Account" }).click();
  await page.getByRole("menuitemradio", { name: "admin" }).click();
});
```

- [ ] **Step 2: Append the live test to `e2e/live/console.spec.ts`**

```ts
test("rule-set switches: a group is added, a failed change keeps the switch and says why, an analyst sees none", async ({ page, browser }) => {
  await signIn(page, "alex");
  await page.goto("/settings?tab=access");
  await page.getByRole("button", { name: "New group" }).click();
  await page.getByLabel("Name").fill("Lab");
  await page.getByLabel("Selectors (one key=value per line)").fill("env=lab");
  await page.getByRole("button", { name: "Create group" }).click();
  await expect(page.locator(".group-card", { hasText: "Lab" })).toBeVisible();

  await page.goto("/settings?tab=rule-sets");
  const l2 = page.getByRole("table", { name: "Rule sets" }).locator("tbody tr").filter({ hasText: "hardening-linux-l2" });
  await expect(l2).toContainText("Not published");
  await l2.click();
  const inspector = page.locator(".inspector");
  await inspector.getByRole("button", { name: "+ Add group" }).click();
  await inspector.getByRole("button", { name: "Add", exact: true }).click();
  await expect(page.locator(".toast").last()).toContainText("hardening-linux-l2 is now on for Lab");

  // A failed change: the switch keeps its state and the error shows.
  const setPath = "**/api/v1/rule-set-assignments/hardening-linux-l2";
  await page.route(setPath, (route) => route.request().method() === "PUT"
    ? route.fulfill({ status: 503, contentType: "application/problem+json", body: JSON.stringify({ status: 503, code: "unavailable", title: "Update unavailable" }) })
    : route.continue());
  const byDefault = inspector.getByRole("switch", { name: "On for Linux hosts by default" });
  await byDefault.click();
  await expect(page.locator(".toast--bad").last()).toContainText("Update unavailable");
  await expect(byDefault).toHaveAttribute("aria-checked", "false");
  await page.unroute(setPath);

  // A group deleted elsewhere (no console route deletes one): the change answers 404.
  const groupPath = "**/api/v1/rule-set-assignments/hardening-linux-l2/groups/*";
  await page.route(groupPath, (route) => route.fulfill({ status: 404, contentType: "application/problem+json", body: JSON.stringify({ status: 404, code: "asset_group_not_found", title: "Asset group not found" }) }));
  const labSwitch = inspector.getByRole("switch", { name: "Runs for Lab" });
  await labSwitch.click();
  await expect(page.locator(".toast--bad").last()).toContainText("Asset group not found");
  await expect(labSwitch).toHaveAttribute("aria-checked", "true");
  await page.unroute(groupPath);

  // An analyst holds neither rules.read nor rules.upload (a second user, as in the dashboards test).
  const sam = await browser.newPage();
  await signIn(sam, "sam");
  await sam.goto("/settings");
  await expect(sam.getByRole("tab", { name: "Rule sets" })).toHaveCount(0);
  await sam.close();
});
```

- [ ] **Step 3: Run the e2e**

Run:
```bash
npm --prefix crates/openvibes-console/web run test:e2e:demo -- rule-set-assignment.spec.ts
eval "$(scripts/test-db.sh)" && bash scripts/test-console-e2e.sh
```
Expected: PASS in Chromium and Firefox. WebKit cannot launch on this host (known); note it for the PR.

- [ ] **Step 4: Commit**

```bash
git add crates/openvibes-console/web/e2e/demo/rule-set-assignment.spec.ts crates/openvibes-console/web/e2e/live/console.spec.ts
git commit -m "console-web e2e: rule-set assignment flows, live and demo

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

- [ ] **Step 5: The local gate (testing.md §2), in order, stop at the first failure**

```bash
cd /home/lime/Projects/OpenVIBES/openvibes-platform-console-assign
git fetch origin && git rebase origin/main
eval "$(scripts/test-db.sh)" && echo "$OPENVIBES_TEST_DATABASE_URL"
export CARGO_TARGET_DIR=~/.cache/openvibes-scratch/target
nice -n 19 bash scripts/build-console.sh
cargo fmt --all --check
bash scripts/check-names.sh
nice -n 19 cargo clippy --locked --workspace --all-targets --all-features -- -D warnings -F unsafe-code
RUSTDOCFLAGS="-D warnings" nice -n 19 cargo doc --locked --workspace --all-features --no-deps
nice -n 19 cargo test --locked --workspace --all-features
cargo audit --deny warnings
bash scripts/test-console-e2e.sh
npm --prefix crates/openvibes-console/web run test:e2e:demo
scripts/test-db.sh stop
```

Expected: all green except WebKit (cannot launch here). The Fedora job (testing.md §3) also runs in CI because migration `0050` changes the schema the installed services use; watch it. The whole demo e2e matters: the demo's `os_id` and third rule set touch other screens (Host details now show System).
