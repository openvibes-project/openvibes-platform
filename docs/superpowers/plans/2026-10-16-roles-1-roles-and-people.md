# Roles and people (step 1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the console's four built-in roles with custom roles made of
48 single-action permissions and a host reach. One protected Administrator
remains. Upgrading existing installs changes nobody's access. The work also
ships the Roles and People screens (approved mockups 1–8, without pictures).

**Architecture:**
- **The permission catalogue** is declared once in Rust: area, matrix
  column, host or platform scope, needs. Web JSON files are generated from
  it.
- **Roles live in the database:** their permissions, plus a reach of
  none, all hosts, or chosen asset groups.
- **Every request** loads the principal's roles with one query and
  resolves effective capabilities into the existing
  `platform_store::console_read::AgentScope`. Nothing downstream of the
  guards changes.
- **A pure share check** stops anyone granting more than they hold.

**Tech Stack:**
- Rust: axum, utoipa, tokio-postgres/deadpool, serde.
- PostgreSQL migrations, embedded.
- React + TypeScript, Vite, Vitest, and Playwright for demo and live e2e.

**Spec:** `docs/specs/2026-10-16-roles-permissions-design.md`: §2, §3, §4,
§6, §12 parts 1–3, §13 (roles, users and service-account routes), §15 and
§16 step 1. The approved screens are 1–8 of `docs/specs/rbac-ui/approved.md`;
run `python3 docs/specs/rbac-ui/gen.py base OUT` to see them.

**Base:** branch `roles-people` from `main` **after platform PRs #287 and
#288 are merged**. This plan uses #288's file layout (`src/access/`,
`src/http/routes.rs`, …). Do not start before #288 is on `main`.
Worktree: `~/Projects/OpenVIBES/openvibes-platform-roles` (create it with
`git worktree add`, and set the git identity: `itismelime`,
`26064407+itismelime@users.noreply.github.com`).

## Global Constraints

- **Files:** every file stays under 500 lines. Each code folder's
  `README.md` lists its files, and `scripts/check-folder-readmes.sh`
  checks this.
- **Docs:** every component change updates its
  `docs/components/<name>.md` in the same commit (`console-rbac.md`,
  `console-auth-http.md`, `console-auth-store.md`, `console-web.md`,
  `openvibes-admin.md`, `platform-store.md`).
- **Commits:** end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- **This host is the user's production platform:**
  - Never touch the host's own openvibes services or database.
  - Tests use only `eval "$(scripts/test-db.sh)"`.
  - Heavy builds run under `nice -n 19` with
    `CARGO_TARGET_DIR=~/.cache/openvibes-scratch/target`.
  - `/tmp` is RAM; put nothing big there.
- **Permission IDs are exactly the 48 in spec §3,** for example
  `hosts.read` and `alarms.suppressions.approve`. Console text is exactly
  the spec's "Permission (console text)" column.
- **Administrator** is role ID `admin`, shown as "Administrator". It holds
  every permission on all hosts. It cannot be edited or deleted, and its
  last enabled member cannot be removed or disabled.
- **Reach** is `none` | `all` | `groups` (one or more asset group IDs). A
  new role starts with no permissions and reach `none`.
- **Platform-scope permissions** always resolve to `AgentScope::Global`.
  Host-scope ones resolve to the union of the reach of every role that
  grants them. Reach `none` grants no host permission.
- **Nobody grants more than they hold** (spec §4.4). The check is
  server-side, and the console only hides what would fail.
- **Refusals:** a 403 body carries a reason that names the permission
  outside the share. Conflicts use 409 with codes `stale_role`,
  `role_name_taken`, `role_in_use`, `last_administrator`.
- **Audit actions:**
  - roles: `rbac.role.created`, `rbac.role.updated`, `rbac.role.deleted`;
  - grants: `rbac.binding.created`, `rbac.binding.revoked`;
  - people: `user.updated`, `user.disabled`, `user.enabled`,
    `user.password_reset`.

  They are written in the same transaction as the change.
- **Migrations:**
  - `0051_permission_catalogue.sql` and `0052_custom_roles.sql`; both
    start with `-- openvibes: needs-backup`.
  - `SCHEMA_VERSION` becomes 52.
- **Generated web files:**
  - `web/src/api/permissions.json` and `web/src/api/templates.json` come
    from `export_openapi --permissions` / `--templates`, and tests compare
    them byte for byte.
  - `web/src/api/roles.json` and `export_openapi --roles` are removed.
- **UI copy:**
  - Role page steps: "Name", "Start from", "Permissions", "Hosts".
  - Sticky bar buttons: "Cancel", "Create role" or "Save role".
  - Platform-wide permissions get the ⓘ title "Applies to the whole
    platform, whatever hosts the role reaches".
  - The prerequisite notice reads "Also turned on: …" / "Also turned
    off: …".

## Review Focus

1. **Holders with several scoped bindings.** A person with a global
   `operator` binding and two scoped `operator` bindings (Lab, Prod) must
   end with the same effective (permission, host) set after the upgrade.
   Their scoped bindings merge into one role, "Operator (Lab, Prod)"
   (Task 2, `upgrade_merges_one_holders_scoped_bindings`).
2. **Names that differ only in case.** Creating or renaming a role to
   "analyst" when "Analyst" exists is refused with 409 `role_name_taken`,
   not a 500 from the unique index
   (Task 5, `role_names_are_unique_regardless_of_case`).
3. **Losing the last Administrator.** It must be impossible through any
   route, including two concurrent requests: disable, role removal, or
   deleting the person's admin binding
   (Task 6, `two_concurrent_removals_leave_one_administrator`).
4. **Service tokens follow role edits.** A token bound to a role whose
   permissions are edited sees the change on its next request, and a
   token whose role loses a permission is refused at once
   (Task 3, `service_token_follows_role_edits`).
5. **A team admin widening their own role.** Editing a role they hold so
   that it reaches all hosts, while they hold a host permission only on
   Lab, is refused with the permission named
   (Task 4 unit test `editing_own_role_cannot_widen_reach` and Task 5
   `team_admin_cannot_widen_a_role_they_hold`).

---

### Task 1: Permission catalogue (48 permissions, templates, ID migration)

Integration task: it touches many files. The DB IDs, the Rust enum and the
web IDs must change together, or tests break in between.

**Files:**
- Modify: `crates/openvibes-console/src/access/permission.rs`, which
  becomes the 48-variant enum with `id()` and `from_id()`.
- Create: `crates/openvibes-console/src/access/catalogue.rs` (metadata,
  needs, closure, JSON).
- Create: `crates/openvibes-console/src/access/templates.rs`.
- Modify: `crates/openvibes-console/src/access/rbac.rs`. Only
  `role_has_permission` / `is_agent_bound` are remapped to the new
  variants; the built-in roles stay until Task 3.
- Modify: every `Permission::` call site in `crates/openvibes-console/src`
  and `tests` (≈260 lines; mapping table below).
- Modify: SQL strings in `crates/platform-store/src/console_cases.rs`
  (`'cases.read'`) and `src/signer.rs` (`'rules.upload'` →
  `'rules.publish'`).
- Create: `migrations/0051_permission_catalogue.sql`.
- Modify: `crates/platform-store/src/migrate.rs` (register 51; set
  `SCHEMA_VERSION` = 51).
- Modify: `crates/openvibes-console/src/bin/export_openapi.rs` (add
  `--permissions` and `--templates`; keep `--roles` until Task 3).
- Create: `crates/openvibes-console/web/src/api/permissions.json` and
  `templates.json` (generated).
- Modify: the web string IDs (`Settings.tsx`, `registry.tsx`,
  `ruleAssignment.ts` `RULE_READERS`, the command palette, panels,
  `demo/routes/*.ts`, `demo/data.ts`), plus regenerate `api/generated.ts`
  and `docs/api/console-v1.openapi.json`.
- Test: `crates/openvibes-console/src/access/catalogue.rs` (unit),
  `crates/platform-store/tests/permission_catalogue.rs` (new),
  `crates/openvibes-console/tests/api_contract.rs`.

**Interfaces:**
- Produces:
  - `crate::Permission` (48 variants), with `Permission::ALL: [Permission; 48]`,
    `fn id(self) -> &'static str` and
    `fn from_id(id: &str) -> Option<Permission>`.
  - `crate::access::catalogue::{PermissionDef, Scope, Column, def(p) -> &'static PermissionDef, with_needs(set: &BTreeSet<Permission>) -> BTreeSet<Permission>, catalogue_json() -> String}`.
  - `crate::access::templates::{Template, TEMPLATES, templates_json() -> String}`.
  - The DB `console_permissions.scope_class`: `'agent'` = host scope,
    `'global'` = platform scope.

**Old → new call-site mapping** (decide per route where one old ID splits):

| Old variant | New variant(s) |
|---|---|
| `AgentsRead` | `HostsRead` |
| `AgentsRevoke` | `HostsRevoke` |
| `CasesManage` | `CasesWrite`; routes that set or change an assignee use `CasesAssign` |
| `TokensCreate`, `TokensRevoke` | `TokensManage`; the installer download route uses `TokensInstaller` |
| `RulesUpload` | `RulesPublish` |
| `RulesWrite` | site-rule draft edit → `SiteRulesWrite`, draft test → `SiteRulesTest`, site-rule publish → `SiteRulesPublish`, rule-set assignment writes → `RulesAssignmentWrite`, draft reads → `SiteRulesRead` |
| `RulesRead` | rule-set list/versions → `RulesRead`; where sets run → `RulesAssignmentRead`; coverage → `RulesCoverageRead`; rule contents → `RulesContentsRead` |
| `RbacRead` | `AccessRead` |
| `RbacManage` | user creation → `AccessUsers`; bindings → `AccessGrant` |
| `AssetGroupsManage` | `HostGroupsManage` |
| `ServiceAccountsManage` | account create/disable → `ServiceAccountsManage`; token routes → `ServiceAccountsTokens` |
| alarm suppression list route | `AlarmsSuppressionsRead` |
| others | same name |

- [ ] **Step 1: Write the failing catalogue tests** in `src/access/catalogue.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn there_are_48_permissions_with_unique_ids_that_round_trip() {
        let ids: BTreeSet<_> = Permission::ALL.iter().map(|p| p.id()).collect();
        assert_eq!(ids.len(), 48);
        for p in Permission::ALL { assert_eq!(Permission::from_id(p.id()), Some(p)); }
        assert_eq!(Permission::from_id("agents.read"), None);
    }

    #[test]
    fn every_permission_has_a_definition_and_needs_are_acyclic() {
        for p in Permission::ALL {
            assert_eq!(def(p).permission, p);
            // acyclic: following needs never returns to p
            let mut seen = BTreeSet::new();
            let mut stack: Vec<Permission> = def(p).needs.to_vec();
            while let Some(n) = stack.pop() {
                assert_ne!(n, p, "{} needs itself through {}", p.id(), n.id());
                if seen.insert(n) { stack.extend(def(n).needs.iter().copied()); }
            }
        }
    }

    #[test]
    fn with_needs_closes_transitively() {
        let got = with_needs(&BTreeSet::from([Permission::CasesAssign]));
        assert_eq!(got, BTreeSet::from([Permission::CasesAssign, Permission::CasesWrite, Permission::CasesRead]));
        let got = with_needs(&BTreeSet::from([Permission::SiteRulesTest]));
        assert!(got.contains(&Permission::SiteRulesWrite) && got.contains(&Permission::SiteRulesRead) && got.contains(&Permission::HostsRead));
    }

    #[test]
    fn templates_are_closed_under_needs_and_use_known_permissions() {
        for t in TEMPLATES {
            let set: BTreeSet<_> = t.permissions.iter().copied().collect();
            assert_eq!(with_needs(&set), set, "template {} misses a need", t.name);
        }
        assert_eq!(TEMPLATES.iter().map(|t| t.name).collect::<Vec<_>>(),
            ["Viewer", "Analyst", "Operator", "Team lead", "Auditor", "Rule author"]);
    }
}
```

(`templates_are_closed_under_needs…` lives in `templates.rs` and imports
`with_needs`.)

- [ ] **Step 2: Run them and watch them fail.**

Run: `cargo test -p openvibes-console --lib access::catalogue`
Expected: FAIL to compile (`Permission::ALL`, `def`, `with_needs` not found).

- [ ] **Step 3: Write `permission.rs`** with the 48 variants, in spec §3
  order.

  Each variant has a doc comment (its console text) and
  `#[serde(rename = "<id>")]`. Add:

```rust
impl Permission {
    pub const ALL: [Permission; 48] = [ /* all 48, spec §3 order */ ];
    pub fn id(self) -> &'static str { crate::access::catalogue::def(self).id }
    pub fn from_id(id: &str) -> Option<Self> { Self::ALL.into_iter().find(|p| p.id() == id) }
}
```

Add `Deserialize` to the derive list (role requests carry IDs).

- [ ] **Step 4: Write `catalogue.rs`.**

```rust
//! The permission catalogue: one entry per action, declared once (spec §3).
use std::collections::BTreeSet;
use serde::Serialize;
use crate::Permission;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope { Host, Platform }

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum Column { View, Change, Export, #[serde(rename = "Approve and publish")] Approve }

#[derive(Debug, Serialize)]
pub struct PermissionDef {
    #[serde(skip)] pub permission: Permission,
    pub id: &'static str,
    pub area: &'static str,
    pub label: &'static str,
    pub column: Column,
    pub scope: Scope,
    #[serde(serialize_with = "ids")] pub needs: &'static [Permission],
}
fn ids<S: serde::Serializer>(needs: &&'static [Permission], s: S) -> Result<S::Ok, S::Error> {
    s.collect_seq(needs.iter().map(|p| p.id()))
}

use Column::*; use Permission as P; use Scope::*;
const fn d(permission: Permission, id: &'static str, area: &'static str, label: &'static str,
    column: Column, scope: Scope, needs: &'static [Permission]) -> PermissionDef {
    PermissionDef { permission, id, area, label, column, scope, needs }
}

/// Spec §3, in order. Areas group the matrix rows.
pub static CATALOGUE: [PermissionDef; 48] = [
    d(P::AlarmsRead, "alarms.read", "Alarms", "View alarms", View, Host, &[]),
    d(P::AlarmsSuppressionsRead, "alarms.suppressions.read", "Alarms", "View suppressions", View, Host, &[P::AlarmsRead]),
    d(P::AlarmsTriage, "alarms.triage", "Alarms", "Triage alarms", Change, Host, &[P::AlarmsRead]),
    d(P::AlarmsSuppress, "alarms.suppress", "Alarms", "Suppress alarms (with a reason)", Change, Host, &[P::AlarmsRead, P::AlarmsSuppressionsRead]),
    d(P::AlarmsExport, "alarms.export", "Alarms", "Export alarms", Export, Host, &[P::AlarmsRead]),
    d(P::AlarmsSuppressionsApprove, "alarms.suppressions.approve", "Alarms", "Approve suppressions", Approve, Host, &[P::AlarmsSuppressionsRead]),
    // … the remaining 42 rows, copied from the spec §3 table: area, console
    // text, column, scope (host/platform) and needs, exactly as written there.
];

pub fn def(p: Permission) -> &'static PermissionDef {
    CATALOGUE.iter().find(|d| d.permission == p).expect("every permission is in the catalogue")
}

/// The set plus everything it needs, transitively.
pub fn with_needs(set: &BTreeSet<Permission>) -> BTreeSet<Permission> {
    let mut out = set.clone();
    let mut stack: Vec<Permission> = set.iter().copied().collect();
    while let Some(p) = stack.pop() {
        for n in def(p).needs { if out.insert(*n) { stack.push(*n); } }
    }
    out
}

pub fn catalogue_json() -> String {
    serde_json::to_string_pretty(&CATALOGUE[..]).expect("catalogue serializes")
}
```

The "remaining 42 rows" comment means copy them all from the spec; leave
no row out. The tests in Step 1 fail on any missing row.

- [ ] **Step 5: Write `templates.rs`.**

  Use the six templates with the exact permission lists of spec §4.2, in
  the IDs of §3. The approved `gen.py` `TEMPLATE_PERMS` gives them in
  console text; map each label to its variant. Each template also has a
  one-line description (gen.py `TEMPLATES`).

```rust
#[derive(Debug, serde::Serialize)]
pub struct Template { pub name: &'static str, pub description: &'static str,
    #[serde(serialize_with = "crate::access::catalogue::serialize_ids")] pub permissions: &'static [Permission] }
pub static TEMPLATES: [Template; 6] = [ /* Viewer, Analyst, Operator, Team lead, Auditor, Rule author */ ];
pub fn templates_json() -> String { serde_json::to_string_pretty(&TEMPLATES[..]).expect("templates serialize") }
```

(Make `ids` in `catalogue.rs` `pub(crate) fn serialize_ids` and use it in
both places.)

- [ ] **Step 6: Run the unit tests.**

Run: `cargo test -p openvibes-console --lib access::`
Expected: the catalogue and template tests PASS. The crate does not yet
build, because the old variants are still used elsewhere.

- [ ] **Step 7: Rename every call site** with the mapping table above.

  Where an old permission splits, read the handler and choose by what it
  does. In `rbac.rs`, `role_has_permission` keeps the four built-in roles
  but maps them onto the new variants: each built-in role gets the
  §12-part-1 mapping of its old set, closed with `with_needs`.
  `is_agent_bound(p)` becomes `def(p).scope == Scope::Host`.

  Store SQL strings:
  - `console_cases.rs` `'cases.read'` stays.
  - `signer.rs` `'rules.upload'` → `'rules.publish'`.

- [ ] **Step 8: Write the failing migration test**
  `crates/platform-store/tests/permission_catalogue.rs`:

```rust
mod common;

#[tokio::test]
async fn old_ids_map_to_the_new_catalogue_and_roles_gain_their_needs() {
    let db = common::TestDb::create().await;
    let client = common::at_version(&db, 50).await;
    let before = role_permissions(&client).await;
    assert!(before.contains(&("operator".into(), "rules.upload".into())));
    drop(client);
    let client = common::at_version(&db, 51).await;
    let after = role_permissions(&client).await;
    for (role, old, new) in [
        ("operator", "agents.read", "hosts.read"), ("operator", "rules.upload", "rules.publish"),
        ("operator", "rules.upload", "rules.coverage.read"), ("analyst", "cases.manage", "cases.assign"),
        ("analyst", "alarms.read", "alarms.suppressions.read"), ("analyst", "alarms.read", "alarms.export"),
        ("admin", "rbac.manage", "access.grant"),
    ] {
        assert!(before.contains(&(role.into(), old.into())), "{role} had {old}");
        assert!(after.contains(&(role.into(), new.into())), "{role} gets {new}");
    }
    let ids: Vec<String> = client.query("SELECT permission_id FROM console_permissions", &[]).await.unwrap()
        .iter().map(|r| r.get(0)).collect();
    assert_eq!(ids.len(), 48);
    assert!(!ids.iter().any(|i| i.starts_with("agents.") || i.starts_with("rbac.")));
    let admin: i64 = client.query_one("SELECT count(*) FROM console_role_permissions WHERE role_id = 'admin'", &[]).await.unwrap().get(0);
    assert_eq!(admin, 48);
    db.drop().await;
}

async fn role_permissions(c: &tokio_postgres::Client) -> std::collections::BTreeSet<(String, String)> {
    c.query("SELECT role_id, permission_id FROM console_role_permissions", &[]).await.unwrap()
        .iter().map(|r| (r.get(0), r.get(1))).collect()
}
```

(If `at_version` returns a deadpool `Client`, deref with `&**client` where
a `tokio_postgres::Client` is needed. Follow `tests/compliance_names.rs`,
the rename-migration precedent.)

Run: `eval "$(scripts/test-db.sh)"; cargo test -p platform-store --test permission_catalogue`
Expected: FAIL (`at_version(&db, 51)` panics: unknown version).

- [ ] **Step 9: Write `migrations/0051_permission_catalogue.sql`.**

```sql
-- openvibes: needs-backup
-- OpenVIBES platform schema version 51: one permission per action
-- (spec 2026-10-16-roles-permissions-design.md §3, §12 part 1).
CREATE TEMP TABLE permission_map (old_id text, new_id text) ON COMMIT DROP;
INSERT INTO permission_map VALUES
  ('agents.read','hosts.read'), ('agents.revoke','hosts.revoke'),
  ('cases.manage','cases.write'), ('cases.manage','cases.assign'),
  ('tokens.create','tokens.manage'), ('tokens.create','tokens.installer'),
  ('tokens.revoke','tokens.manage'), ('tokens.revoke','tokens.installer'),
  ('rules.upload','rules.publish'), ('rules.upload','rules.read'),
  ('rules.upload','rules.assignment.read'), ('rules.upload','rules.coverage.read'),
  ('rules.write','rules.assignment.write'), ('rules.write','site_rules.write'),
  ('rules.write','site_rules.test'), ('rules.write','site_rules.publish'),
  ('rules.write','site_rules.read'),
  ('rules.read','rules.read'), ('rules.read','rules.assignment.read'),
  ('rules.read','rules.coverage.read'), ('rules.read','rules.contents.read'),
  ('rbac.read','access.read'),
  ('rbac.manage','access.users'), ('rbac.manage','access.roles'), ('rbac.manage','access.grant'),
  ('asset_groups.manage','host_groups.manage'),
  ('service_accounts.manage','service_accounts.manage'), ('service_accounts.manage','service_accounts.tokens'),
  ('alarms.read','alarms.read'), ('alarms.read','alarms.suppressions.read'), ('alarms.read','alarms.export'),
  ('compliance.read','compliance.read'), ('compliance.read','compliance.export'),
  ('vulnerabilities.read','vulnerabilities.read'), ('vulnerabilities.read','vulnerabilities.export'),
  ('agents.read','hosts.export');
-- every other old id maps to itself
INSERT INTO permission_map SELECT permission_id, permission_id FROM console_permissions
  WHERE permission_id NOT IN (SELECT old_id FROM permission_map);

INSERT INTO console_permissions (permission_id, scope_class) VALUES
  -- all 48 new ids with 'agent' for host scope and 'global' for platform scope
  ('alarms.read','agent') /* …all 48, spec §3 … */
ON CONFLICT (permission_id) DO UPDATE SET scope_class = EXCLUDED.scope_class;

CREATE TEMP TABLE mapped ON COMMIT DROP AS
  SELECT DISTINCT rp.role_id, m.new_id AS permission_id
  FROM console_role_permissions rp JOIN permission_map m ON m.old_id = rp.permission_id;
DELETE FROM console_role_permissions;
INSERT INTO console_role_permissions (role_id, permission_id) SELECT role_id, permission_id FROM mapped;
-- needs, closed (repeat until nothing is added: the deepest chain is 3)
CREATE TEMP TABLE needs (permission_id text, needs text) ON COMMIT DROP;
INSERT INTO needs VALUES /* every (permission, need) pair of spec §3 */ ('alarms.suppressions.read','alarms.read');
INSERT INTO console_role_permissions SELECT rp.role_id, n.needs FROM console_role_permissions rp JOIN needs n USING (permission_id) ON CONFLICT DO NOTHING;
INSERT INTO console_role_permissions SELECT rp.role_id, n.needs FROM console_role_permissions rp JOIN needs n USING (permission_id) ON CONFLICT DO NOTHING;
INSERT INTO console_role_permissions SELECT rp.role_id, n.needs FROM console_role_permissions rp JOIN needs n USING (permission_id) ON CONFLICT DO NOTHING;
-- Administrator holds everything
INSERT INTO console_role_permissions SELECT 'admin', permission_id FROM console_permissions ON CONFLICT DO NOTHING;
DELETE FROM console_permissions WHERE permission_id NOT IN (SELECT new_id FROM permission_map) AND permission_id NOT IN (
  /* the 48 new ids */ 'alarms.read');
```

Fill in every elided list completely (48 IDs; every needs pair). Then
register 51 in `migrate.rs` and set `SCHEMA_VERSION` to 51.

Run: `cargo test -p platform-store --test permission_catalogue && cargo test -p platform-store --test migrate`
Expected: PASS (the migrate test enforces the needs-backup marker).

- [ ] **Step 10: Update the parity test and the web.**

  - In `tests/auth_http.rs` `database_builtin_permissions_match_the_rust_role_table`
    now compares against the remapped built-in roles.
  - Add `--permissions` / `--templates` to `export_openapi` (they print
    `catalogue_json()` / `templates_json()`).
  - Add to `tests/api_contract.rs`:

```rust
#[test]
fn the_web_permission_catalogue_matches_the_rust_one() {
    assert_eq!(include_str!("../web/src/api/permissions.json").trim_end(), openvibes_console::catalogue_json());
    assert_eq!(include_str!("../web/src/api/templates.json").trim_end(), openvibes_console::templates_json());
}
```

Export `catalogue_json` and `templates_json` from `lib.rs`, then
regenerate the generated files:

```bash
cargo run -p openvibes-console --bin export_openapi -- --permissions > crates/openvibes-console/web/src/api/permissions.json
cargo run -p openvibes-console --bin export_openapi -- --templates > crates/openvibes-console/web/src/api/templates.json
cargo run -p openvibes-console --bin export_openapi -- --roles > crates/openvibes-console/web/src/api/roles.json
cargo run --locked -p openvibes-console --bin export_openapi > docs/api/console-v1.openapi.json
npm --prefix crates/openvibes-console/web run generate:api
```

Then fix every string ID in the web with the mapping table, and type-check:
`npm --prefix crates/openvibes-console/web run build`.

- [ ] **Step 11: Run the whole gate** (testing.md: fmt, check-names,
  check-folder-readmes, clippy, doc, `cargo test --workspace
  --all-features`, `npm … test`, `npm … run test:e2e:demo`).

  Expected: all PASS. Add `catalogue.rs` and `templates.rs` to
  `src/access/README.md`. Update `docs/components/console-rbac.md` with
  the catalogue.

- [ ] **Step 12: Commit.**

```bash
git add -A && git commit -m "console: one permission per action (48), declared once; migration 51 maps the old ids

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2: Roles in the database, and the upgrade (store)

**Files:**
- Create: `migrations/0052_custom_roles.sql`.
- Modify: `crates/platform-store/src/migrate.rs` (52, `SCHEMA_VERSION` 52).
- Create: `crates/platform-store/src/console_roles.rs` (role CRUD and
  principal grants; under 500 lines).
- Modify: `crates/platform-store/src/lib.rs` (`pub mod console_roles;`).
- Modify: `crates/platform-store/src/console_auth.rs`:
  - `create_user_role_binding` loses `asset_group_id`;
  - the last-admin guard is generalised to `admin` with
    `asset_group_id` gone;
  - `create_session` sets `last_sign_in_at`.
- Test: `crates/platform-store/tests/custom_roles.rs` (new).

**Interfaces:**
- Produces, in `platform_store::console_roles`:

```rust
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reach { None, All, Groups(Vec<String>) }          // group ids, sorted
#[derive(Clone, Debug)]
pub struct StoredRole { pub role_id: String, pub name: String, pub description: String, pub builtin: bool,
    pub permissions: Vec<String>, pub reach: Reach, pub group_names: Vec<(String, String)>,
    pub members: i64, pub version: i32 }
pub struct RoleInput<'a> { pub name: &'a str, pub description: &'a str, pub permissions: &'a [String], pub reach: &'a Reach }
pub enum RoleWrite { Saved(StoredRole), NameTaken, Stale, NotFound, Protected, InUse(i64) }
pub enum Principal<'a> { User(&'a str), ServiceAccount(&'a str) }
pub struct Grant { pub role_id: String, pub permissions: Vec<String>, pub reach: Reach }

pub async fn list_roles(client: &Client) -> Result<Vec<StoredRole>, StoreError>;
pub async fn role(client: &Client, role_id: &str) -> Result<Option<StoredRole>, StoreError>;
pub async fn create_role(client: &mut Client, input: &RoleInput<'_>, actor_id: &str, now: DateTime<Utc>) -> Result<RoleWrite, StoreError>;
pub async fn update_role(client: &mut Client, role_id: &str, version: i32, input: &RoleInput<'_>, actor_id: &str, now: DateTime<Utc>) -> Result<RoleWrite, StoreError>;
pub async fn delete_role(client: &mut Client, role_id: &str, actor_id: &str, now: DateTime<Utc>) -> Result<RoleWrite, StoreError>;
pub async fn grants(client: &Client, principal: Principal<'_>) -> Result<Vec<Grant>, StoreError>;
```

- `console_auth::UserRoleBinding` loses `asset_group_id`.
- Callers of `create_user_role_binding` drop the argument. Task 3 fixes
  the console callers. Until then, the console crate is allowed to fail
  to build only inside this task's branch commit series. Run the store
  tests here, and the gate after Task 3.

- [ ] **Step 1: Write the failing upgrade tests** in `tests/custom_roles.rs`:
  - `upgrade_keeps_everyones_effective_access`:
    - at version 51, seed:
      - users `ana` (global analyst);
      - `op` (global operator + scoped operator on group Lab);
      - `lab` (scoped operator on Lab and on Prod);
      - `adm` (admin);
      - service account `ci` (global viewer);
      - roles nobody holds stay unseeded;
    - compute each principal's effective (permission, agent-visible-set)
      with a SQL helper that mirrors v51 semantics (global binding →
      every permission of the role on all hosts; scoped binding → only
      `scope_class='agent'` permissions on the group);
    - migrate to 52, compute the same from `console_roles::grants`
      (reach all → all agents; groups → the group's agents);
    - assert the two maps are equal.
  - `upgrade_merges_one_holders_scoped_bindings`: after the upgrade, `lab`
    holds exactly one role named `Operator (Lab, Prod)` whose reach is
    both groups, and whose permissions are only the old operator's
    agent-scoped ones.
  - `unused_builtin_roles_are_dropped_and_admin_stays_protected`: viewer
    is gone (nobody held it), analyst and operator are `builtin = false`
    with reach all, and `admin` is `builtin = true`, named
    "Administrator", with reach all.
  - `roles_crud_round_trips_and_refuses_name_clash_and_stale_versions`:
    `create_role` → `update_role` with an old version returns `Stale`;
    a name differing only in case returns `NameTaken`; `delete_role` of
    `admin` returns `Protected`; deleting a held role returns `InUse(1)`.
  - `grants_are_one_query_per_principal`: a user with two roles gets two
    `Grant`s with their reach. A service account works the same.

Run: `cargo test -p platform-store --test custom_roles`
Expected: FAIL (version 52 unknown; `console_roles` missing).

- [ ] **Step 2: Write `migrations/0052_custom_roles.sql`.**

```sql
-- openvibes: needs-backup
-- OpenVIBES platform schema version 52: custom roles with a host reach
-- (spec 2026-10-16-roles-permissions-design.md §4, §12 parts 2–3).
ALTER TABLE console_roles
  ADD COLUMN description text NOT NULL DEFAULT '' CHECK (char_length(description) <= 500),
  ADD COLUMN all_hosts boolean NOT NULL DEFAULT false,
  ADD COLUMN version integer NOT NULL DEFAULT 1 CHECK (version > 0),
  ADD COLUMN created_at timestamptz NOT NULL DEFAULT now(),
  ADD COLUMN created_by text NOT NULL DEFAULT 'migration',
  ADD CONSTRAINT console_roles_name_length CHECK (char_length(display_name) BETWEEN 1 AND 64);
CREATE UNIQUE INDEX console_roles_name_unique ON console_roles (lower(display_name));
CREATE TABLE console_role_groups (
  role_id text NOT NULL REFERENCES console_roles ON DELETE CASCADE,
  asset_group_id uuid NOT NULL REFERENCES console_asset_groups ON DELETE RESTRICT,
  PRIMARY KEY (role_id, asset_group_id));

-- part 2: built-in roles
UPDATE console_roles SET display_name = 'Administrator', all_hosts = true WHERE role_id = 'admin';
UPDATE console_roles SET builtin = false, all_hosts = true WHERE role_id IN ('viewer','analyst','operator');

-- part 3: a holder's scoped bindings of one role, as one set of groups
CREATE TEMP TABLE scoped ON COMMIT DROP AS
  SELECT b.user_id, b.service_account_id, b.role_id,
         array_agg(b.asset_group_id ORDER BY g.name) AS groups,
         string_agg(g.name, ', ' ORDER BY g.name) AS names
  FROM console_role_bindings b JOIN console_asset_groups g USING (asset_group_id)
  WHERE b.revoked_at IS NULL AND b.asset_group_id IS NOT NULL
  GROUP BY b.user_id, b.service_account_id, b.role_id;
CREATE TEMP TABLE new_roles ON COMMIT DROP AS
  SELECT DISTINCT ON (s.role_id, s.groups) s.role_id AS old_role, s.groups,
         'r_' || substr(md5(s.role_id || array_to_string(s.groups, ',')), 1, 16) AS new_role,
         left(r.display_name || ' (' || s.names || ')', 64) AS name
  FROM scoped s JOIN console_roles r USING (role_id);
-- names that would clash get " 2", " 3", … (append row_number over lower(name))
INSERT INTO console_roles (role_id, display_name, builtin, all_hosts)
  SELECT new_role, name, false, false FROM new_roles;
INSERT INTO console_role_groups SELECT new_role, unnest(groups) FROM new_roles;
INSERT INTO console_role_permissions (role_id, permission_id)
  SELECT n.new_role, rp.permission_id FROM new_roles n
  JOIN console_role_permissions rp ON rp.role_id = n.old_role
  JOIN console_permissions p USING (permission_id) WHERE p.scope_class = 'agent';
-- move bindings: revoke the scoped ones, add one binding to the new role
INSERT INTO console_role_bindings (binding_id, user_id, service_account_id, role_id, asset_group_id, created_at, created_by)
  SELECT gen_random_uuid(), s.user_id, s.service_account_id, n.new_role, NULL, now(), 'migration'
  FROM scoped s JOIN new_roles n ON n.old_role = s.role_id AND n.groups = s.groups;
UPDATE console_role_bindings SET revoked_at = now(), revoked_by = 'migration'
  WHERE revoked_at IS NULL AND asset_group_id IS NOT NULL;

-- unused built-ins go (dashboards shared with them become private: ON DELETE SET NULL)
DELETE FROM console_roles r WHERE r.role_id IN ('viewer','analyst','operator')
  AND NOT EXISTS (SELECT 1 FROM console_role_bindings b WHERE b.role_id = r.role_id AND b.revoked_at IS NULL);

-- bindings no longer carry a scope
DROP INDEX console_role_bindings_active_unique_idx;
ALTER TABLE console_role_bindings DROP CONSTRAINT console_role_bindings_group_fk;
ALTER TABLE console_role_bindings DROP COLUMN asset_group_id;
CREATE UNIQUE INDEX console_role_bindings_active_unique_idx ON console_role_bindings
  (user_id, service_account_id, role_id) NULLS NOT DISTINCT WHERE revoked_at IS NULL;

-- people
ALTER TABLE console_users
  ADD COLUMN email text CHECK (email IS NULL OR (char_length(email) <= 254 AND email ~ '^[^@\s]+@[^@\s]+$')),
  ADD COLUMN auth_source text NOT NULL DEFAULT 'password' CHECK (auth_source IN ('password','sso')),
  ADD COLUMN last_sign_in_at timestamptz;

GRANT SELECT, INSERT, UPDATE, DELETE ON console_roles, console_role_permissions, console_role_groups TO "openvibes-console";
GRANT UPDATE (email, display_name, last_sign_in_at) ON console_users TO "openvibes-console";
```

Check `gen_random_uuid()` is available (PostgreSQL 13+ core). If the
revoked scoped bindings' `asset_group_id` history matters to the audit
page, keep it by copying it into the audit detail before the column is
dropped: insert one `audit_log` row per moved binding, action
`rbac.binding.migrated`, with detail `{old_role, groups, new_role}`.
Register 52 and set `SCHEMA_VERSION` = 52.

- [ ] **Step 3: Write `console_roles.rs`.**
  - `grants` is one query:

```sql
SELECT r.role_id, r.all_hosts,
       COALESCE(array_agg(DISTINCT rp.permission_id) FILTER (WHERE rp.permission_id IS NOT NULL), '{}'),
       COALESCE(array_agg(DISTINCT rg.asset_group_id::text) FILTER (WHERE rg.asset_group_id IS NOT NULL), '{}')
FROM console_role_bindings b JOIN console_roles r USING (role_id)
LEFT JOIN console_role_permissions rp USING (role_id)
LEFT JOIN console_role_groups rg USING (role_id)
WHERE b.revoked_at IS NULL AND (b.user_id = $1::uuid OR b.service_account_id = $2::uuid)
GROUP BY r.role_id, r.all_hosts
```

  - Reach: `all_hosts` → `All`; otherwise non-empty groups → `Groups`;
    otherwise `None`.
  - Writes run in one transaction:
    - the existing advisory lock `ACCESS_BINDING_LOCK`;
    - `SELECT … FOR UPDATE` on the role;
    - version check;
    - map the unique-index violation on `lower(display_name)` (SQLSTATE
      23505, constraint `console_roles_name_unique`) to `NameTaken`;
    - `version = version + 1`;
    - replace permissions and groups;
    - insert the audit row (`rbac.role.created/updated/deleted`, target
      kind `role`, detail `{name, permissions, reach}`).
  - New role IDs are `"r_" + 16 lowercase hex`. Use the crate's existing
    random helper; if there is none, use `rand` as the console does.
  - Refuse `admin` in update and delete with `Protected`.
  - `delete_role` counts active bindings and returns `InUse(n)` when
    n > 0.

- [ ] **Step 4: Generalise the last-admin guard.**
  - In `revoke_user_role_binding`, drop the `group_id.is_none()`
    condition; the rule becomes "role is `admin` and the target is
    enabled".
  - Add `pub async fn enabled_administrators(tx: &Transaction<'_>) -> Result<i64, StoreError>`
    and use it from `revoke_user_role_binding` and `disable_local_user`
    (Task 6 calls it).
  - `disable_local_user` must also take `ACCESS_BINDING_LOCK`. It returns
    a new `pub enum DisableOutcome { Disabled, NotFound, LastAdministrator }`
    in place of `bool`; update its admin-CLI caller to print "That is the
    last enabled Administrator." and exit 1.

- [ ] **Step 5: Run the store tests.**

Run: `cargo test -p platform-store --test custom_roles --test console_auth --test migrate`
Expected: PASS.

- [ ] **Step 6: Commit.**

```bash
git add -A && git commit -m "store: custom roles with a host reach; migration 52 converts scoped bindings into roles

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 3: The access check reads roles from the database

**Files:**
- Modify: `crates/openvibes-console/src/access/rbac.rs`. Rewrite it:
  delete `BuiltInRole`, `RoleBinding`, `builtin_roles*`, and add
  `resolve_capabilities(&[Grant])`.
- Modify: `crates/openvibes-console/src/access/guard.rs`. The two
  duplicated loops become one call.
- Modify: `crates/openvibes-console/src/access/session.rs`.
- Modify: `crates/openvibes-console/src/access/users.rs:132` and
  `service_accounts.rs:96`. Role validation goes to the DB (an unknown
  role is a 400 `unknown_role`).
- Modify: `crates/openvibes-console/src/lib.rs` (re-exports).
- Modify: `crates/openvibes-console/src/seeded/access.rs` and
  `seeded/persona.rs`. Personas build their capabilities from
  `TEMPLATES`: viewer → Viewer, analyst → Analyst, operator → Operator,
  scoped_operator → Operator on group Prod, admin → every permission.
- Modify: `crates/openvibes-console/src/bin/export_openapi.rs` (drop
  `--roles`).
- Delete: `crates/openvibes-console/web/src/api/roles.json` and
  `web/src/app/roles.ts`. Callers switch to the live role list:
  - `panels/admin/ServiceAccountPanel.tsx` uses
    `useResource("/api/v1/roles")`;
  - `dashboards/DashboardsView.tsx` uses the same;
  - `UserPanel.tsx` is replaced in Task 9; until then it reads
    `/api/v1/roles`.
- Modify: `crates/openvibes-admin/src/user.rs`. `--role` becomes a role ID
  string (default `admin`); `BuiltInRole` goes. `user list` prints role
  names from `console_roles::list_roles`.
- Modify: `crates/platform-store/src/console_triage.rs` (~L385). The
  assignee query swaps `b.role_id IN ('analyst','admin')` for a join on
  `console_role_permissions` holding the matching `*.triage` permission.
- Test: `crates/openvibes-console/src/access/rbac.rs` (unit),
  `crates/openvibes-console/tests/auth_http.rs`.

**Interfaces:**
- Consumes: `platform_store::console_roles::{grants, Grant, Reach, Principal}`
  (Task 2) and `catalogue::def` (Task 1).
- Produces:
  - `pub fn resolve_capabilities(grants: &[platform_store::console_roles::Grant]) -> Vec<EffectiveCapability>`;
  - `pub(crate) async fn principal_capabilities(client: &Client, principal: Principal<'_>) -> Result<Vec<EffectiveCapability>, StoreError>`
    in `rbac.rs`, used by guard and session.
  - `EffectiveCapability`/`PermissionScope` are unchanged on the wire.

- [ ] **Step 1: Write the failing unit tests** in `rbac.rs`:

```rust
fn g(role: &str, perms: &[&str], reach: Reach) -> Grant {
    Grant { role_id: role.into(), permissions: perms.iter().map(|s| s.to_string()).collect(), reach }
}
fn scope_of(caps: &[EffectiveCapability], p: Permission) -> Option<PermissionScope> {
    caps.iter().find(|c| c.permission == p).map(|c| c.scope.clone())
}

#[test]
fn host_permissions_follow_the_union_of_reaches_and_platform_ones_are_global() {
    let caps = resolve_capabilities(&[
        g("a", &["hosts.read", "access.read"], Reach::Groups(vec!["lab".into()])),
        g("b", &["hosts.read"], Reach::Groups(vec!["prod".into()])),
    ]);
    assert_eq!(scope_of(&caps, Permission::HostsRead), Some(PermissionScope::AssetGroups { asset_group_ids: vec!["lab".into(), "prod".into()] }));
    assert_eq!(scope_of(&caps, Permission::AccessRead), Some(PermissionScope::Global));
}

#[test]
fn all_hosts_dominates_and_reach_none_grants_no_host_permission() {
    let caps = resolve_capabilities(&[
        g("a", &["alarms.read"], Reach::Groups(vec!["lab".into()])),
        g("b", &["alarms.read"], Reach::All),
        g("c", &["hosts.read", "audit.read"], Reach::None),
    ]);
    assert_eq!(scope_of(&caps, Permission::AlarmsRead), Some(PermissionScope::Global));
    assert_eq!(scope_of(&caps, Permission::HostsRead), None);
    assert_eq!(scope_of(&caps, Permission::AuditRead), Some(PermissionScope::Global));
}

#[test]
fn administrator_has_everything_whatever_is_stored() {
    let caps = resolve_capabilities(&[g("admin", &[], Reach::None)]);
    assert_eq!(caps.len(), 48);
    assert!(caps.iter().all(|c| c.scope == PermissionScope::Global));
}

#[test]
fn unknown_stored_ids_are_ignored() {
    let caps = resolve_capabilities(&[g("a", &["agents.read"], Reach::All)]);
    assert!(caps.is_empty());
}
```

Run: `cargo test -p openvibes-console --lib access::rbac`
Expected: FAIL (signature mismatch).

- [ ] **Step 2: Implement.**

```rust
pub fn resolve_capabilities(grants: &[Grant]) -> Vec<EffectiveCapability> {
    let admin = grants.iter().any(|g| g.role_id == ADMIN_ROLE);
    Permission::ALL.iter().filter_map(|&p| {
        if admin { return Some(EffectiveCapability { permission: p, scope: PermissionScope::Global }); }
        let holders = grants.iter().filter(|g| g.permissions.iter().any(|id| id == p.id()));
        let mut groups = BTreeSet::new();
        let mut global = false;
        for g in holders {
            match (def(p).scope, &g.reach) {
                (Scope::Platform, _) | (Scope::Host, Reach::All) => global = true,
                (Scope::Host, Reach::Groups(ids)) => groups.extend(ids.iter().cloned()),
                (Scope::Host, Reach::None) => {}
            }
        }
        if global { Some(EffectiveCapability { permission: p, scope: PermissionScope::Global }) }
        else if !groups.is_empty() { Some(EffectiveCapability { permission: p, scope: PermissionScope::AssetGroups { asset_group_ids: groups.into_iter().collect() } }) }
        else { None }
    }).collect()
}
pub const ADMIN_ROLE: &str = "admin";
```

  Wire `principal_capabilities` into `guard.rs`, for both bearer and
  session, and into `session.rs`, replacing the three `BuiltInRole::from_id`
  loops. `session.rs` keeps stripping `AssistantUse` when the assistant is
  off.

- [ ] **Step 3: Add the HTTP regression test** `service_token_follows_role_edits`
  to `tests/auth_http.rs`:
  1. Create role R with `hosts.read`, reach all, using
     `console_roles::create_role`.
  2. Create a service account bound to R and issue it a token.
  3. `GET /api/v1/agents` with the bearer token returns 200.
  4. `update_role` R to drop `hosts.read`; the same request now returns
     403.
  5. Restore it; 200 again.

  Also rewrite the existing scoped-binding journeys in `auth_http.rs` to
  create a role with reach `Groups([lab])` in place of a scoped binding.
  The assertions on which agents are visible stay the same.

- [ ] **Step 4: Run the console tests and the gate.**

Run: `eval "$(scripts/test-db.sh)"; cargo test -p openvibes-console && cargo test -p openvibes-admin && cargo test -p platform-store`
Expected: PASS. Then run the full gate from testing.md, and the demo
e2e.

- [ ] **Step 5: Docs and commit.**

  Update `docs/components/console-rbac.md` (resolution rules, admin),
  `console-auth-http.md`, `openvibes-admin.md` (`--role <id>`) and the
  `src/access/README.md` table.

```bash
git add -A && git commit -m "console: capabilities come from database roles and their reach; built-in role table removed

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 4: The share check (pure)

**Files:**
- Create: `crates/openvibes-console/src/access/share.rs`.
- Modify: `crates/openvibes-console/src/access/mod.rs` and
  `src/access/README.md`.

**Interfaces:**
- Consumes: `EffectiveCapability`, `PermissionScope` (unchanged),
  `catalogue::{def, Scope}`.
- Produces:

```rust
pub enum RoleReach<'a> { None, All, Groups(&'a [String]) }
pub struct ShareRefusal { pub permission: Permission, pub reason: &'static str }
/// Does a role with these permissions and this reach fit inside the editor's capabilities?
pub fn fits(editor: &[EffectiveCapability], permissions: &[Permission], reach: RoleReach<'_>) -> Result<(), ShareRefusal>;
/// Are all of these roles inside the editor's share (People/Service-account visibility, §4.4)?
pub fn all_fit<'a>(editor: &[EffectiveCapability], roles: impl IntoIterator<Item = (&'a [Permission], RoleReach<'a>)>) -> bool;
pub fn refusal_message(r: &ShareRefusal) -> String; // "You can only give roles that fit inside your own access (<console text> is outside it)"
```

- [ ] **Step 1: Write the failing tests:**

```rust
use super::*;
fn cap(p: Permission, groups: Option<&[&str]>) -> EffectiveCapability {
    EffectiveCapability { permission: p, scope: match groups { None => PermissionScope::Global,
        Some(g) => PermissionScope::AssetGroups { asset_group_ids: g.iter().map(|s| s.to_string()).collect() } } }
}
#[test] fn a_permission_the_editor_lacks_is_refused() {
    let r = fits(&[cap(Permission::HostsRead, None)], &[Permission::HostsRevoke], RoleReach::All).unwrap_err();
    assert_eq!(r.permission, Permission::HostsRevoke);
}
#[test] fn host_permissions_must_cover_the_roles_reach() {
    let editor = [cap(Permission::AlarmsRead, Some(&["lab"]))];
    assert!(fits(&editor, &[Permission::AlarmsRead], RoleReach::Groups(&["lab".into()])).is_ok());
    assert!(fits(&editor, &[Permission::AlarmsRead], RoleReach::Groups(&["prod".into()])).is_err());
    assert!(fits(&editor, &[Permission::AlarmsRead], RoleReach::All).is_err());
    assert!(fits(&editor, &[Permission::AlarmsRead], RoleReach::None).is_ok());
}
#[test] fn platform_permissions_ignore_reach() {
    let editor = [cap(Permission::AuditRead, None)];
    assert!(fits(&editor, &[Permission::AuditRead], RoleReach::Groups(&["lab".into()])).is_ok());
}
#[test] fn editing_own_role_cannot_widen_reach() {
    // the editor holds HostsRead only on lab (through role X); editing role X to reach All is refused
    let editor = [cap(Permission::HostsRead, Some(&["lab"])), cap(Permission::AccessRoles, None)];
    let r = fits(&editor, &[Permission::HostsRead], RoleReach::All).unwrap_err();
    assert_eq!(r.permission, Permission::HostsRead);
}
#[test] fn the_refusal_names_the_permission_in_console_words() {
    let msg = refusal_message(&ShareRefusal { permission: Permission::HostsRevoke, reason: "outside" });
    assert!(msg.contains("Revoke a host"));
}
```

Run: `cargo test -p openvibes-console --lib access::share`
Expected: FAIL (module missing).

- [ ] **Step 2: Implement.**

  For each permission, find the editor's capability:
  - no capability → refused;
  - platform scope → ok;
  - host scope:
    - editor `Global` → ok;
    - editor `AssetGroups(e)`:
      - role reach `None` → ok;
      - `All` → refused;
      - `Groups(r)` → ok only if r ⊆ e.

  Run the tests. Expected: PASS.

- [ ] **Step 3: Commit.**

```bash
git add -A && git commit -m "console: the share check (nobody grants more than they hold)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 5: Roles API

**Files:**
- Create: `crates/openvibes-console/src/access/roles.rs` (handlers,
  utoipa paths, request/response types).
- Modify: `crates/openvibes-console/src/access/mod.rs` `routes()`, and the
  OpenAPI path list in `src/http/openapi.rs`.
- Test: `crates/openvibes-console/tests/roles_http.rs` (new, using the
  helpers pattern of `tests/users_http.rs`).

**Interfaces:**
- Routes:
  - `GET /v1/permissions` returns `catalogue_json()` as JSON (any
    signed-in user).
  - `GET /v1/role-templates` (any signed-in user).
  - `GET /v1/roles` (`access.read`) returns `[RoleView]`.
  - `POST /v1/roles` (`access.roles` + csrf + share) takes `SaveRole`
    and returns 201 `RoleView`.
  - `GET /v1/roles/{role_id}` (`access.read`).
  - `PATCH /v1/roles/{role_id}` (`access.roles` + csrf + share on the
    resulting role) takes `SaveRole` with a `version` field.
  - `DELETE /v1/roles/{role_id}` (`access.roles` + csrf; share on the
    role being deleted).
- Types:

```rust
#[derive(Deserialize, ToSchema)] #[serde(deny_unknown_fields)]
pub struct SaveRole { pub name: String, #[serde(default)] pub description: String,
    pub permissions: Vec<Permission>, pub reach: ReachInput, pub version: Option<i32> }
#[derive(Deserialize, Serialize, ToSchema)] #[serde(tag = "kind", rename_all = "snake_case")]
pub enum ReachInput { None, All, Groups { asset_group_ids: Vec<String> } }
#[derive(Serialize, ToSchema)]
pub struct RoleView { pub role_id: String, pub name: String, pub description: String, pub builtin: bool,
    pub permissions: Vec<Permission>, pub reach: ReachView, pub members: i64, pub version: i32 }
#[derive(Serialize, ToSchema)] #[serde(tag = "kind", rename_all = "snake_case")]
pub enum ReachView { None, All, Groups { groups: Vec<GroupRef> } }
#[derive(Serialize, ToSchema)] pub struct GroupRef { pub asset_group_id: String, pub name: String }
```

- **Validation:**
  - `name` is trimmed, 1–64 characters, with no control characters;
  - `description` is at most 500 characters;
  - the permissions must already be closed under needs; if not, return
    422 `missing_needs` with `{"permission": "<id>", "needs": "<id>"}`;
  - groups are 1–64 unique UUIDs that exist (otherwise 422
    `unknown_group`).
- **Errors:** 409 `stale_role` / `role_name_taken` / `role_in_use`
  (with `{"holders": n}`); 403 `permission_denied` with the share
  message; 403 `protected_role` for `admin`.

- [ ] **Step 1: Write the failing HTTP tests** in `tests/roles_http.rs`:
  - `an_admin_creates_edits_and_deletes_a_role`: POST, then GET shows it
    with members 0, then PATCH with `version: 1` (200, version 2), then
    PATCH with `version: 1` (409 `stale_role`), then DELETE (204). The
    audit has `rbac.role.created`, `rbac.role.updated` and
    `rbac.role.deleted`.
  - `role_names_are_unique_regardless_of_case`: create "Analyst", then
    create "analyst" → 409 `role_name_taken`; renaming another role to
    "ANALYST" also → 409.
  - `permissions_must_include_what_they_need`: `["cases.assign"]` → 422
    `missing_needs` naming `cases.write`.
  - `the_administrator_role_cannot_be_changed_or_deleted`: PATCH and
    DELETE `admin` → 403 `protected_role`.
  - `a_held_role_cannot_be_deleted`: → 409 `role_in_use` with
    `holders: 1`.
  - `team_admin_cannot_widen_a_role_they_hold`:
    1. Seed role "Windows lead" (`access.read`, `access.roles`,
       `hosts.read`, reach Groups[win]).
    2. Bind user `wl` to it.
    3. As `wl`, PATCH that role to reach All → 403 whose message names
       "View hosts".
    4. As `wl`, POST a role with `hosts.revoke` → 403 naming "Revoke a
       host".
    5. As `wl`, POST a role with `hosts.read` on Groups[win] → 201.
  - `roles_are_listed_with_their_reach_and_members`.

Run: `cargo test -p openvibes-console --test roles_http`
Expected: FAIL (404 on `/api/v1/roles`).

- [ ] **Step 2: Implement `roles.rs`.**
  - Use `authenticated_permission(&state, &headers, Permission::AccessRoles, true)`.
  - Load the editor's capabilities with `principal_capabilities` (Task 3).
  - Check `share::fits` before calling `console_roles::create_role` /
    `update_role` / `delete_role`.
  - Map `RoleWrite` to the statuses above.

- [ ] **Step 3: Register the routes and the OpenAPI paths, then
  regenerate.**

```bash
cargo run --locked -p openvibes-console --bin export_openapi > docs/api/console-v1.openapi.json
npm --prefix crates/openvibes-console/web run generate:api
```

Run: `cargo test -p openvibes-console --test roles_http --test api_contract`
Expected: PASS.

- [ ] **Step 4: Commit.**

```bash
git add -A && git commit -m "console: roles API (create, edit, delete) with the share check

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 6: People API (users, their roles, disable, reset, service-account roles)

**Files:**
- Create: `crates/openvibes-console/src/access/people.rs` (list, detail,
  create, patch, disable/enable, reset password).
- Create: `crates/openvibes-console/src/access/people_roles.rs` (give and
  remove roles for users and service accounts).
- Create: `crates/platform-store/src/console_people.rs` (user detail with
  roles, recent activity from `audit_log` where `actor_id = user`, last
  10; set details; enable).
- Modify: `crates/openvibes-console/src/access/mod.rs`. Remove
  `GET /v1/access-control`, `POST /v1/access-control/users`,
  `POST /v1/access-control/bindings` and
  `DELETE /v1/access-control/bindings/{id}`. Delete
  `access/inventory.rs` and `access/bindings.rs`, and move what
  `users.rs` keeps (`change_password` and helpers) into `people.rs`, or
  keep `users.rs` for the password route only.
- Modify: `crates/openvibes-console/src/access/service_accounts.rs`.
  Create takes `role_ids: Vec<String>` (at least one); add role routes.
- Add `GET /v1/host-groups`, returning `[{asset_group_id, name, selectors, roles: n}]`
  with `access.read` or `host_groups.manage`. It feeds the Host groups
  tab and the role reach picker until step 2 replaces it.
- Test: `crates/openvibes-console/tests/people_http.rs` (new).

**Interfaces:**
- Routes:
  - `GET /v1/users` (`access.read`) returns `[PersonRow]`, filtered to
    the share for non-administrators (§4.4).
  - `GET /v1/users/{user_id}` (`access.read`, or self) returns
    `PersonView { user_id, username, display_name, email, enabled, auth_source, last_sign_in_at, created_at, roles: Vec<RoleView>, access: Vec<AccessLine>, recent: Vec<ActivityLine> }`,
    where:
    - `AccessLine { permission, label, area, applies: "all" | "groups" | "platform", groups: Vec<GroupRef>, from_role: String }`;
    - `ActivityLine { action, target, at }`.
  - `POST /v1/users` (`access.users` + share for the given roles) takes
    `{username, display_name, email?, role_ids}` and returns 201 with
    `CreatedUser` (a one-time password).
  - `PATCH /v1/users/{id}` (self, or `access.users` within the share)
    takes `{display_name?, email?}`.
  - `POST /v1/users/{id}/disable` and `/enable` (`access.users` within
    the share; never self-disable). A last-admin refusal is 409
    `last_administrator`.
  - `POST /v1/users/{id}/reset-password` (`access.users` within the
    share) returns `{one_time_password}`. It sets `password_must_change`
    and revokes the user's sessions.
  - `PUT /v1/users/{id}/roles/{role_id}` and `DELETE` likewise
    (`access.grant` + the share on the role; last-admin guarded; nobody
    changes their own roles).
  - `PUT|DELETE /v1/service-accounts/{id}/roles/{role_id}` (`access.grant`
    + share).

- [ ] **Step 1: Write the failing HTTP tests** in `tests/people_http.rs`:
  - `people_list_shows_roles_with_reach_and_sign_in_source`: rows carry
    `auth_source: "password"`, `last_sign_in_at` set after sign-in, and
    role badges with reach.
  - `a_team_admin_sees_only_people_inside_their_share`: the Windows lead
    sees people whose roles all fit; an Administrator is not listed for
    them.
  - `giving_a_role_needs_the_whole_role_inside_the_share`: PUT a role
    with `hosts.revoke` as the Windows lead → 403.
  - `nobody_changes_their_own_roles`: PUT on self → 403.
  - `two_concurrent_removals_leave_one_administrator`:
    1. Two admins, A and B.
    2. Concurrently (`tokio::join!`), A removes B's admin role and B
       removes A's.
    3. Exactly one gets 204, the other 409 `last_administrator`.
    4. Then disabling the remaining admin → 409.
  - `person_page_lists_access_by_where_it_applies_and_recent_activity`:
    `access` has lines with `applies` of all, groups and platform, plus
    `from_role`; `recent` lists the person's last actions.
  - `reset_password_returns_a_one_time_password_and_ends_sessions`.
  - `editing_details_works_for_self_and_validates_email`: a bad email →
    422.

Run: `cargo test -p openvibes-console --test people_http`
Expected: FAIL (404).

- [ ] **Step 2: Implement** the store functions in `console_people.rs`
  and the handlers in `people.rs` and `people_roles.rs`.
  - Audit actions: `user.updated`, `user.disabled`, `user.enabled`,
    `user.password_reset`, `rbac.binding.created` and
    `rbac.binding.revoked`, each in the change's transaction.
  - The one-time password uses the generator in today's `users.rs`.

- [ ] **Step 3: Fix the tests that used the removed routes**
  (`users_http.rs`, `auth_http.rs`, `cases_http.rs`, …).
  - Use `POST /v1/users` and `PUT /v1/users/{id}/roles/{role}`.
  - Update `docs/components/console-auth-http.md` (route table) and
    `console-auth-store.md`.

Run: `cargo test -p openvibes-console && cargo test -p platform-store`
Expected: PASS.

- [ ] **Step 4: Regenerate the OpenAPI and client types (as in Task 5),
  then commit.**

```bash
git add -A && git commit -m "console: people API (list, person page, roles, disable, reset) replaces access-control routes

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 7: Web foundations (permission helpers, Settings tabs, routing)

**Files:**
- Create: `crates/openvibes-console/web/src/app/permissions.ts` (catalogue
  from `api/permissions.json`, templates from `api/templates.json`,
  closure helpers).
- Create: `crates/openvibes-console/web/src/app/permissions.test.ts`.
- Modify: `crates/openvibes-console/web/src/app/session.tsx`:
  - drop `global` from `Access`;
  - `allows(session, { permission })`;
  - `can(permission)`.

  Fix every caller (`grantsAny`, `RULE_READERS`, the registry,
  `Settings.tsx`, the command palette).
- Modify: `crates/openvibes-console/web/src/views/admin/settings/Settings.tsx`:
  - The tabs are People (`access.read`), Roles (`access.read`), Host
    groups (`access.read` or `host_groups.manage`), Service accounts
    (`service_accounts.read`), Enrollment (`tokens.read`), Rule sets
    (`rules.read`) and Assistant (`assistant.admin`).
  - The "General" tab arrives in step 3.
  - Sub-routes: `/settings/roles/new`, `/settings/roles/{id}` and
    `/settings/people/{id}` render a full page in place of the tab
    panel, with the tabs still shown.
- Modify: `crates/openvibes-console/web/src/app/registry.tsx`, where
  Settings gets `prefix: "/settings/"`.
- Create: `crates/openvibes-console/web/src/views/admin/settings/HostGroups.tsx`,
  holding today's asset-group cards moved out of `Access.tsx` unchanged.
  It reads `GET /api/v1/host-groups`.
- Delete: `web/src/views/admin/settings/Access.tsx` and
  `web/src/panels/admin/UserPanel.tsx`; remove the `user` panel kind.
- Modify: the folder READMEs (`views/admin/settings`, `panels/admin`,
  `app`).

**Interfaces:**
- Produces, in `app/permissions.ts`:

```ts
export type PermissionId = Permission;                       // generated union
export type PermissionDef = { id: PermissionId; area: string; label: string; column: "View" | "Change" | "Export" | "Approve and publish"; scope: "host" | "platform"; needs: PermissionId[] };
export const CATALOGUE: readonly PermissionDef[];
export const AREAS: readonly string[];                        // in catalogue order
export const TEMPLATES: readonly { name: string; description: string; permissions: PermissionId[] }[];
export function turnOn(on: ReadonlySet<PermissionId>, p: PermissionId): { next: Set<PermissionId>; added: PermissionId[] };   // p + its needs, transitively
export function turnOff(on: ReadonlySet<PermissionId>, p: PermissionId): { next: Set<PermissionId>; removed: PermissionId[] }; // p + everything that needs it, transitively
export function labelOf(p: PermissionId): string;
```

- [ ] **Step 1: Write the failing Vitest file** `app/permissions.test.ts`:

```ts
import { describe, expect, it } from "vitest";
import { CATALOGUE, TEMPLATES, turnOff, turnOn } from "./permissions";

describe("permission helpers", () => {
  it("turning on Assign cases brings what it needs", () => {
    const { next, added } = turnOn(new Set(), "cases.assign");
    expect([...next].sort()).toEqual(["cases.assign", "cases.read", "cases.write"]);
    expect(added.sort()).toEqual(["cases.read", "cases.write"]);
  });
  it("turning off View cases takes what depends on it", () => {
    const { next, removed } = turnOff(new Set(["cases.read", "cases.write", "cases.assign"]), "cases.read");
    expect(next.size).toBe(0);
    expect(removed.sort()).toEqual(["cases.assign", "cases.write"]);
  });
  it("has 48 permissions and six templates", () => {
    expect(CATALOGUE).toHaveLength(48);
    expect(TEMPLATES.map((t) => t.name)).toEqual(["Viewer", "Analyst", "Operator", "Team lead", "Auditor", "Rule author"]);
  });
});
```

Run: `npm --prefix crates/openvibes-console/web test -- permissions`
Expected: FAIL (module missing).

- [ ] **Step 2: Implement `permissions.ts`.**

  `turnOn` walks `needs` with a stack. `turnOff` repeatedly removes every
  permission whose `needs` include a removed one. Run the test.
  Expected: PASS.

- [ ] **Step 3: Make the Settings, routing and `can()` changes.**

  Run: `npm --prefix crates/openvibes-console/web run build && npm --prefix crates/openvibes-console/web test`
  Expected: PASS. `registry.test.tsx` is updated for the new tabs and
  access lists.

- [ ] **Step 4: Commit.**

```bash
git add -A && git commit -m "web: permission catalogue helpers, Settings tabs (People, Roles, Host groups…), settings sub-pages

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 8: Roles list and the role page (screens 1–5)

The visual reference is `docs/specs/rbac-ui/gen.py` screens 1–5. Build
with the existing `ui/` pieces (`DataTable`, `Select`, `Switch`,
`ViewHeader`, `Field`, `Icon`), and use no native `<select>`
(`ui/no-native-controls.test.ts`).

**Files:**
- Create: `crates/openvibes-console/web/src/views/admin/settings/Roles.tsx`
  (the list).
- Create: `crates/openvibes-console/web/src/views/admin/roles/RolePage.tsx`
  (load or new, state, save).
- Create: `crates/openvibes-console/web/src/views/admin/roles/PermissionMatrix.tsx`.
- Create: `crates/openvibes-console/web/src/views/admin/roles/HostsPicker.tsx`.
- Create: `crates/openvibes-console/web/src/views/admin/roles/RoleBar.tsx`
  (the sticky summary bar).
- Create: `crates/openvibes-console/web/src/views/admin/roles/README.md`.
- Create: `crates/openvibes-console/web/src/views/admin/roles/RolePage.test.tsx`.
- Modify: `web/src/styles/*.css`. Add the matrix and sticky-bar styles
  next to the existing settings styles.

**Interfaces:**
- Consumes: `CATALOGUE`, `AREAS`, `TEMPLATES`, `turnOn`, `turnOff`,
  `labelOf` (Task 7); `GET/POST/PATCH /api/v1/roles`;
  `GET /api/v1/host-groups` (Task 6).
- Produces: `RolePage({ roleId }: { roleId: string | "new" })` and
  `Roles()`.

**What each part does (from the approved screens):**
- **Roles list:** name, description, members, where it applies ("All
  hosts" / group names / "No hosts"), and permissions count.
  Administrator comes first with a "Protected" badge. "+ New role" (with
  `access.roles`) goes to `/settings/roles/new`. Templates are not listed.
- **Role page:** full width.
  - **Name and Start from** sit side by side as 1 and 2. Start from is
    Blank or one of the six templates; changing it replaces the
    permission set with the template's. Each chip that differs from the
    previous choice gets an outline (added green, removed red) until the
    next change.
  - **3, Permissions:** the matrix.
    - Rows are `AREAS`, and columns are View / Change / Export /
      Approve and publish.
    - Each permission is a chip (`aria-pressed`) in its column cell.
    - Each row has an "All" toggle, and each column heading toggles that
      column in every area.
    - Platform-scope permissions get an ⓘ with the title from Global
      Constraints: at area level when every permission in the area is
      platform scope, otherwise on the chip.
    - A click uses `turnOn` / `turnOff`, and when others changed, a
      notice under the matrix says "Also turned on: …" / "Also turned
      off: …".
  - **4, Hosts:**
    - a search field over host groups with "All hosts" first;
    - chosen groups show as chips with an × icon;
    - choosing All hosts clears the groups;
    - nothing chosen means "No hosts", and a note says host permissions
      then apply nowhere.
  - **Sticky bar:** "<n> permissions · <hosts summary>", Cancel, then
    "Create role" (new; disabled until there is a name, with the title
    "Give it a name first") or "Save role" (existing). A 403/409/422
    shows the server message above the bar. A 409 `stale_role` reloads
    the role and says "Someone else changed this role; your edits were
    not saved."
  - **Administrator** opens read-only, with "Administrator has every
    permission on all hosts and cannot be changed."

- [ ] **Step 1: Write the failing component tests** in `RolePage.test.tsx`
  (Vitest + Testing Library, mocking `fetch` as the existing view tests
  do):
  - "starts blank with no hosts": no chip is pressed; the bar says
    "0 permissions · No hosts"; Create role is disabled.
  - "picking Analyst fills the matrix and outlines the change": after
    choosing Analyst in Start from, "Triage alarms" is pressed and has
    `data-changed="added"`.
  - "Assign cases brings View cases and says so": clicking Assign
    presses "Create and edit cases" and "View cases" and shows the text
    "Also turned on: Create and edit cases, View cases".
  - "turning off View cases turns off Assign and says so".
  - "platform permissions have the info mark": the Rule sets area row
    has an element with the title "Applies to the whole platform,
    whatever hosts the role reaches".
  - "All hosts replaces chosen groups": choose WindowsServers, then All
    hosts; the chips show only "All hosts".
  - "Create sends the closed set and reach": the POST body has
    `permissions` including the needs and
    `reach: {kind: "groups", asset_group_ids: [...]}`.
  - "Administrator is read-only".

Run: `npm --prefix crates/openvibes-console/web test -- RolePage`
Expected: FAIL (module missing).

- [ ] **Step 2: Implement the components** to make the tests pass. Keep
  each file under 300 lines; the matrix is its own component.

- [ ] **Step 3: Compare by eye with the mockup.**
  1. Run the demo build (Task 10 adds the demo routes; until then use the
     live console from `scripts/console-e2e-server.sh` against the test
     DB).
  2. Open `/settings/roles/new` at 1440×900 and screenshot it.
  3. Compare it with screen 2 (`python3 docs/specs/rbac-ui/gen.py base OUT`,
     open `OUT/2-new-role.html`). Layout and copy must match. Colours
     come from the console tokens.

- [ ] **Step 4: Commit.**

```bash
git add -A && git commit -m "web: Roles list and the role page (matrix, start from, hosts, sticky bar)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 9: People list, person page, add role (screens 6–8)

**Files:**
- Create: `crates/openvibes-console/web/src/views/admin/settings/People.tsx`.
- Create: `crates/openvibes-console/web/src/views/admin/people/PersonPage.tsx`.
- Create: `crates/openvibes-console/web/src/views/admin/people/AddRoleDialog.tsx`.
- Create: `crates/openvibes-console/web/src/views/admin/people/NewPersonDialog.tsx`
  (replaces UserPanel's new-user form; shows the one-time password once).
- Create: `crates/openvibes-console/web/src/views/admin/people/README.md`.
- Create: `crates/openvibes-console/web/src/views/admin/people/PersonPage.test.tsx`.

**Interfaces:**
- Consumes: `GET /api/v1/users`, `GET/PATCH /api/v1/users/{id}`,
  `POST …/disable|enable|reset-password`,
  `PUT|DELETE …/roles/{role_id}`, `GET /api/v1/roles` (Task 6).

**What each part does:**
- **People list:**
  - One search field (the outer Settings filter is gone).
  - Columns:
    - Person (display name, username);
    - Roles, as badges "<role> · <where>";
    - Signs in with ("Password", or "Single sign-on" for `sso`);
    - Status (Active / Disabled);
    - Last sign-in.
  - "+ New person" with `access.users`.
  - A row opens `/settings/people/{id}`.
- **Person page** (one page, no tabs):
  - **Header:** initials avatar (no camera button in this step), name,
    status badge, and "<n> roles · <n> permissions · last signed in
    <when>". Edit details (self or `access.users`), and ⋯ with Reset
    password and Disable/Enable (`access.users`, hidden on self).
  - **Left column:** Details (read-only until Edit: display name, email,
    username, created) and Recent activity (the `recent` lines, plus a
    link to the Audit log filtered to this person).
  - **Right column:**
    - **Roles:** compact cards (name, where it applies, permissions
      count, Remove). "+ Add role" opens AddRoleDialog.
    - **Access**, grouped under "On all hosts", "Only on <groups>" and
      "Across the platform", each line "<permission> · from <role>".
  - **Errors:** a 409 `last_administrator` shows "This is the last
    Administrator. Give someone else the Administrator role first."
- **AddRoleDialog:** a search field over the roles the person does not
  hold. Each role shows where it applies and how many permissions it
  has. Roles outside the viewer's share are not offered (the server
  refuses them anyway).

- [ ] **Step 1: Write the failing tests** in `PersonPage.test.tsx`:
  - "groups access by where it applies" (three headings, lines with
    "from <role>");
  - "Add role sends PUT and refreshes";
  - "the last Administrator message is shown on 409";
  - "own page has no Disable".

  Add a People list test: "badges show where each role applies".

Run: `npm --prefix crates/openvibes-console/web test -- People`
Expected: FAIL.

- [ ] **Step 2: Implement**, then run the tests. Expected: PASS.

- [ ] **Step 3: Compare by eye** with screens 6, 7 and 8 (as in Task 8,
  Step 3).

- [ ] **Step 4: Commit.**

```bash
git add -A && git commit -m "web: People list, person page and Add role

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 10: Demo server and demo e2e

**Files:**
- Modify: `crates/openvibes-console/web/src/demo/routes/access.ts`. It
  implements the routes of Tasks 5–6:
  - `/api/v1/permissions`, `/role-templates`, `/roles` CRUD, `/users` and
    sub-routes, `/host-groups`, service-account roles;
  - it applies the same share check as the server, using a TS port of
    `fits` in `demo/share.ts`;
  - audit action names match the Global Constraints.
- Create: `crates/openvibes-console/web/src/demo/share.ts`.
- Modify: `crates/openvibes-console/web/src/demo/data.ts`. Roles are the
  migrated shape:
  - Administrator, Analyst (all hosts), Operator (all hosts);
  - "Windows lead" (Team lead template, reach WindowsServers);
  - "Operator (Prod)".
- Modify: `crates/openvibes-console/web/src/demo/context.ts`. Persona
  capabilities come from the persona's demo roles via a TS
  `resolveCapabilities` mirroring Task 3.
- Create: `crates/openvibes-console/web/e2e/demo/roles.spec.ts`.
- Create: `crates/openvibes-console/web/e2e/demo/people.spec.ts`.

- [ ] **Step 1: Write the e2e specs.**
  - `roles.spec.ts`:
    1. As admin, open Settings › Roles and click + New role.
    2. Type the name "Night shift" and pick Analyst; "Triage alarms" is
       pressed.
    3. Click Assign under Cases; the notice says "Also turned on".
    4. Pick the WindowsServers group and click Create role.
    5. The list shows "Night shift · WindowsServers".
  - `people.spec.ts`:
    1. As admin, open a person and add the role "Night shift".
    2. The Access card shows "Only on WindowsServers".
    3. Remove the role.
    4. On your own page, Disable and Remove are not offered. The
       last-Administrator refusal is covered by `people_http.rs` and
       `PersonPage.test.tsx`.

Run: `npm --prefix crates/openvibes-console/web run test:e2e:demo -- roles people`
Expected: FAIL first, then PASS after the demo routes are implemented.

- [ ] **Step 2: Implement the demo routes and data.** Run the whole demo
  e2e suite. Expected: PASS (the other specs still pass with the new
  personas).

- [ ] **Step 3: Commit.**

```bash
git add -A && git commit -m "web demo: custom roles, people and the share check; roles and people e2e

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 11: Live e2e, docs and the gate

**Files:**
- Modify: `crates/openvibes-console/web/e2e/live/console.spec.ts`. Add a
  two-team journey:
  1. Admin creates roles "Linux team" (Analyst template, reach group
     Linux) and "Windows team" (Analyst template, reach group Windows),
     and two people, one per team.
  2. Each person signs in, sees only their own hosts in Hosts and
     Alarms, and cannot open Settings › Roles.
  3. Admin makes the Linux person's role a Team lead role on Linux.
  4. The Linux person can give "Linux team" to a new person, but cannot
     give "Windows team" (refused with the message).
  5. If `scripts/console-e2e-server.sh` seeds agents without tags,
     extend its seed so two agents carry `os=linux` and two
     `os=windows`, and create the groups through the asset-group API.
- Modify: `docs/components/console-rbac.md`, `console-auth-http.md`,
  `console-auth-store.md`, `console-web.md`, `openvibes-admin.md` and
  `platform-store.md`.
- Modify: `docs/components/README.md` if a page is added.
- Modify: `CHANGELOG.md` (if the repository keeps one). Add an entry
  "Custom roles: … Existing roles are kept; scoped grants become roles
  like Operator (Lab)."

- [ ] **Step 1: Write the live journey and run it.**

Run: `eval "$(scripts/test-db.sh)"; nice -n 19 bash scripts/test-console-e2e.sh`
Expected: PASS.

- [ ] **Step 2: Run the full local gate** from
  `~/Projects/OpenVIBES/testing.md`: everything in order, plus the demo
  e2e and the folder READMEs check.

  Expected: all green.

- [ ] **Step 3: Commit, then open the PR** (the user merges).

```bash
git add -A && git commit -m "console: two-team live journey; docs for custom roles and people

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push -u origin roles-people
gh pr create --title "Custom roles and people (roles step 1)" --body "$(cat <<'EOF'
Spec: docs/specs/2026-10-16-roles-permissions-design.md (§16 step 1). Plan: docs/superpowers/plans/2026-10-16-roles-1-roles-and-people.md.

- 48 single-action permissions; custom roles with a host reach; protected Administrator.
- Upgrade keeps everyone's access (scoped grants become roles like "Operator (Lab)"); migrations 51–52 need a backup.
- Roles and People screens (mockups 1–8, no pictures yet).

Local gate green.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

---

## Self-review notes

- **Spec coverage:**
  - §3 → Task 1;
  - §4.1–4.3 → Tasks 2, 3 and 5;
  - §4.4 → Tasks 4, 5 and 6;
  - §4.5 → Task 2 (bindings lose their scope);
  - §4.6 (`auth_source`, `last_sign_in_at`) → Task 2's migration and
    Task 9's column;
  - §6 → Task 3;
  - §12 parts 1–3 → Tasks 1 and 2;
  - §13 roles, users and service-account routes → Tasks 5 and 6;
  - §15 → the tests in each task;
  - screens 1–8 → Tasks 8 and 9.
- **Not in this step (later plans):**
  - the General tab, and the SSO purge setting with it (step 3);
  - host-group kinds and labels (step 2);
  - pictures (step 7);
  - the locked SSO fields of screen 7b, which ship with the SSO spec;
  - case visibility by hosts (§6, the case bullet), which belongs with
    step 5's Cases page. Cases keep today's `cases.read` scoping until
    then.
