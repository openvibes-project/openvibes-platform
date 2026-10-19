# Host groups and labels (roles step 2) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace tag-selected asset groups with three kinds of host group,
and replace host tags with free labels.
- **Automatic:** made from agent facts.
- **Rule:** the user's own, built from OS family, distribution, hostname
  and IP.
- **Manual:** hosts picked by hand.

Upgrading keeps everyone's access unchanged. The work also ships approved
screens 9, 10, 10b and 10c, and a host's groups and labels.

**Architecture:**
- **One SQL function decides membership:** `console_host_in_group(agent_id,
  group_id)`, from the group's kind, its conditions or its picked members,
  and the agent's facts. Every caller uses it: the `agent_visibility`
  helper, the hand-copied membership SQL, rule-set assignment and
  distribution. Membership is never stored, so it is never stale.
- **New agent facts:** ingest records the peer address of the agent's
  mTLS connection as `agents.last_address`. Inventory creates automatic
  groups when a new OS family or distribution appears.
- **API:** the API and web move from `/access-control/asset-groups` and
  `/agents/{id}/tags` to `/host-groups` and `/hosts/{id}/labels`. The
  database keeps the `console_asset_groups` table and `asset_group_id`
  column names to avoid churn across many foreign keys.

**Tech Stack:**
- Rust: axum, utoipa, tokio-postgres/deadpool, hyper/rustls in
  platform-agent-server.
- PostgreSQL: SQL functions and generated columns.
- Web: React and TypeScript, Vitest, Playwright for demo and live e2e.

**Spec:** `docs/specs/2026-10-16-roles-permissions-design.md`: §5
(amended 2026-10-19 with negated conditions, unknown facts, and who may
change groups), §6 (lists follow reach), §12 part 4, §13 (host-group,
label and preview routes), §15 and §16 step 2. The approved screens are 9,
10, 10b and 10c, plus the "Groups and labels" card of screen 17, in
`docs/specs/rbac-ui/approved.md`; see them with
`python3 docs/specs/rbac-ui/gen.py docs/specs/rbac-ui/base OUT`.

**Base:**
- Worktree `~/Projects/OpenVIBES/openvibes-platform-hostgroups`, branch
  `host-groups` from `main` at e781d48 (step 1 merged). The git identity is
  set.
- A code map of the current group, tag and membership code (paths, line
  numbers, every hand-copied membership SQL, the fixture locations) is at
  `/home/lime/.claude/jobs/aaa00361/tmp/hostgroups-code-map.md`. Read it.

## Global Constraints

- **Files:** every file stays under 500 lines, and folder READMEs list
  their files (`scripts/check-folder-readmes.sh`).
- **Docs:** component docs change in the same commit:
  - `console-rbac.md`;
  - `console-auth-http.md`;
  - `console-auth-store.md`;
  - `rule-set-assignment.md`;
  - `console-read.md`;
  - `console-web.md`;
  - `platform-store.md`;
  - `platform-agent-server.md`;
  - `openvibes-ingest.md`.
- **Commits:** end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
  Never push; the controller pushes.
- **This host is the user's desktop and production platform:**
  - Never touch its own openvibes services or database.
  - Tests use only `eval "$(scripts/test-db.sh)"`; stop it afterwards.
  - Every cargo command runs with
    `export CARGO_TARGET_DIR=~/.cache/openvibes-scratch/target CARGO_BUILD_JOBS=6 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0`
    under `nice -n 19 ionice -c3`.
  - Run focused tests while iterating and full suites once. Never run two
    heavy jobs at once.
  - Playwright runs demo with `--workers=4` and live with `--workers=2`.
- **Group kinds:** `automatic` | `rule` | `manual`. Kinds are never mixed.
  Editing an automatic group turns it into `rule`. Deleting an automatic
  group records its key in `console_host_group_dismissed`.
- **Rule conditions:**
  - All conditions must hold. Each has `field`, `negate`, and 1–64
    `values`, any of which may match.
  - `field` is `os_family` | `distribution` | `hostname` | `ip`.
  - There are at most 16 conditions.
  - `hostname` values are glob patterns where `*` is any run of
    characters, matched case-insensitively; `%`, `_` and `\` are literal.
  - `ip` values are CIDR or single addresses, v4 or v6.
  - An unknown fact never satisfies a condition, negated or not.
  - Labels are never a field.
- **Fact values:**
  - `os_family` is lowercase (`linux`, `windows`). Today every `os_id`
    except `windows` is `linux`.
  - `distribution` is lowercase `<os_id> <release>`, where release is
    `os_release` (major version for rocky and almalinux), e.g.
    `debian 12`, `fedora 44`, `rocky 9`.
  - The console shows `Linux` and `Debian 12` (display names come from one
    Rust map).
- **Membership:** only `status = 'active'` agents are members of any
  group. Revoked and imported hosts are members of none.
- **Group names:** unique regardless of case, 1–128 characters, no control
  characters. The optional description is at most 500 characters.
- **Labels:**
  - Each label is 1–64 characters with no control characters, at most 32
    per host, and kept as entered (no case-folding). Duplicates are
    ignored.
  - Changing labels needs `hosts.label` on that host.
  - Labels never affect access, groups or rule assignment.
- **Who may change groups:**
  - Writes (create, edit, delete) need `host_groups.manage` **and**
    `hosts.read` on all hosts (Administrators qualify). Otherwise the
    answer is 403 with the title "Changing host groups needs access to
    every host".
  - Reading groups needs `access.read` or `host_groups.manage`.
  - Host lists and host counts on group responses are limited to the
    viewer's `hosts.read` reach.
- **Refusals:**
  - 409 `group_name_taken`, `stale_group`, `group_in_use` (with
    `{"roles": [names]}`);
  - 422 `invalid_condition` (naming the field), `unknown_host`;
  - 404 `group_not_found`, `host_not_found`;
  - 403 `permission_denied`.
- **Audit actions:**
  - `host_group.created`, `host_group.updated`, `host_group.deleted`;
  - `host_group.created_automatically` (actor kind `system`, actor
    `openvibes`);
  - `host.label_added`, `host.label_removed`;
  - `host_group.migrated` (one per upgraded group).
- **Migration:** `0053_host_groups.sql` starts with
  `-- openvibes: needs-backup`, and `SCHEMA_VERSION` becomes 53.
- **UI copy** is exactly the approved screens. The key strings are in each
  web task.

## Review Focus

1. **Hostname patterns with SQL wildcards.** A rule "hostname matches
   `web_01`" must match only `web_01`, not `web-01`, because `_` is
   literal. Uppercase hostnames match lowercase patterns
   (Task 1, `hostname_patterns_are_literal_except_star_and_ignore_case`).
2. **Negated condition on a host with no facts yet.** A freshly enrolled
   host with no hostname or address must not join "hostname does not match
   \*test\*", or a Windows-only group would quietly gain every new host
   (Task 1, `unknown_facts_never_match_even_when_negated`).
3. **Upgrade keeps access.** Every role's visible host set is identical
   before and after migration 53, including groups whose tag selectors
   match nothing and hosts carrying extra tags
   (Task 1, `upgrade_keeps_every_roles_hosts`).
4. **Deleting a group a role reaches.** It is refused with the role names,
   not a 500 from the foreign key. Deleting an unused group also removes
   its rule-set overrides, and the preview says so
   (Task 3, `deleting_a_group_in_use_names_the_roles`).
5. **Address changes write at once.** An agent whose address changes
   between two heartbeats inside the 5-minute write throttle gets the new
   `last_address` immediately
   (Task 2, `a_new_address_is_written_even_inside_the_throttle`).

---

### Task 1: Membership in one SQL function, and the upgrade (migration 53)

Integration task, most capable model. The schema, the function, every
membership caller and every test fixture that inserts tags or selectors
change together.

**Files:**
- Create: `migrations/0053_host_groups.sql`.
- Modify: `crates/platform-store/src/migrate.rs` (register 53, set
  `SCHEMA_VERSION` = 53).
- Modify: `crates/platform-store/src/console_read.rs`.
  - `agent_visibility` keeps its signature and calls the function.
  - Replace the four inline copies (~555, ~643, ~720, ~804) with
    `agent_visibility(...)`.
- Modify: `crates/platform-store/src/console_auth.rs`.
  - `revoke_agent_in_scope` uses the function.
  - Delete `tag_group_membership`, `preview_agent_tags`,
    `apply_agent_tags`, `tag_binding_impacts`, `AgentTag`,
    `AgentTagPreview`, `TagBindingImpact` and `save_asset_group`. Tasks 3
    and 4 replace them.
- Modify: `crates/platform-store/src/rule_assignment.rs` (`FLEET` and
  `HOST_STATE` use the function; the selectors listing becomes a
  membership summary).
- Modify: `crates/openvibes-distribution/src` (reads through the store; no
  change if it already calls `rule_assignment::assigned`).
- Modify: every test fixture that inserts into `console_agent_tags` or
  `console_asset_group_selectors` (grep both names in `crates/`). Use the
  new helpers.
- Modify: `crates/platform-store/tests/common/mod.rs`. Add
  `pub async fn manual_group(client: &Client, name: &str, agent_ids: &[&str]) -> String`
  and
  `pub async fn rule_group(client: &Client, name: &str, conditions: &[(&str, bool, &[&str])]) -> String`.
  Console tests get the same helpers in `crates/openvibes-console/tests/common`.
- Modify: the console code that called the deleted store functions. Until
  Task 4, comment-free stubs answer 410 `moved` on the old tag and
  asset-group routes, so the crate builds.
- Test: `crates/platform-store/tests/host_groups_membership.rs` (new) and
  `crates/platform-store/tests/host_groups_upgrade.rs` (new).

**Interfaces:**
- Produces:
  - SQL `console_host_in_group(agent_id text, group_id uuid) RETURNS boolean`;
  - generated columns `agents.os_family`, `agents.distribution`, and
    column `agents.last_address inet`;
  - tables `console_host_group_conditions`, `console_host_group_members`,
    `console_host_group_dismissed`, `console_host_labels`;
  - `console_asset_groups` gains `kind`, `description`, `auto_key`,
    `version`, `changed_at`, `changed_by`, `upgraded_from_tags boolean`.
- `agent_visibility` is unchanged for its ~40 callers.

- [ ] **Step 1: Write the failing membership tests** in
  `host_groups_membership.rs`. Seed agents with explicit facts by direct
  `UPDATE agents SET os_id, os_version, hostname, last_address`.
  - `os_family_and_distribution_match_reported_facts`: debian 12 and
    fedora 44 hosts. The `linux` group holds both, and `distribution is
    debian 12` holds one.
  - `hostname_patterns_are_literal_except_star_and_ignore_case`:
    - `WEB-01` matches `web-*`;
    - `web-01` does not match `web_01`;
    - `a%b` matches only the literal `a%b`;
    - `*test*` matches `win-test-01`.
  - `ip_conditions_take_cidrs_and_single_addresses_v4_and_v6`.
  - `negated_conditions_exclude` (`hostname does not match *test*`).
  - `unknown_facts_never_match_even_when_negated`: a host with NULL
    hostname is in neither "matches \*" nor "does not match \*test\*".
  - `any_value_in_a_condition_and_all_conditions`: values are OR'ed and
    conditions AND'ed.
  - `a_rule_group_with_no_conditions_holds_no_one`.
  - `manual_groups_hold_exactly_their_picked_hosts`.
  - `revoked_and_imported_hosts_are_in_no_group`.
  - `agent_visibility_uses_the_function`: an `AgentScope::AssetGroups`
    list returns the members.

Run: `eval "$(scripts/test-db.sh)"; cargo test -p platform-store --test host_groups_membership`
Expected: FAIL (schema 53 unknown).

- [ ] **Step 2: Write `migrations/0053_host_groups.sql`.**

```sql
-- openvibes: needs-backup
-- OpenVIBES platform schema version 53: host groups of three kinds, labels
-- (spec 2026-10-16-roles-permissions-design.md §5, §12 part 4).
ALTER TABLE agents
  ADD COLUMN last_address inet,
  ADD COLUMN os_family text GENERATED ALWAYS AS
    (CASE WHEN os_id IS NULL THEN NULL WHEN os_id = 'windows' THEN 'windows' ELSE 'linux' END) STORED,
  ADD COLUMN distribution text GENERATED ALWAYS AS
    (CASE WHEN os_id IS NULL OR os_version IS NULL THEN NULL
          WHEN os_id IN ('rocky','almalinux') THEN lower(os_id || ' ' || split_part(os_version, '.', 1))
          ELSE lower(os_id || ' ' || os_version) END) STORED;
CREATE INDEX agents_os_family_idx ON agents (os_family);
CREATE INDEX agents_distribution_idx ON agents (distribution);

ALTER TABLE console_asset_groups
  ADD COLUMN kind text NOT NULL DEFAULT 'manual' CHECK (kind IN ('automatic','rule','manual')),
  ADD COLUMN description text NOT NULL DEFAULT '' CHECK (char_length(description) <= 500),
  ADD COLUMN auto_key text UNIQUE,                           -- 'os_family:linux', 'distribution:debian 12'
  ADD COLUMN version integer NOT NULL DEFAULT 1 CHECK (version > 0),
  ADD COLUMN changed_at timestamptz,
  ADD COLUMN changed_by text,
  ADD COLUMN upgraded_from_tags boolean NOT NULL DEFAULT false,
  ADD CONSTRAINT console_asset_groups_auto_key_kind CHECK ((kind = 'automatic') = (auto_key IS NOT NULL));
ALTER TABLE console_asset_groups DROP CONSTRAINT console_asset_groups_name_key;
CREATE UNIQUE INDEX console_asset_groups_name_unique ON console_asset_groups (lower(name));

CREATE TABLE console_host_group_conditions (
  asset_group_id uuid NOT NULL REFERENCES console_asset_groups ON DELETE CASCADE,
  position smallint NOT NULL CHECK (position BETWEEN 0 AND 15),
  field text NOT NULL CHECK (field IN ('os_family','distribution','hostname','ip')),
  negate boolean NOT NULL DEFAULT false,
  vals text[] NOT NULL CHECK (cardinality(vals) BETWEEN 1 AND 64),
  PRIMARY KEY (asset_group_id, position));
CREATE TABLE console_host_group_members (
  asset_group_id uuid NOT NULL REFERENCES console_asset_groups ON DELETE CASCADE,
  agent_id text NOT NULL REFERENCES agents ON DELETE CASCADE,
  added_at timestamptz NOT NULL, added_by text NOT NULL,
  PRIMARY KEY (asset_group_id, agent_id));
CREATE INDEX console_host_group_members_agent_idx ON console_host_group_members (agent_id);
CREATE TABLE console_host_group_dismissed (auto_key text PRIMARY KEY, dismissed_at timestamptz NOT NULL, dismissed_by text NOT NULL);
CREATE TABLE console_host_labels (
  agent_id text NOT NULL REFERENCES agents ON DELETE CASCADE,
  label text NOT NULL CHECK (char_length(label) BETWEEN 1 AND 64),
  added_at timestamptz NOT NULL, added_by text NOT NULL,
  PRIMARY KEY (agent_id, label));
CREATE INDEX console_host_labels_label_idx ON console_host_labels (label);

-- '*' is the only wildcard; %, _ and \ are literal
CREATE FUNCTION console_glob_like(pattern text) RETURNS text LANGUAGE sql IMMUTABLE AS $$
  SELECT replace(replace(replace(replace(lower(pattern), '\', '\\'), '%', '\%'), '_', '\_'), '*', '%') $$;

CREATE FUNCTION console_condition_holds(a agents, field text, negate boolean, vals text[]) RETURNS boolean
LANGUAGE sql STABLE AS $$
  SELECT CASE
    WHEN field = 'os_family'    THEN a.os_family IS NOT NULL     AND negate <> (a.os_family = ANY (vals))
    WHEN field = 'distribution' THEN a.distribution IS NOT NULL  AND negate <> (a.distribution = ANY (vals))
    WHEN field = 'hostname'     THEN a.hostname IS NOT NULL      AND negate <> EXISTS (
        SELECT 1 FROM unnest(vals) v WHERE lower(a.hostname) LIKE console_glob_like(v) ESCAPE '\')
    WHEN field = 'ip'           THEN a.last_address IS NOT NULL  AND negate <> EXISTS (
        SELECT 1 FROM unnest(vals) v WHERE a.last_address <<= v::inet)
    ELSE false END $$;

-- ponytail: evaluated per (host, group) at query time; if large fleets need it,
-- materialise membership in a table refreshed on fact/rule changes.
CREATE FUNCTION console_host_in_group(agent text, gid uuid) RETURNS boolean LANGUAGE sql STABLE AS $$
  SELECT EXISTS (
    SELECT 1 FROM agents a JOIN console_asset_groups g ON g.asset_group_id = gid
    WHERE a.agent_id = agent AND a.status = 'active'
      AND CASE WHEN g.kind = 'manual' THEN EXISTS (
            SELECT 1 FROM console_host_group_members m WHERE m.asset_group_id = gid AND m.agent_id = a.agent_id)
          ELSE EXISTS (SELECT 1 FROM console_host_group_conditions c WHERE c.asset_group_id = gid)
           AND NOT EXISTS (SELECT 1 FROM console_host_group_conditions c
                           WHERE c.asset_group_id = gid AND NOT console_condition_holds(a, c.field, c.negate, c.vals))
          END) $$;

-- upgrade (§12 part 4): every tag group becomes a manual group of its current members
INSERT INTO console_host_group_members (asset_group_id, agent_id, added_at, added_by)
SELECT g.asset_group_id, a.agent_id, now(), 'migration'
FROM console_asset_groups g JOIN agents a ON a.status = 'active'
WHERE EXISTS (SELECT 1 FROM console_asset_group_selectors s WHERE s.asset_group_id = g.asset_group_id)
  AND NOT EXISTS (SELECT 1 FROM console_asset_group_selectors s WHERE s.asset_group_id = g.asset_group_id
                  AND NOT EXISTS (SELECT 1 FROM console_agent_tags t WHERE t.agent_id = a.agent_id
                                  AND t.tag_key = s.tag_key AND t.tag_value = s.tag_value));
UPDATE console_asset_groups g SET kind = 'manual', upgraded_from_tags = true,
  description = 'Upgraded from an asset group (it used the ' ||
    (SELECT string_agg(tag_key || '=' || tag_value, ', ' ORDER BY tag_key) FROM console_asset_group_selectors s
     WHERE s.asset_group_id = g.asset_group_id) || ' tag): the same hosts, now hand-picked. Turn it into a rule when you can.'
WHERE EXISTS (SELECT 1 FROM console_asset_group_selectors s WHERE s.asset_group_id = g.asset_group_id);
INSERT INTO audit_log (actor, action, target, result, detail, actor_kind, actor_id, target_kind, target_id)
SELECT 'migration', 'host_group.migrated', g.name, 'success',
       jsonb_build_object('selectors', (SELECT jsonb_agg(tag_key || '=' || tag_value) FROM console_asset_group_selectors s WHERE s.asset_group_id = g.asset_group_id),
                          'hosts', (SELECT count(*) FROM console_host_group_members m WHERE m.asset_group_id = g.asset_group_id)),
       'system', 'openvibes', 'host_group', g.asset_group_id::text
FROM console_asset_groups g;
INSERT INTO console_host_labels (agent_id, label, added_at, added_by)
SELECT agent_id, left(tag_key || ':' || tag_value, 64), changed_at, changed_by FROM console_agent_tags
ON CONFLICT DO NOTHING;
-- automatic groups for facts already reported (names clash → " (automatic)")
-- (insert os_family groups and distribution groups from DISTINCT active agents' facts;
--  names via the display map below; condition rows: field os_family / distribution, one value)
DROP TABLE console_agent_tags;
DROP TABLE console_asset_group_selectors;

GRANT SELECT, INSERT, UPDATE, DELETE ON console_host_group_conditions, console_host_group_members, console_host_labels, console_host_group_dismissed TO "openvibes-console";
GRANT UPDATE (kind, description, auto_key, version, changed_at, changed_by, upgraded_from_tags, name) ON console_asset_groups TO "openvibes-console";
GRANT DELETE ON console_asset_groups TO "openvibes-console";
GRANT SELECT ON console_host_group_conditions, console_host_group_members TO "openvibes-distribution";
GRANT SELECT (agent_id, status, os_family, distribution, hostname, last_address) ON agents TO "openvibes-distribution";
GRANT SELECT (asset_group_id, kind) ON console_asset_groups TO "openvibes-distribution";
GRANT INSERT, SELECT ON console_asset_groups, console_host_group_conditions TO "openvibes-ingest";
GRANT SELECT ON console_host_group_dismissed TO "openvibes-ingest";
```

  - The automatic-group block for facts already reported is written in
    SQL in the same migration.
    - Display names: `linux` → `Linux`, `windows` → `Windows`.
      Distribution names are the os_id name map (debian → Debian,
      ubuntu → Ubuntu, fedora → Fedora, rocky → Rocky Linux, almalinux →
      AlmaLinux, any other id capitalised) plus the release, as in
      `Debian 12`.
    - Do it with a `CASE` in SQL that matches the Rust map of Task 2
      exactly; a test compares the two.
    - A name already taken (case-insensitive) gets ` (automatic)`
      appended.
  - Check the existing grants named in the code map (0022, 0049) and drop
    nothing that a remaining table still needs.
  - Check whether `console_role_bindings.asset_group_id` still exists (it
    was dropped in 0052). If it exists, leave it alone.
  - Register 53.

- [ ] **Step 3: Point every membership caller at the function.**
  - `agent_visibility`:

```rust
pub(crate) fn agent_visibility(agent_id: &str, global: &str, groups: &str) -> String {
    format!("({global}::boolean OR EXISTS (
            SELECT 1 FROM unnest({groups}::text[]) gid
            WHERE console_host_in_group({agent_id}, gid::uuid)
        )) AND ({global}::boolean OR a.status <> 'imported')")
}
```

  - Replace the hand-copied copies listed in the code map (four in
    console_read.rs, `revoke_agent_in_scope`, and the `FLEET` and
    `HOST_STATE` constants in rule_assignment.rs) with the function.
  - Delete the Rust matcher `tag_group_membership` and the tag store
    functions.

- [ ] **Step 4: Write the failing upgrade test**
  `host_groups_upgrade.rs::upgrade_keeps_every_roles_hosts`.
  1. At version 52, seed:
     - agents with tags (`env=prod`, `env=lab`, an extra tag);
     - groups with one selector, two selectors, and none;
     - a revoked agent with the tags;
     - an imported agent;
     - roles reaching each group.
  2. Record, for every role, the set of agents visible through
     `agent_visibility` with that role's groups.
  3. Migrate to 53 and compare the sets.

  Also assert:
  - the tags became labels (`env:prod`);
  - every group is `manual` with `upgraded_from_tags` and the
    description;
  - the selector-less group has no members;
  - one `host_group.migrated` audit row per group;
  - automatic groups exist for each distinct `os_family`/`distribution`
    among active agents.

  Run it. Expected: FAIL first (no 53), then PASS after Steps 2–3.

- [ ] **Step 5: Port every fixture** that inserted tags or selectors to
  `manual_group` / `rule_group`.
  - Run the store and console suites once:
    `cargo test -p platform-store && cargo test -p openvibes-console && cargo test -p openvibes-distribution`.
  - Expected: PASS. Only the old tag and asset-group console routes answer
    410 until Task 4, and the tests that exercised them are deleted or
    moved to Task 4's new tests. List them in your report.

- [ ] **Step 6: Docs, READMEs, commit.**

```bash
git add -A && git commit -m "store: host groups of three kinds decided by one SQL function; migration 53 turns tag groups into manual groups and tags into labels

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2: Agent facts — the peer address, and automatic groups

**Files:**
- Modify: `crates/platform-agent-server/src/serve.rs:133-156`. Keep the
  peer address from `listener.accept()` and add
  `.layer(Extension(PeerAddr(addr.ip())))` next to `Extension(Peer(peer))`.
- Modify: `crates/platform-agent-server/src/auth.rs` (add
  `pub(crate) struct PeerAddr(pub std::net::IpAddr)`, exported for
  handlers).
- Modify: `crates/openvibes-ingest/src/delivery.rs:33` (the heartbeat
  handler takes `Extension(PeerAddr(ip))` and passes `Some(ip)`).
- Modify: `crates/platform-store/src/ingest.rs` `heartbeat`. Add
  `address: Option<IpAddr>`, set
  `last_address = COALESCE($8::inet, last_address)`, and add
  `OR last_address IS DISTINCT FROM COALESCE($8::inet, last_address)` to
  the throttle `WHERE`.
- Create: `crates/platform-store/src/host_group_facts.rs`, with
  `pub fn os_family_name(os_family: &str) -> String`,
  `pub fn distribution_name(distribution: &str) -> String` and
  `pub async fn ensure_automatic_groups(client: &Client, os_family: &str, distribution: &str, now: DateTime<Utc>) -> Result<(), StoreError>`.
- Modify: `crates/platform-store/src/inventory.rs` `finish`. After
  writing `os_id`/`os_version`, call `ensure_automatic_groups` with the
  row's generated `os_family`/`distribution`, read back in the same
  statement through `RETURNING os_family, distribution`.
- Test: `crates/platform-store/tests/host_group_facts.rs` (new), and the
  ingest tests for the heartbeat.

**Interfaces:**
- Produces `ensure_automatic_groups`. Its behaviour:
  - For each key in `os_family:<f>` and `distribution:<d>`, insert a group
    with that `auto_key` when it doesn't exist and isn't dismissed.
  - Kind `automatic`, one condition row (`field` os_family/distribution,
    one value), and the display name. A name clash gets " (automatic)".
  - Description: "Every host that reports Linux. Kept up to date by
    OpenVIBES." / "Hosts running Debian 12."
  - It writes audit `host_group.created_automatically`.
  - Idempotent: `ON CONFLICT (auto_key) DO NOTHING`.
- `ensure_automatic_groups` runs as the `openvibes-ingest` database role: confirm it may INSERT into `audit_log` and the group tables (migration 53 grants); add any missing grant to migration 53.
- The display-name map is the single source in Rust. Task 1's migration
  `CASE` must agree, and a test compares both over a fixed list.

- [ ] **Step 1: Write the failing tests:**
  - `a_new_distribution_creates_its_group_once`;
  - `a_dismissed_key_is_not_created_again`;
  - `a_name_taken_by_a_user_group_gets_automatic_appended`;
  - `display_names_match_the_migration` (call the SQL `CASE` through a
    small SQL function or the migration's helper, and compare);
  - `a_new_address_is_written_even_inside_the_throttle`: two heartbeats 1
    minute apart from different IPs, with `last_address` the second;
  - `an_unchanged_address_inside_the_throttle_writes_nothing`.

  For serve.rs, add a unit or integration test if the crate has a
  connection test harness. Otherwise test the ingest path with a fake
  `Extension(PeerAddr)` on the router, and say so.

- [ ] **Step 2: Implement.** Run the focused tests, then
  `cargo test -p platform-store -p openvibes-ingest -p platform-agent-server`.
  Expected: PASS.

- [ ] **Step 3: Docs (platform-agent-server.md, openvibes-ingest.md,
  platform-store.md), commit.**

```bash
git add -A && git commit -m "ingest: record the agent's address; inventory makes automatic host groups for new OS families and distributions

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 3: Host-group store API (list, detail, write, preview, labels)

**Files:**
- Create: `crates/platform-store/src/host_groups.rs`, holding list,
  detail and members.
- Create: `crates/platform-store/src/host_group_writes.rs`, holding
  create/update/delete and preview.
- Create: `crates/platform-store/src/host_labels.rs`, holding labels for
  a host, add and remove.
- Modify: `crates/platform-store/src/lib.rs`, and
  `console_roles.rs::host_groups` (remove it; it is replaced).
- Test: `crates/platform-store/tests/host_group_writes.rs` and
  `host_labels.rs` (new).

**Interfaces:**
- Produces:

```rust
pub enum GroupKind { Automatic, Rule, Manual }
pub struct Condition { pub field: String, pub negate: bool, pub values: Vec<String> }
pub struct GroupSummary { pub asset_group_id: String, pub name: String, pub kind: GroupKind, pub description: String,
    pub conditions: Vec<Condition>, pub picked: i64, pub hosts: i64, pub online: i64,
    pub open_alarms: i64, pub critical: i64, pub roles: Vec<(String, String)>, pub people: i64,
    pub upgraded_from_tags: bool, pub changed_at: Option<DateTime<Utc>>, pub changed_by: Option<String>, pub version: i32 }
pub struct GroupHost { pub agent_id: String, pub hostname: Option<String>, pub distribution: Option<String>,
    pub last_address: Option<String>, pub labels: Vec<String>, pub last_seen_at: Option<DateTime<Utc>>,
    pub online: bool, pub open_alarms: i64, pub critical: i64, pub why: String }
pub enum GroupContent<'a> { Rule(&'a [Condition]), Manual(&'a [String]) }
pub struct GroupInput<'a> { pub name: &'a str, pub description: &'a str, pub content: GroupContent<'a> }
pub enum GroupWrite { Saved(GroupSummary), NameTaken, Stale, NotFound, InUse(Vec<String>), UnknownHost(String) }
pub struct Preview { pub joins: Vec<HostRef>, pub leaves: Vec<HostRef>, pub gains: Vec<PersonRef>, pub loses: Vec<PersonRef>, pub overrides_removed: i64 }

pub async fn list(client: &Client, scope: &AgentScope) -> Result<Vec<GroupSummary>, StoreError>;
pub async fn detail(client: &Client, id: &str, scope: &AgentScope) -> Result<Option<GroupSummary>, StoreError>;
pub async fn hosts(client: &Client, id: &str, scope: &AgentScope, after: Option<&str>, limit: i64) -> Result<Vec<GroupHost>, StoreError>;
pub async fn recent_changes(client: &Client, id: &str, limit: i64) -> Result<Vec<AuditLine>, StoreError>;
pub async fn create(client: &mut Client, input: &GroupInput<'_>, actor: &str, now: DateTime<Utc>) -> Result<GroupWrite, StoreError>;
pub async fn update(client: &mut Client, id: &str, version: i32, input: &GroupInput<'_>, actor: &str, now: DateTime<Utc>) -> Result<GroupWrite, StoreError>;
pub async fn delete(client: &mut Client, id: &str, version: i32, actor: &str, now: DateTime<Utc>) -> Result<GroupWrite, StoreError>;
pub async fn preview(client: &Client, id: Option<&str>, proposed: Option<&GroupContent<'_>>) -> Result<Option<Preview>, StoreError>; // proposed None = delete
pub async fn labels(client: &Client, agent_id: &str) -> Result<Vec<String>, StoreError>;
pub async fn add_label(client: &mut Client, agent_id: &str, label: &str, actor: &str, now: DateTime<Utc>) -> Result<LabelWrite, StoreError>; // Added | AlreadyThere | TooMany | NotFound
pub async fn remove_label(client: &mut Client, agent_id: &str, label: &str, actor: &str, now: DateTime<Utc>) -> Result<bool, StoreError>;
```

- **Behaviour:**
  - **Counts follow scope.** Host counts, online, problems and host lists
    count only agents inside `scope` (via `agent_visibility`).
  - **Who reaches a group:** roles from `console_role_groups`, and people
    as distinct enabled users bound to those roles.
  - **`why`** is "Matches the rule" or "Picked by hand".
  - **`update` of an automatic group** turns it into `rule`: it clears
    `auto_key` (the key is not dismissed) and stores the given
    conditions.
  - **`delete`:**
    - refuses with `InUse(role names)` when `console_role_groups`
      references the group;
    - deletes an automatic group's key into `console_host_group_dismissed`;
    - cascades rule-set overrides;
    - writes audit `host_group.deleted` with
      `{name, kind, overrides_removed}`.
  - **Writes** run in one transaction under an advisory lock, check the
    version, map the unique-index violation on `lower(name)` to
    `NameTaken`, bump `version`, and write audit `host_group.created` /
    `host_group.updated` with `{name, kind, conditions | picked}`.
    `UnknownHost` covers an agent id that doesn't exist or isn't active.
  - **`preview`:**
    - joins and leaves compare current membership with the proposed one,
      by evaluating the proposed conditions with `console_condition_holds`
      over active agents, or the proposed picked list;
    - gains and loses are the people bound to roles reaching this group
      who see a host now and wouldn't, or the reverse, given their other
      roles' reach. The simplification is acceptable: people of roles
      reaching the group gain the joins and lose the leaves, unless
      another of their roles reaches all hosts;
    - `overrides_removed` is set for deletes;
    - lists are capped at 50 entries with totals.
  - **Labels:**
    - trimmed, 1–64 characters, no control characters, at most 32 per
      host (`TooMany`);
    - audit `host.label_added` / `host.label_removed`;
    - `NotFound` for a missing or non-active agent.

- [ ] **Step 1: Write the failing tests:**
  - `groups_are_listed_with_counts_inside_the_scope`;
  - `group_names_are_unique_regardless_of_case`;
  - `editing_an_automatic_group_makes_it_a_rule_group`;
  - `deleting_an_automatic_group_is_remembered`;
  - `deleting_a_group_in_use_names_the_roles`;
  - `deleting_removes_rule_set_overrides_and_the_preview_counts_them`;
  - `preview_lists_joins_leaves_and_who_gains_or_loses`;
  - `stale_versions_are_refused`;
  - `unknown_or_revoked_hosts_cannot_be_picked`;
  - `labels_are_capped_at_32_and_deduplicated`;
  - `labels_never_change_membership`.

  Run them. Expected: FAIL (module missing).

- [ ] **Step 2: Implement.** Run the focused tests, then
  `cargo test -p platform-store`. Expected: PASS.

- [ ] **Step 3: Docs (console-auth-store.md, platform-store.md), commit.**

---

### Task 4: Host-group and label HTTP API

**Files:**
- Create: `crates/openvibes-console/src/hosts/groups.rs`, holding the
  handlers and request/response types (split into `groups_types.rs` if
  over 300 lines).
- Create: `crates/openvibes-console/src/hosts/labels.rs`.
- Modify: `crates/openvibes-console/src/hosts/mod.rs` routes, and
  `src/access/mod.rs`. Remove `asset_groups.rs` and `tags.rs`, the
  `/v1/access-control/asset-groups*` routes, the `/v1/agents/{id}/tags*`
  routes and the 410 stubs from Task 1.
- Modify: `src/http/openapi.rs`, and regenerate
  `docs/api/console-v1.openapi.json` and the web client.
- Modify: `crates/openvibes-console/src/rules/assignment.rs`.
  `AssignableGroupView` loses `selectors` and gains `kind` and `summary`
  (the human membership sentence from the shared Rust formatter below).
- Create: `crates/openvibes-console/src/hosts/group_words.rs` with
  `pub fn membership_sentence(kind: GroupKind, conditions: &[Condition], picked: i64) -> String`.
  - The approved copy: "Hosts where os family is **Windows** and hostname
    does not match **\*test\***". Rendered as plain text without the
    asterisks for bold: "Hosts where OS family is Windows and hostname
    does not match *test*". For manual groups: "N hosts picked by hand".
  - Field words: OS family, distribution, hostname, IP address.
  - Ops: "is", "is not", "matches", "does not match", "is in", "is not
    in".
- Test: `crates/openvibes-console/tests/host_groups_http.rs` and
  `host_labels_http.rs` (new).

**Interfaces (routes):**
- `GET /v1/host-groups` (access.read or host_groups.manage) returns
  `[HostGroupView]`, which carries the summary fields plus
  `membership: String` from `membership_sentence`.
- `POST /v1/host-groups` (host_groups.manage + hosts.read on all hosts +
  csrf) takes
  `{name, description?, kind: "rule"|"manual", conditions?, agent_ids?}`.
- `GET /v1/host-groups/{id}` (as list) returns the detail plus
  `recent: [ActivityLine]`.
- `GET /v1/host-groups/{id}/hosts?after=&limit=` returns `[GroupHostView]`.
- `PATCH /v1/host-groups/{id}` takes
  `{name?, description?, conditions?, agent_ids?, version}`.
- `DELETE /v1/host-groups/{id}?version=`.
- `POST /v1/host-groups/{id}/preview` (`{conditions?|agent_ids?}`, or
  `{}` for delete) and `POST /v1/host-groups/preview` (a new group's
  joins only) return
  `{joins, leaves, gains, loses, joins_total, leaves_total, overrides_removed}`.
- `GET /v1/hosts/{agent_id}/labels` (hosts.read on that host) returns
  `{labels, groups: [{asset_group_id, name, kind}]}`.
- `PUT /v1/hosts/{agent_id}/labels/{label}` and `DELETE` (hosts.label on
  that host + csrf) return 204. 409 `too_many_labels`; 404 if out of reach
  (indistinguishable from missing).
- **Validation:**
  - conditions 1–16;
  - field from the four;
  - values 1–64, each 1–255 characters;
  - `ip` values parse as `IpNet` or `IpAddr` (use the `ipnet` crate if
    the workspace already depends on it, else a std parse of
    `addr/prefix`);
  - `os_family` values in `linux` | `windows`;
  - `distribution` values match `^[a-z0-9._-]+ [a-z0-9._-]+$`;
  - otherwise 422 `invalid_condition` naming the field.
- Writes check "hosts.read on all hosts" with
  `editor.capabilities` → `HostsRead` scope Global.

- [ ] **Step 1: Write the failing HTTP tests:**
  - `an_administrator_creates_edits_previews_and_deletes_rule_and_manual_groups`;
  - `changing_groups_needs_every_host` (a Team-lead role on WindowsServers
    with host_groups.manage gets 403 with the title);
  - `group_lists_count_only_hosts_in_reach`;
  - `deleting_a_group_in_use_names_the_roles` (409 with roles);
  - `invalid_conditions_name_the_field`;
  - `labels_need_hosts_label_on_that_host` (in reach gives 204, out of
    reach gives 404, no permission gives 403);
  - `the_old_tag_and_asset_group_routes_are_gone` (404);
  - `rule_set_assignment_lists_groups_with_their_membership_sentence`.

  Run them. Expected: FAIL.

- [ ] **Step 2: Implement.** Regenerate OpenAPI and the client. Run
  `cargo test -p openvibes-console`. Expected: PASS.

- [ ] **Step 3: Docs (console-auth-http.md routes, console-rbac.md "who
  may change groups", rule-set-assignment.md), commit.**

---

### Task 5: Host groups list and group page (screens 9, 10, 10b, 10c)

**Files:**
- Replace: `crates/openvibes-console/web/src/views/admin/settings/HostGroups.tsx`
  (screen 9 list).
- Create: `web/src/views/admin/groups/GroupPage.tsx` (screens 10/10b/10c,
  plus new),
- Create: `web/src/views/admin/groups/RuleEditor.tsx`.
- Create: `web/src/views/admin/groups/PickedHosts.tsx`.
- Create: `web/src/views/admin/groups/GroupHosts.tsx`.
- Create: `web/src/views/admin/groups/groupState.ts` (a pure reducer, and
  preview text).
- Create: `web/src/views/admin/groups/README.md`.
- Create: `web/src/views/admin/groups/GroupPage.test.tsx`.
- Modify: `web/src/views/admin/settings/Settings.tsx` (sub-routes
  `/settings/host-groups/new` and `/settings/host-groups/{id}` through the
  existing `subPage()` hook).
- Modify: `web/src/app/frontend-contract.json` and its test (deep links).
- Delete: `web/src/panels/admin/AssetGroupPanel.tsx` and the
  `asset-group` panel kind.

**What it shows (approved copy; see screens 9–10c):**
- **List:**
  - Header "Host groups" with a count, "+ New group" (only for those who
    may change groups), and filter "Filter groups, rules or hosts…".
  - The intro text from screen 9.
  - Columns:
    - Group: name, kind badge ("Automatic" plain / "Rule" accent /
      "Manual" outlined), and description;
    - Membership: the `membership` sentence, or "N hosts picked by hand";
    - Hosts: "N hosts", with "M online";
    - Open problems: "N alarms" / "N critical" badges, or "None open";
    - Who reaches it: role badges or "No role yet", with "N people" or
      "Nobody reaches it".
  - A row opens `/settings/host-groups/{id}`.
- **Group page:** breadcrumb "Settings › Host groups".
  - **Header:** icon, name, kind badge, and "N hosts · M online · used by
    K role(s) · P person/people reach it". Buttons "Edit" / "Stop editing"
    and "⋯" with "Duplicate…" and "Delete group…", shown only for those
    who may change groups.
  - **Left column:**
    - **Details:** the description, then Kind ("Automatic: made by
      OpenVIBES" / "Rule: stays up to date" / "Manual: hand-picked"),
      Membership sentence, Open problems, and Changed ("<when> by
      <who>" or "Never by hand").
    - **Who reaches it:** roles linked to the role page, "N permissions",
      and person chips. Empty: "No role uses this group yet. Choose it in
      a role's Hosts."
    - **Recent changes:** readable labels via `ui/auditActions.ts` (add
      the host_group.* and host.label_* actions), plus an "Audit log"
      link.
  - **Right column:**
    - **Rule** card, for rule and automatic groups:
      - rows "Where" / "and", each with field, op and values;
      - in edit mode: value inputs (a chip input for several values), a
        per-row remove control "Remove this condition", "+ Add
        condition", the note "Rules use what agents report: OS family,
        distribution, hostname and IP address. Labels never count. Hosts
        join and leave by themselves as they change.", "Save changes" /
        "Cancel", and an "Editing" badge.
      - The IP field shows the hint "The address OpenVIBES sees; behind
        NAT this is the router."
    - **Hosts picked by hand** card, for manual groups: the note "Hosts
      picked by hand. New hosts are never added by themselves.",
      removable host chips, and search "Search hosts to add" over
      `/api/v1/agents?q=`.
    - **Automatic groups** show the callout "Made by OpenVIBES from what
      agents report. Editing it makes it yours: OpenVIBES won't change it
      again. Deleting it is remembered; it won't come back."
    - **Upgraded groups** (`upgraded_from_tags`) show the one-time note
      "This group was made from tags. You can turn it into a rule group."
      with a "Turn into a rule" action that switches to a new rule draft.
    - **Hosts in this group** card: count, filter "Filter hosts…", and
      columns Host (name and distribution), IP address, Labels, Last seen
      (warn when offline), Open problems. Empty: "No host matches yet.".
  - **Preview while editing** (debounced POST preview, warn callout,
    shown only when something changes): "If you save: **+N** (names),
    **−M** (names)." followed by " {people} gain access to them" / " lose
    access to them" / " gain and lose access accordingly".
  - **Delete** shows the same preview, plus "Removes N rule-set
    switches." when non-zero. A 409 `group_in_use` shows "Roles still use
    this group: …".
- **New group** page: name, description, and a "Rule" / "Manual"
  segmented choice, then the same editor.

- [ ] **Step 1: Write the failing tests** (reducer + server render +
  stubbed fetch, the pattern of `views/admin/roles` tests):
  - preview sentence variants;
  - condition add, remove and edit;
  - the automatic callout;
  - the upgraded note;
  - write controls hidden without every-host access;
  - the list's membership column.

  Run them. Expected: FAIL.

- [ ] **Step 2: Implement.** Run vitest, tsc and eslint. Compare against
  screens 9, 10, 10b and 10c by screenshot, saved to
  `~/.cache/openvibes-scratch/hostgroup-shots/`. Expected: PASS and a
  match.

- [ ] **Step 3: Commit.**

---

### Task 6: A host's groups and labels; pickers and rule-set UI follow

**Files:**
- Modify: `web/src/panels/hosts/AgentPanel.tsx`. Replace `TagEditor` with
  a "Groups and labels" section, as in screen 17's card.
  - **Groups:** chips linking to the group page, each with a small kind
    word.
  - **Labels:** removable chips (aria-label "Remove label X") and an
    input "Add a label" (Enter adds, trims, ignores duplicates).
  - The helper text reads "For filtering and finding hosts. Labels never
    change who can see a host."
  - It is editable only with `hosts.label` (canEverywhere is not needed;
    the server checks the host).
- Modify: `web/src/views/admin/roles/HostsPicker.tsx` (shows each
  group's kind word and host count; `HostGroup` type change).
- Modify: `web/src/panels/rules/*` (WhereItRuns and assignment group rows
  show `summary` in place of selectors).
- Modify: `web/src/ui/auditActions.ts` (host_group.*, host.label_*).
- Test: vitest for the labels editor (add, duplicate, remove, cap
  message) and the picker kind word.

- [ ] **Step 1: Write the failing tests. Step 2: implement. Step 3: run
  vitest, tsc and eslint. Step 4: commit.**

---

### Task 7: Demo server and demo e2e

**Files:**
- Modify: `web/src/demo/data.ts`. Replace demo tags and asset groups with
  host facts, `last_address`, labels, and these groups:
  - automatic (Linux, Debian 12, Fedora 44, …);
  - rule (WindowsServers, HQ network, Lab);
  - manual (Production, upgraded from tags; Pilot hosts).

  Keep the same roles' reach ids.
- Create: `web/src/demo/hostGroups.ts`, the membership evaluator mirroring
  the SQL function: glob with literal `%` and `_`, case-insensitive; CIDR;
  negate; unknown facts never match; active only.
- Modify: `web/src/demo/routes/roles.ts` and `hosts.ts`. Mirror every
  Task 4 route and refusal, including "Changing host groups needs access
  to every host".
- Modify: the demo e2e specs that used tags or asset groups
  (`smoke.spec.ts` "a host group is created…", `roles.spec.ts`,
  `where-it-runs-focus.spec.ts`).
- Create: `web/e2e/demo/host-groups.spec.ts`:
  - an admin creates a rule group (hostname `*web*`, `ip` in
    `10.0.0.0/16`), sees the preview "+N", saves, and sees it in the
    list;
  - edits Debian 12 and sees it become "Rule";
  - deletes an unused group;
  - a group in use is refused with the role names;
  - a host's labels are added and removed;
  - axe runs on the list and the group page.
- Test: `web/src/demo/hostGroups.test.ts`, the evaluator table mirroring
  Task 1's membership cases.

- [ ] **Steps: failing specs first, implement, run vitest and the full
  demo e2e (`--workers=4`), commit.**

---

### Task 8: Live e2e, distribution, docs and the gate

**Files:**
- Modify: `scripts/console-e2e-server.sh`. Seed facts (`os_id`,
  `os_version`, `hostname`, `last_address`) in place of tags.
- Modify: `web/e2e/live/teams.spec.ts`. The two teams use rule groups
  ("hostname matches `linux-*`" / "`windows-*`") made through
  `POST /v1/host-groups`. Assertions are unchanged.
- Modify: `web/e2e/live/console.spec.ts` (the rule-set switch test's
  group creation).
- Modify: `crates/openvibes-distribution/tests/assignment.rs`. Its `tag`
  and `group` helpers become `rule_group` / `manual_group`, and
  `on_wins_across_groups` keeps its meaning.
- Docs: one coherent pass over the pages in Global Constraints, plus an
  "Upgrading" note in `console-rbac.md`: tag groups become manual groups,
  tags become labels, and IP rules need an agent heartbeat after the
  upgrade to know addresses.

- [ ] **Step 1: Port and run the live journey (`--workers=2`, chromium +
  firefox).**
- [ ] **Step 2: Run the full local gate** (testing.md) once. Expected:
  all green. Webkit can't launch on this host, a known limitation.
- [ ] **Step 3: Commit.** No push, no PR; the controller opens it.

---

## Self-review notes

- **Spec coverage:**
  - §5.1 kinds, rules, IP and preview → Tasks 1–5;
  - §5.2 labels → Tasks 1, 3, 4 and 6;
  - §5.3 upgrade → Task 1;
  - §6 lists follow reach → Tasks 3–4;
  - §12 part 4 → Task 1;
  - §13 host-group, label and preview routes → Task 4;
  - §15 → the tests in each task;
  - screens 9–10c and the 17 card → Tasks 5–6.
- **Not here:**
  - the Hosts list label filter and the host page itself (step 4);
  - dashboard sharing (step 6);
  - pictures (step 7).
- **Rulings** (in the spec, 2026-10-19):
  - negated conditions;
  - unknown facts never match;
  - group writes need every host;
  - lists follow reach.
- **Membership function:** the ponytail note in Task 1 names its limit,
  query-time evaluation, and the upgrade path.
