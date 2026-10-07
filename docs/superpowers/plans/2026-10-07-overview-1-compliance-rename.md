# Overview clarity 1: "findings" becomes "compliance" — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every user-visible "finding(s)" in the console, its API paths and its permission IDs says "compliance" instead; stored dashboards, role grants and case items are migrated.

**Architecture:** One data-changing migration (0043) rewrites permission IDs, saved dashboard layouts and case item kinds. The console's Rust routes, permission enum and problem codes are renamed; the OpenAPI snapshot and TS client are regenerated; the web console follows. Ingest's agent-facing `/v1/findings` is the wire protocol and is NOT touched.

**Tech Stack:** Rust (axum, utoipa, tokio-postgres), PostgreSQL, React + TypeScript (vitest, Playwright).

**Spec:** `docs/superpowers/specs/2026-10-07-overview-clarity-design.md` §3.

## Global Constraints

- Names: **Alarms**, **Vulnerabilities**, **Compliance findings**; short form "Compliance"; one item "Compliance finding".
- Clean rename, no aliases: old console paths return 404.
- Unchanged: `crates/openvibes-ingest` (wire protocol), `openvibes-protocol`, agent, tables `findings`, `current_findings`, `console_finding_triage*`, audit log rows, case event history rows.
- Data-changing migrations start with the line `-- openvibes: needs-backup` (`crates/platform-store/src/migrate.rs` `NEEDS_BACKUP`).
- Inspector panel kind `finding` (internal URL state) stays; only its label changes.
- Gate: `testing.md` §2 in the workspace, run from the worktree root.

## Review Focus

1. A saved dashboard using `findings.open.high`, source `findings`, attention kind `findings` or list view `/findings` renders the same counts after upgrade (migration test, Task 1).
2. A dashboard draft kept in the browser's sessionStorage from before the upgrade still shows its compliance tiles, not a default count (web normalizer test, Task 5).
3. A case created before the upgrade with a finding item still lists it, and its timeline event "item added: finding" still has a readable label (Task 1 migration + Task 5 label test).
4. A custom role granted `findings.read` keeps compliance read access after migration (Task 1).
5. An API script calling `/api/v1/findings/summary` gets 404, not a 500 or the SPA's HTML (Task 3 test).

---

### Task 1: Migration 0043 renames stored IDs

**Files:**
- Create: `migrations/0043_compliance_names.sql`
- Modify: `crates/platform-store/src/migrate.rs` (`SCHEMA_VERSION` → 43; add `(43, include_str!("../../../migrations/0043_compliance_names.sql"))` after line 153)
- Modify: `crates/platform-store/tests/migrate.rs` (`automatic_migration_applies_additive_ones`: start `at_version(&db, 43)`; the 24→current path now crosses a data-changing migration)
- Create: `crates/platform-store/tests/compliance_names.rs`

**Interfaces:**
- Produces: permission IDs `compliance.read`, `compliance.triage`; case item kind `compliance_finding`; dashboard config values `compliance.open.<sev>`, source `compliance`, include kind `compliance`, view `/compliance`.

- [ ] **Step 1: Write the failing test** `crates/platform-store/tests/compliance_names.rs`

```rust
//! Migration 43 renames findings to compliance in stored IDs.
mod common;

use common::TestDb;

#[tokio::test]
async fn migration_43_renames_permissions_dashboards_and_case_items() {
    let db = TestDb::create().await;
    let client = common::at_version(&db, 42).await;
    client.batch_execute(
        "INSERT INTO console_roles (role_id, display_name, builtin) VALUES ('custom', 'Custom', false);
         INSERT INTO console_role_permissions VALUES ('custom', 'findings.read');
         INSERT INTO console_users (user_id, username, display_name, created_at)
              VALUES ('00000000-0000-0000-0000-000000000001', 'u', 'U', now());
         INSERT INTO console_dashboards (dashboard_id, owner_user_id, name, layout, created_at, updated_at)
         VALUES ('00000000-0000-0000-0000-0000000000d1', '00000000-0000-0000-0000-000000000001', 'Mine',
           '{\"schema\":1,\"widgets\":[
              {\"id\":\"a\",\"type\":\"number\",\"x\":0,\"y\":0,\"w\":3,\"h\":2,\"config\":{\"metric\":\"findings.open.high\"}},
              {\"id\":\"b\",\"type\":\"breakdown\",\"x\":3,\"y\":0,\"w\":3,\"h\":2,\"config\":{\"source\":\"findings\"}},
              {\"id\":\"c\",\"type\":\"attention\",\"x\":6,\"y\":0,\"w\":3,\"h\":2,\"config\":{\"include\":[\"alarms\",\"findings\"]}},
              {\"id\":\"d\",\"type\":\"list\",\"x\":9,\"y\":0,\"w\":3,\"h\":2,\"config\":{\"view\":\"/findings\",\"query\":\"severity=high\"}},
              {\"id\":\"e\",\"type\":\"note\",\"x\":0,\"y\":2,\"w\":3,\"h\":2,\"config\":{}}]}', now(), now());",
    ).await.unwrap();
    // A case item of kind 'finding' (fill the NOT NULL columns of cases / case_items as 0035 defines them).
    common::insert_case_with_item(&client, "finding", "agent-1/site/R-1").await;
    drop(client);
    let mut client = db.pool.get().await.unwrap();
    platform_store::migrate(&mut client).await.unwrap();

    let perms: Vec<String> = client
        .query("SELECT permission_id FROM console_role_permissions WHERE role_id = 'custom'", &[])
        .await.unwrap().iter().map(|r| r.get(0)).collect();
    assert_eq!(perms, ["compliance.read"]);
    let old: i64 = client
        .query_one("SELECT count(*) FROM console_permissions WHERE permission_id LIKE 'findings.%'", &[])
        .await.unwrap().get(0);
    assert_eq!(old, 0);
    let analyst: i64 = client
        .query_one("SELECT count(*) FROM console_role_permissions WHERE role_id = 'analyst'
                    AND permission_id IN ('compliance.read', 'compliance.triage')", &[])
        .await.unwrap().get(0);
    assert_eq!(analyst, 2);

    let layout: serde_json::Value = client
        .query_one("SELECT layout FROM console_dashboards", &[]).await.unwrap().get(0);
    let w = &layout["widgets"];
    assert_eq!(w[0]["config"]["metric"], "compliance.open.high");
    assert_eq!(w[1]["config"]["source"], "compliance");
    assert_eq!(w[2]["config"]["include"], serde_json::json!(["alarms", "compliance"]));
    assert_eq!(w[3]["config"]["view"], "/compliance");
    assert_eq!(w[3]["config"]["query"], "severity=high");
    assert_eq!(w[4]["config"], serde_json::json!({}));

    let kind: String = client.query_one("SELECT kind FROM case_items", &[]).await.unwrap().get(0);
    assert_eq!(kind, "compliance_finding");
    drop(client);
    db.drop().await;
}
```

Before running, check `console_users`' NOT NULL columns in `migrations/0017_console_identity.sql` and later migrations and adjust that INSERT. Move `at_version` from `tests/migrate.rs` into `tests/common/mod.rs` as `pub async fn at_version(...)` (same body) and use it from both files. Add `insert_case_with_item(client, kind, reference)` to `tests/common/mod.rs`, inserting one `cases` row and one `case_items` row with the columns `0035_cases.sql` requires (read the file; use fixed UUIDs).

- [ ] **Step 2: Run it, expect FAIL**

Run: `eval "$(scripts/test-db.sh)" && cargo test -p platform-store --test compliance_names`
Expected: FAIL (`perms` is `["findings.read"]`).

- [ ] **Step 3: Write `migrations/0043_compliance_names.sql`**

```sql
-- openvibes: needs-backup
-- OpenVIBES platform schema version 43: rule results are "compliance
-- findings" (user, 2026-10-07). Renames the console's stored IDs; the
-- agent wire protocol and the findings tables keep their names. Audit rows
-- and case events are history and are not rewritten.
INSERT INTO console_permissions (permission_id, scope_class) VALUES
    ('compliance.read', 'agent'), ('compliance.triage', 'agent');
INSERT INTO console_role_permissions (role_id, permission_id)
SELECT role_id, replace(permission_id, 'findings.', 'compliance.')
FROM console_role_permissions
WHERE permission_id IN ('findings.read', 'findings.triage');
DELETE FROM console_permissions WHERE permission_id IN ('findings.read', 'findings.triage');

UPDATE console_dashboards d
SET layout = jsonb_set(d.layout, '{widgets}', (
        SELECT COALESCE(jsonb_agg(
            CASE WHEN jsonb_typeof(w->'config') = 'object' THEN jsonb_set(w, '{config}', COALESCE((
                SELECT jsonb_object_agg(k, CASE
                    WHEN k = 'metric' AND v #>> '{}' LIKE 'findings.open.%'
                        THEN to_jsonb('compliance.open.' || substr(v #>> '{}', 15))
                    WHEN k = 'source' AND v = '"findings"' THEN '"compliance"'::jsonb
                    WHEN k = 'view' AND v = '"/findings"' THEN '"/compliance"'::jsonb
                    WHEN k = 'include' AND jsonb_typeof(v) = 'array' THEN COALESCE((
                        SELECT jsonb_agg(CASE WHEN e = '"findings"' THEN '"compliance"'::jsonb ELSE e END ORDER BY i)
                        FROM jsonb_array_elements(v) WITH ORDINALITY AS x(e, i)), '[]'::jsonb)
                    ELSE v END)
                FROM jsonb_each(w->'config') AS c(k, v)), '{}'::jsonb))
            ELSE w END ORDER BY n), '[]'::jsonb)
        FROM jsonb_array_elements(d.layout->'widgets') WITH ORDINALITY AS t(w, n))),
    version = d.version + 1
WHERE jsonb_typeof(d.layout->'widgets') = 'array';

ALTER TABLE case_items DROP CONSTRAINT case_items_kind_check;
UPDATE case_items SET kind = 'compliance_finding' WHERE kind = 'finding';
ALTER TABLE case_items ADD CONSTRAINT case_items_kind_check
    CHECK (kind IN ('alarm', 'compliance_finding', 'vulnerability', 'host', 'software'));
```

Check the constraint name first: `psql "$OPENVIBES_TEST_DATABASE_URL" -c '\d case_items'` on a migrated DB; use the name shown.

- [ ] **Step 4: Register it and run tests**

Edit `migrate.rs` as listed under Files. Run: `cargo test -p platform-store --test compliance_names --test migrate`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add migrations/0043_compliance_names.sql crates/platform-store
git commit -m "Store: rename findings permissions, dashboard IDs and case kind to compliance"
```

### Task 2: Rust permission and case kind names

**Files:**
- Modify: `crates/openvibes-console/src/api.rs:116-123` (variants + serde names)
- Modify: `crates/openvibes-console/src/rbac.rs`, `seeded.rs`, `detection.rs`, `router.rs`, `assistant.rs` and any other user of `Permission::Findings*`
- Modify: `crates/platform-store/src/console_cases.rs` (kind string `finding` → `compliance_finding`)
- Test: existing `crates/openvibes-console/tests/*.rs`, `crates/platform-store/tests/console_cases.rs`

**Interfaces:**
- Produces: `Permission::ComplianceRead` (`"compliance.read"`), `Permission::ComplianceTriage` (`"compliance.triage"`); case kind `"compliance_finding"`.

- [ ] **Step 1: Rename the variants**

```rust
    #[serde(rename = "compliance.read")]
    ComplianceRead,
    ...
    #[serde(rename = "compliance.triage")]
    ComplianceTriage,
```

Then: `grep -rln 'FindingsRead\|FindingsTriage' crates | xargs sed -i 's/FindingsRead/ComplianceRead/g; s/FindingsTriage/ComplianceTriage/g'`

- [ ] **Step 2: Case kind** — in `console_cases.rs` and console case handlers replace the kind literal `"finding"` (only where it is a case item kind; check each hit with `grep -n '"finding"'`) with `"compliance_finding"`. Update `crates/platform-store/tests/console_cases.rs` expectations the same way.

- [ ] **Step 3: Update test strings** — `grep -rln '"findings.read"\|"findings.triage"' crates/*/tests crates/*/src | xargs sed -i 's/"findings\.read"/"compliance.read"/g; s/"findings\.triage"/"compliance.triage"/g'`

- [ ] **Step 4: Run** `cargo test -p platform-store -p openvibes-console --all-features`
Expected: PASS except tests calling `/api/v1/findings/...` routes (fixed in Task 3).

- [ ] **Step 5: Commit** `git commit -am "Console: compliance permission and case item names"`

### Task 3: Console routes move to /api/v1/compliance

**Files:**
- Modify: `crates/openvibes-console/src/router.rs:470-505` (routes) and every `#[utoipa::path(... path = "/api/v1/findings...", tag = "findings")]`
- Modify: `crates/openvibes-console/src/detection.rs:186`, `crates/openvibes-console/src/openapi.rs:284`, `crates/openvibes-console/src/seeded.rs` (5 paths)
- Modify: problem codes `finding_not_found` → `compliance_finding_not_found` (10 sites in `crates/openvibes-console/src`)
- Modify tests: `crates/openvibes-console/tests/{auth_http,alarms_http,software_http,users_http}.rs`
- NOT: anything under `crates/openvibes-ingest`

- [ ] **Step 1: Failing test** — add to `crates/openvibes-console/tests/auth_http.rs`, next to the existing summary test, using that file's existing helpers for a signed-in analyst:

```rust
#[tokio::test]
async fn compliance_summary_moved_and_old_path_is_gone() {
    let server = AuthServer::start().await; // existing helper in this file
    let session = server.sign_in_as("analyst").await;
    assert_eq!(session.get("/api/v1/compliance/summary").await.status(), 200);
    let old = session.get("/api/v1/findings/summary").await;
    assert_eq!(old.status(), 404);
    assert_eq!(old.headers()["content-type"], "application/problem+json");
    server.stop().await;
}
```

Use the file's real helper names (read the top of `auth_http.rs`); keep the assertions.

- [ ] **Step 2: Run, expect FAIL** — `cargo test -p openvibes-console --test auth_http compliance_summary_moved`

- [ ] **Step 3: Rename**

```bash
sed -i 's#"/v1/findings/#"/v1/compliance/#g; s#"/v1/findings"#"/v1/compliance"#g' crates/openvibes-console/src/router.rs crates/openvibes-console/src/seeded.rs
sed -i 's#/api/v1/findings#/api/v1/compliance#g; s#tag *= *"findings"#tag = "compliance"#g' crates/openvibes-console/src/*.rs
sed -i 's/"finding_not_found"/"compliance_finding_not_found"/g; s/"Finding not found"/"Compliance finding not found"/g' crates/openvibes-console/src/*.rs
sed -i 's#(name = "findings", description = "Scope-filtered observation reads")#(name = "compliance", description = "Scope-filtered compliance finding reads")#' crates/openvibes-console/src/openapi.rs
sed -i 's#/api/v1/findings#/api/v1/compliance#g' crates/openvibes-console/tests/*.rs
git diff --stat -- crates/openvibes-ingest   # must print nothing
```

Rename the handler functions `authenticated_finding_*` → `authenticated_compliance_*` only if clippy or readability asks; not required.

- [ ] **Step 4: Run** `cargo test -p openvibes-console --all-features` — Expected: PASS.

- [ ] **Step 5: Commit** `git commit -am "Console API: /api/v1/findings moves to /api/v1/compliance"`

### Task 4: OpenAPI snapshot and generated client

- [ ] **Step 1:** `cargo run --locked -p openvibes-console --bin export_openapi > docs/api/console-v1.openapi.json`
- [ ] **Step 2:** `npm --prefix crates/openvibes-console/web run generate:api`
- [ ] **Step 3:** `grep -c "v1/findings" docs/api/console-v1.openapi.json crates/openvibes-console/web/src/api/generated.ts` — Expected: `0` for both.
- [ ] **Step 4: Commit** `git commit -am "OpenAPI: regenerate for compliance paths"`

### Task 5: Web console names, paths and legacy IDs

**Files:**
- Modify: every web file listed by `grep -rln 'v1/findings\|findings\.read\|findings\.triage\|"/findings"\|findings\.open' crates/openvibes-console/web/src crates/openvibes-console/web/e2e`
- Modify: `web/src/app/registry.tsx:54` (path `/compliance`, keys unchanged), `web/src/dashboards/tiles.tsx` (metric IDs + labels), `tiles2.tsx`, `attention.tsx`, `widgets.tsx` (`widgetTitle` source map), `panels/cases.ts` (`kindLabel`), `views/rows.ts` (`LIST_VIEWS`), demo `server.ts`/`data.ts`/`cases.ts`
- Create: `web/src/dashboards/legacy.ts`, `web/src/dashboards/legacy.test.ts`
- Modify: `web/src/dashboards/layout.ts` (call `upgradeLayout` wherever a layout is parsed, server or sessionStorage draft)

**Interfaces:**
- Produces: `upgradeLayout(layout: Layout): Layout`; metric IDs `compliance.open.{critical,high,medium,low}`; breakdown source `"compliance"`; attention kind `"compliance"`; list view `"/compliance"`; `kindLabel.compliance_finding = "Compliance finding"`, `kindLabel.finding = "Compliance finding"` (old case events).

- [ ] **Step 1: Failing test** `web/src/dashboards/legacy.test.ts`

```ts
import { describe, expect, it } from "vitest";
import { upgradeLayout } from "./legacy";

describe("upgradeLayout", () => {
  it("maps pre-0.2.6 finding IDs to compliance IDs and leaves the rest", () => {
    const old = { schema: 1, widgets: [
      { id: "a", type: "number", x: 0, y: 0, w: 3, h: 2, config: { metric: "findings.open.critical" } },
      { id: "b", type: "breakdown", x: 0, y: 0, w: 3, h: 2, config: { source: "findings" } },
      { id: "c", type: "attention", x: 0, y: 0, w: 3, h: 2, config: { include: ["alarms", "findings"] } },
      { id: "d", type: "list", x: 0, y: 0, w: 3, h: 2, config: { view: "/findings", query: "severity=high" } },
      { id: "e", type: "number", x: 0, y: 0, w: 3, h: 2, config: { metric: "alarms.active" } },
    ] } as const;
    const up = upgradeLayout(structuredClone(old) as never);
    expect(up.widgets.map((w) => w.config)).toEqual([
      { metric: "compliance.open.critical" }, { source: "compliance" }, { include: ["alarms", "compliance"] },
      { view: "/compliance", query: "severity=high" }, { metric: "alarms.active" },
    ]);
  });
});
```

- [ ] **Step 2:** `npm --prefix crates/openvibes-console/web test -- legacy` — Expected: FAIL (module missing).

- [ ] **Step 3: Implement** `web/src/dashboards/legacy.ts`

```ts
// Dashboards saved before the compliance rename (schema migration 43) can
// still arrive from a browser draft; map their IDs like the migration does.
import type { Layout } from "./layout";

export function upgradeLayout(layout: Layout): Layout {
  return { ...layout, widgets: layout.widgets.map((w) => {
    const c: Record<string, unknown> = { ...w.config };
    if (typeof c.metric === "string" && c.metric.startsWith("findings.open.")) c.metric = `compliance.open.${c.metric.slice(14)}`;
    if (c.source === "findings") c.source = "compliance";
    if (c.view === "/findings") c.view = "/compliance";
    if (Array.isArray(c.include)) c.include = c.include.map((k) => (k === "findings" ? "compliance" : k));
    return { ...w, config: c as typeof w.config };
  }) };
}
```

Call it in `layout.ts` where layouts are validated/parsed (one place; find it with `grep -n "export function" web/src/dashboards/layout.ts`).

- [ ] **Step 4: Rename IDs, paths and labels** (then fix type errors by hand)

```bash
cd crates/openvibes-console/web
grep -rl 'v1/findings' src e2e | xargs sed -i 's#/api/v1/findings#/api/v1/compliance#g'
grep -rl 'findings\.read\|findings\.triage' src e2e | xargs sed -i 's/findings\.read/compliance.read/g; s/findings\.triage/compliance.triage/g'
grep -rl 'findings\.open\.' src e2e | xargs sed -i 's/findings\.open\./compliance.open./g'
grep -rl '"/findings"' src e2e | xargs sed -i 's#"/findings"#"/compliance"#g'
```

Then edit texts by hand (exact strings):

| File | Old | New |
|---|---|---|
| `dashboards/tiles.tsx` METRICS | `Open critical findings` (etc. per severity) | `Open critical compliance findings` (etc.) |
| `dashboards/widgets.tsx` `widgetTitle` | `findings: "Open findings by severity"` | `compliance: "Compliance findings by severity"` (source key and allowed list `"compliance"`) |
| `dashboards/tiles2.tsx:54` | `<option value="findings">Open findings by severity` | `<option value="compliance">Compliance findings by severity` |
| `dashboards/tiles2.tsx:65` | `findings: "Open critical and high findings"` | `compliance: "Open critical and high compliance findings"` |
| `dashboards/tiles2.tsx:22,87` | `Choose a finding…`, `Finding (rule set/rule…` | `Choose a compliance rule…`, `Compliance rule (rule set/rule…` |
| `dashboards/attention.tsx` kind key | `"findings"` | `"compliance"` (and `ATTENTION_KINDS`) |
| `panels/cases.ts:15,17` | `"finding"`, `finding: "Finding"` | `"compliance_finding"`, `compliance_finding: "Compliance finding", finding: "Compliance finding"` |
| `panels/AgentPanel.tsx:121` | `No findings` | `No compliance findings` |
| `shell/CommandPalette.tsx:97` | `hosts, CVEs, findings,` | `hosts, CVEs, compliance findings,` |
| `shell/AssistantDock.tsx:71` | `hosts, findings and vulnerabilities` | `hosts, alarms, vulnerabilities and compliance findings` |
| `views/Cases.tsx:53,69`, `panels/CasePanel.tsx:346` | `alarms, findings and vulnerabilities` / `alarm, finding or host` | `alarms, vulnerabilities and compliance findings` / `alarm, compliance finding or host` |
| `views/SiteRules.tsx:21` | `a match is a finding under Compliance.` | `a match is a compliance finding.` |
| `panels/SiteRulePanel.tsx:40,166` | `raise a finding`, `"Finding message"` | `raise a compliance finding`, `"Compliance finding message"` |
| `views/Findings.tsx:37` | `resolved finding is` / `findings are` | `resolved compliance finding is` / `compliance findings are` |
| `app/registry.tsx:88` | `finding: { label: "Finding"` | `finding: { label: "Compliance finding"` |

- [ ] **Step 5: Verify no bare word remains**

Run: `grep -rn -E "\b[Ff]indings?\b" src --include='*.tsx' | grep -v -E "compliance finding|Compliance finding|import |\bfinding(s)?[A-Z_.]|\.findings|findings\(|finding\.|kind === \"finding\"|\"finding\"" `
Expected: no user-visible string left (identifiers are fine).

- [ ] **Step 6: Tests** — `npm --prefix crates/openvibes-console/web test` and `npm --prefix crates/openvibes-console/web run test:e2e:demo`. Update e2e selectors that clicked "Open critical findings" etc. to the new labels. Expected: PASS.

- [ ] **Step 7: Commit** `git commit -am "Web console: compliance names, paths and legacy dashboard IDs"`

### Task 6: Docs, release note and gate

**Files:** `docs/components/openvibes-console.md`, `console-web.md`, `console-assistant.md` (any `findings.read`, `/api/v1/findings`), `CHANGELOG.md` or the release notes file the repo uses (`ls`; follow its format).

- [ ] **Step 1:** `grep -rln "api/v1/findings\|findings\.read\|findings\.triage" docs | grep -v superpowers` — update each hit to the new names.
- [ ] **Step 2:** Release note entry: "Console: rule results are now 'compliance findings'. API paths moved from `/api/v1/findings/*` to `/api/v1/compliance/*`; permissions `findings.read`/`findings.triage` are now `compliance.read`/`compliance.triage` (roles and saved dashboards are migrated; update scripts). Migration 43 changes stored data: run Update, which takes a backup."
- [ ] **Step 3:** Run the whole gate (`testing.md` §2) plus `bash scripts/test-console-e2e.sh`. Expected: all green.
- [ ] **Step 4: Commit** `git commit -am "Docs: compliance names"` and open PR 1.
