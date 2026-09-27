# Account rename (admin TUI PR 0) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:executing-plans (native) or superpowers:subagent-driven-development. Steps use checkboxes.

**Goal:** Service accounts and their PostgreSQL roles use hyphenated names (`openvibes-admin`, `-ingest`, `-distribution`, `-vulns`, `-llm`), on fresh installs and on upgrade.

**Architecture:** New databases create the hyphenated roles directly (the role-creating migrations are edited; applied migrations never re-run and carry no checksum). Existing installs are renamed once by the RPM: `%pre` renames the OS user and group (stopping the unit first), `%post` rewrites `user=` in the kept config and renames the PostgreSQL role as `postgres`. Everything else is a mechanical rename, guarded by a check that no old name remains.

**Tech Stack:** SQL migrations, RPM spec scriptlets (bash), systemd units, Rust tests, bash e2e scripts, GitHub Actions.

**Spec:** `docs/specs/2026-09-27-admin-tui-design.md` §2.

## Global Constraints

- Names: `openvibes-admin`, `openvibes-ingest`, `openvibes-distribution`, `openvibes-vulns`, `openvibes-llm` (OS user = group = PostgreSQL role). The console's `openvibes-console` is Codex's (#29).
- In SQL, always quote: `"openvibes-ingest"`. In `pg_roles` lookups use the plain string `'openvibes-ingest'`.
- Old names appear only in: the RPM rename scriptlets, the `check-names` guard's pattern, historical comments of applied migrations that are not role statements, and docs describing the upgrade.
- The upgrade never leaves the admin CLI without a database login: OS rename (`%pre`) and role rename + config rewrite (`%post`) happen in the same transaction set.
- A remote (non-local) PostgreSQL is not renamed automatically; `%post` prints the exact `ALTER ROLE` statements.
- Files under 500 lines; docs updated in the same PR; commits end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- Build with `CARGO_NET_GIT_FETCH_WITH_CLI=true`; test DB via `eval "$(scripts/test-db.sh)"`.

## Review Focus

- Upgrade while services are running: `usermod -l` refuses a user with processes; `%pre` stops the unit first and the unit restarts afterwards (Task 3 upgrade e2e).
- rpm creating the new-named user from sysusers before `%pre`: the empty new account is removed and the old one renamed, so files and the database keep one owner (Task 3 upgrade e2e asserts one `openvibes-ingest` user whose uid owns `/var/lib/openvibes-ingest`).
- Re-running the upgrade scriptlets (reinstall, `dnf reinstall`): every step checks state and does nothing the second time (Task 2 check, Task 3 e2e runs `dnf reinstall`).
- A test cluster that already holds old-named roles from earlier runs: new databases still get working grants on the new roles (Task 1 migrate test).
- A config the operator edited: only the exact `user=openvibes_X` token in `database_url` changes; the rest of the file is untouched (Task 2 unit test of the sed expression).
- PostgreSQL stopped during the upgrade: `%post` does not fail the transaction; it prints the statements to run (Task 2 test).

---

### Task 1: Roles in migrations and code

**Files:**
- Modify: `migrations/0001_initial.sql`, `0004_ingest_least_privilege.sql`, `0006_rule_distribution.sql`, `0007_inventory.sql`, `0008_vulnerabilities.sql`, `0010_cve_enrichment.sql`, `0012_vulns_analyze.sql`, `0014_version_vulnerabilities.sql`, `0015_imported_hosts.sql` (any role reference)
- Modify: every `crates/**` file with `openvibes_(admin|ingest|distribution|vulns|llm)` in SQL, role names, or comments (`git grep -n -E 'openvibes_(admin|ingest|distribution|vulns|llm)' crates`)
- Test: `crates/platform-store/tests/migrate.rs`

- [ ] **Step 1:** Branch `account-rename` from `main`. In `tests/migrate.rs` add:

```rust
// Fresh databases create the hyphenated roles (spec §2), with the grants the
// services need, even in a cluster that still holds old-named roles.
#[tokio::test]
async fn roles_are_hyphenated() {
    let db = TestDb::create().await;
    let mut client = db.pool.get().await.unwrap();
    platform_store::migrate(&mut client).await.unwrap();
    for (role, table, privilege) in [
        ("openvibes-ingest", "findings", "INSERT"),
        ("openvibes-distribution", "rule_bundles", "SELECT"),
        ("openvibes-vulns", "vulnerabilities", "INSERT"),
    ] {
        let granted: bool = client
            .query_one("SELECT has_table_privilege($1, $2, $3)", &[&role, &table, &privilege])
            .await
            .unwrap()
            .get(0);
        assert!(granted, "{role} {privilege} {table}");
    }
    db.drop().await;
}
```

- [ ] **Step 2:** `eval "$(scripts/test-db.sh)"; cargo test -q -p platform-store --test migrate roles_are_hyphenated` → FAIL: `role "openvibes-ingest" does not exist`.
- [ ] **Step 3:** In the migrations, replace every role identifier: `openvibes_X` → `"openvibes-X"` in `CREATE ROLE`, `GRANT … TO`, `REVOKE … FROM`, and `'openvibes_X'` → `'openvibes-X'` in `pg_roles` lookups. Script it and read the diff:

```bash
for r in admin ingest distribution vulns llm; do
  sed -i -E "s/rolname = 'openvibes_${r}'/rolname = 'openvibes-${r}'/g; s/\\bopenvibes_${r}\\b/\"openvibes-${r}\"/g" migrations/*.sql
done
git diff migrations | grep '^[-+]' | grep -v '^[-+][-+]' | head -60
```

Fix any comment that became `"openvibes-X"` back to plain `openvibes-X` (comments need no quotes). Then the Rust side: `SET ROLE openvibes_X` → `SET ROLE "openvibes-X"`; string role names in tests/examples → `openvibes-X`; doc comments → `openvibes-X`.
- [ ] **Step 4:** `cargo test -q --workspace --all-features` → all pass; `cargo clippy -q --workspace --all-targets --all-features -- -D warnings` clean.
- [ ] **Step 5:** Commit `Roles: hyphenated names for new databases`.

### Task 2: Packaging and the upgrade scriptlets

**Files:**
- Modify: `packaging/rpm/*.sysusers`, `packaging/rpm/*.service` (`User=`, `Group=`), `packaging/rpm/*.toml` (`database_url` `user=`), `packaging/rpm/openvibes-platform.spec` (`%attr`, a `%rename_pre` macro, `%pre`/`%post`)
- Create: `packaging/rpm/rename-account.sh` (the `%post` step; installed per package as `%{_libexecdir}/openvibes/rename-account-NAME`)
- Modify: `scripts/check-rpm.sh` (assert names and scriptlets in the built RPMs)
- Test: `scripts/test-rename-account.sh` (the post step with fake commands; CI lint job)

**Interfaces — Produces:** `rename-account-NAME post NAME [CONFIG]`, NAME ∈ `admin ingest distribution vulns llm`; spec macro `%rename_pre NAME UNIT`.

Why two pieces: on the first upgrade the new package's `%pre` runs before any of its files exist, so the OS rename must be inline in the spec (`%rename_pre`); `%post` runs after files are installed and can call the script. Fedora's rpm may create the new user from the sysusers file before `%pre`; the macro handles both orders: at `%pre` time no file of the new package exists yet, so an empty just-created new account can be removed before the old one takes its name.

- [ ] **Step 1:** `scripts/test-rename-account.sh`: put fake `runuser` on `PATH` (logs argv; answers the `pg_roles` query from a state file; can be told to fail), run `packaging/rpm/rename-account.sh`, and assert:
  - `post ingest CONFIG` rewrites exactly `user=openvibes_ingest` to `user=openvibes-ingest` in a config that also contains `# openvibes_ingest note` and `user=openvibes_ingestion` (both unchanged); run twice → same file;
  - old role present → `ALTER ROLE openvibes_ingest RENAME TO "openvibes-ingest";` issued once; new role present → nothing;
  - psql failing (PostgreSQL down) → exit 0 and stderr contains that `ALTER ROLE` statement;
  - `post llm` → no psql call at all (no database role), exit 0.
- [ ] **Step 2:** `bash scripts/test-rename-account.sh` → FAIL (`rename-account.sh: No such file`).
- [ ] **Step 3:** `packaging/rpm/rename-account.sh`:

```bash
#!/bin/bash
# After an upgrade from openvibes_NAME accounts (admin TUI spec §2): point the
# kept config at the renamed role and rename the PostgreSQL role. Idempotent;
# never fails the RPM transaction.
set -u
[[ ${1:-} == post ]] || exit 0
name=${2:-} config=${3:-}
case $name in admin|ingest|distribution|vulns) ;; *) exit 0 ;; esac
old=openvibes_$name new=openvibes-$name
if [[ -n $config && -f $config ]]; then
    sed -i -E "s/([?&]user=)${old}([&\"])/\1${new}\2/" "$config"
fi
sql="ALTER ROLE ${old} RENAME TO \"${new}\";"
if has=$(runuser -u postgres -- psql -AtqX -c \
        "SELECT rolname FROM pg_roles WHERE rolname IN ('$old','$new')" 2>/dev/null); then
    if [[ $has == "$old" ]]; then
        runuser -u postgres -- psql -qX -c "$sql" || echo "openvibes: run as postgres: $sql" >&2
    fi
else
    echo "openvibes: PostgreSQL not reachable here; on the database server run as postgres: $sql" >&2
fi
exit 0
```

In the spec, the macro (near the top) and its use, e.g. for ingest:

```
%define rename_pre() \
old=openvibes_%1; new=openvibes-%1; \
if getent passwd $old >/dev/null; then \
    if getent passwd $new >/dev/null && ! pgrep -u $new >/dev/null; then userdel $new; groupdel $new 2>/dev/null; fi; \
    if ! getent passwd $new >/dev/null; then systemctl stop %2 2>/dev/null; usermod -l $new $old && groupmod -n $new $old; fi; \
fi; :

%pre -n openvibes-ingest
%rename_pre ingest openvibes-ingest.service
%post -n openvibes-ingest
%{_libexecdir}/openvibes/rename-account-ingest post ingest %{_sysconfdir}/openvibes/ingest.toml
%systemd_post openvibes-ingest.service
```

Same for distribution, vulns, admin (`%rename_pre admin openvibes-maintenance.service`; config `admin.toml`) and llm (`%rename_pre llm openvibes-llm.service`; `%post` needs no script call). Install the script per package (`install -D -m 0755 packaging/rpm/rename-account.sh %{buildroot}%{_libexecdir}/openvibes/rename-account-ingest`, and so on) and list it in each `%files`. Rename `sysusers` (`u openvibes-ingest - "OpenVIBES ingest service" /var/lib/openvibes-ingest -`), `User=`/`Group=`, `%attr(… openvibes-X …)`, and `user=openvibes-X` in the shipped TOMLs.
- [ ] **Step 4:** `bash scripts/test-rename-account.sh` → PASS. `bash scripts/build-rpm.sh` then `bash scripts/check-rpm.sh target/rpm`, extended to assert: `rpm -qp --scripts` of each package contains `usermod -l openvibes-X openvibes_X`; `rpm -qp --dump` shows files owned by `openvibes-X`; no shipped file other than the rename script and scriptlets contains `openvibes_`. → PASS (in the fedora container as CI does, or CI).
- [ ] **Step 5:** Add `bash scripts/test-rename-account.sh` to CI's lint job. Commit `Packaging: hyphenated service accounts; rename on upgrade`.

### Task 3: Scripts, docs, name guard, upgrade test

**Files:**
- Modify: `scripts/systemd-e2e.sh`, `scripts/integration-lib.sh`, `scripts/integration-agent.sh`, `docs/**` (not `docs/specs`, `docs/plans`, `docs/handover`), `README.md`
- Create: `scripts/check-names.sh`, `scripts/upgrade-e2e.sh`
- Modify: `.github/workflows/ci.yml` (lint runs `check-names.sh`; fedora job also builds base RPMs from the PR base; new `upgrade-e2e` job)

- [ ] **Step 1:** `scripts/check-names.sh`:

```bash
#!/bin/bash
# Old service account names may appear only where the rename needs them.
cd "$(dirname "$0")/.."
hits=$(git grep -n -E 'openvibes_(admin|ingest|distribution|vulns|llm)\b' -- \
    ':!packaging/rpm/rename-account.sh' ':!packaging/rpm/openvibes-platform.spec' \
    ':!scripts/check-names.sh' ':!scripts/test-rename-account.sh' ':!scripts/upgrade-e2e.sh' \
    ':!scripts/check-rpm.sh' \
    ':!docs/specs' ':!docs/plans' ':!docs/handover' ':!docs/components/packaging.md')
[[ -z $hits ]] || { echo "old account names:"; echo "$hits"; exit 1; }
```

Run → FAIL listing the scripts and docs.
- [ ] **Step 2:** Rename in the listed files (`openvibes_X` → `openvibes-X`; in `psql -c` SQL inside scripts quote as `\"openvibes-X\"`). In `docs/components/packaging.md` rewrite the install steps with the new names and add "Upgrading from openvibes_* accounts": what `%pre`/`%post` do and the manual `ALTER ROLE` statements for a remote database. `check-names.sh` → PASS.
- [ ] **Step 3:** `scripts/upgrade-e2e.sh BASE_RPM_DIR NEW_RPM_DIR`: in the same podman fedora:44 systemd container as `systemd-e2e.sh` (reuse its helpers by sourcing a new `scripts/e2e-lib.sh` extracted from it): install PostgreSQL and the base RPMs, create `openvibes_admin` role and database, `migrate`, `maintenance`, start ingest with a test certificate (reuse the CA steps), wait ready; then `dnf -y upgrade NEW_RPM_DIR/*.rpm`; assert:
  - `getent passwd openvibes-ingest` and no `openvibes_ingest` (each account), and `stat -c %U /var/lib/openvibes-ingest` is `openvibes-ingest`;
  - `psql -Atc "SELECT rolname FROM pg_roles WHERE rolname LIKE 'openvibes%'"` lists only hyphenated names;
  - `/etc/openvibes/ingest.toml` has `user=openvibes-ingest`;
  - ingest `/ready` 200 again; `runuser -u openvibes-admin -- openvibes-admin status` succeeds;
  - `dnf -y reinstall NEW_RPM_DIR/*.rpm` changes nothing and ingest stays ready.
- [ ] **Step 4:** CI: in the fedora job, after the normal build, `git worktree add /tmp/base ${{ github.event.pull_request.base.sha || 'HEAD~1' }}` and build base RPMs there into `dist-base/` (upload as a second artifact); new job `upgrade-e2e` (needs fedora) runs `bash scripts/upgrade-e2e.sh dist-base dist`. Run locally if podman is available, otherwise rely on CI.
- [ ] **Step 5:** `systemd-e2e.sh` passes with the new names (CI). Commit `Scripts and docs: hyphenated accounts; name guard; upgrade test`; push; open PR "Hyphenated service accounts (admin TUI PR 0)" noting for Codex that #29 must use `openvibes-console` and quote it in SQL.

### After merge

Workspace `status.md`: PR 0 merged; note for Codex. Then the PR 1 plan (`platform-host` + Services screen).
