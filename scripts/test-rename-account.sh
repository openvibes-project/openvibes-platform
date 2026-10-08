#!/bin/bash
# Tests packaging/rpm/rename-account.sh (the %post step of the account
# rename, admin TUI spec §2) with a fake runuser/psql. No root needed.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
SCRIPT=$ROOT/packaging/rpm/rename-account.sh
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
mkdir -p "$T/bin"
# Fake `runuser -u postgres -- psql ...`: logs its SQL; answers the pg_roles
# query with the contents of $T/roles; fails when $T/down exists.
cat > "$T/bin/runuser" <<'FAKE'
#!/bin/bash
[[ -e $STATE/down ]] && exit 2
sql=${@: -1}
echo "$sql" >> "$STATE/log"
[[ $sql == SELECT* ]] && cat "$STATE/roles" 2>/dev/null
exit 0
FAKE
chmod +x "$T/bin/runuser"
# Fake `getent passwd NAME`: the users listed in $T/users exist.
cat > "$T/bin/getent" <<'FAKE'
#!/bin/bash
grep -qx "$2" "$STATE/users" 2>/dev/null
FAKE
chmod +x "$T/bin/getent"
printf '%s\n' openvibes-ingest openvibes-vulns openvibes-llm openvibes-admin > "$T/users"
export PATH=$T/bin:$PATH STATE=$T
run() { : > "$T/log"; bash "$SCRIPT" "$@" 2> "$T/err" || { cat "$T/err" >&2; return 1; }; }

# Config: only the exact user= token of database_url changes.
cfg=$T/ingest.toml
printf '%s\n' '# openvibes_ingest note' \
  'database_url = "postgresql:///openvibes?host=/run/postgresql&user=openvibes_ingest"' \
  'other = "postgresql:///x?user=openvibes_ingestion&a=1"' > "$cfg"
echo openvibes_ingest > "$T/roles"
run post ingest "$cfg"
grep -qx '# openvibes_ingest note' "$cfg" || fail "comment changed"
grep -q 'user=openvibes-ingest"' "$cfg" || fail "user= not rewritten"
grep -q 'user=openvibes_ingestion&' "$cfg" || fail "a longer name was changed"
grep -qx 'ALTER ROLE openvibes_ingest RENAME TO "openvibes-ingest";' "$T/log" || fail "role not renamed: $(cat "$T/log")"
cp "$cfg" "$T/before"; echo openvibes-ingest > "$T/roles"
run post ingest "$cfg"
cmp -s "$cfg" "$T/before" || fail "second run changed the config"
grep -q ALTER "$T/log" && fail "renamed a role that is already renamed"

# PostgreSQL unreachable: success, and the statement is printed.
echo postgres >> "$T/users"
touch "$T/down"
run post vulns || fail "failed the transaction"
grep -q 'ALTER ROLE openvibes_vulns RENAME TO "openvibes-vulns";' "$T/err" || fail "statement not printed"
sed -i '/^postgres$/d' "$T/users"

# A fresh install (install walkthrough, 2026-10-08): PostgreSQL is not on
# this host yet (Setup installs it) and the config points here: no database,
# nothing to rename, nothing to say.
local_cfg=$T/admin.toml
echo 'database_url = "postgresql:///openvibes?host=/run/postgresql&user=openvibes-admin"' > "$local_cfg"
run post admin "$local_cfg" || fail "failed the transaction"
[[ ! -s $T/err ]] || fail "a fresh install printed: $(cat "$T/err")"
# The database on another server: still say what to run there.
remote_cfg=$T/remote.toml
echo 'database_url = "postgresql://db.example/openvibes?user=openvibes_admin"' > "$remote_cfg"
run post admin "$remote_cfg" || fail "failed the transaction"
grep -q 'ALTER ROLE openvibes_admin RENAME TO "openvibes-admin";' "$T/err" || fail "remote database: statement not printed"
rm "$T/down"

# The OS rename did not happen (old user still there): change nothing, say so.
printf '%s\n' openvibes_ingest > "$T/users"
cp "$T/before" "$cfg"; sed -i 's/user=openvibes-ingest"/user=openvibes_ingest"/' "$cfg"; cp "$cfg" "$T/kept"
echo openvibes_ingest > "$T/roles"
run post ingest "$cfg"
cmp -s "$cfg" "$T/kept" || fail "config rewritten although the OS user was not renamed"
grep -q ALTER "$T/log" && fail "role renamed although the OS user was not renamed"
grep -q 'openvibes_ingest was not renamed' "$T/err" || fail "no message when the OS rename is missing: $(cat "$T/err")"
printf '%s\n' openvibes-ingest openvibes-vulns openvibes-llm > "$T/users"

# Roles in an unexpected state: both names, or neither: warn with the statement.
printf '%s\n' openvibes_ingest openvibes-ingest > "$T/roles"
run post ingest
grep -q ALTER "$T/log" && fail "renamed with both roles present"
grep -q 'both openvibes_ingest and openvibes-ingest exist' "$T/err" || fail "no warning with both roles: $(cat "$T/err")"
: > "$T/roles"
run post ingest
grep -q 'neither openvibes_ingest nor openvibes-ingest' "$T/err" || fail "no warning with neither role: $(cat "$T/err")"

# llm has no database role: no psql at all.
run post llm
[[ ! -s $T/log ]] || fail "llm touched the database"
echo "ok: rename-account"
