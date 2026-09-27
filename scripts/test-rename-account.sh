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
touch "$T/down"
run post vulns || fail "failed the transaction"
grep -q 'ALTER ROLE openvibes_vulns RENAME TO "openvibes-vulns";' "$T/err" || fail "statement not printed"
rm "$T/down"

# llm has no database role: no psql at all.
run post llm
[[ ! -s $T/log ]] || fail "llm touched the database"
echo "ok: rename-account"
