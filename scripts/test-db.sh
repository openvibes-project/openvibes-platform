#!/usr/bin/env bash
# Throwaway PostgreSQL for local tests, under target/pg (no root, no system
# service, Unix socket only). Usage:
#   eval "$(scripts/test-db.sh)"   start (if needed) and export the URL
#   scripts/test-db.sh stop        stop it
set -euo pipefail
cd "$(dirname "$0")/.."
DATA="$PWD/target/pg/data"
RUN="$PWD/target/pg/run"
LOG="$PWD/target/pg/log"
mkdir -p "$RUN"
if [[ "${1:-}" == "stop" ]]; then
    pg_ctl -D "$DATA" -m fast stop >/dev/null
    exit 0
fi
if [[ ! -d "$DATA" ]]; then
    initdb -D "$DATA" -U openvibes_test --auth=trust >/dev/null
fi
# max_locks_per_transaction=256: the parallel test databases' migrations
# ran out of lock slots ("out of shared memory, increase
# max_locks_per_transaction" in target/pg/log, seen as `migrate
# Err(Query)`). A running cluster picks it up only after stop and start.
if ! pg_ctl -D "$DATA" status >/dev/null 2>&1; then
    pg_ctl -D "$DATA" -o "-k $RUN -c listen_addresses='' -c max_locks_per_transaction=256" -l "$LOG" -w start >/dev/null
fi
echo "export OPENVIBES_TEST_DATABASE_URL=\"postgresql:///postgres?host=$RUN&user=openvibes_test\""
