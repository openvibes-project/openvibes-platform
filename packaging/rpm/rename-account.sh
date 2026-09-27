#!/bin/bash
# After an upgrade from openvibes_NAME service accounts (admin TUI spec §2):
# point the kept config at the renamed PostgreSQL role, then rename the role
# as postgres. The OS user and group are renamed by the spec's %rename_pre.
# Idempotent; never fails the RPM transaction.
set -u
[[ ${1:-} == post ]] || exit 0
name=${2:-} config=${3:-}
case $name in admin | ingest | distribution | vulns) ;; *) exit 0 ;; esac
old=openvibes_$name new=openvibes-$name
if [[ -n $config && -f $config ]]; then
    sed -i -E "s/([?&]user=)${old}([&\"])/\\1${new}\\2/" "$config"
fi
sql="ALTER ROLE ${old} RENAME TO \"${new}\";"
if has=$(runuser -u postgres -- psql -AtqX -c \
    "SELECT rolname FROM pg_roles WHERE rolname IN ('$old','$new')" 2>/dev/null); then
    if [[ $has == "$old" ]]; then
        runuser -u postgres -- psql -qX -c "$sql" ||
            echo "openvibes: run as postgres: $sql" >&2
    fi
else
    echo "openvibes: PostgreSQL not reachable here; on the database server run as postgres: $sql" >&2
fi
exit 0
