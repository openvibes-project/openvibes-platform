#!/bin/bash
# After an upgrade from openvibes_NAME service accounts (admin TUI spec §2):
# point the kept config at the renamed PostgreSQL role, then rename the role
# as postgres. The OS user and group are renamed by the spec's %rename_pre;
# nothing here runs unless that rename happened. Idempotent; never fails the
# RPM transaction, and says what to do when it cannot finish.
set -u
[[ ${1:-} == post ]] || exit 0
name=${2:-} config=${3:-}
case $name in admin | ingest | distribution | vulns) ;; *) exit 0 ;; esac
old=openvibes_$name new=openvibes-$name
if getent passwd "$old" >/dev/null || ! getent passwd "$new" >/dev/null; then
    echo "openvibes: the OS account $old was not renamed to $new; config and database role left as they are" >&2
    exit 0
fi
if [[ -n $config && -f $config ]]; then
    sed -i -E "s/([?&]user=)${old}([&\"])/\\1${new}\\2/" "$config"
fi
sql="ALTER ROLE ${old} RENAME TO \"${new}\";"
if ! has=$(runuser -u postgres -- psql -AtqX -c \
    "SELECT rolname FROM pg_roles WHERE rolname IN ('$old','$new') ORDER BY 1" 2>/dev/null); then
    # A fresh install: PostgreSQL is not on this host yet (Setup installs it)
    # and the config points here, so there is no database and no role to
    # rename. A database on another server still gets the statement.
    if ! getent passwd postgres >/dev/null &&
        { [[ -z $config || ! -f $config ]] || grep -q 'host=/' "$config"; }; then
        exit 0
    fi
    echo "openvibes: PostgreSQL not reachable here; on the database server run as postgres: $sql" >&2
    exit 0
fi
case $has in
"$new") ;;
"$old")
    runuser -u postgres -- psql -qX -c "$sql" ||
        echo "openvibes: run as postgres: $sql" >&2 ;;
"")
    echo "openvibes: neither $old nor $new exists in this host's PostgreSQL; if the database is elsewhere, run there as postgres: $sql" >&2 ;;
*)
    echo "openvibes: both $old and $new exist in PostgreSQL; $new has no grants from the upgrade. Move the database to $new by hand (see packaging.md)." >&2 ;;
esac
exit 0
