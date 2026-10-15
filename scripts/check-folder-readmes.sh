#!/bin/bash
# Every code folder under the roots below has a README.md that names each of
# its code files (`name.ts`) and subfolders (`name/`), and names nothing that
# is gone, so a folder's description cannot fall behind its contents.
# Tests (*.test.*) and assets need no line.
cd "$(dirname "$0")/.." || exit 2
roots=(crates/openvibes-console/web/src crates/openvibes-console/src)
failed=0
fail() { echo "$1"; failed=1; }

while IFS= read -r dir; do
    readme="$dir/README.md"
    entries=$(git ls-files -- "$dir" | sed "s#^$dir/##" | awk -F/ '
        NF > 1 { print $1 "/"; next }
        /\.(rs|ts|tsx|css|json)$/ && !/\.test\./ { print }' | sort -u)
    [[ -n $entries ]] || continue
    [[ -f $readme ]] || { fail "missing $readme"; continue; }
    while IFS= read -r entry; do
        grep -qF "\`$entry\`" "$readme" || fail "$readme does not name $entry"
    done <<< "$entries"
    # Names in backticks that look like this folder's files or subfolders.
    while IFS= read -r named; do
        grep -qxF "$named" <<< "$entries" || fail "$readme names $named, which is not in $dir"
    done < <(grep -oE '^\| `[A-Za-z0-9_.-]+/?`' "$readme" | tr -d '|` ')
done < <(for root in "${roots[@]}"; do
    git ls-files -- "$root" | xargs -n1 dirname | sort -u |
        while IFS= read -r d; do while [[ $d == "$root"* ]]; do echo "$d"; d=$(dirname "$d"); done; done
done | sort -u)

[[ $failed -eq 0 ]] && echo "ok: every folder README matches its folder"
exit $failed
