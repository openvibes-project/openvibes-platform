#!/usr/bin/env bash
# Verifies installed openvibes-ingest, -distribution, -vulns, -admin, and -llm (run as root).
set -euo pipefail
fail() { echo "FAIL: $*" >&2; exit 1; }
expect_stat() { # PATH MODE OWNER:GROUP
    [[ "$(stat -c '%a %U:%G' "$1")" == "$2 $3" ]] || fail "$1 is $(stat -c '%a %U:%G' "$1"), want $2 $3"
}
for user in openvibes-ingest openvibes-distribution openvibes-vulns openvibes-admin; do
    getent passwd "$user" >/dev/null || fail "no user $user"
done
expect_stat /etc/openvibes/ingest.toml 640 root:openvibes-ingest
expect_stat /etc/openvibes/admin.toml 640 root:openvibes-admin
expect_stat /etc/openvibes/distribution.toml 640 root:openvibes-distribution
expect_stat /etc/openvibes/vulns.toml 640 root:openvibes-vulns
expect_stat /var/lib/openvibes-ingest 700 openvibes-ingest:openvibes-ingest
rpm -qc openvibes-ingest | grep -qx /etc/openvibes/ingest.toml || fail "ingest.toml not %config"
rpm -qc openvibes-admin | grep -qx /etc/openvibes/admin.toml || fail "admin.toml not %config"
rpm -qc openvibes-distribution | grep -qx /etc/openvibes/distribution.toml || fail "distribution.toml not %config"
rpm -qc openvibes-vulns | grep -qx /etc/openvibes/vulns.toml || fail "vulns.toml not %config"
[[ "$(rpm -q --qf '[%{FILENAMES} %{FILEFLAGS:fflags}\n]' openvibes-ingest openvibes-distribution openvibes-vulns openvibes-admin | grep -c '\.toml cn')" == 4 ]] || fail "configs not noreplace"
systemd-analyze verify /usr/lib/systemd/system/openvibes-ingest.service \
    /usr/lib/systemd/system/openvibes-distribution.service \
    /usr/lib/systemd/system/openvibes-vulns.service \
    /usr/lib/systemd/system/openvibes-maintenance.service \
    /usr/lib/systemd/system/openvibes-maintenance.timer || fail "unit verification"
grep -q '^KillSignal=SIGINT' /usr/lib/systemd/system/openvibes-ingest.service || fail "unit lacks KillSignal=SIGINT (the drain signal)"
grep -q '^KillSignal=SIGINT' /usr/lib/systemd/system/openvibes-distribution.service || fail "distribution unit lacks KillSignal=SIGINT"
grep -q '^KillSignal=SIGINT' /usr/lib/systemd/system/openvibes-vulns.service || fail "vulns unit lacks KillSignal=SIGINT"
/usr/bin/openvibes-admin --help >/dev/null || fail "openvibes-admin does not run"
# Administration TUI operators (admin TUI spec §3).
getent group openvibes-operators >/dev/null || fail "no openvibes-operators group"
visudo -cf /etc/sudoers.d/openvibes-operators >/dev/null || fail "sudoers drop-in does not parse"
[[ "$(stat -c '%a %U' /etc/sudoers.d/openvibes-operators)" == "440 root" ]] || fail "sudoers drop-in mode"
[[ -f /usr/share/polkit-1/rules.d/50-openvibes-operators.rules ]] || fail "no polkit rule"
# Hyphenated service accounts (admin TUI spec §2) and the upgrade rename.
for n in admin ingest distribution vulns; do
    getent passwd openvibes-$n >/dev/null || fail "no openvibes-$n user"
    [[ -x /usr/libexec/openvibes/rename-account-$n ]] || fail "no rename-account-$n"
    rpm -q --scripts openvibes-$n | grep -q "old=openvibes_$n; new=openvibes-$n" || fail "openvibes-$n lacks the %pre rename"
    rpm -q --scripts openvibes-$n | grep -q "rename-account-$n post $n" || fail "openvibes-$n lacks the %post rename"
done
out=$(/usr/bin/openvibes-ingest --config /nonexistent 2>&1) && fail "ingest started without config"
[[ "$out" == *"invalid ingest configuration"* ]] || fail "ingest error: $out"
out=$(/usr/bin/openvibes-distribution --config /nonexistent 2>&1) && fail "distribution started without config"
[[ "$out" == *"invalid distribution configuration"* ]] || fail "distribution error: $out"
out=$(/usr/bin/openvibes-vulns --config /nonexistent 2>&1) && fail "vulns started without config"
[[ "$out" == *"invalid vulns configuration"* ]] || fail "vulns error: $out"

# openvibes-llm: files, the generated API key, the unit, and the pre-start
# check (which refuses root and a missing model).
getent passwd openvibes-llm >/dev/null || fail "no user openvibes-llm"
expect_stat /etc/openvibes/llm.conf 644 root:root
expect_stat /etc/openvibes/llm-api-key 600 root:root
[[ "$(cat /etc/openvibes/llm-api-key)" =~ ^[0-9a-f]{64}$ ]] || fail "llm-api-key is not 64 hex characters"
expect_stat /var/lib/openvibes-llm 775 root:openvibes-admin
expect_stat /var/lib/openvibes-llm/models 775 root:openvibes-admin
rpm -qc openvibes-llm | grep -qx /etc/openvibes/llm.conf || fail "llm.conf not %config"
systemd-analyze verify /usr/lib/systemd/system/openvibes-llm.service || fail "llm unit verification"
for line in 'IPAddressDeny=any' 'IPAddressAllow=localhost' 'CapabilityBoundingSet=' 'NoExecPaths=/' \
    'LoadCredential=api-key:/etc/openvibes/llm-api-key' 'ExecStartPre=/usr/libexec/openvibes-llm/openvibes-llm-check'; do
    grep -qx "$line" /usr/lib/systemd/system/openvibes-llm.service || fail "llm unit lacks $line"
done
/usr/libexec/openvibes-llm/llama-server --help 2>&1 | grep -q -- '--api-key-file' || fail "llama-server does not run"
out=$(/usr/libexec/openvibes-llm/openvibes-llm-check 2>&1) && fail "llm check ran as root"
[[ "$out" == *"must not run as root"* ]] || fail "llm check as root: $out"
out=$(runuser -u openvibes-llm -- env -i $(grep -E '^OPENVIBES_LLM_' /etc/openvibes/llm.conf) \
    /usr/libexec/openvibes-llm/openvibes-llm-check 2>&1) && fail "llm check passed without a model"
[[ "$out" == *"OPENVIBES_LLM_MODEL is not set"* ]] || fail "llm check without a model: $out"
echo "check-rpm: ok"
