#!/usr/bin/env bash
# Verifies installed openvibes-ingest, -distribution, -vulns, -admin, -signer and -llm (run as root).
set -euo pipefail
fail() { echo "FAIL: $*" >&2; exit 1; }
expect_stat() { # PATH MODE OWNER:GROUP
    [[ "$(stat -c '%a %U:%G' "$1")" == "$2 $3" ]] || fail "$1 is $(stat -c '%a %U:%G' "$1"), want $2 $3"
}
# Built packages (OV_CHECK_BUILT=1, after build-rpm.sh): the model is not
# packaged, and openvibes-llm-model keeps owning its path so upgrades from
# 0.2.5 (which shipped it) leave the user's model alone.
if [[ ${OV_CHECK_BUILT:-0} == 1 ]]; then
    rpms=${OV_RPM_TOPDIR:-target/rpm}/RPMS/x86_64
    . packaging/llm/model.pin
    for f in "$rpms"/openvibes-*.rpm; do
        # A %ghost model path (the bridge) lists the name but has no bytes.
        list=$(rpm -qp --qf '[%{FILESIZES} %{FILEFLAGS:fflags} %{FILENAMES}\n]' "$f")
        [[ -z "$(awk '$3 ~ /\.(gguf|part0|part1)$/ && ($1 > 0 || $2 !~ /g/)' <<<"$list")" ]] || fail "$f contains model bytes"
    done
    ! ls "$rpms"/openvibes-llm-model-part*.rpm >/dev/null 2>&1 || fail "a model part package was built"
    meta=$(ls "$rpms"/openvibes-llm-model-[0-9]*.rpm)
    [[ "$(rpm -qlp "$meta" | grep -v '^/usr/share/licenses/')" == "$(printf '%s\n' \
        /var/lib/openvibes-llm/model.conf "/var/lib/openvibes-llm/models/$LLM_MODEL_FILE" | sort)" ]] ||
        fail "openvibes-llm-model lists other files than model.conf and the model path"
    rpm -qp --obsoletes "$meta" | grep -q '^openvibes-llm-model-part1 <' || fail "no Obsoletes part1"
    rpm -qp --obsoletes "$meta" | grep -q '^openvibes-llm-model-part2 <' || fail "no Obsoletes part2"
    rpm -qp --requires "$meta" | grep -q '^openvibes-llm = ' || fail "bridge does not require openvibes-llm"
    rpm -qlp "$rpms"/openvibes-llm-[0-9]*.rpm | grep -qx /usr/share/openvibes-llm/model.pin || fail "openvibes-llm lacks model.pin"
    rpm -qp --recommends "$rpms"/openvibes-llm-[0-9]*.rpm | grep -q '^openvibes-llm-model = ' || fail "openvibes-llm does not recommend the bridge"
    rpm2cpio "$meta" | cpio -i --quiet --to-stdout ./var/lib/openvibes-llm/model.conf |
        grep -qx "OPENVIBES_LLM_MODEL_SHA256=$LLM_MODEL_SHA256" || fail "model.conf lacks the pinned SHA-256"
    echo "check-rpm (built): ok"
    exit 0
fi
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
    /usr/lib/systemd/system/openvibes-maintenance.timer \
    /usr/lib/systemd/system/openvibes-migrate.service || fail "unit verification"
# A plain `dnf upgrade` migrates before the services start (board #77).
for unit in ingest distribution vulns maintenance; do
    grep -q '^After=.*openvibes-migrate.service' /usr/lib/systemd/system/openvibes-$unit.service \
        && grep -q '^Wants=.*openvibes-migrate.service' /usr/lib/systemd/system/openvibes-$unit.service \
        || fail "openvibes-$unit.service does not start after openvibes-migrate.service"
done
grep -qx 'ExecStart=/usr/bin/openvibes-admin migrate --additive' /usr/lib/systemd/system/openvibes-migrate.service \
    || fail "openvibes-migrate.service does not run additive migrations only"
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
systemd-analyze verify /usr/lib/systemd/system/openvibes-llm.{socket,service} \
    /usr/lib/systemd/system/openvibes-llm-proxy.service || fail "llm unit verification"
# Idle unloading stops the process; llama-server's own idle sleep has a
# use-after-free (CVE-2026-43631).
# The Vulkan drop-in (openvibes-llm-vulkan) has its own ExecStart; without
# it the directory is absent, so only files that exist are listed. Comments
# name the flag (to say it is never passed): only other lines count. One
# grep, no pipeline, so set -e/pipefail cannot hide a match.
llm_units=(/usr/lib/systemd/system/openvibes-llm.service)
for f in /usr/lib/systemd/system/openvibes-llm.service.d/*.conf; do
    [[ -f "$f" ]] && llm_units+=("$f")
done
if grep -qE '^[[:space:]]*[^[:space:]#].*--sleep-idle-seconds' "${llm_units[@]}"; then
    fail "llm unit passes --sleep-idle-seconds"
fi
# Qwen3 thinks by default and reasoning eats the whole output budget.
for f in "${llm_units[@]}"; do
    grep -qE '^[[:space:]]*[^[:space:]#].*--jinja --reasoning off' "$f" || fail "$f lacks --reasoning off"
done
grep -qx 'FlushPending=yes' /usr/lib/systemd/system/openvibes-llm.socket ||
    fail "llm socket lacks FlushPending=yes"
for line in 'IPAddressDeny=any' 'PrivateNetwork=yes' 'RestrictAddressFamilies=AF_UNIX' \
    'CapabilityBoundingSet=' 'NoExecPaths=/' 'Restart=no' \
    'LoadCredential=api-key:/etc/openvibes/llm-api-key' 'ExecStartPre=/usr/libexec/openvibes-llm/openvibes-llm-check'; do
    grep -qx "$line" /usr/lib/systemd/system/openvibes-llm.service || fail "llm unit lacks $line"
done
/usr/libexec/openvibes-llm/llama-server --help 2>&1 | grep -q -- '--api-key-file' || fail "llama-server does not run"
out=$(/usr/libexec/openvibes-llm/openvibes-llm-check 2>&1) && fail "llm check ran as root"
[[ "$out" == *"must not run as root"* ]] || fail "llm check as root: $out"
out=$(runuser -u openvibes-llm -- env -i $(grep -E '^OPENVIBES_LLM_' /etc/openvibes/llm.conf) \
    /usr/libexec/openvibes-llm/openvibes-llm-check 2>&1) && fail "llm check passed without a model"
[[ "$out" == *"OPENVIBES_LLM_MODEL is not set"* ]] || fail "llm check without a model: $out"
# The SELinux module compiles against Fedora's policy (an unknown type or
# permission fails). -n: build the store only; it works with SELinux
# disabled, as in this container. Needs selinux-policy-targeted.
llm_cil=/usr/share/selinux/packages/targeted/openvibes-llm.cil
[[ -f "$llm_cil" ]] || fail "no $llm_cil"
rpm -q --scripts openvibes-llm | grep -q "semodule -n -s targeted -X 200 -i $llm_cil" || fail "openvibes-llm does not load its SELinux module"
rpm -q selinux-policy-targeted >/dev/null || fail "install selinux-policy-targeted to check the SELinux module"
semodule -n -X 200 -i "$llm_cil" || fail "the SELinux module does not compile"
semodule -l | grep -qx openvibes-llm || fail "the SELinux module is not in the store"
semodule -n -X 200 -r openvibes-llm || fail "the SELinux module does not remove"

# openvibes-signer (board #107): the socket's group, a state directory only
# it writes (setgid, so status.json reaches operators), and `seed` creating
# the key and version state once.
getent passwd openvibes-signer >/dev/null || fail "no user openvibes-signer"
getent group openvibes-signer-clients >/dev/null || fail "no group openvibes-signer-clients"
expect_stat /etc/openvibes/signer.toml 640 root:openvibes-signer-clients
expect_stat /var/lib/openvibes-signer 2750 openvibes-signer:openvibes-operators
rpm -qc openvibes-signer | grep -qx /etc/openvibes/signer.toml || fail "signer.toml not %config"
systemd-analyze verify /usr/lib/systemd/system/openvibes-signer.service || fail "signer unit verification"
for line in 'User=openvibes-signer' 'Group=openvibes-signer-clients' 'PrivateNetwork=yes' \
    'RestrictAddressFamilies=AF_UNIX' 'CapabilityBoundingSet=' 'ReadWritePaths=/var/lib/openvibes-signer'; do
    grep -qx "$line" /usr/lib/systemd/system/openvibes-signer.service || fail "signer unit lacks $line"
done
seed() { runuser -u openvibes-signer -g openvibes-signer-clients -- /usr/bin/openvibes-signer seed --min-version "$1"; }
lines=$(seed 3) || fail "signer seed failed"
grep -qE '^site site\.key [A-Za-z0-9_-]{43}$' <<<"$lines" || fail "seed printed no site trust line: $lines"
grep -qE '^site-alarms site\.key [A-Za-z0-9_-]{43}$' <<<"$lines" || fail "seed printed no site-alarms trust line"
expect_stat /var/lib/openvibes-signer/site.key 600 openvibes-signer:openvibes-operators
grep -q '"version": 2' /var/lib/openvibes-signer/versions.json || fail "seed did not set the next version to 3"
[[ "$(seed 1)" == "$lines" ]] || fail "a second seed changed the key"
grep -q '"version": 2' /var/lib/openvibes-signer/versions.json || fail "a second seed lowered the version"
out=$(/usr/bin/openvibes-signer --config /nonexistent 2>&1) && fail "signer started without config"
[[ "$out" == *"openvibes-signer:"* ]] || fail "signer error: $out"
echo "check-rpm: ok"
