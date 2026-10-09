#!/usr/bin/env bash
# Tests an offline kit with no network: one clean fedora container with
# networking disabled installs the platform from the kit.
# Usage: offline-kit-e2e.sh KIT_TAR [NEWER_KIT_TAR [BAD_SIGNATURE_TAR]]
#   NEWER_KIT_TAR  the same kit with a higher package release, signed by the same
#                  key: a rerun with it must upgrade the installed packages
#   BAD_SIGNATURE_TAR  a kit whose checksums are signed right but with one RPM
#                  signed by another key: --check passes, the install must be refused
# Env: OPENVIBES_KEY_FINGERPRINT  the signing key's fingerprint, for kits signed
#        with a test key (scripts/offline-kit-test-kit.sh writes it to
#        OUT_DIR/fingerprint); unset: the installer's built-in release key
#      PODMAN, FEDORA (default 44), OLD_FEDORA (default 43)
# Checks, in one container: --check, then a first install whose --model file
# has the wrong SHA-256 (must fail at the model step, packages installed, nothing
# staged), then a second install (the upgrade path) that succeeds, then a model
# file matching a test pin (written into the container's model.pin) that must
# be staged for Setup, mode 0444 root. Separate containers:
# a tampered SHA256SUMS, a tampered package and an extra file each fail
# --check, and a Fedora OLD_FEDORA host refuses with the right kit's name.
set -euo pipefail
PODMAN=${PODMAN:-podman}
FEDORA=${FEDORA:-44}
OLD_FEDORA=${OLD_FEDORA:-43}
[[ $# -ge 1 && $# -le 3 && -f $1 ]] || { echo "usage: $0 KIT_TAR [NEWER_KIT_TAR [BAD_SIGNATURE_TAR]]" >&2; exit 2; }
tar_name=$(basename "$1")
# The containers mount a private copy of the tar, relabelled for SELinux: the
# checkout is never relabelled.
kit_dir=$(mktemp -d); trap 'rm -rf "$kit_dir"' EXIT
cp "$1" "$kit_dir/$tar_name"
newer_name='' bad_name=''
[[ -n ${2:-} ]] && { newer_name=newer.tar; cp "$2" "$kit_dir/$newer_name"; }
[[ -n ${3:-} ]] && { bad_name=bad.tar; cp "$3" "$kit_dir/$bad_name"; }
image() { echo "registry.fedoraproject.org/fedora:$1"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
ok() { echo "ok: $*"; }
env_args=()
[[ -n ${OPENVIBES_KEY_FINGERPRINT:-} ]] && env_args=(-e "OPENVIBES_KEY_FINGERPRINT=$OPENVIBES_KEY_FINGERPRINT")
# run FEDORA SCRIPT: SCRIPT in a network-less container, the kit's tar at /kit.
run() {
    "$PODMAN" run --rm --network none -v "$kit_dir:/kit:ro,Z" "${env_args[@]}" \
        -e "TAR=/kit/$tar_name" -e "NEWER=${newer_name:+/kit/$newer_name}" -e "BAD=${bad_name:+/kit/$bad_name}" \
        "$(image "$1")" bash -c "$2"
}

# Negative cases first: cheap, and nothing is installed in them.
tamper() { # NAME SHELL-COMMANDS EXPECTED-MESSAGE
    local out
    out=$(run "$FEDORA" "set -u; mkdir /w && cd /w && tar xf \$TAR && $2
        if ./openvibes-offline/install --check 2>&1; then echo UNEXPECTED-SUCCESS; fi
        rpm -q openvibes-admin >/dev/null 2>&1 && echo CHANGED-HOST; true" 2>&1) || fail "$1: $out"
    [[ $out != *UNEXPECTED-SUCCESS* && $out != *CHANGED-HOST* && $out == *"$3"* ]] || fail "$1: wanted '$3', got: $out"
    ok "$1: --check refuses ('$3')"
}
tamper 'tampered SHA256SUMS' 'echo >> openvibes-offline/SHA256SUMS' 'is not signed by the OpenVIBES package key'
tamper 'tampered package' 'printf x >> openvibes-offline/packages/openvibes-admin-*.rpm' 'does not match SHA256SUMS'
tamper 'extra file in the kit' 'echo x > openvibes-offline/packages/extra.rpm' 'does not list'
if [[ -n $bad_name ]]; then
    out=$(run "$FEDORA" 'mkdir /w && cd /w && tar xf $BAD && ./openvibes-offline/install --check &&
        echo CHECK-PASSED; ./openvibes-offline/install --no-setup 2>&1 && echo UNEXPECTED-SUCCESS
        rpm -q openvibes-admin >/dev/null 2>&1 && echo CHANGED-HOST; true' 2>&1) || fail "bad signature: $out"
    [[ $out == *CHECK-PASSED* && $out != *UNEXPECTED-SUCCESS* && $out != *CHANGED-HOST* && $out == *"dnf could not install"* ]] ||
        fail "an RPM signed by another key was not refused: $out"
    ok "an RPM signed by a third key: --check passes, the install is refused (gpgcheck is on)"
fi
out=$(run "$OLD_FEDORA" 'mkdir /w && cd /w && tar xf $TAR && ./openvibes-offline/install --check 2>&1 || true')
[[ $out == *"this kit is for Fedora $FEDORA; download openvibes-platform-"*"-offline-fedora$OLD_FEDORA.tar"* ]] ||
    fail "fedora:$OLD_FEDORA did not refuse with the kit's name: $out"
ok "fedora:$OLD_FEDORA refuses: ${out##*openvibes offline install: }"

# The install itself.
run "$FEDORA" '
set -euo pipefail
fail() { echo "FAIL: $*" >&2; exit 1; }
mkdir /w && cd /w && tar xf "$TAR"
./openvibes-offline/install --check
echo "ok: --check"
# 1. A model file with the wrong SHA-256, under /root (not readable by
# openvibes-admin): the packages install, the model step fails clearly.
echo not-the-model > /root/wrong.gguf
if out=$(./openvibes-offline/install --no-setup --model /root/wrong.gguf 2>&1); then fail "a wrong model was accepted: $out"; fi
case $out in *"the platform packages are installed, but the model file does not match the pinned SHA-256"*) ;; *) fail "unclear model error: $out" ;; esac
rpm -q openvibes-admin >/dev/null || fail "packages missing after the model step failed"
ls /var/lib/openvibes-offline/*.gguf /var/lib/openvibes-offline/.*.part 2>/dev/null && fail "a wrong model was left staged"
echo "ok: wrong model refused after the packages were installed: ${out##*openvibes offline install: }"
# 2. The same kit again (the update path), no model.
./openvibes-offline/install --no-setup
. /usr/share/openvibes-llm/model.pin
# 3. A model matching the pin (a test pin: the container'"'"'s model.pin is edited): staged.
. /usr/share/openvibes-llm/model.pin
echo tiny-model > /root/tiny.gguf
sed -i "s/^LLM_MODEL_SHA256=.*/LLM_MODEL_SHA256=$(sha256sum /root/tiny.gguf | cut -d" " -f1)/" /usr/share/openvibes-llm/model.pin
./openvibes-offline/install --no-setup --model /root/tiny.gguf
staged=/var/lib/openvibes-offline/$LLM_MODEL_FILE
[[ $(stat -c "%a %U %G" "$staged") == "444 root root" ]] || fail "staged model has the wrong mode or owner"
[[ $(sha256sum < "$staged") == $(sha256sum < /root/tiny.gguf) ]] || fail "staged model differs"
[[ -f /root/tiny.gguf ]] || fail "the original was removed"
echo "ok: a model matching the pin is staged for Setup"
for p in openvibes-admin openvibes-console openvibes-ingest openvibes-distribution openvibes-vulns \
         openvibes-signer openvibes-llm openvibes-llm-model postgresql-server; do
    rpm -q "$p" >/dev/null || fail "$p is not installed"
done
rpm -qa "openvibes-rules-*" | grep -q . || fail "no rule set installed"
[[ -f /usr/share/openvibes-llm/model.pin ]] || fail "model.pin missing"
echo "ok: every package installed with no network"
if [[ -n ${NEWER:-} ]]; then
    before=$(rpm -q --qf "%{VERSION}-%{RELEASE}" openvibes-admin)
    mkdir /w2 && cd /w2 && tar xf "$NEWER"
    ./openvibes-offline/install --no-setup
    after=$(rpm -q --qf "%{VERSION}-%{RELEASE}" openvibes-admin)
    [[ $before != "$after" ]] || fail "the newer kit did not upgrade openvibes-admin ($before)"
    echo "ok: a newer kit upgrades the installed packages ($before -> $after)"
fi
'
