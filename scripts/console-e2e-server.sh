#!/usr/bin/env bash
# Starts the real openvibes-console (embedded web UI, production CSP, direct
# TLS 1.3 with a throwaway self-signed certificate) on a fresh throwaway
# database for the browser tests: schema migrated, users
# alex (admin) and sam (analyst), imported findings for six hosts. Needs
# OPENVIBES_TEST_DATABASE_URL (scripts/test-db.sh locally; the CI job sets it)
# and the binaries built by scripts/test-console-e2e.sh.
set -euo pipefail

readonly root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
: "${OPENVIBES_TEST_DATABASE_URL:?set OPENVIBES_TEST_DATABASE_URL (see scripts/test-db.sh)}"
readonly password="e2e-console-Passw0rd!"
readonly name="ov_console_e2e"
readonly work="${root}/target/console-e2e"

# The same server with a different database name, keeping any ?query.
base="${OPENVIBES_TEST_DATABASE_URL%%\?*}"
query="${OPENVIBES_TEST_DATABASE_URL#"${base}"}"
readonly database_url="${base%/*}/${name}${query}"

psql -q "${OPENVIBES_TEST_DATABASE_URL}" -c "DROP DATABASE IF EXISTS ${name} WITH (FORCE)" -c "CREATE DATABASE ${name}" >/dev/null

rm -rf -- "${work}"
mkdir -p -- "${work}/exports"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
    -subj "/CN=127.0.0.1" -addext "subjectAltName=IP:127.0.0.1" \
    -keyout "${work}/key.pem" -out "${work}/cert.pem" 2>/dev/null
printf 'database_url = "%s"\n' "${database_url}" > "${work}/admin.toml"
cat > "${work}/console.toml" <<EOF
development_listen = "127.0.0.1:18490"
health_listen = "127.0.0.1:18491"
transport_mode = "direct_tls"
database_url = "${database_url}"
public_origin = "https://127.0.0.1:18490"
server_certificate_file = "${work}/cert.pem"
server_key_file = "${work}/key.pem"
EOF

admin() { "${root}/target/debug/openvibes-admin" --config "${work}/admin.toml" "$@"; }
admin migrate >/dev/null
admin maintenance >/dev/null
printf '%s\n' "${password}" | admin user create --username alex --display-name "Alex Admin" --role admin --password-stdin >/dev/null
printf '%s\n' "${password}" | admin user create --username sam --display-name "Sam Analyst" --role analyst --password-stdin >/dev/null

# Findings as agent export files (the import path), observed minutes ago.
node --input-type=module - "${work}/exports" <<'EOF'
import { writeFileSync } from "node:fs";
const [out] = process.argv.slice(2);
const now = Date.now();
const rules = [["ssh.root_login", "critical", "SSH permits root login with a password"], ["firewall.disabled", "high", "Host firewall is disabled"],
  ["updates.auto_off", "medium", "Automatic security updates are off"], ["time.unsynced", "low", "Time synchronisation is not configured"]];
for (let n = 0; n < 6; n += 1) {
  const findings = rules.filter((_, i) => (n + i) % 3 !== 2).map(([rule, severity, message], i) => ({
    schema_version: 1, finding_id: `finding.${n}.${i}`, scan_id: `scan.${n}`, rule_id: rule, rule_version: 1,
    observed_at_unix_ms: now - (n * 7 + i) * 60_000, severity, confidence: 90, message, evidence: [rule],
  }));
  const install = `${n}`.repeat(32);
  writeFileSync(`${out}/${n}.json`, JSON.stringify({ schema_version: 1, install_id: install, hostname: `lab-${n}.example.test`,
    scanner_version: "0.4.2", exported_at_unix_ms: now - 30_000, findings }));
}
EOF
admin import "${work}/exports" >/dev/null

exec "${root}/target/debug/openvibes-console" --config "${work}/console.toml"
