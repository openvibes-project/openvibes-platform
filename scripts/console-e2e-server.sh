#!/usr/bin/env bash
# Starts the real openvibes-console (embedded web UI, production CSP, direct
# TLS 1.3 with a throwaway self-signed certificate) on a fresh throwaway
# database for the browser tests: schema migrated, users
# alex (admin) and sam (analyst), imported findings for six hosts, and
# four enrolled hosts tagged os=linux or os=windows, one finding and one
# alarm each. Needs
# OPENVIBES_TEST_DATABASE_URL (scripts/test-db.sh locally; the CI job sets it)
# and the binaries built by scripts/test-console-e2e.sh.
set -euo pipefail

readonly root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
: "${OPENVIBES_TEST_DATABASE_URL:?set OPENVIBES_TEST_DATABASE_URL (see scripts/test-db.sh)}"
readonly password="e2e-console-Passw0rd!"
readonly name="ov_console_e2e"
readonly work="${root}/target/console-e2e"
# The binaries scripts/test-console-e2e.sh just built, wherever cargo put them.
readonly bin="${CARGO_TARGET_DIR:-${root}/target}/debug"

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

admin() { "${bin}/openvibes-admin" --config "${work}/admin.toml" "$@"; }
admin migrate >/dev/null
admin maintenance >/dev/null
printf '%s\n' "${password}" | admin user create --username alex --display-name "Alex Admin" --role admin --password-stdin >/dev/null
# A fresh install holds only Administrator (schema 52): sam's role is the
# Analyst template, reaching every host.
psql -qX -v ON_ERROR_STOP=1 "${database_url}" >/dev/null <<'SQL'
INSERT INTO console_roles (role_id, display_name, all_hosts) VALUES ('analyst', 'Analyst', true);
INSERT INTO console_role_permissions (role_id, permission_id)
SELECT 'analyst', unnest(ARRAY['alarms.read', 'alarms.suppressions.read', 'compliance.read',
    'vulnerabilities.read', 'hosts.read', 'cases.read', 'rules.read', 'rules.coverage.read',
    'alarms.triage', 'alarms.suppress', 'compliance.triage', 'vulnerabilities.triage',
    'cases.write', 'assistant.use']);
SQL
printf '%s\n' "${password}" | admin user create --username sam --display-name "Sam Analyst" --role analyst --password-stdin >/dev/null
# alex holds Analyst too, to share a dashboard with sam's role (only roles
# you hold can be shared with).
psql -qX -v ON_ERROR_STOP=1 "${database_url}" >/dev/null <<'SQL'
INSERT INTO console_role_bindings (binding_id, user_id, role_id, created_at, created_by)
SELECT gen_random_uuid(), user_id, 'analyst', now(), 'e2e' FROM console_users WHERE username = 'alex';
SQL

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
# Two Linux and two Windows enrolled hosts for the two-team journey (a role
# limited to host groups never reaches imported hosts), each with one low
# finding and one low alarm of their own rules, so the other tests' findings
# stay as they are.
# The journey makes its groups through the asset-group API.
psql -qX -v ON_ERROR_STOP=1 "${database_url}" >/dev/null <<'SQL'
INSERT INTO agents (agent_id, status, enrolled_at, last_seen_at, scanner_version, hostname)
SELECT 'agent.00000000-0000-4000-8000-00000000000' || n, 'active', now() - interval '1 day', now(), '0.4.2', name
FROM (VALUES (1, 'linux-1.example.test'), (2, 'linux-2.example.test'),
             (3, 'windows-1.example.test'), (4, 'windows-2.example.test')) AS hosts (n, name);
INSERT INTO console_host_labels (agent_id, label, added_at, added_by)
SELECT agent_id, 'os:' || split_part(hostname, '-', 1), now(), 'e2e' FROM agents WHERE status = 'active';
INSERT INTO current_findings
SELECT (jsonb_populate_record(c, jsonb_build_object('agent_id', a.agent_id, 'origin', 'online', 'authenticated', true,
    'rule_set_id', 'e2e', 'rule_id', 'e2e.team_host', 'severity', 'low', 'message', 'Seeded for the two-team journey'))).*
FROM current_findings c CROSS JOIN agents a
WHERE c.agent_id = 'import.00000000000000000000000000000000' AND c.rule_id = 'time.unsynced' AND a.status = 'active';
INSERT INTO alarms (first_seen_day, agent_id, alarm_id, rule_set_id, rule_set_version, rule_id, rule_version,
    severity, confidence, message, first_seen, last_seen, count, process, ancestors, received_at, state)
SELECT (now() AT TIME ZONE 'UTC')::date, agent_id, md5(agent_id), 'e2e', 1, 'e2e.team_alarm', 1, 'low', 50,
    'Team alarm on ' || split_part(hostname, '.', 1), now(), now(), 1, '{}', '[]', now(), 'open'
FROM agents WHERE status = 'active';
SQL

exec "${bin}/openvibes-console" --config "${work}/console.toml"
