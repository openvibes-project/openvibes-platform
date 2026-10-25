#!/usr/bin/env bash
# Starts the real openvibes-console (embedded web UI, production CSP, direct
# TLS 1.3 with a throwaway self-signed certificate) on a fresh throwaway
# database for the browser tests: schema migrated, users
# alex (admin) and sam (analyst), imported findings for six hosts, and
# eight enrolled hosts with their facts (OS, version, hostname, address), one
# finding and one alarm each (page-1's alarm with two siblings), and three
# hosts per browser with vulnerabilities for vulnerabilities.spec.ts, and four
# per browser with compliance findings and health for compliance.spec.ts, and
# three per browser with one alarm each for cases.spec.ts. Needs
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
# stay as they are. lin-sup-1/2/3 carry one alarm per browser for the
# suppression approval journey (suppressions.spec.ts), outside both teams.
# The journeys make their rule groups through the host-group API.
psql -qX -v ON_ERROR_STOP=1 "${database_url}" >/dev/null <<'SQL'
INSERT INTO agents (agent_id, status, enrolled_at, last_seen_at, scanner_version, hostname, os_id, os_version, last_address)
SELECT 'agent.00000000-0000-4000-8000-00000000000' || n, 'active', now() - interval '1 day', now(), '0.4.2', name, os, version,
    ('192.0.2.' || n)::inet
FROM (VALUES (1, 'linux-1.example.test', 'debian', '12'), (2, 'linux-2.example.test', 'debian', '12'),
             (3, 'windows-1.example.test', 'windows', '11'), (4, 'windows-2.example.test', 'windows', '11'),
             (5, 'lin-sup-1.example.test', 'debian', '12'), (6, 'lin-sup-2.example.test', 'debian', '12'),
             (7, 'lin-sup-3.example.test', 'debian', '12'), (8, 'page-1.example.test', 'debian', '12'))
     AS hosts (n, name, os, version);
INSERT INTO current_findings
SELECT (jsonb_populate_record(c, jsonb_build_object('agent_id', a.agent_id, 'origin', 'online', 'authenticated', true,
    'rule_set_id', 'e2e', 'rule_id', 'e2e.team_host', 'severity', 'low', 'message', 'Seeded for the two-team journey'))).*
FROM current_findings c CROSS JOIN agents a
WHERE c.agent_id = 'import.00000000000000000000000000000000' AND c.rule_id = 'time.unsynced' AND a.status = 'active';
INSERT INTO alarms (first_seen_day, agent_id, alarm_id, rule_set_id, rule_set_version, rule_id, rule_version,
    severity, confidence, message, first_seen, last_seen, count, process, ancestors, received_at, state)
SELECT (now() AT TIME ZONE 'UTC')::date, agent_id, md5(agent_id), 'e2e', 1, 'e2e.team_alarm', 1, 'low', 50,
    'Team alarm on ' || split_part(hostname, '.', 1), now(), now(), 1,
    '{"exe": "/usr/local/bin/backup-job", "args": ["backup-job", "--nightly"]}', '[]', now(), 'open'
FROM agents WHERE status = 'active';
-- page-1's alarm has two siblings (same rule and program, other arguments)
-- and this hour's starts, for an alarm's page (alarms.spec.ts).
INSERT INTO alarms (first_seen_day, agent_id, alarm_id, rule_set_id, rule_set_version, rule_id, rule_version,
    severity, confidence, message, first_seen, last_seen, count, process, ancestors, received_at, state)
SELECT (now() AT TIME ZONE 'UTC')::date, agent_id, md5(agent_id || flag), 'e2e', 1, 'e2e.team_alarm', 1, 'low', 50,
    'Team alarm on page-1', now(), now(), n,
    jsonb_build_object('exe', '/usr/local/bin/backup-job', 'args', jsonb_build_array('backup-job', flag)), '[]', now(), 'open'
FROM agents, (VALUES ('--weekly', 5), ('--monthly', 2)) AS s (flag, n)
WHERE hostname = 'page-1.example.test';
INSERT INTO alarm_hourly_starts (alarm_row_id, hour, starts)
SELECT id, date_trunc('hour', now()), count FROM alarms
WHERE agent_id = (SELECT agent_id FROM agents WHERE hostname = 'page-1.example.test');
SQL
# The Vulnerabilities journey (vulnerabilities.spec.ts), one set per browser
# P = n (1 chromium, 2 firefox, 3 webkit) so their triage never races, added
# after the alarms and findings above so these hosts carry neither:
# vuln-P-1 and vuln-P-2 (the lead's reach) and out-P-1 (outside it).
# DSA-E2E-P-1 (openssl, CVE-2099-n001 and n002) is on all three hosts,
# DSA-E2E-P-2 (CVE-2099-n003) only on out-P-1, DSA-E2E-P-3 (bash,
# CVE-2099-n004) on vuln-P-1. No feed_sources row: the Overview still says
# vulnerability scanning is not set up (console.spec.ts).
psql -qX -v ON_ERROR_STOP=1 "${database_url}" >/dev/null <<'SQL'
CREATE TEMP TABLE e2e_browsers AS
SELECT * FROM (VALUES (1, 'chromium'), (2, 'firefox'), (3, 'webkit')) AS b (n, p);
INSERT INTO agents (agent_id, status, enrolled_at, last_seen_at, scanner_version, hostname, os_id, os_version, last_address)
SELECT 'agent.00000000-0000-4000-8000-0000000001' || n || h, 'active', now() - interval '1 day', now(), '0.4.2',
    name || '.example.test', 'debian', '12', ('198.51.100.' || (n * 10 + h))::inet
FROM e2e_browsers, LATERAL (VALUES (1, 'vuln-' || p || '-1'), (2, 'vuln-' || p || '-2'), (3, 'out-' || p || '-1')) AS x (h, name);
INSERT INTO advisories (advisory_id, source, os_id, os_version, severity, title, url)
SELECT 'DSA-E2E-' || p || '-' || a, 'debian-12', 'debian', '12', severity, title || ' (' || p || ')', 'https://security-tracker.debian.org/'
FROM e2e_browsers, (VALUES (1, 'important', 'openssl: two flaws'), (2, 'critical', 'secret: flaw'), (3, 'low', 'bash: flaw')) AS x (a, severity, title);
INSERT INTO advisory_cves
SELECT 'DSA-E2E-' || p || '-' || a, 'CVE-2099-' || n || '00' || c
FROM e2e_browsers, (VALUES (1, 1), (1, 2), (2, 3), (3, 4)) AS x (a, c);
INSERT INTO advisory_packages (advisory_id, name, arch, scheme, match_on, fixed)
SELECT 'DSA-E2E-' || p || '-' || a, pkg, '', 'dpkg', 'source', fixed
FROM e2e_browsers, (VALUES (1, 'openssl', '3.0.2'), (2, 'secretpkg', '2'), (3, 'bash', '5.1')) AS x (a, pkg, fixed);
INSERT INTO cve_enrichment (cve_id, epss, epss_percentile, cvss_score)
SELECT 'CVE-2099-' || n || '001', 0.2, 0.8, 7.5 FROM e2e_browsers;
INSERT INTO vulnerabilities (agent_id, advisory_id, packages, first_seen_at, fixed_at, last_evaluated_at, reboot_needed)
SELECT 'agent.00000000-0000-4000-8000-0000000001' || n || h, 'DSA-E2E-' || p || '-' || a,
    jsonb_build_array(jsonb_build_object('name', pkg, 'installed', installed, 'fixed', fixed)), now(), NULL, now(), false
FROM e2e_browsers, (VALUES (1, 1, 'openssl', '3.0.1', '3.0.2'), (2, 1, 'openssl', '3.0.1', '3.0.2'), (3, 1, 'openssl', '3.0.1', '3.0.2'),
                           (3, 2, 'secretpkg', '1', '2'), (1, 3, 'bash', '5.0', '5.1')) AS x (h, a, pkg, installed, fixed);
SQL
# The Compliance journey (compliance.spec.ts), one rule set e2e-comp-P per
# browser P = n, on hosts with heartbeat health that runs the set (version 1,
# the hardening collector ok) and no other finding: comp-P-1 fails
# harden.ssh.e2e_a (high) and harden.ssh.e2e_b (medium), comp-P-2 fails
# e2e_a, comp-P-3 fails nothing (it passes both), and other-comp-P-1, outside
# the lead's reach, fails e2e_a and harden.ssh.e2e_c (low). No rule metadata:
# a check shows its rule ID.
psql -qX -v ON_ERROR_STOP=1 "${database_url}" >/dev/null <<'SQL'
CREATE TEMP TABLE e2e_browsers AS
SELECT * FROM (VALUES (1, 'chromium'), (2, 'firefox'), (3, 'webkit')) AS b (n, p);
INSERT INTO agents (agent_id, status, enrolled_at, last_seen_at, scanner_version, hostname, os_id, os_version, last_address,
                    health, health_at)
SELECT 'agent.00000000-0000-4000-8000-0000000002' || n || h, 'active', now() - interval '1 day', now(), '0.4.2',
    name || '.example.test', 'debian', '12', ('203.0.113.' || (n * 10 + h))::inet,
    jsonb_build_object('rule_sets', jsonb_build_array(jsonb_build_object('id', 'e2e-comp-' || p, 'version', 1)),
                       'last_scan', jsonb_build_object('collectors', '{"hardening": "ok"}'::jsonb,
                                                       'finished_at_unix_ms', (extract(epoch FROM now()) * 1000)::bigint)), now()
FROM e2e_browsers, LATERAL (VALUES (1, 'comp-' || p || '-1'), (2, 'comp-' || p || '-2'), (3, 'comp-' || p || '-3'),
                                   (4, 'other-comp-' || p || '-1')) AS x (h, name);
INSERT INTO current_findings
SELECT (jsonb_populate_record(c, jsonb_build_object('agent_id', 'agent.00000000-0000-4000-8000-0000000002' || n || h,
    'origin', 'online', 'authenticated', true, 'rule_set_id', 'e2e-comp-' || p, 'rule_id', 'harden.ssh.e2e_' || r,
    'severity', x.sev, 'message', 'Seeded for the Compliance journey'))).*
FROM current_findings c, e2e_browsers,
     (VALUES (1, 'a', 'high'), (1, 'b', 'medium'), (2, 'a', 'high'), (4, 'a', 'high'), (4, 'c', 'low')) AS x (h, r, sev)
WHERE c.agent_id = 'import.00000000000000000000000000000000' AND c.rule_id = 'time.unsynced';
SQL

# The Cases journey (cases.spec.ts), one set per browser P = n: case-P-1
# and case-P-2 (the lead's reach) and caseout-P-1 (outside it), each with one
# open alarm and nothing else; the journey makes its cases through the API.
psql -qX -v ON_ERROR_STOP=1 "${database_url}" >/dev/null <<'SQL'
CREATE TEMP TABLE e2e_browsers AS
SELECT * FROM (VALUES (1, 'chromium'), (2, 'firefox'), (3, 'webkit')) AS b (n, p);
INSERT INTO agents (agent_id, status, enrolled_at, last_seen_at, scanner_version, hostname, os_id, os_version, last_address)
SELECT 'agent.00000000-0000-4000-8000-0000000003' || n || h, 'active', now() - interval '1 day', now(), '0.4.2',
    name || '.example.test', 'debian', '12', ('192.0.2.' || (100 + n * 10 + h))::inet
FROM e2e_browsers, LATERAL (VALUES (1, 'case-' || p || '-1'), (2, 'case-' || p || '-2'), (3, 'caseout-' || p || '-1')) AS x (h, name);
INSERT INTO alarms (first_seen_day, agent_id, alarm_id, rule_set_id, rule_set_version, rule_id, rule_version,
    severity, confidence, message, first_seen, last_seen, count, process, ancestors, received_at, state)
SELECT (now() AT TIME ZONE 'UTC')::date, agent_id, md5(agent_id), 'e2e', 1, 'e2e.case_alarm', 1, 'medium', 50,
    'Case alarm on ' || split_part(hostname, '.', 1), now(), now(), 1,
    '{"exe": "/usr/bin/curl", "args": ["curl", "http://198.51.100.9/x"]}', '[]', now(), 'open'
FROM agents WHERE agent_id LIKE 'agent.00000000-0000-4000-8000-0000000003%';
SQL

exec "${bin}/openvibes-console" --config "${work}/console.toml"
