//! The Compliance list fixture shared by `check_list.rs` and
//! `check_list_filters.rs`: twelve hosts, three groups, six checks in reach.
#![allow(dead_code, reason = "each test binary uses some of these")]

use chrono::Utc;
use platform_store::{
    Client,
    check_list::{CheckListPage, CheckListRow, CheckQuery, CheckSort, CheckState, check_list},
    console_read::AgentScope,
};

pub const ANN: &str = "00000000-0000-4000-8000-0000000000a1";
pub const BOB: &str = "00000000-0000-4000-8000-0000000000b2";

pub fn h(n: u8) -> String {
    format!("agent.00000000-0000-4000-8000-0000000000{n:02}")
}

pub const HEALTHY: &str = r#"{"rule_sets":[{"id":"baseline","version":2},{"id":"hardening-linux-l1","version":1}],
  "last_scan":{"collectors":{"ports":"ok","packages":"ok","hardening":"ok","processes":"ok"}}}"#;

/// Every finding as (host, set, rule, severity, last seen, ended), then
/// every triage row as (host, set, rule, state, assignee, accepted until).
pub const FINDINGS: &str = "
INSERT INTO current_findings (agent_id, rule_set_id, rule_id, last_finding_id, rule_version, severity,
                              first_observed_at, last_observed_at, last_observed_day, scan_id, confidence,
                              message, evidence, received_at, origin, authenticated, source, ended_at)
SELECT 'agent.00000000-0000-4000-8000-0000000000' || lpad(v.h::text, 2, '0'), v.s, v.r, 'f', 1, v.sev,
       now() - make_interval(days => 10 + v.h), v.seen, (v.seen AT TIME ZONE 'UTC')::date, 's', 90, 'm', '{}',
       now(), 'online', true, 'changes', CASE WHEN v.ended THEN now() - interval '1 hour' END
FROM (VALUES
  (1, 'baseline', 'port.ssh.exposed', 'high', now() - interval '5 minutes', false),
  (2, 'baseline', 'port.ssh.exposed', 'medium', now() - interval '1 hour', false),
  (3, 'baseline', 'port.ssh.exposed', 'medium', now() - interval '2 hours', false),
  (4, 'baseline', 'port.ssh.exposed', 'critical', now(), false),
  (1, 'baseline', 'package.telnet_server.installed', 'medium', now(), true),
  (4, 'baseline', 'package.telnet_server.installed', 'medium', now(), false),
  (2, 'hardening-linux-l1', 'harden.ssh.permit_root_login', 'critical', now(), false),
  (3, 'hardening-linux-l1', 'harden.ssh.permit_root_login', 'critical', now(), false),
  (1, 'hardening-linux-l1', 'harden.ssh.permit_root_login', 'critical', now() - interval '3 days', false),
  (4, 'hardening-linux-l1', 'harden.kernel.aslr', 'medium', now(), false),
  (1, 'site-x', 'custom.check', 'low', now(), false),
  (2, 'site-x', 'custom.check', 'low', now(), false),
  (3, 'site-x', 'custom.check', 'low', now(), false),
  (4, 'site-x', 'custom.check', 'low', now(), false),
  (4, 'site-x', 'secret.rule', 'high', now(), false)) v(h, s, r, sev, seen, ended);
INSERT INTO console_finding_triage (agent_id, rule_set_id, rule_id, state, rule_version, assigned_to,
                                    note, accepted_until, version, updated_at, updated_by)
SELECT 'agent.00000000-0000-4000-8000-0000000000' || lpad(v.h::text, 2, '0'), v.s, v.r, v.state, 1, v.who::uuid,
       CASE WHEN v.state <> 'open' THEN 'n' END, v.until, 1, now(), 't'
FROM (VALUES
  (1, 'baseline', 'port.ssh.exposed', 'open', '00000000-0000-4000-8000-0000000000a1', NULL::timestamptz),
  (2, 'baseline', 'port.ssh.exposed', 'mitigated', '00000000-0000-4000-8000-0000000000b2', NULL),
  (3, 'baseline', 'port.ssh.exposed', 'accepted_risk', NULL, now() - interval '1 day'),
  (2, 'hardening-linux-l1', 'harden.ssh.permit_root_login', 'false_positive', '00000000-0000-4000-8000-0000000000a1', NULL),
  (3, 'hardening-linux-l1', 'harden.ssh.permit_root_login', 'open', '00000000-0000-4000-8000-0000000000b2', NULL),
  (1, 'site-x', 'custom.check', 'open', '00000000-0000-4000-8000-0000000000a1', NULL),
  (2, 'site-x', 'custom.check', 'open', '00000000-0000-4000-8000-0000000000b2', NULL),
  (3, 'site-x', 'custom.check', 'accepted_risk', '00000000-0000-4000-8000-0000000000a1', now() + interval '30 days'))
  v(h, s, r, state, who, until);
INSERT INTO current_findings (agent_id, rule_set_id, rule_id, last_finding_id, rule_version, severity,
                              first_observed_at, last_observed_at, last_observed_day, scan_id, confidence,
                              message, evidence, received_at, origin, authenticated, source)
VALUES ('agent.00000000-0000-4000-8000-000000000009', 'hardening-linux-l1', 'harden.kernel.aslr', 'f', 1,
        'medium', now() - interval '5 days', now() - interval '3 days', current_date - 3, 's', 90, 'm', '{}',
        now(), 'online', true, 'scan');";

/// Group Web (the scope) holds hosts 1–3 and 5–12; Alpha holds host 1;
/// Other holds host 4, out of reach. Every host is active with fresh
/// health running baseline 2 and hardening-linux-l1 1, except: 5 (health
/// two days old), 6 (baseline `not_assigned`), 7 (baseline refused), 8
/// (the ports collector failed), 10 (baseline with no version: never
/// accepted), 11 (baseline 1, which has no port.redis.exposed), 12
/// (baseline at a version above `i64::MAX`: not running). Hosts 8
/// and 9 also run site-x 3 (no metadata; its rules need every collector ok).
///
/// - baseline/port.ssh.exposed (newest meta "SSH port exposed"): host 1
///   open (Ann, high, newest), 2 mitigated (Bob, medium), 3 accepted risk
///   expired (nobody), 4 open (critical, out of reach).
/// - baseline/package.telnet_server.installed: host 1 ended (medium),
///   host 4 open.
/// - baseline/port.redis.exposed: indexed only in baseline version 2, high.
/// - hardening-linux-l1/harden.ssh.permit_root_login: host 2 false positive
///   (Ann), 3 open (Bob, critical); host 1's open P13 match is three days
///   old (neither failing nor passing).
/// - hardening-linux-l1/harden.kernel.aslr: host 4; host 9's legacy scan
///   row is three days old (passing).
/// - site-x/secret.rule (no metadata): host 4 only, so never named in reach.
/// - site-x/custom.check (no metadata, low): host 1 open (Ann), 2 open
///   (Bob), 3 accepted risk (Ann, until next month).
pub async fn fixture(c: &Client) -> (String, String) {
    let mut sql = format!(
        "INSERT INTO console_users (user_id, username, display_name, created_at) VALUES
           ('{ANN}', 'ann', 'Ann', now()), ('{BOB}', 'bob', 'Bob', now());
         INSERT INTO rule_sets (rule_set_id) VALUES ('baseline'), ('hardening-linux-l1');
         INSERT INTO rule_trust_keys (rule_set_id, issuer_key_id, public_key)
           VALUES ('baseline', 'k', '\\x{k}'), ('hardening-linux-l1', 'k', '\\x{k}');
         INSERT INTO rule_bundles (rule_set_id, version, envelope, envelope_sha256, issuer_key_id,
                                   created_at_ms, expires_at_ms, published_by)
           SELECT s, v, '{{}}', sha256((s || v)::bytea), 'k', 1, 9e15, 't'
           FROM (VALUES ('baseline', 1), ('baseline', 2), ('hardening-linux-l1', 1)) x(s, v);
         INSERT INTO console_rule_meta (rule_set_id, rule_set_version, rule_id, rule_version, title, message, attack, techniques, severity)
           VALUES ('baseline', 1, 'port.ssh.exposed', 1, 'SSH exposed', 'm', '[]', '{{}}', 'high'),
                  ('baseline', 1, 'package.telnet_server.installed', 1, 'Telnet server installed', 'm', '[]', '{{}}', 'medium'),
                  ('baseline', 2, 'port.ssh.exposed', 2, 'SSH port exposed', 'm', '[]', '{{}}', 'high'),
                  ('baseline', 2, 'package.telnet_server.installed', 1, 'Telnet server installed', 'm', '[]', '{{}}', 'medium'),
                  ('baseline', 2, 'port.redis.exposed', 1, 'Redis exposed', 'm', '[]', '{{}}', 'high'),
                  ('hardening-linux-l1', 1, 'harden.ssh.permit_root_login', 1, 'Root login over SSH', 'm', '[]', '{{}}', 'critical'),
                  ('hardening-linux-l1', 1, 'harden.kernel.aslr', 1, 'ASLR off', 'm', '[]', '{{}}', 'medium');",
        k = "07".repeat(32),
    );
    for n in 1..=12u8 {
        let health = match n {
            6 => HEALTHY.replace(
                r#"{"id":"baseline","version":2}"#,
                r#"{"id":"baseline","version":null,"state":"not_assigned"}"#,
            ),
            7 => HEALTHY.replace(
                r#"{"id":"baseline","version":2}"#,
                r#"{"id":"baseline","version":2,"refused":"signature"}"#,
            ),
            8 => HEALTHY
                .replace(r#""ports":"ok""#, r#""ports":"permission_denied""#)
                .replace(
                    r#"{"id":"baseline","version":2}"#,
                    r#"{"id":"baseline","version":2},{"id":"site-x","version":3}"#,
                ),
            9 => HEALTHY.replace(
                r#"{"id":"baseline","version":2}"#,
                r#"{"id":"baseline","version":2},{"id":"site-x","version":3}"#,
            ),
            10 => HEALTHY.replace(
                r#"{"id":"baseline","version":2}"#,
                r#"{"id":"baseline","version":null}"#,
            ),
            12 => HEALTHY.replace(
                r#"{"id":"baseline","version":2}"#,
                r#"{"id":"baseline","version":18446744073709551615}"#,
            ),
            11 => HEALTHY.replace(
                r#"{"id":"baseline","version":2}"#,
                r#"{"id":"baseline","version":1}"#,
            ),
            _ => HEALTHY.to_owned(),
        };
        let at = if n == 5 {
            "now() - interval '2 days'"
        } else {
            "now()"
        };
        sql += &format!(
            "INSERT INTO agents (agent_id, status, enrolled_at, last_seen_at, hostname, health, health_at)
             VALUES ('{}', 'active', now(), now(), 'host-{n}', '{health}', {at});",
            h(n)
        );
    }
    sql += FINDINGS;
    c.batch_execute(&sql).await.unwrap();
    let web: Vec<String> = [1, 2, 3, 5, 6, 7, 8, 9, 10, 11, 12].map(h).to_vec();
    let web: Vec<&str> = web.iter().map(String::as_str).collect();
    let web = super::manual_group(c, "Web", &web).await;
    let alpha = super::manual_group(c, "Alpha", &[&h(1)]).await;
    super::manual_group(c, "Other", &[&h(4)]).await;
    (web, alpha)
}

pub fn query() -> CheckQuery<'static> {
    CheckQuery {
        q: None,
        state: CheckState::Open,
        severity: None,
        rule_set: None,
        area: None,
        group: None,
        host: None,
        assignee: None,
        sort: CheckSort::Severity,
        descending: true,
        offset: 0,
        limit: 100,
    }
}

pub fn every() -> CheckQuery<'static> {
    CheckQuery {
        state: CheckState::All,
        ..query()
    }
}

pub async fn run(c: &Client, q: &CheckQuery<'_>, scope: &AgentScope) -> CheckListPage {
    check_list(c, q, scope, ANN, Utc::now()).await.unwrap()
}

pub fn keys(page: &CheckListPage) -> Vec<String> {
    page.rows
        .iter()
        .map(|r| format!("{}/{}", r.rule_set_id, r.rule_id))
        .collect()
}

pub fn row<'a>(page: &'a CheckListPage, key: &str) -> &'a CheckListRow {
    page.rows
        .iter()
        .find(|r| format!("{}/{}", r.rule_set_id, r.rule_id) == key)
        .unwrap_or_else(|| panic!("{key} missing from {:?}", keys(page)))
}

pub fn n<K: PartialEq>(values: &[(K, i64)], key: K) -> i64 {
    values
        .iter()
        .find(|(k, _)| *k == key)
        .map_or(0, |(_, n)| *n)
}

pub const SSH: &str = "baseline/port.ssh.exposed";
pub const TELNET: &str = "baseline/package.telnet_server.installed";
pub const REDIS: &str = "baseline/port.redis.exposed";
pub const ROOT: &str = "hardening-linux-l1/harden.ssh.permit_root_login";
pub const ASLR: &str = "hardening-linux-l1/harden.kernel.aslr";
pub const CUSTOM: &str = "site-x/custom.check";
