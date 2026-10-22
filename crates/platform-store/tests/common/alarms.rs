//! The Alarms list fixture shared by `alarm_list.rs` and
//! `alarm_list_timing.rs`: the Hosts fleet with its own alarms.
#![allow(dead_code, reason = "each test binary uses some of these")]

use chrono::Utc;
use platform_store::{
    Client,
    alarm_list::{AlarmListPage, AlarmQuery, AlarmSort, AlarmState, alarm_list},
    console_read::AgentScope,
    rule_meta::{self, RuleMetaRow},
    rules::{self, NewBundle},
};

use super::hosts::{Groups, fleet, id};

pub const ANN: &str = "00000000-0000-4000-8000-0000000000a1";
pub const BOB: &str = "00000000-0000-4000-8000-0000000000b2";
pub const CID: &str = "00000000-0000-4000-8000-0000000000c3";

/// Stores bundle `rs` v1 and indexes `r` (T1059.004, T1105) and
/// `ps-encoded` (T1059.001) at rule version 1; `cron` stays unindexed.
pub async fn rule_index(c: &mut Client) {
    rules::add_trust_key(c, "rs", "org.rules", [7; 32])
        .await
        .unwrap();
    rules::publish(
        c,
        &NewBundle {
            rule_set_id: "rs",
            version: 1,
            envelope: b"{}",
            envelope_sha256: [1; 32],
            issuer_key_id: "org.rules",
            created_at_ms: 1,
            expires_at_ms: i64::MAX,
            published_by: "test",
        },
    )
    .await
    .unwrap();
    let meta = |id: &str, techniques: &[&str]| RuleMetaRow {
        rule_id: id.into(),
        rule_version: 1,
        title: id.into(),
        message: id.into(),
        explain: None,
        check: None,
        attack: techniques
            .iter()
            .map(|t| ("TA0002".to_owned(), Some((*t).to_owned())))
            .collect(),
    };
    rule_meta::upsert_from_bundle(
        c,
        "rs",
        1,
        &[
            meta("r", &["T1059.004", "T1105"]),
            meta("ps-encoded", &["T1059.001"]),
        ],
    )
    .await
    .unwrap();
}

/// The Hosts fleet (its alarms removed) plus, by message:
/// a1 web-01 `r` high open, nginx < systemd, count 3, seen 2 d → 10 min, Ann, in case C;
/// a2 web-01 `cron` low open, crontab < fish, 1, 1 d → 1 h, unassigned, once in a closed case;
/// a3 web-02 `r` critical mitigated, 7, 5 d → 2 h, Bob;
/// a4 win-01 `ps-encoded` medium open, 2, 3 h → 30 min, Cid, in case C;
/// a5 db-01 `r` critical open, suppressed, 1, 4 h → 4 h;
/// a6 win-01 `cron` info false positive, 4, 6 d → 3 d, Bob;
/// one device alarm. win-01 is online with alarms off by a fault.
pub async fn alarm_fleet(c: &mut Client) -> Groups {
    let groups = fleet(c).await;
    let week_ago = Utc::now().date_naive() - chrono::Duration::days(7);
    platform_store::ensure_partitions(c, week_ago, 9)
        .await
        .unwrap();
    rule_index(c).await;
    let off = r#"{"collector": "ok", "events_dropped_total": 5, "alarms_dropped_total": 0, "pending": 0,
        "platform_unsupported": false, "rules_accepted": 4, "rules_refused": 0,
        "rules_without_prefilter": 0, "events_budget_cut_total": 0, "source": "none",
        "fallback": {"detail": "no_btf", "audit_rule_loaded": true}}"#;
    c.batch_execute(&format!(
        "DELETE FROM alarms;
         UPDATE agents SET health = jsonb_build_object('alarms', '{off}'::jsonb), health_at = now()
         WHERE agent_id = '{w}';
         INSERT INTO console_users (user_id, username, display_name, created_at) VALUES
           ('{ANN}', 'ann', 'Ann', now()), ('{BOB}', 'bob', 'Bob', now()), ('{CID}', 'cid', 'Cid', now());
         INSERT INTO alarm_suppressions (rule_set_id, rule_id, scope, exe, note, created_by, created_at,
                                         state, activated_at)
         VALUES ('rs', 'r', 'program', '/usr/bin/x', 'n', 'a', now(), 'active', now());
         INSERT INTO alarms (first_seen_day, agent_id, alarm_id, rule_set_id, rule_set_version, rule_id,
                             rule_version, severity, confidence, message, first_seen, last_seen, count,
                             process, ancestors, received_at, state, note, assigned_to, suppressed_by)
         SELECT ((now() - v.first::interval) AT TIME ZONE 'UTC')::date, v.agent, v.msg, 'rs', 1, v.rule, 1, v.sev, 50, v.msg,
                now() - v.first::interval, now() - v.last::interval, v.n,
                jsonb_build_object('exe', v.exe), jsonb_build_array(jsonb_build_object('exe', v.parent)),
                now(), v.state, CASE WHEN v.state <> 'open' THEN 'n' END, v.who::uuid,
                CASE WHEN v.sup THEN (SELECT min(id) FROM alarm_suppressions) END
         FROM (VALUES
           ('a1', '{h1}', 'r', 'high', 'open', '/usr/sbin/nginx', '/usr/lib/systemd/systemd', 3, '2 days', '10 minutes', '{ANN}', false),
           ('a2', '{h1}', 'cron', 'low', 'open', '/usr/bin/crontab', '/usr/bin/fish', 1, '1 day', '1 hour', NULL, false),
           ('a3', '{h2}', 'r', 'critical', 'mitigated', '/bin/sh', NULL, 7, '5 days', '2 hours', '{BOB}', false),
           ('a4', '{w}', 'ps-encoded', 'medium', 'open', 'powershell.exe', NULL, 2, '3 hours', '30 minutes', '{CID}', false),
           ('a5', '{h3}', 'r', 'critical', 'open', '/bin/sh', NULL, 1, '4 hours', '4 hours', NULL, true),
           ('a6', '{w}', 'cron', 'info', 'false_positive', '/bin/sh', NULL, 4, '6 days', '3 days', '{BOB}', false))
           AS v(msg, agent, rule, sev, state, exe, parent, n, first, last, who, sup)
         ORDER BY v.msg;
         INSERT INTO devices (name, kind, address, created_by, created_at)
         VALUES ('gw', 'unifi', '192.168.1.1', 't', now());
         INSERT INTO alarms (first_seen_day, source, device_id, network, alarm_id, rule_set_id, rule_set_version,
                             rule_id, rule_version, severity, confidence, message, first_seen, last_seen, count,
                             received_at)
         SELECT (now() AT TIME ZONE 'UTC')::date, 'device', id, '{{}}', 'dev', 'rs', 1, 'r', 1, 'high', 50, 'dev',
                now(), now(), 1, now() FROM devices;
         INSERT INTO cases (case_id, title, status, severity, opened_by_user_id, created_at, updated_at)
         VALUES ('00000000-0000-0000-0000-0000000000c1', 'C', 'open', 'high', '{ANN}', now(), now());
         INSERT INTO cases (case_id, title, status, resolution, resolution_note, severity, opened_by_user_id,
                            created_at, updated_at, closed_at)
         VALUES ('00000000-0000-0000-0000-0000000000c2', 'Old', 'closed', 'mitigated', 'n', 'low', '{ANN}',
                 now(), now(), now());
         INSERT INTO case_items (item_id, case_id, kind, ref, agent_id, active, added_by_user_id, added_at)
         SELECT gen_random_uuid(), x.case_id::uuid, 'alarm', al.id::text, al.agent_id, x.active, '{ANN}', now()
         FROM alarms al JOIN (VALUES ('a1', '00000000-0000-0000-0000-0000000000c1', true),
                                     ('a4', '00000000-0000-0000-0000-0000000000c1', true),
                                     ('a2', '00000000-0000-0000-0000-0000000000c2', false)) x(msg, case_id, active)
           ON x.msg = al.message;",
        w = id(4),
        h1 = id(1),
        h2 = id(2),
        h3 = id(3),
    ))
    .await
    .unwrap();
    groups
}

/// Open, unsuppressed, newest first, 50 rows.
pub fn query() -> AlarmQuery<'static> {
    AlarmQuery {
        q: None,
        state: Some(AlarmState::Open),
        severity: None,
        suppressed: false,
        host: None,
        group: None,
        technique: None,
        case: None,
        assignee: None,
        sort: AlarmSort::LastSeen,
        descending: true,
        offset: 0,
        limit: 50,
    }
}

/// The list for a caller with `hosts.read` over the same reach as `alarms.read`.
pub async fn run(c: &Client, q: &AlarmQuery<'_>, scope: &AgentScope) -> AlarmListPage {
    run_hosts(c, q, scope, Some(scope)).await
}

/// The list with `hosts.read` over `hosts` (`None`: without it).
pub async fn run_hosts(
    c: &Client,
    q: &AlarmQuery<'_>,
    scope: &AgentScope,
    hosts: Option<&AgentScope>,
) -> AlarmListPage {
    alarm_list(c, q, scope, hosts, ANN, Utc::now())
        .await
        .unwrap()
}

/// The page's messages, which the fixture makes the alarms' names.
pub fn names(page: &AlarmListPage) -> Vec<&str> {
    page.rows.iter().map(|r| r.message.as_str()).collect()
}
