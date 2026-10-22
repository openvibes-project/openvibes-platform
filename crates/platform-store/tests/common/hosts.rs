//! The Hosts list fixture shared by `host_list.rs` and
//! `host_list_timing.rs`: eight hosts, four groups, labels and problems.
#![allow(dead_code, reason = "each test binary uses some of these")]

use chrono::Utc;
use platform_store::{
    Client,
    console_read::AgentScope,
    host_list::{HostListPage, HostQuery, HostScopes, HostSort, hosts},
};

pub const fn id(n: u8) -> &'static str {
    match n {
        1 => "agent.00000000-0000-4000-8000-000000000001",
        2 => "agent.00000000-0000-4000-8000-000000000002",
        3 => "agent.00000000-0000-4000-8000-000000000003",
        4 => "agent.00000000-0000-4000-8000-000000000004",
        5 => "agent.00000000-0000-4000-8000-000000000005",
        6 => "agent.00000000-0000-4000-8000-000000000006",
        7 => "agent.00000000-0000-4000-8000-000000000007",
        _ => "import.hosts-8",
    }
}

/// Group ids made by [`fleet`].
pub struct Groups {
    pub web: String,
    pub windows: String,
}

/// 1 web-01 debian online 0.4.1 · 2 web-02 debian online 0.4.2 ·
/// 3 db-01 fedora offline 0.4.2 · 4 win-01 windows online 0.4.1 ·
/// 5 mail-01 ubuntu offline 0.4.2-rc1 · 6 app-01 rocky online 0.4.2+build ·
/// 7 old-01 debian revoked 0.4.1 · 8 imp-01 windows imported, no version.
/// Groups: Linux (rule) 1,2,3,5,6; Web 1,2; Alpha 1; Windows box 4.
/// Labels: prod on 1,2,4; win-only on 4. Open alarms: 1 (two), 4; a mitigated
/// one on 2. Critical: 2 (three), 3 (one). Failing checks: 1, 5.
pub async fn fleet(c: &Client) -> Groups {
    c.batch_execute(&format!(
        "INSERT INTO agents (agent_id, status, enrolled_at, revoked_at, last_seen_at, hostname, os_id, os_version, last_address, scanner_version) VALUES
           ('{}','active',now(),NULL,now(),'web-01','debian','12','10.0.1.5','0.4.1'),
           ('{}','active',now(),NULL,now(),'web-02','debian','12','10.0.1.6','0.4.2'),
           ('{}','active',now(),NULL,now() - interval '1 day','db-01','fedora','44','10.0.2.7','0.4.2'),
           ('{}','active',now(),NULL,now(),'win-01','windows','11','10.1.0.4','0.4.1'),
           ('{}','active',now(),NULL,now() - interval '2 days','mail-01','ubuntu','24.04','192.168.1.9','0.4.2-rc1'),
           ('{}','active',now(),NULL,now(),'app-01','rocky','9.4','10.0.3.3','0.4.2+build'),
           ('{}','revoked',now(),now(),now() - interval '1 hour','old-01','debian','12','10.0.4.4','0.4.1'),
           ('{}','imported',now(),NULL,NULL,'imp-01','windows','10','10.2.0.8',NULL);
         INSERT INTO console_host_labels (agent_id, label, added_at, added_by) VALUES
           ('{}','prod',now(),'t'), ('{}','prod',now(),'t'), ('{}','prod',now(),'t'), ('{}','win-only',now(),'t');",
        id(1), id(2), id(3), id(4), id(5), id(6), id(7), id(8), id(1), id(2), id(4), id(4)
    ))
    .await
    .unwrap();
    super::rule_group(c, "Linux", &[("os_family", false, &["linux"])]).await;
    let web = super::manual_group(c, "Web", &[id(1), id(2)]).await;
    super::manual_group(c, "Alpha", &[id(1)]).await;
    let windows = super::manual_group(c, "Windows box", &[id(4)]).await;
    super::seed_alarm(c, id(1), "high", "open").await;
    super::seed_alarm(c, id(1), "low", "open").await;
    super::seed_alarm(c, id(4), "high", "open").await;
    super::seed_alarm(c, id(2), "high", "mitigated").await;
    super::seed_host_vuln_counts(c, id(2), 3, 0, 0, 0).await;
    super::seed_host_vuln_counts(c, id(3), 1, 0, 0, 0).await;
    super::seed_current_finding(c, id(1), "high").await;
    super::seed_current_finding(c, id(5), "low").await;
    Groups { web, windows }
}

pub fn query() -> HostQuery<'static> {
    HostQuery {
        q: None,
        status: None,
        os_family: None,
        group: None,
        label: None,
        problems: None,
        agent: None,
        sort: HostSort::Host,
        descending: false,
        offset: 0,
        limit: 50,
    }
}

pub const GLOBAL: AgentScope = AgentScope::Global;

pub fn everywhere() -> HostScopes<'static> {
    HostScopes {
        hosts: &GLOBAL,
        alarms: Some(&GLOBAL),
        vulnerabilities: Some(&GLOBAL),
        compliance: Some(&GLOBAL),
    }
}

pub async fn run(
    c: &Client,
    q: &HostQuery<'_>,
    s: &HostScopes<'_>,
    latest: Option<&str>,
) -> HostListPage {
    hosts(c, q, s, latest, Utc::now()).await.unwrap()
}

/// Hosts per group through `console_host_in_group`, by name, empty ones left out.
pub async fn in_group_counts(c: &Client) -> Vec<(String, i64)> {
    c.query(
        "SELECT g.name, count(*) FROM console_asset_groups g JOIN agents a
           ON console_host_in_group(a.agent_id, g.asset_group_id)
         GROUP BY g.asset_group_id, g.name ORDER BY lower(g.name)",
        &[],
    )
    .await
    .unwrap()
    .iter()
    .map(|r| (r.get(0), r.get(1)))
    .collect()
}

/// 20,000 agents (every 29th revoked; five distributions; seen within 15
/// hours) and 20 groups: 5 distribution and 5 host-name rule groups, 10
/// manual groups of about 1,000 hosts. Shared by the timing tests.
pub async fn large_fleet(c: &Client) {
    c.batch_execute(
        "INSERT INTO agents (agent_id, status, enrolled_at, last_seen_at, hostname, os_id, os_version,
                             last_address, scanner_version)
         SELECT 'agent.' || gen_random_uuid()::text, CASE WHEN n % 29 = 0 THEN 'revoked' ELSE 'active' END,
                now() - interval '180 days', now() - make_interval(mins => (n % 900)::int), 'host-' || n,
                (ARRAY['debian','ubuntu','fedora','windows','rocky'])[n % 5 + 1], '12',
                ('10.' || (n / 65536) || '.' || (n / 256 % 256) || '.' || (n % 256))::inet,
                CASE WHEN n % 3 = 0 THEN '0.4.1' ELSE '0.4.2' END
         FROM generate_series(1, 20000) n;",
    )
    .await
    .unwrap();
    for (i, os) in ["debian", "ubuntu", "fedora", "windows", "rocky"]
        .iter()
        .enumerate()
    {
        super::rule_group(
            c,
            &format!("os {i}"),
            &[("distribution", false, &[&format!("{os} 12")])],
        )
        .await;
        super::rule_group(
            c,
            &format!("name {i}"),
            &[("hostname", false, &[&format!("host-{i}*")])],
        )
        .await;
    }
    for i in 0..10 {
        let members: Vec<String> = c
            .query(
                "SELECT agent_id FROM agents WHERE abs(hashtext(agent_id || $1)) % 20 = 0",
                &[&i.to_string()],
            )
            .await
            .unwrap()
            .iter()
            .map(|r| r.get(0))
            .collect();
        let members: Vec<&str> = members.iter().map(String::as_str).collect();
        super::manual_group(c, &format!("manual {i}"), &members).await;
    }
}
