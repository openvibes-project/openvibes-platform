//! The ports fixture shared by the Ports list and port page tests: web-01
//! (A), web-02 (B), db-01 (C), a revoked host and one outside the scope.

#![allow(dead_code, reason = "each test binary uses some of these")]

use deadpool_postgres::Client;

pub const A: &str = "agent.00000000-0000-4000-8000-000000000701";
pub const B: &str = "agent.00000000-0000-4000-8000-000000000702";
pub const C: &str = "agent.00000000-0000-4000-8000-000000000703";
pub const GONE: &str = "agent.00000000-0000-4000-8000-000000000704";
pub const OUTSIDE: &str = "agent.00000000-0000-4000-8000-000000000705";

/// web-01 (A), web-02 (B), db-01 (C), a revoked host and one outside the
/// scope group; returns (the scope group's id, the web group's id).
pub async fn fixture(c: &Client) -> (String, String) {
    for (id, name, status) in [
        (A, "web-01", "active"),
        (B, "web-02", "active"),
        (C, "db-01", "active"),
        (GONE, "old-01", "revoked"),
        (OUTSIDE, "far-01", "active"),
    ] {
        c.execute(
            "INSERT INTO agents (agent_id, status, enrolled_at, hostname, os_id, os_version,
                                 last_address, services_at, services_owners)
             VALUES ($1, $2, now(), $3, 'debian', '12', '10.0.0.1', now(), 'partial')",
            &[&id, &status, &name],
        )
        .await
        .unwrap();
    }
    for (host, protocol, address, port, service) in [
        (A, "tcp", "0.0.0.0", 22, Some("sshd.service")),
        (A, "tcp", "::", 22, Some("sshd.service")),
        (A, "tcp", "0.0.0.0", 443, Some("nginx.service")),
        (A, "tcp", "127.0.0.1", 5432, Some("postgresql.service")),
        (A, "tcp", "0.0.0.0", 9999, None),
        (B, "tcp", "0.0.0.0", 22, Some("sshd.service")),
        (B, "tcp", "127.0.0.1", 443, Some("nginx.service")),
        (B, "tcp", "10.0.0.6", 443, Some("nginx.service")),
        (B, "udp", "0.0.0.0", 53, Some("named.service")),
        (B, "tcp", "127.0.0.1", 631, Some("cups.service")),
        (C, "tcp", "0.0.0.0", 5432, Some("postgresql.service")),
        (C, "tcp", "0.0.0.0", 22, Some("sshd.service")),
        (GONE, "tcp", "0.0.0.0", 22, Some("sshd.service")),
        (OUTSIDE, "tcp", "0.0.0.0", 22, Some("sshd.service")),
        (OUTSIDE, "tcp", "0.0.0.0", 7777, Some("far.service")),
    ] {
        let exposed = address != "127.0.0.1";
        let address: std::net::IpAddr = address.parse().unwrap();
        let port: i32 = port;
        c.execute(
            "INSERT INTO host_listeners (agent_id, protocol, address, port, exposed, service, program)
             VALUES ($1, $2, $3, $4, $5, $6, CASE WHEN $4 = 22 THEN 'sshd' END)",
            &[&host, &protocol, &address, &port, &exposed, &service],
        )
        .await
        .unwrap();
    }
    for (host, key, days) in [
        (A, "tcp/9999", 1),
        (B, "tcp/22", 2),
        (C, "tcp/22", 10),
        (OUTSIDE, "tcp/7777", 1),
    ] {
        c.execute(
            "INSERT INTO change_log (at, agent_id, kind, key, change)
             VALUES (now() - make_interval(days => $3), $1, 'listener', $2, 'appeared')",
            &[&host, &key, &days],
        )
        .await
        .unwrap();
    }
    // One stopped listening this week.
    c.execute(
        "INSERT INTO change_log (at, agent_id, kind, key, change)
         VALUES (now() - interval '1 day', $1, 'listener', 'tcp/22', 'went_away')",
        &[&C],
    )
    .await
    .unwrap();
    let mine = super::manual_group(c, "mine", &[A, B, C, GONE]).await;
    let web = super::rule_group(c, "Web", &[("hostname", false, &["web-*"])]).await;
    (mine, web)
}
