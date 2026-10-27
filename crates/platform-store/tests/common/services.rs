//! The services fixture shared by the Services list and service page tests:
//! the ports fixture's hosts (web-01 A, web-02 B, db-01 C, a revoked host and
//! one outside the scope) running units, with packages.

#![allow(dead_code, reason = "each test binary uses some of these")]

use deadpool_postgres::Client;

pub use super::ports::{A, B, C, GONE, OUTSIDE};

/// Runs the ports fixture, then adds the units, their packages and some
/// service changes; returns (the scope group's id, the web group's id).
///
/// Units in scope: sshd (A, B, C: root, from `openssh-server`), nginx (A, B:
/// www-data, from `nginx`, A and B expose 443), postgresql (A local only,
/// C exposed; `postgres`, from `postgresql`), named (B: root, from `bind`,
/// exposes udp/53), cups (B: root, no package, local 631), mystery (B: root,
/// not in the map, no package; appeared 2 days ago). Outside the scope:
/// far.service. The revoked host runs sshd.
pub async fn fixture(c: &Client) -> (String, String) {
    let groups = super::ports::fixture(c).await;
    for (host, unit, programs, processes, run_as) in [
        (A, "sshd.service", vec!["sshd"], 1, Some("root")),
        (A, "nginx.service", vec!["nginx"], 3, Some("www-data")),
        (A, "postgresql.service", vec!["postgres"], 5, Some("postgres")),
        (B, "sshd.service", vec!["sshd"], 1, Some("root")),
        (B, "nginx.service", vec!["nginx"], 2, Some("www-data")),
        (B, "named.service", vec!["named"], 1, Some("root")),
        (B, "cups.service", vec!["cupsd"], 1, Some("root")),
        (B, "mystery.service", vec!["mystery", "helper"], 2, Some("root")),
        (C, "sshd.service", vec!["sshd"], 1, Some("root")),
        (C, "postgresql.service", vec!["postgres"], 6, Some("postgres")),
        (GONE, "sshd.service", vec!["sshd"], 1, Some("root")),
        (OUTSIDE, "sshd.service", vec!["sshd"], 1, Some("root")),
        (OUTSIDE, "far.service", vec!["far"], 1, None),
    ] {
        let programs: Vec<String> = programs.into_iter().map(String::from).collect();
        c.execute(
            "INSERT INTO host_services (agent_id, unit, programs, processes, run_as)
             VALUES ($1, $2, $3, $4, $5)",
            &[&host, &unit, &programs, &processes, &run_as],
        )
        .await
        .unwrap();
    }
    for (host, name, version) in [
        (A, "openssh-server", "9.2p1"),
        (A, "nginx", "1.22.1"),
        (A, "postgresql", "15.8"),
        (B, "openssh-server", "9.2p1"),
        (B, "nginx", "1.24.0"),
        (B, "bind", "9.18"),
        (C, "openssh-server", "9.6p1"),
        (C, "postgresql", "16.4"),
        (OUTSIDE, "openssh-server", "9.2p1"),
    ] {
        let id: i64 = match c
            .query_opt(
                "SELECT id FROM package_versions WHERE manager = 'deb' AND name = $1 AND version = $2",
                &[&name, &version],
            )
            .await
            .unwrap()
        {
            Some(row) => row.get(0),
            None => c
                .query_one(
                    "INSERT INTO package_versions (manager, name, version, arch)
                     VALUES ('deb', $1, $2, 'amd64') RETURNING id",
                    &[&name, &version],
                )
                .await
                .unwrap()
                .get(0),
        };
        c.execute(
            "INSERT INTO host_packages (agent_id, package_version_id) VALUES ($1, $2)",
            &[&host, &id],
        )
        .await
        .unwrap();
    }
    for (host, key, change, days) in [
        (B, "mystery.service", "appeared", 2),
        (A, "nginx.service", "appeared", 40),
        (C, "cups.service", "went_away", 3),
        (OUTSIDE, "far.service", "appeared", 1),
    ] {
        c.execute(
            "INSERT INTO change_log (at, agent_id, kind, key, change)
             VALUES (now() - make_interval(days => $4), $1, 'service', $2, $3)",
            &[&host, &key, &change, &days],
        )
        .await
        .unwrap();
    }
    groups
}
