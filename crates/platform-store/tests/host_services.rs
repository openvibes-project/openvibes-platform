//! Open ports and running services (P15): ingest replaces a host's rows,
//! the console reads them scoped. Run as the service roles.

mod common;

use chrono::Utc;
use common::TestDb;
use platform_store::{
    Client,
    console_read::AgentScope,
    host_services::{self, Listener, Report, Service},
};

const WEB: &str = "agent.00000000-0000-4000-8000-000000000501";
const DB: &str = "agent.00000000-0000-4000-8000-000000000502";
const GONE: &str = "agent.00000000-0000-4000-8000-000000000503";

fn listener(port: i32, exposed: bool, service: Option<&str>) -> Listener {
    Listener {
        protocol: "tcp".into(),
        address: if exposed { "0.0.0.0" } else { "127.0.0.1" }
            .parse()
            .unwrap(),
        port,
        exposed,
        service: service.map(str::to_owned),
        program: service.map(|s| s.trim_end_matches(".service").to_owned()),
    }
}

fn report(sha: char, listeners: Vec<Listener>, units: &[&str]) -> Report {
    Report {
        sha256: sha.to_string().repeat(64),
        owners: "partial".into(),
        truncated: false,
        listeners,
        services: units
            .iter()
            .map(|unit| Service {
                unit: (*unit).into(),
                programs: vec![unit.trim_end_matches(".service").into()],
                processes: 2,
                run_as: Some("root".into()),
            })
            .collect(),
    }
}

async fn as_role(db: &TestDb, role: &str) -> Client {
    let client = db.pool.get().await.unwrap();
    client
        .batch_execute(&format!("SET ROLE \"{role}\""))
        .await
        .unwrap();
    client
}

async fn setup() -> TestDb {
    let db = TestDb::create().await;
    let mut admin = db.pool.get().await.unwrap();
    platform_store::migrate(&mut admin).await.unwrap();
    for (id, status) in [(WEB, "active"), (DB, "active"), (GONE, "revoked")] {
        admin
            .execute(
                "INSERT INTO agents (agent_id, status, enrolled_at) VALUES ($1, $2, now())",
                &[&id, &status],
            )
            .await
            .unwrap();
    }
    let mut ingest = as_role(&db, "openvibes-ingest").await;
    let now = Utc::now();
    let web = report(
        'a',
        vec![
            listener(443, true, Some("nginx.service")),
            listener(22, true, None),
        ],
        &["nginx.service", "sshd.service"],
    );
    let dbr = report(
        'b',
        vec![listener(5432, false, None), listener(22, true, None)],
        &["postgresql.service", "sshd.service"],
    );
    let gone = report('c', vec![listener(22, true, None)], &["sshd.service"]);
    for (id, r) in [(WEB, &web), (DB, &dbr), (GONE, &gone)] {
        host_services::replace(&mut ingest, id, r, now)
            .await
            .unwrap();
    }
    db
}

#[tokio::test]
async fn a_report_replaces_the_hosts_rows_and_an_unchanged_one_keeps_them() {
    let db = setup().await;
    let mut ingest = as_role(&db, "openvibes-ingest").await;
    let console = as_role(&db, "openvibes-console").await;
    let global = AgentScope::Global;
    let host = host_services::for_host(&console, &global, WEB)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(host.listeners.len(), 2);
    assert!(host.listeners[0].exposed);
    assert_eq!(host.owners.as_deref(), Some("partial"));
    // A new digest replaces everything.
    let changed = report(
        'd',
        vec![listener(8443, true, Some("nginx.service"))],
        &["nginx.service"],
    );
    host_services::replace(&mut ingest, WEB, &changed, Utc::now())
        .await
        .unwrap();
    let host = host_services::for_host(&console, &global, WEB)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        host.listeners.iter().map(|l| l.port).collect::<Vec<_>>(),
        [8443]
    );
    assert_eq!(host.services.len(), 1);
    drop((ingest, console));
    db.drop().await;
}

#[tokio::test]
async fn fleet_views_count_visible_non_revoked_hosts() {
    let db = setup().await;
    let console = as_role(&db, "openvibes-console").await;
    let global = AgentScope::Global;
    let ports = host_services::fleet_ports(&console, &global, false)
        .await
        .unwrap();
    let ssh = ports.iter().find(|p| p.port == 22).unwrap();
    assert_eq!(
        (ssh.hosts, ssh.exposed_hosts),
        (2, 2),
        "the revoked host is not counted"
    );
    let https = ports.iter().find(|p| p.port == 443).unwrap();
    assert_eq!(https.services, ["nginx.service"]);
    let exposed = host_services::fleet_ports(&console, &global, true)
        .await
        .unwrap();
    assert!(exposed.iter().all(|p| p.port != 5432), "5432 is local only");
    let units = host_services::fleet_services(&console, &global)
        .await
        .unwrap();
    assert_eq!(
        units
            .iter()
            .find(|u| u.unit == "sshd.service")
            .unwrap()
            .hosts,
        2
    );
    let nobody = AgentScope::AssetGroups(vec!["00000000-0000-4000-8000-00000000000f".into()]);
    assert!(
        host_services::fleet_ports(&console, &nobody, false)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        host_services::for_host(&console, &nobody, WEB)
            .await
            .unwrap()
            .is_none()
    );
    drop(console);
    db.drop().await;
}

#[tokio::test]
async fn a_refusal_shows_until_the_next_good_report_and_keeps_the_lists() {
    let db = setup().await;
    let mut ingest = as_role(&db, "openvibes-ingest").await;
    let console = as_role(&db, "openvibes-console").await;
    let global = AgentScope::Global;
    let now = Utc::now();
    host_services::refused(&ingest, WEB, host_services::Refusal::TooLarge, now)
        .await
        .unwrap();
    let host = host_services::for_host(&console, &global, WEB)
        .await
        .unwrap()
        .unwrap();
    let (at, code) = host.refused.clone().unwrap();
    assert_eq!(code, "too_large");
    assert!((at - now).num_seconds().abs() < 2);
    assert_eq!(host.listeners.len(), 2, "the last good lists stay");
    // The next good report, even with an unchanged digest, clears it.
    let same = report(
        'a',
        vec![
            listener(443, true, Some("nginx.service")),
            listener(22, true, None),
        ],
        &["nginx.service", "sshd.service"],
    );
    host_services::replace(&mut ingest, WEB, &same, Utc::now())
        .await
        .unwrap();
    let host = host_services::for_host(&console, &global, WEB)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(host.refused, None);
    drop((ingest, console));
    db.drop().await;
}

#[tokio::test]
async fn hosts_of_a_port_or_unit_are_scoped_paged_and_skip_revoked_hosts() {
    let db = setup().await;
    let console = as_role(&db, "openvibes-console").await;
    let global = AgentScope::Global;
    // :22 is on WEB, DB and the revoked GONE: two hosts, one page each.
    let first = host_services::port_hosts(&console, &global, "tcp", 22, None, 1)
        .await
        .unwrap();
    assert_eq!(first.len(), 1);
    let key = (
        first[0].hostname.clone().unwrap_or_default(),
        first[0].agent_id.clone(),
        first[0].address.to_string(),
    );
    let second = host_services::port_hosts(
        &console,
        &global,
        "tcp",
        22,
        Some((&key.0, &key.1, &key.2)),
        10,
    )
    .await
    .unwrap();
    let mut seen: Vec<String> = first
        .iter()
        .chain(&second)
        .map(|h| h.agent_id.clone())
        .collect();
    seen.sort();
    let mut want = vec![WEB.to_owned(), DB.to_owned()];
    want.sort();
    assert_eq!(seen, want, "no revoked host, none twice");
    assert!(
        host_services::port_hosts(&console, &global, "udp", 22, None, 10)
            .await
            .unwrap()
            .is_empty(),
        "the protocol is part of the key"
    );
    let units = host_services::unit_hosts(&console, &global, "nginx.service", None, 10)
        .await
        .unwrap();
    assert_eq!(units.len(), 1);
    assert_eq!((units[0].agent_id.as_str(), units[0].processes), (WEB, 2));
    let nobody = AgentScope::AssetGroups(vec!["00000000-0000-4000-8000-00000000000f".into()]);
    assert!(
        host_services::unit_hosts(&console, &nobody, "sshd.service", None, 10)
            .await
            .unwrap()
            .is_empty()
    );
    drop(console);
    db.drop().await;
}

#[tokio::test]
async fn truncated_is_stored_with_the_report() {
    let db = setup().await;
    let mut ingest = as_role(&db, "openvibes-ingest").await;
    let console = as_role(&db, "openvibes-console").await;
    let global = AgentScope::Global;
    assert!(
        !host_services::for_host(&console, &global, WEB)
            .await
            .unwrap()
            .unwrap()
            .truncated
    );
    let cut = Report {
        truncated: true,
        ..report('e', vec![listener(443, true, None)], &["nginx.service"])
    };
    host_services::replace(&mut ingest, WEB, &cut, Utc::now())
        .await
        .unwrap();
    assert!(
        host_services::for_host(&console, &global, WEB)
            .await
            .unwrap()
            .unwrap()
            .truncated
    );
    drop((ingest, console));
    db.drop().await;
}
