//! A running netlog against a test database: alarms, collapse, counters,
//! unknown senders, a new source port after a log daemon restart.

#[path = "../../platform-store/tests/common/mod.rs"]
mod common;

use std::time::Duration;

use chrono::Utc;
use common::TestDb;
use openvibes_netlog::{config::NetlogConfig, service};
use tokio::net::{TcpListener, UdpSocket};

const REAL: &str = include_str!("fixtures/ucgmax-ips-blacksun.cef");
const SYSLOG: &str = include_str!("fixtures/ucgmax-syslog.txt");

#[tokio::test]
async fn ips_lines_from_a_registered_device_become_one_alarm() {
    let db = TestDb::create().await;
    let admin = db.pool.get().await.unwrap();
    {
        let mut c = db.pool.get().await.unwrap();
        platform_store::migrate(&mut c).await.unwrap();
    }
    platform_store::ensure_partitions(
        &admin,
        Utc::now().date_naive() - chrono::Duration::days(1),
        3,
    )
    .await
    .unwrap();
    let device = platform_store::devices::add(
        &admin,
        "UCG Max",
        "unifi",
        "127.0.0.1".parse().unwrap(),
        "t",
        Utc::now(),
    )
    .await
    .unwrap()
    .unwrap();
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    let health = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let config = NetlogConfig {
        database_url: db.url(),
        listen: addr,
        health_listen: health.local_addr().unwrap(),
        batch_seconds: 1,
        collapse_minutes: 10,
        max_collapse_keys: 100,
    };
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(service::run(config, socket, health, async {
        let _ = stopped.await;
    }));
    let line = REAL.replace("UNIFIdeviceIp=192.168.1.1", "UNIFIdeviceIp=127.0.0.1");
    // The first log daemon, then a restarted one on a new source port.
    for _ in 0..2 {
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sender.send_to(line.as_bytes(), addr).await.unwrap();
        sender.send_to(SYSLOG.as_bytes(), addr).await.unwrap();
    }
    let stranger = UdpSocket::bind("127.0.0.2:0").await.unwrap();
    stranger.send_to(line.as_bytes(), addr).await.unwrap();
    let mut seen = 0_i64;
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(200)).await;
        if let Some(row) = admin
            .query_opt("SELECT count FROM alarms WHERE device_id = $1", &[&device])
            .await
            .unwrap()
        {
            seen = row.get(0);
            if seen == 2 {
                break;
            }
        }
    }
    assert_eq!(seen, 2, "two IPS lines, one alarm");
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let d = platform_store::devices::list(&admin)
        .await
        .unwrap()
        .remove(0);
    assert_eq!((d.received, d.alarms, d.not_cef), (4, 2, 2));
    let _ = stop.send(());
    task.await.unwrap().unwrap();
    db.drop().await;
}
