//! Network devices that send events to `openvibes-netlog` (spec
//! 2026-10-10-network-device-alarms §4). The address is the identity; a
//! removed device keeps its row because alarms point at it.

use std::{collections::BTreeMap, net::IpAddr};

use chrono::{DateTime, Duration, Utc};
use deadpool_postgres::Client;

use crate::StoreError;

/// Device kinds netlog understands.
pub const KINDS: [&str; 1] = ["unifi"];
/// Shown for a device with no packet 10 minutes after it was added.
pub const NO_EVENTS: &str = "No events received yet: check the router's SIEM server setting \
    (this host, port 514) and that UDP 514 is open in this host's firewall";
/// Shown when a device that did send has been silent for a day (its SIEM
/// setting changed, or the host's firewall did).
pub const SILENT: &str = "No events for a day: check the router's SIEM server setting \
    (this host, port 514) and that UDP 514 is still open in this host's firewall";
const MAX_CLASSES: usize = 64;

/// One active device and its counters.
#[derive(Clone, Debug)]
pub struct Device {
    /// Its id.
    pub id: i64,
    /// Shown in the console.
    pub name: String,
    /// One of [`KINDS`].
    pub kind: String,
    /// The address its syslog comes from.
    pub address: IpAddr,
    /// When it was added.
    pub created_at: DateTime<Utc>,
    /// Last datagram from it.
    pub last_seen: Option<DateTime<Utc>>,
    /// Datagrams received.
    pub received: i64,
    /// IPS/IDS events that went into alarms.
    pub alarms: i64,
    /// Plain syslog (no CEF).
    pub not_cef: i64,
    /// CEF that did not parse or validate.
    pub unparsed: i64,
    /// CEF events that are not IPS/IDS.
    pub dropped_other: i64,
    /// `UNIFIdeviceIp` was not this address.
    pub mismatch: i64,
    /// Dropped events per class key, at most 64 keys.
    pub dropped_classes: serde_json::Value,
}

/// 1–64 characters, no control characters.
pub fn check_name(name: &str) -> Result<(), String> {
    let n = name.chars().count();
    if n == 0 || n > 64 || name.chars().any(char::is_control) {
        return Err("a device name is 1 to 64 characters without control characters".into());
    }
    Ok(())
}

/// Adds a device; the inner error is for the person adding it.
pub async fn add(
    client: &Client,
    name: &str,
    kind: &str,
    address: IpAddr,
    actor: &str,
    now: DateTime<Utc>,
) -> Result<Result<i64, String>, StoreError> {
    if let Err(error) = check_name(name) {
        return Ok(Err(error));
    }
    // Netlog matches canonical senders (`::ffff:a.b.c.d` is a.b.c.d).
    let address = address.to_canonical();
    if !KINDS.contains(&kind) {
        return Ok(Err(format!(
            "unknown device kind {kind}; known: {}",
            KINDS.join(", ")
        )));
    }
    // ponytail: check then insert; two concurrent adds of one address end in
    // the unique index refusing the second as a query error.
    let taken = client
        .query_opt(
            "SELECT 1 FROM devices WHERE address = $1 AND removed_at IS NULL",
            &[&address],
        )
        .await?;
    if taken.is_some() {
        return Ok(Err(format!(
            "a device with address {address} already exists"
        )));
    }
    let id = client
        .query_one(
            "INSERT INTO devices (name, kind, address, created_by, created_at)
             VALUES ($1, $2, $3, $4, $5) RETURNING id",
            &[&name, &kind, &address, &actor, &now],
        )
        .await?
        .get(0);
    Ok(Ok(id))
}

/// Marks a device removed; false if there was no active device `id`.
pub async fn remove(
    client: &Client,
    id: i64,
    actor: &str,
    now: DateTime<Utc>,
) -> Result<bool, StoreError> {
    let n = client
        .execute(
            "UPDATE devices SET removed_at = $2, removed_by = $3
             WHERE id = $1 AND removed_at IS NULL",
            &[&id, &now, &actor],
        )
        .await?;
    Ok(n == 1)
}

/// Active devices by name.
pub async fn list(client: &Client) -> Result<Vec<Device>, StoreError> {
    let rows = client
        .query(
            "SELECT id, name, kind, address, created_at, last_seen, received, alarms, not_cef,
                unparsed, dropped_other, mismatch, dropped_classes
             FROM devices WHERE removed_at IS NULL ORDER BY name, id",
            &[],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|r| Device {
            id: r.get(0),
            name: r.get(1),
            kind: r.get(2),
            address: r.get(3),
            created_at: r.get(4),
            last_seen: r.get(5),
            received: r.get(6),
            alarms: r.get(7),
            not_cef: r.get(8),
            unparsed: r.get(9),
            dropped_other: r.get(10),
            mismatch: r.get(11),
            dropped_classes: r.get(12),
        })
        .collect())
}

/// `(id, address)` of every active device, for netlog's sender filter.
pub async fn active(client: &Client) -> Result<Vec<(i64, IpAddr)>, StoreError> {
    let rows = client
        .query(
            "SELECT id, address FROM devices WHERE removed_at IS NULL",
            &[],
        )
        .await?;
    Ok(rows.iter().map(|r| (r.get(0), r.get(1))).collect())
}

/// What netlog counted for one device since its last flush.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Counters {
    /// Datagrams received.
    pub received: i64,
    /// IPS/IDS events that went into alarms.
    pub alarms: i64,
    /// Plain syslog (no CEF).
    pub not_cef: i64,
    /// CEF that did not parse or validate.
    pub unparsed: i64,
    /// CEF events that are not IPS/IDS.
    pub dropped_other: i64,
    /// `UNIFIdeviceIp` was not this address.
    pub mismatch: i64,
    /// Dropped events per class key.
    pub classes: BTreeMap<String, i64>,
    /// Last datagram from it.
    pub last_seen: Option<DateTime<Utc>>,
}

/// Adds `counters` to device `id`; `dropped_classes` keeps at most 64 keys
/// (existing keys grow, new ones in key order until full).
pub async fn flush(client: &mut Client, id: i64, counters: &Counters) -> Result<(), StoreError> {
    let tx = client.transaction().await?;
    let Some(row) = tx
        .query_opt(
            "SELECT dropped_classes FROM devices WHERE id = $1 FOR UPDATE",
            &[&id],
        )
        .await?
    else {
        return Ok(());
    };
    let mut classes: serde_json::Map<String, serde_json::Value> = match row.get(0) {
        serde_json::Value::Object(map) => map,
        _ => serde_json::Map::new(),
    };
    for (key, n) in &counters.classes {
        let old = classes.get(key).and_then(serde_json::Value::as_i64);
        if old.is_some() || classes.len() < MAX_CLASSES {
            classes.insert(key.clone(), (old.unwrap_or(0) + n).into());
        }
    }
    tx.execute(
        "UPDATE devices SET received = received + $2, alarms = alarms + $3,
            not_cef = not_cef + $4, unparsed = unparsed + $5,
            dropped_other = dropped_other + $6, mismatch = mismatch + $7,
            dropped_classes = $8, last_seen = GREATEST(last_seen, $9)
         WHERE id = $1",
        &[
            &id,
            &counters.received,
            &counters.alarms,
            &counters.not_cef,
            &counters.unparsed,
            &counters.dropped_other,
            &counters.mismatch,
            &serde_json::Value::Object(classes),
            &counters.last_seen,
        ],
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

/// [`NO_EVENTS`] when nothing arrived in the 10 minutes after adding,
/// [`SILENT`] when the last packet is more than a day old. Any datagram
/// counts (plain syslog too), so a gateway with only "Security Detections"
/// ticked may trip SILENT on a quiet day; ponytail: one fixed day, a
/// per-device setting if that proves noisy.
#[must_use]
pub fn heads_up(device: &Device, now: DateTime<Utc>) -> Option<&'static str> {
    match device.last_seen {
        None => (now - device.created_at > Duration::minutes(10)).then_some(NO_EVENTS),
        Some(seen) => (now - seen > Duration::days(1)).then_some(SILENT),
    }
}
