//! The shared change log: what appeared and went away on each host, for
//! packages, listening ports and services. Ingest diffs a host's old rows
//! against the new report inside the transaction that replaces them and
//! writes only the differences. A host's first report is its baseline and
//! writes nothing. Rules: `docs/specs/2026-10-16-roles-permissions-design.md`
//! §10, step 5e rulings 2 to 6.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Duration, Utc};
use deadpool_postgres::Transaction;
use serde_json::{Value, json};

use crate::{Client, StoreError, host_services::Listener, inventory::PackageRow};

/// What a change is about.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChangeKind {
    /// An installed package (key: the name).
    Package,
    /// A listening port (key: `tcp/22`).
    Listener,
    /// A running service (key: the unit).
    Service,
}

impl ChangeKind {
    /// The stored code.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            ChangeKind::Package => "package",
            ChangeKind::Listener => "listener",
            ChangeKind::Service => "service",
        }
    }
}

/// What happened.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Change {
    /// Present now, not before.
    Appeared,
    /// Present before, not now.
    WentAway,
    /// A port that stays, now bound to a non-loopback address.
    Exposed,
    /// A port that stays, now bound only to loopback.
    Local,
}

impl Change {
    /// The stored code.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Change::Appeared => "appeared",
            Change::WentAway => "went_away",
            Change::Exposed => "exposed",
            Change::Local => "local",
        }
    }
}

/// One difference to write.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Event {
    /// The thing that changed (see the module doc).
    pub key: String,
    /// What happened to it.
    pub change: Change,
    /// Extra facts (a package's manager, version and architecture).
    pub detail: Option<Value>,
}

/// The log key of a listening port.
#[must_use]
pub fn listener_key(protocol: &str, port: i32) -> String {
    format!("{protocol}/{port}")
}

/// Per port: is any bound address non-loopback?
fn exposure<'a>(rows: impl Iterator<Item = (&'a str, i32, bool)>) -> BTreeMap<String, bool> {
    let mut ports = BTreeMap::new();
    for (protocol, port, exposed) in rows {
        *ports.entry(listener_key(protocol, port)).or_insert(false) |= exposed;
    }
    ports
}

/// Ports that appeared or went away, and ports that stayed but flipped
/// exposure. `old` is the stored `(protocol, port, exposed)` rows. Addresses
/// alone changing writes nothing.
#[must_use]
pub fn listener_diff(old: &[(String, i32, bool)], new: &[Listener]) -> Vec<Event> {
    let before = exposure(old.iter().map(|(p, n, e)| (p.as_str(), *n, *e)));
    let after = exposure(new.iter().map(|l| (l.protocol.as_str(), l.port, l.exposed)));
    let mut events = Vec::new();
    for (key, exposed) in &after {
        let change = match before.get(key) {
            None => Change::Appeared,
            Some(was) if was == exposed => continue,
            Some(_) if *exposed => Change::Exposed,
            Some(_) => Change::Local,
        };
        events.push(Event {
            key: key.clone(),
            change,
            detail: None,
        });
    }
    for key in before.keys().filter(|key| !after.contains_key(*key)) {
        events.push(Event {
            key: key.clone(),
            change: Change::WentAway,
            detail: None,
        });
    }
    events
}

/// Keys that appeared or went away.
#[must_use]
pub fn key_diff(old: &BTreeSet<String>, new: &BTreeSet<String>) -> Vec<Event> {
    let event = |key: &String, change| Event {
        key: key.clone(),
        change,
        detail: None,
    };
    new.difference(old)
        .map(|key| event(key, Change::Appeared))
        .chain(old.difference(new).map(|key| event(key, Change::WentAway)))
        .collect()
}

/// A package version as the log tells it: `epoch:version-release`.
fn package_version(p: &PackageRow) -> String {
    let release = if p.release.is_empty() {
        String::new()
    } else {
        format!("-{}", p.release)
    };
    format!("{}:{}{release}", p.epoch, p.version)
}

/// The identity of an installed package in the log: one per name, manager,
/// version and architecture.
type PackageId = (String, String, String, String);

fn package_ids(rows: &[PackageRow]) -> BTreeSet<PackageId> {
    rows.iter()
        .map(|p| {
            (
                p.name.clone(),
                p.manager.clone(),
                package_version(p),
                p.arch.clone(),
            )
        })
        .collect()
}

/// Package versions that appeared or went away; an upgrade is the old
/// version going away plus the new one appearing.
#[must_use]
pub fn package_diff(old: &[PackageRow], new: &[PackageRow]) -> Vec<Event> {
    let (before, after) = (package_ids(old), package_ids(new));
    let event = |(name, manager, version, arch): &PackageId, change| Event {
        key: name.clone(),
        change,
        detail: Some(json!({ "manager": manager, "version": version, "arch": arch })),
    };
    after
        .difference(&before)
        .map(|id| event(id, Change::Appeared))
        .chain(
            before
                .difference(&after)
                .map(|id| event(id, Change::WentAway)),
        )
        .collect()
}

/// Writes `events` for `agent_id` in one statement; nothing at all for an
/// empty slice.
pub(crate) async fn record(
    tx: &Transaction<'_>,
    agent_id: &str,
    kind: ChangeKind,
    at: DateTime<Utc>,
    events: &[Event],
) -> Result<(), StoreError> {
    if events.is_empty() {
        return Ok(());
    }
    let keys: Vec<&str> = events.iter().map(|e| e.key.as_str()).collect();
    let changes: Vec<&str> = events.iter().map(|e| e.change.code()).collect();
    let details: Vec<Option<&Value>> = events.iter().map(|e| e.detail.as_ref()).collect();
    tx.execute(
        "INSERT INTO change_log (at, agent_id, kind, key, change, detail)
         SELECT $1, $2, $3, k, c, d
         FROM unnest($4::text[], $5::text[], $6::jsonb[]) AS u(k, c, d)",
        &[&at, &agent_id, &kind.code(), &keys, &changes, &details],
    )
    .await?;
    Ok(())
}

/// Deletes rows older than 90 days before `now`; returns how many went.
// ponytail: one DELETE a day; daily partitions are the upgrade path if the
// table outgrows it.
pub async fn prune(client: &Client, now: DateTime<Utc>) -> Result<u64, StoreError> {
    Ok(client
        .execute(
            "DELETE FROM change_log WHERE at < $1",
            &[&(now - Duration::days(90))],
        )
        .await?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn listener(protocol: &str, port: i32, exposed: bool, address: &str) -> Listener {
        Listener {
            protocol: protocol.into(),
            address: address.parse().unwrap(),
            port,
            exposed,
            service: None,
            program: None,
        }
    }

    fn row(name: &str, version: &str, release: &str) -> PackageRow {
        PackageRow {
            manager: "rpm".into(),
            name: name.into(),
            epoch: 0,
            version: version.into(),
            release: release.into(),
            arch: "x86_64".into(),
            source: None,
            source_version: None,
        }
    }

    #[test]
    fn ports_appear_go_away_and_flip() {
        let old = vec![
            ("tcp".to_string(), 22, true),
            ("tcp".to_string(), 5432, true),
            ("tcp".to_string(), 80, false),
        ];
        let new = [
            listener("tcp", 22, true, "0.0.0.0"),
            listener("tcp", 5432, false, "127.0.0.1"),
            listener("tcp", 80, true, "::"),
            listener("udp", 53, true, "0.0.0.0"),
        ];
        let events = listener_diff(&old, &new);
        let got: Vec<_> = events.iter().map(|e| (e.key.as_str(), e.change)).collect();
        assert_eq!(
            got,
            [
                ("tcp/5432", Change::Local),
                ("tcp/80", Change::Exposed),
                ("udp/53", Change::Appeared),
            ]
        );
        let gone = listener_diff(&old, &[]);
        assert_eq!(gone.len(), 3);
        assert!(gone.iter().all(|e| e.change == Change::WentAway));
    }

    #[test]
    fn another_address_for_the_same_port_is_no_change() {
        let old = vec![("tcp".to_string(), 22, true)];
        let new = [listener("tcp", 22, true, "::")];
        assert!(listener_diff(&old, &new).is_empty());
        // One more bound address of the same port: still no change.
        let old = vec![
            ("tcp".to_string(), 22, false),
            ("tcp".to_string(), 22, true),
        ];
        let new = [listener("tcp", 22, true, "::")];
        assert!(listener_diff(&old, &new).is_empty());
    }

    #[test]
    fn units_appear_and_go_away() {
        let old: BTreeSet<String> = ["a.service", "b.service"].map(String::from).into();
        let new: BTreeSet<String> = ["b.service", "c.service"].map(String::from).into();
        let events = key_diff(&old, &new);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].key, "c.service");
        assert_eq!(events[0].change, Change::Appeared);
        assert_eq!(events[1].key, "a.service");
        assert_eq!(events[1].change, Change::WentAway);
    }

    #[test]
    fn an_upgrade_is_two_events_with_the_versions() {
        let events = package_diff(
            &[row("openssl", "3.0.1", "1"), row("bash", "5.2", "1")],
            &[row("openssl", "3.0.2", "1"), row("bash", "5.2", "1")],
        );
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].change, Change::Appeared);
        assert_eq!(events[0].detail.as_ref().unwrap()["version"], "0:3.0.2-1");
        assert_eq!(events[1].change, Change::WentAway);
        assert_eq!(events[1].detail.as_ref().unwrap()["version"], "0:3.0.1-1");
        assert!(package_diff(&[row("bash", "5.2", "")], &[row("bash", "5.2", "")]).is_empty());
    }
}
