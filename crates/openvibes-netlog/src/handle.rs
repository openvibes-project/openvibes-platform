//! One datagram: sender filter, parse, classify, collapse, count.

use std::{collections::HashMap, net::IpAddr};

use chrono::{DateTime, Utc};
use platform_store::devices::Counters;

use crate::{
    cef::{Parsed, parse},
    collapse::Collapser,
    unifi::{Outcome, classify},
};

/// Class keys kept per device between flushes (the stored map is capped
/// at the same size).
pub const MAX_CLASSES: usize = 64;

/// Drops that belong to no device; logged at each flush.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HostCounters {
    pub unknown_sender: u64,
    pub collapse_full: u64,
    pub unstorable: u64,
}

fn bump(classes: &mut std::collections::BTreeMap<String, i64>, key: String) {
    if classes.len() < MAX_CLASSES || classes.contains_key(&key) {
        *classes.entry(key).or_default() += 1;
    }
}

pub fn handle(
    datagram: &[u8],
    sender: IpAddr,
    now: DateTime<Utc>,
    devices: &HashMap<IpAddr, i64>,
    counters: &mut HashMap<i64, Counters>,
    collapser: &mut Collapser,
    host: &mut HostCounters,
) {
    let sender = sender.to_canonical();
    let Some(&id) = devices.get(&sender) else {
        host.unknown_sender += 1;
        return;
    };
    let c = counters.entry(id).or_default();
    c.received += 1;
    c.last_seen = Some(now);
    match parse(datagram) {
        Parsed::NotCef => c.not_cef += 1,
        Parsed::Unparsed => c.unparsed += 1,
        Parsed::Cef(cef) => match classify(&cef, sender) {
            Outcome::Other(key) => {
                c.dropped_other += 1;
                bump(&mut c.classes, key);
            }
            Outcome::Mismatch => c.mismatch += 1,
            Outcome::Unparsed => c.unparsed += 1,
            Outcome::Ips(ips) => {
                if let Some(risk) = &ips.unknown_risk {
                    bump(&mut c.classes, format!("risk:{risk}"));
                }
                if collapser.add(id, &ips, now) {
                    c.alarms += 1;
                } else {
                    host.collapse_full += 1;
                }
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use chrono::{Duration, Utc};

    use super::*;
    use crate::collapse::Collapser;

    const REAL: &str = include_str!("../tests/fixtures/ucgmax-ips-blacksun.cef");
    const SYSLOG: &str = include_str!("../tests/fixtures/ucgmax-syslog.txt");

    struct World {
        devices: HashMap<IpAddr, i64>,
        counters: HashMap<i64, Counters>,
        collapser: Collapser,
        host: HostCounters,
    }

    impl World {
        fn new(max_keys: usize) -> Self {
            Self {
                devices: HashMap::from([("192.168.1.1".parse().unwrap(), 7)]),
                counters: HashMap::new(),
                collapser: Collapser::new(Duration::minutes(10), max_keys),
                host: HostCounters::default(),
            }
        }
        fn send(&mut self, line: &str, from: &str, now: DateTime<Utc>) {
            handle(
                line.as_bytes(),
                from.parse().unwrap(),
                now,
                &self.devices,
                &mut self.counters,
                &mut self.collapser,
                &mut self.host,
            );
        }
    }

    #[test]
    fn repeats_collapse_and_every_datagram_is_counted() {
        let mut w = World::new(100);
        let now = Utc::now();
        w.send(REAL, "192.168.1.1", now);
        w.send(REAL, "192.168.1.1", now + Duration::seconds(1));
        w.send(SYSLOG, "192.168.1.1", now);
        w.send(REAL, "192.168.1.99", now);
        let dirty = w.collapser.dirty();
        assert_eq!(dirty.len(), 1);
        assert_eq!(
            (
                dirty[0].count,
                dirty[0].rule_id.as_str(),
                dirty[0].confidence
            ),
            (2, "ips.2008983", 80)
        );
        let c = &w.counters[&7];
        assert_eq!((c.received, c.alarms, c.not_cef), (3, 2, 1));
        assert_eq!(w.host.unknown_sender, 1);
    }

    #[test]
    fn a_new_alarm_after_the_quiet_window_and_stored_entries_expire() {
        let mut w = World::new(100);
        let now = Utc::now();
        w.send(REAL, "192.168.1.1", now);
        let batch = w.collapser.dirty();
        w.collapser.stored(&batch);
        w.send(REAL, "192.168.1.1", now + Duration::minutes(11));
        let dirty = w.collapser.dirty();
        assert_eq!(dirty.len(), 1);
        assert_ne!(dirty[0].alarm_id, batch[0].alarm_id);
    }

    #[test]
    fn unstored_alarms_never_expire_and_the_map_is_capped() {
        let mut w = World::new(2);
        let now = Utc::now();
        for n in 0..5 {
            let line = REAL.replace("src=192.168.1.10", &format!("src=10.0.0.{n}"));
            w.send(&line, "192.168.1.1", now + Duration::minutes(20 * n));
        }
        assert_eq!(
            w.collapser.len(),
            2,
            "database down: the first two wait, the rest are dropped"
        );
        assert_eq!(w.host.collapse_full, 3);
    }

    #[test]
    fn a_spoofed_flood_of_sources_cannot_crowd_out_a_real_alarm() {
        // Map full of alarms already stored (database up): the oldest
        // stored one makes room, so a new signature is still raised.
        let mut w = World::new(3);
        let now = Utc::now();
        for n in 0..3 {
            let line = REAL.replace("src=192.168.1.10", &format!("src=10.0.0.{n}"));
            w.send(&line, "192.168.1.1", now + Duration::seconds(n));
        }
        let batch = w.collapser.dirty();
        w.collapser.stored(&batch);
        let real = REAL.replace("SignatureId=2008983", "SignatureId=2402000");
        w.send(&real, "192.168.1.1", now + Duration::seconds(5));
        assert_eq!(w.host.collapse_full, 0);
        let dirty = w.collapser.dirty();
        assert_eq!(dirty.len(), 1);
        assert_eq!(dirty[0].rule_id, "ips.2402000");
        assert_eq!(w.collapser.len(), 3);
    }

    #[test]
    fn class_keys_per_flush_are_capped() {
        let mut w = World::new(100);
        for n in 0..200 {
            let line = format!("CEF:0|Ubiquiti|UniFi Network|1|{n}|x|1|UNIFIcategory=System");
            w.send(&line, "192.168.1.1", Utc::now());
        }
        assert_eq!(w.counters[&7].classes.len(), MAX_CLASSES);
        assert_eq!(w.counters[&7].dropped_other, 200);
    }
}
