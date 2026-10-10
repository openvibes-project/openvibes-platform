//! Same device + signature + source within `window` of the last event is
//! one alarm (sliding: a scan that keeps going stays one alarm, quiet by
//! default). The map is also the retry buffer: a dirty entry (not yet
//! stored) never expires, and a full map drops new keys.

use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
};

use chrono::{DateTime, Duration, Utc};
use platform_store::device_alarms::DeviceAlarm;

use crate::unifi::Ips;

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
struct Key {
    device_id: i64,
    signature_id: String,
    src: IpAddr,
}

struct Entry {
    alarm: DeviceAlarm,
    dirty: bool,
}

pub struct Collapser {
    window: Duration,
    max_keys: usize,
    open: HashMap<Key, Entry>,
}

impl Collapser {
    #[must_use]
    pub fn new(window: Duration, max_keys: usize) -> Self {
        Self {
            window,
            max_keys,
            open: HashMap::new(),
        }
    }

    /// Counts `ips` into its alarm; false when the map is full.
    pub fn add(&mut self, device_id: i64, ips: &Ips, now: DateTime<Utc>) -> bool {
        // ponytail: expire on add, O(keys); a time wheel if max_collapse_keys
        // grows past ~100k.
        let window = self.window;
        self.open
            .retain(|_, e| e.dirty || e.alarm.last_seen + window > now);
        let key = Key {
            device_id,
            signature_id: ips.signature_id.clone(),
            src: ips.src,
        };
        if let Some(entry) = self.open.get_mut(&key) {
            entry.alarm.count += 1;
            entry.alarm.last_seen = now;
            entry.alarm.network = ips.network();
            entry.dirty = true;
            return true;
        }
        if self.open.len() >= self.max_keys {
            return false;
        }
        let alarm = DeviceAlarm {
            device_id,
            alarm_id: format!(
                "{}/{}/{}",
                ips.signature_id,
                ips.src,
                now.timestamp_millis()
            ),
            rule_id: format!("ips.{}", ips.signature_id),
            severity: ips.severity.to_owned(),
            confidence: 80,
            message: ips.message.clone(),
            first_seen: now,
            last_seen: now,
            count: 1,
            network: ips.network(),
        };
        self.open.insert(key, Entry { alarm, dirty: true });
        true
    }

    /// Alarms changed since they were last stored.
    #[must_use]
    pub fn dirty(&self) -> Vec<DeviceAlarm> {
        self.open
            .values()
            .filter(|e| e.dirty)
            .map(|e| e.alarm.clone())
            .collect()
    }

    /// `batch` (from [`Self::dirty`]) is stored: entries that did not change
    /// since are clean.
    pub fn stored(&mut self, batch: &[DeviceAlarm]) {
        let done: HashSet<(i64, &str, i64)> = batch
            .iter()
            .map(|a| (a.device_id, a.alarm_id.as_str(), a.count))
            .collect();
        for entry in self.open.values_mut() {
            if done.contains(&(
                entry.alarm.device_id,
                entry.alarm.alarm_id.as_str(),
                entry.alarm.count,
            )) {
                entry.dirty = false;
            }
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.open.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.open.is_empty()
    }
}
