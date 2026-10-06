//! Agent health status (protocol P12): Healthy, Degraded, Offline or
//! Unknown, with reasons, computed when read from the stored report, never
//! stored. Shared by the admin CLI and the console.

use chrono::{DateTime, Duration, Utc};
use openvibes_core::{CollectorOutcome, Health};

use crate::OFFLINE_AFTER_MINUTES;

/// A health report older than this no longer counts as current. It is
/// separate from the offline threshold: the report is saved on the throttled
/// heartbeat write (every 5 minutes), not on every heartbeat.
pub const HEALTH_REPORT_FRESH_MINUTES: i64 = 15;
/// The oldest pending finding may wait this long before delivery counts as
/// stalled.
pub const DELIVERY_STALLED_S: u64 = 3_600;
/// A queue fuller than this share of its limit is nearly full.
pub const QUEUE_NEARLY_FULL_PERCENT: u64 = 80;
/// A rule set expiring sooner than this is flagged.
pub const RULE_SET_EXPIRING_DAYS: i64 = 7;
/// A clock jump larger than this is flagged.
pub const CLOCK_JUMP_S: i64 = 300;

/// An active agent's health.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HealthStatus {
    /// Reporting, with nothing wrong.
    Healthy,
    /// Reporting, with at least one reason.
    Degraded,
    /// No heartbeat for [`OFFLINE_AFTER_MINUTES`].
    Offline,
    /// Online, but no current health report (an agent before P12).
    Unknown,
}

impl HealthStatus {
    /// The lowercase name used by the CLI and the API.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Degraded => "degraded",
            Self::Offline => "offline",
            Self::Unknown => "unknown",
        }
    }

    /// The status with this name.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        [Self::Healthy, Self::Degraded, Self::Offline, Self::Unknown]
            .into_iter()
            .find(|status| status.as_str() == name)
    }
}

/// The status and its reasons (codes, in a fixed order) for an active agent.
#[must_use]
pub fn health_status(
    last_seen_at: Option<DateTime<Utc>>,
    health_at: Option<DateTime<Utc>>,
    health: Option<&Health>,
    previous: Option<&Health>,
    now: DateTime<Utc>,
) -> (HealthStatus, Vec<&'static str>) {
    let window = Duration::minutes(OFFLINE_AFTER_MINUTES);
    if last_seen_at.is_none_or(|seen| seen < now - window) {
        return (HealthStatus::Offline, Vec::new());
    }
    let (Some(health), Some(at)) = (health, health_at) else {
        return (HealthStatus::Unknown, Vec::new());
    };
    if at < now - Duration::minutes(HEALTH_REPORT_FRESH_MINUTES) {
        return (HealthStatus::Unknown, Vec::new());
    }
    let now_ms = now.timestamp_millis();
    let rose = |current: u64, before: fn(&Health) -> u64| {
        previous.is_some_and(|previous| current > before(previous))
    };
    let queue = &health.queue;
    let scan = health.last_scan.as_ref();
    let checks = [
        (
            "queue_dropping",
            rose(queue.dropped_total, |h| h.queue.dropped_total),
        ),
        (
            "delivery_stalled",
            queue
                .oldest_pending_age_s
                .is_some_and(|age| age > DELIVERY_STALLED_S),
        ),
        (
            "queue_nearly_full",
            queue.max_bytes > 0
                && u128::from(queue.bytes) * 100
                    > u128::from(queue.max_bytes) * u128::from(QUEUE_NEARLY_FULL_PERCENT),
        ),
        (
            "scan_overdue",
            scan.is_some_and(|scan| {
                let interval_ms = i64::try_from(scan.interval_s).unwrap_or(i64::MAX / 4) * 1000;
                now_ms.saturating_sub(scan.finished_at_unix_ms) > interval_ms.saturating_mul(2)
            }),
        ),
        (
            "collector_failing",
            // Nothing to read on this host (another OS, no package
            // database) is not a failure; a later version's code is.
            scan.is_some_and(|scan| {
                scan.collectors.values().any(|o| {
                    !matches!(
                        o,
                        CollectorOutcome::Ok
                            | CollectorOutcome::Unsupported
                            | CollectorOutcome::NotFound
                    )
                })
            }),
        ),
        (
            "rule_set_expiring",
            health.rule_sets.iter().any(|set| {
                set.expires_at_unix_ms.is_some_and(|expires| {
                    expires.saturating_sub(now_ms) < RULE_SET_EXPIRING_DAYS * 86_400_000
                })
            }),
        ),
        (
            "rule_set_refused",
            health.rule_sets.iter().any(|set| set.refused.is_some()),
        ),
        (
            "storage_errors",
            rose(health.storage_errors, |h| h.storage_errors),
        ),
        (
            "clock_jump",
            health
                .clock_jump_s
                .is_some_and(|jump| jump.saturating_abs() > CLOCK_JUMP_S),
        ),
    ];
    let reasons: Vec<&'static str> = checks
        .into_iter()
        .filter_map(|(code, hit)| hit.then_some(code))
        .collect();
    let status = if reasons.is_empty() {
        HealthStatus::Healthy
    } else {
        HealthStatus::Degraded
    };
    (status, reasons)
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Duration, Utc};
    use openvibes_core::{
        BundleRefusal, CollectorOutcome, Health, Identifier, QueueHealth, RuleSetHealth, ScanHealth,
    };

    use super::{HealthStatus, health_status};

    fn now() -> DateTime<Utc> {
        DateTime::from_timestamp(1_790_000_000, 0).unwrap()
    }

    fn clean() -> Health {
        let now = now().timestamp_millis();
        Health {
            queue: QueueHealth {
                pending: 1,
                oldest_pending_age_s: Some(60),
                bytes: 1_000,
                max_bytes: 10_000,
                dropped_total: 3,
                rejected_total: Default::default(),
            },
            last_scan: Some(ScanHealth {
                finished_at_unix_ms: now - 60_000,
                interval_s: 3_600,
                rules_evaluated: 5,
                rules_unavailable: 0,
                rules_failed: 0,
                collectors: [(Identifier::new("packages").unwrap(), CollectorOutcome::Ok)].into(),
            }),
            rule_sets: vec![RuleSetHealth {
                id: Identifier::new("baseline").unwrap(),
                version: Some(2),
                expires_at_unix_ms: Some(now + 30 * 86_400_000),
                refused: None,
            }],
            storage_errors: 1,
            clock_jump_s: None,
            matches_truncated: None,
            alarms: None,
        }
    }

    fn check(health: &Health, previous: Option<&Health>) -> (HealthStatus, Vec<&'static str>) {
        health_status(Some(now()), Some(now()), Some(health), previous, now())
    }

    #[test]
    fn offline_after_the_threshold() {
        let seen = now() - Duration::minutes(16);
        let (status, _) = health_status(Some(seen), Some(seen), Some(&clean()), None, now());
        assert_eq!(status, HealthStatus::Offline);
        assert_eq!(
            health_status(None, None, None, None, now()).0,
            HealthStatus::Offline
        );
    }

    #[test]
    fn unknown_without_a_report() {
        assert_eq!(
            health_status(Some(now()), None, None, None, now()),
            (HealthStatus::Unknown, vec![])
        );
    }

    #[test]
    fn a_stale_report_is_unknown() {
        let old = now() - Duration::minutes(16);
        let (status, _) = health_status(Some(now()), Some(old), Some(&clean()), None, now());
        assert_eq!(status, HealthStatus::Unknown);
    }

    #[test]
    fn healthy_with_a_clean_report() {
        assert_eq!(
            check(&clean(), Some(&clean())),
            (HealthStatus::Healthy, vec![])
        );
    }

    fn degraded(health: &Health, previous: Option<&Health>, reason: &str) {
        let (status, reasons) = check(health, previous);
        assert_eq!(status, HealthStatus::Degraded, "{reason}");
        assert_eq!(reasons, [reason]);
    }

    #[test]
    fn each_reason() {
        let base = clean();
        let mut h = clean();
        h.queue.dropped_total = 5;
        degraded(&h, Some(&base), "queue_dropping");
        let mut h = clean();
        h.queue.oldest_pending_age_s = Some(3_601);
        degraded(&h, None, "delivery_stalled");
        let mut h = clean();
        h.queue.bytes = 8_100;
        degraded(&h, None, "queue_nearly_full");
        let mut h = clean();
        h.last_scan.as_mut().unwrap().finished_at_unix_ms = now().timestamp_millis() - 7_201_000;
        degraded(&h, None, "scan_overdue");
        let mut h = clean();
        h.last_scan.as_mut().unwrap().collectors.insert(
            Identifier::new("ports").unwrap(),
            CollectorOutcome::PermissionDenied,
        );
        degraded(&h, None, "collector_failing");
        let mut h = clean();
        h.rule_sets[0].expires_at_unix_ms = Some(now().timestamp_millis() + 6 * 86_400_000);
        degraded(&h, None, "rule_set_expiring");
        let mut h = clean();
        h.rule_sets[0].refused = Some(BundleRefusal::Signature);
        degraded(&h, None, "rule_set_refused");
        let mut h = clean();
        h.storage_errors = 2;
        degraded(&h, Some(&base), "storage_errors");
        let mut h = clean();
        h.clock_jump_s = Some(-301);
        degraded(&h, None, "clock_jump");
    }

    /// Review of P12: a collector with nothing to read on this host (no
    /// package database, another operating system) is not failing; a code
    /// from a later version is.
    #[test]
    fn unsupported_or_missing_collectors_are_not_failing() {
        let mut h = clean();
        let collectors = &mut h.last_scan.as_mut().unwrap().collectors;
        collectors.insert(
            Identifier::new("packages").unwrap(),
            CollectorOutcome::NotFound,
        );
        collectors.insert(
            Identifier::new("ports").unwrap(),
            CollectorOutcome::Unsupported,
        );
        assert_eq!(check(&h, None), (HealthStatus::Healthy, vec![]));
        h.last_scan.as_mut().unwrap().collectors.insert(
            Identifier::new("processes").unwrap(),
            CollectorOutcome::Other,
        );
        assert_eq!(
            check(&h, None),
            (HealthStatus::Degraded, vec!["collector_failing"])
        );
    }

    #[test]
    fn no_reason_at_the_boundaries() {
        let mut h = clean();
        h.queue.bytes = 8_000;
        h.queue.oldest_pending_age_s = Some(3_600);
        h.rule_sets[0].expires_at_unix_ms = Some(now().timestamp_millis() + 7 * 86_400_000);
        h.clock_jump_s = Some(300);
        h.last_scan.as_mut().unwrap().finished_at_unix_ms = now().timestamp_millis() - 7_200_000;
        assert_eq!(check(&h, Some(&clean())), (HealthStatus::Healthy, vec![]));
    }
}
