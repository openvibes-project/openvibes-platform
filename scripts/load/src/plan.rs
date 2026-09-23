//! Scheduling and statistics, kept pure so they are unit-tested.

use std::time::Duration;

/// When agent `index` of `agents` first ticks: spread evenly over one interval.
pub fn first_tick(index: usize, agents: usize, interval: Duration) -> Duration {
    interval.mul_f64(index as f64 / agents.max(1) as f64)
}

/// Whether `agent`'s tick number `tick` also delivers a findings batch: once
/// every `every` ticks, staggered so each tick carries 1/`every` of agents.
pub fn delivers_findings(agent: usize, tick: u64, every: u64) -> bool {
    every > 0 && (tick + agent as u64).is_multiple_of(every)
}

/// Nearest-rank percentile (`p` in 0–100) of ascending `sorted`; 0 if empty.
pub fn percentile(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let rank = ((p / 100.0) * sorted.len() as f64).ceil() as usize;
    sorted[rank.clamp(1, sorted.len()) - 1]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ticks_spread_over_one_interval() {
        let interval = Duration::from_secs(2);
        assert_eq!(first_tick(0, 4, interval), Duration::ZERO);
        assert_eq!(first_tick(1, 4, interval), Duration::from_millis(500));
        assert_eq!(first_tick(3, 4, interval), Duration::from_millis(1500));
    }

    #[test]
    fn findings_are_staggered_across_agents() {
        let per_tick: Vec<usize> = (0..3)
            .map(|tick| {
                (0..30)
                    .filter(|&agent| delivers_findings(agent, tick, 3))
                    .count()
            })
            .collect();
        assert_eq!(
            per_tick,
            [10, 10, 10],
            "each tick carries a third of the agents"
        );
        assert_eq!(
            (0..6).filter(|&tick| delivers_findings(7, tick, 3)).count(),
            2
        );
        assert!(!delivers_findings(0, 0, 0), "0 disables findings");
    }

    #[test]
    fn nearest_rank_percentiles() {
        let samples: Vec<u64> = (1..=100).collect();
        assert_eq!(percentile(&samples, 50.0), 50);
        assert_eq!(percentile(&samples, 99.0), 99);
        assert_eq!(percentile(&samples, 100.0), 100);
        assert_eq!(percentile(&[7], 99.0), 7);
        assert_eq!(percentile(&[], 99.0), 0);
    }
}
