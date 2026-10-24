//! A check's Hosts table by triage state (step 5c task 8): the state that
//! narrows the Failing segment, and the failing pairs per state.

use serde::Deserialize;

use crate::host_list::values;

values!(
    /// A failing pair's triage state, to narrow the Failing segment.
    CheckHostState {
        /// Open (an expired acceptance counts).
        Open = "open",
        /// Mitigated.
        Mitigated = "mitigated",
        /// Accepted risk, not expired.
        AcceptedRisk = "accepted_risk",
        /// False positive.
        FalsePositive = "false_positive",
    }
);

/// Failing pairs per triage state.
#[derive(Clone, Copy, Debug, Default, Deserialize)]
pub struct CheckStateCounts {
    /// Open (an expired acceptance counts).
    pub open: i64,
    /// Mitigated.
    pub mitigated: i64,
    /// Accepted risk.
    pub accepted_risk: i64,
    /// False positive.
    pub false_positive: i64,
}

impl CheckStateCounts {
    pub(crate) fn of(self, state: CheckHostState) -> i64 {
        match state {
            CheckHostState::Open => self.open,
            CheckHostState::Mitigated => self.mitigated,
            CheckHostState::AcceptedRisk => self.accepted_risk,
            CheckHostState::FalsePositive => self.false_positive,
        }
    }
}
