use crate::{Applies, Definition, Kind};

/// The console's own settings (roles spec §7).
pub(crate) static DEFINITIONS: [Definition; 1] = [Definition {
    key: "suppressions.require_approval",
    section: "Alarm suppressions",
    label: "Suppressions need approval",
    help: "A new suppression waits until someone else who can approve on those hosts accepts it. Matching alarms keep arriving while it waits.",
    kind: Kind::Bool { default: false },
    applies: Applies::Live,
}];
