use crate::{Applies, Definition, Kind};

/// The console's own settings (roles spec §7).
pub(crate) static DEFINITIONS: [Definition; 2] = [
    Definition {
        key: "suppressions.require_approval",
        section: "Alarm suppressions",
        label: "Suppressions need approval",
        help: "A new suppression waits until someone else who can approve on those hosts accepts it. Matching alarms keep arriving while it waits.",
        kind: Kind::Bool { default: false },
        applies: Applies::Live,
    },
    Definition {
        key: "sso.remove_inactive_days",
        section: "Single sign-on",
        label: "Remove inactive single sign-on users",
        help: "Days without a sign-in before a single sign-on user is removed. Takes effect once single sign-on is set up.",
        kind: Kind::Int {
            min: 1,
            max: 3650,
            default: 90,
        },
        applies: Applies::Live,
    },
];
