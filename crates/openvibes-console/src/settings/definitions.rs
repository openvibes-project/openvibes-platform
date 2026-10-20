//! The typed general settings: key, wording, type, range and default. A key
//! with no stored row has its default.

use serde_json::Value;

/// A setting's type and limits.
pub(crate) enum Kind {
    Bool { default: bool },
    Int { min: i64, max: i64, default: i64 },
}

/// One setting.
pub(crate) struct Definition {
    pub key: &'static str,
    pub section: &'static str,
    pub label: &'static str,
    pub help: &'static str,
    pub kind: Kind,
}

pub(crate) static DEFINITIONS: [Definition; 2] = [
    Definition {
        key: "suppressions.require_approval",
        section: "Alarm suppressions",
        label: "Suppressions need approval",
        help: "A new suppression waits until someone else who can approve on those hosts accepts it. Matching alarms keep arriving while it waits.",
        kind: Kind::Bool { default: false },
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
    },
];

pub(crate) fn find(key: &str) -> Option<&'static Definition> {
    DEFINITIONS.iter().find(|d| d.key == key)
}

impl Definition {
    /// The default as JSON.
    pub(crate) fn default_value(&self) -> Value {
        match self.kind {
            Kind::Bool { default } => default.into(),
            Kind::Int { default, .. } => default.into(),
        }
    }

    /// Whether `value` fits this setting's type and range.
    pub(crate) fn check(&self, value: &Value) -> Result<(), String> {
        match self.kind {
            Kind::Bool { .. } if value.is_boolean() => Ok(()),
            Kind::Bool { .. } => Err("Use true or false".into()),
            Kind::Int { min, max, .. } => match value.as_i64() {
                Some(n) if (min..=max).contains(&n) => Ok(()),
                _ => Err(format!("Use a whole number from {min} to {max}")),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn ints_must_be_whole_numbers_in_range() {
        let d = find("sso.remove_inactive_days").unwrap();
        for good in [json!(1), json!(3650)] {
            assert!(d.check(&good).is_ok());
        }
        for bad in [json!(0), json!(3651), json!("90"), json!(1.5), json!(true)] {
            assert!(d.check(&bad).is_err(), "{bad}");
        }
        assert!(
            find("suppressions.require_approval")
                .unwrap()
                .check(&json!(1))
                .is_err()
        );
    }
}
