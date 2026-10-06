//! How a vulnerability was mapped to a host, and how sure we are (spec
//! `docs/specs/2026-10-06-vulnerability-confidence-design.md`).
//!
//! Derived when read from the advisory's source and the packages, so it
//! needs no stored state; later mapping methods (CPE, tracker data) add
//! their own entries here.

use serde_json::Value;

/// The mapping behind one vulnerability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Mapping {
    /// Stable method id, e.g. `distribution-advisory`.
    pub method: &'static str,
    /// Confidence, 0 to 100.
    pub confidence: u8,
    /// A sentence saying how the host was matched, for the console.
    pub basis: String,
}

/// Maps an advisory's feed `source` (`fedora-44-x86_64`, `debian-12`, ...)
/// and the affected `packages` (`[{name, installed, fixed}]`) to its
/// mapping.
#[must_use]
pub fn mapping(source: &str, packages: &Value) -> Mapping {
    let distribution = source.split('-').next().unwrap_or(source);
    let no_fix = packages.as_array().is_some_and(|all| {
        !all.is_empty()
            && all
                .iter()
                .all(|p| p.get("fixed").is_none_or(Value::is_null))
    });
    match (distribution, no_fix) {
        ("fedora", _) => Mapping {
            method: "distribution-advisory",
            confidence: 98,
            basis: "Fedora's own security advisory names this package; the installed version is older than the fixed one.".into(),
        },
        ("debian" | "ubuntu" | "rocky", false) => Mapping {
            method: "distribution-advisory",
            confidence: 95,
            basis: format!("The {} security record names the source package of an installed package; the installed version is older than the fixed one.", name(distribution)),
        },
        ("almalinux", false) => Mapping {
            method: "distribution-advisory",
            confidence: 97,
            basis: "AlmaLinux's own advisory names this package; the installed version is older than the fixed one.".into(),
        },
        (_, true) => Mapping {
            method: "distribution-unfixed",
            confidence: 90,
            basis: format!("The {} tracker lists this package version as affected and has no fix yet.", name(distribution)),
        },
        _ => Mapping {
            method: "unknown",
            confidence: 50,
            basis: "The advisory source is not recognised.".into(),
        },
    }
}

fn name(distribution: &str) -> &'static str {
    match distribution {
        "debian" => "Debian",
        "ubuntu" => "Ubuntu",
        "rocky" => "Rocky Linux",
        "almalinux" => "AlmaLinux",
        _ => "distribution",
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::mapping;

    #[test]
    fn fedora_advisory_is_highest() {
        let m = mapping(
            "fedora-44-x86_64",
            &json!([{"name":"curl","installed":"1","fixed":"2"}]),
        );
        assert_eq!((m.method, m.confidence), ("distribution-advisory", 98));
    }

    #[test]
    fn osv_source_package_and_unfixed() {
        let fixed = json!([{"name":"curl","installed":"1","fixed":"2"}]);
        let open = json!([{"name":"curl","installed":"1","fixed":null}]);
        assert_eq!(mapping("debian-12", &fixed).confidence, 95);
        assert_eq!(mapping("almalinux-9", &fixed).confidence, 97);
        let m = mapping("ubuntu-24.04", &open);
        assert_eq!((m.method, m.confidence), ("distribution-unfixed", 90));
    }

    #[test]
    fn unknown_source_is_middling() {
        assert_eq!(mapping("mystery", &json!([])).confidence, 50);
    }
}
