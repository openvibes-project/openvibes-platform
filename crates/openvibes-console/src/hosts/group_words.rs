//! A host group's membership in one plain sentence, e.g. "Hosts where OS
//! family is Windows and hostname does not match *test*", shared by the
//! host-group list and rule-set assignment.

use platform_store::host_group_facts::{distribution_name, os_family_name};
use platform_store::host_groups::{Condition, GroupKind};

/// The membership sentence: the rule's conditions joined by "and", or
/// "N hosts picked by hand" for a manual group.
pub fn membership_sentence(kind: GroupKind, conditions: &[Condition], picked: i64) -> String {
    if kind == GroupKind::Manual {
        let noun = if picked == 1 { "host" } else { "hosts" };
        return format!("{picked} {noun} picked by hand");
    }
    let parts: Vec<String> = conditions.iter().map(condition).collect();
    format!("Hosts where {}", parts.join(" and "))
}

fn condition(c: &Condition) -> String {
    let (field, op, negated) = match c.field.as_str() {
        "os_family" => ("OS family", "is", "is not"),
        "distribution" => ("distribution", "is", "is not"),
        "hostname" => ("hostname", "matches", "does not match"),
        "ip" => ("IP address", "is in", "is not in"),
        other => (other, "is", "is not"),
    };
    let values: Vec<String> = c
        .values
        .iter()
        .map(|v| match c.field.as_str() {
            "os_family" => os_family_name(v),
            "distribution" => distribution_name(v),
            _ => v.clone(),
        })
        .collect();
    let values = match values.split_last() {
        Some((last, rest)) if !rest.is_empty() => format!("{} or {last}", rest.join(", ")),
        _ => values.concat(),
    };
    format!("{field} {} {values}", if c.negate { negated } else { op })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(field: &str, negate: bool, values: &[&str]) -> Condition {
        Condition {
            field: field.into(),
            negate,
            values: values.iter().map(|v| (*v).into()).collect(),
        }
    }

    #[test]
    fn sentences() {
        let rule = [
            c("os_family", false, &["windows"]),
            c("hostname", true, &["*test*"]),
        ];
        assert_eq!(
            membership_sentence(GroupKind::Rule, &rule, 0),
            "Hosts where OS family is Windows and hostname does not match *test*"
        );
        let rule = [
            c("distribution", true, &["debian 12", "fedora 44", "x 1"]),
            c("ip", true, &["10.0.0.0/8"]),
        ];
        assert_eq!(
            membership_sentence(GroupKind::Automatic, &rule, 0),
            "Hosts where distribution is not Debian 12, Fedora 44 or x 1 and IP address is not in 10.0.0.0/8"
        );
        assert_eq!(
            membership_sentence(GroupKind::Manual, &[], 1),
            "1 host picked by hand"
        );
        assert_eq!(
            membership_sentence(GroupKind::Manual, &[], 3),
            "3 hosts picked by hand"
        );
    }
}
