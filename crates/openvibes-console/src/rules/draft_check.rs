use std::collections::BTreeSet;

use openvibes_core::{ResourceLimits, Rule, RuleKind, RuleSet, SchemaVersion, Validate};
use platform_store::rule_drafts::{Draft, SITE, SITE_ALARMS};
use serde_json::{Value, json};

use super::draft_types::{RuleDraftInput, RuleProblem};

/// Most distinct programs one alarm rule may name (agent contract P14).
const RULE_PROGRAMS: usize = 8;
/// Most distinct programs across one alarm rule set.
const SET_PROGRAMS: usize = 32;

pub(super) fn problem(field: &str, message: impl Into<String>) -> RuleProblem {
    RuleProblem {
        field: field.to_owned(),
        message: message.into(),
    }
}

pub(super) fn known_set(rule_set_id: &str) -> bool {
    rule_set_id == SITE || rule_set_id == SITE_ALARMS
}

/// The rule as the agent's loader reads it.
pub(super) fn rule_json(
    rule_set_id: &str,
    rule_id: &str,
    version: u64,
    input: &RuleDraftInput,
) -> Value {
    let mut rule = json!({
        "id": rule_id,
        "version": version,
        "title": input.title,
        "severity": input.severity,
        "confidence": input.confidence,
        "expression": input.expression,
        "finding_message": input.finding_message,
    });
    if rule_set_id == SITE_ALARMS {
        rule["kind"] = json!("process_event");
        rule["programs"] = json!(input.programs.clone().unwrap_or_default());
    }
    if let Some(attack) = input.attack.as_ref().filter(|a| !a.is_empty()) {
        rule["attack"] = json!(attack);
    }
    rule
}

/// What the agent's loader, the CEL compiler and the restricted-set caps say
/// about `input`. `others` are the programs the set's other drafts name.
pub(super) fn check(
    rule_set_id: &str,
    rule_id: &str,
    input: &RuleDraftInput,
    others: &BTreeSet<String>,
) -> Vec<RuleProblem> {
    let mut problems = Vec::new();
    if openvibes_core::Identifier::new(rule_id).is_err() {
        problems.push(problem(
            "id",
            "use letters, digits, dots, dashes and underscores, up to 128 characters",
        ));
    }
    if input.programs.is_some() && rule_set_id != SITE_ALARMS {
        problems.push(problem(
            "programs",
            "only alarm rules have a program prefilter",
        ));
    }
    if serde_json::from_value::<openvibes_core::Severity>(json!(input.severity)).is_err() {
        problems.push(problem(
            "severity",
            "use info, low, medium, high or critical",
        ));
    }
    if input.confidence > 100 {
        problems.push(problem("confidence", "use a number from 0 to 100"));
    }
    if !problems.is_empty() {
        return problems;
    }
    let rule: Rule = match serde_json::from_value(rule_json(rule_set_id, rule_id, 1, input)) {
        Ok(rule) => rule,
        Err(error) => {
            problems.push(problem("rule", error.to_string()));
            return problems;
        }
    };
    let set = RuleSet {
        schema_version: SchemaVersion::V1,
        rules: vec![rule.clone()],
    };
    if let Err(error) = set.validate(ResourceLimits::V1) {
        let field = error.field();
        problems.push(problem(
            field.strip_prefix("rules.").unwrap_or(field),
            error.message(),
        ));
    }
    for pair in rule.attack.iter().flatten() {
        if let Some(message) = super::coverage::unknown_pair(pair) {
            problems.push(problem("attack", message));
        }
    }
    // The agent's own static check: what its loader refuses.
    if let Err(error) = openvibes_rules::check_rule(&rule, ResourceLimits::V1) {
        problems.push(problem("expression", error.to_string()));
    }
    if rule.kind == RuleKind::ProcessEvent && !problems.iter().any(|p| p.field == "programs") {
        let named: BTreeSet<&String> = rule.programs.iter().flatten().collect();
        if rule.programs.iter().flatten().any(|name| name.is_empty()) {
            problems.push(problem("programs", "a program name is empty"));
        }
        if !(1..=RULE_PROGRAMS).contains(&named.len()) {
            problems.push(problem(
                "programs",
                format!("name one to {RULE_PROGRAMS} distinct programs"),
            ));
        }
        let all: BTreeSet<&String> = named.iter().copied().chain(others).collect();
        if all.len() > SET_PROGRAMS {
            problems.push(problem(
                "programs",
                format!("a set may name at most {SET_PROGRAMS} distinct programs"),
            ));
        }
    }
    problems
}

/// The distinct programs named by every draft of the set except `rule_id`.
pub(super) fn other_programs(drafts: &[Draft], rule_id: &str) -> BTreeSet<String> {
    drafts
        .iter()
        .filter(|draft| draft.rule_id != rule_id)
        .filter_map(|draft| draft.rule.get("programs")?.as_array())
        .flatten()
        .filter_map(|name| name.as_str().map(str::to_owned))
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{RuleDraftInput, check};

    fn input(expression: &str, programs: Option<Vec<&str>>) -> RuleDraftInput {
        RuleDraftInput {
            title: "Title".to_owned(),
            severity: "high".to_owned(),
            confidence: 90,
            expression: expression.to_owned(),
            finding_message: "Message".to_owned(),
            programs: programs.map(|names| names.into_iter().map(str::to_owned).collect()),
            attack: None,
        }
    }

    fn pair(tactic: &str, technique: Option<&str>) -> crate::rules::coverage::AttackPairInput {
        crate::rules::coverage::AttackPairInput {
            tactic: tactic.into(),
            technique: technique.map(Into::into),
        }
    }

    #[test]
    fn attack_pairs_are_checked_against_the_bundled_release() {
        let mut rule = input("'sshd' in facts['process.names']", None);
        rule.attack = Some(vec![pair("TA0001", Some("T1190")), pair("TA0005", None)]);
        assert!(check("site", "r", &rule, &BTreeSet::new()).is_empty());
        rule.attack = Some(vec![pair("TA0002", Some("T1190"))]);
        let problems = check("site", "r", &rule, &BTreeSet::new());
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert_eq!(problems[0].field, "attack");
        rule.attack = Some(vec![pair("TA0002", Some("T1059.4"))]);
        assert!(
            check("site", "r", &rule, &BTreeSet::new())
                .iter()
                .any(|p| p.field == "attack"),
            "a malformed id is refused by the agent's own validation"
        );
    }

    fn fields(problems: &[super::RuleProblem]) -> Vec<&str> {
        problems.iter().map(|p| p.field.as_str()).collect()
    }

    #[test]
    fn a_baseline_style_findings_rule_passes() {
        let rule = input("'6379' in facts['port.tcp.exposed']", None);
        assert!(check("site", "port.redis.exposed", &rule, &BTreeSet::new()).is_empty());
    }

    #[test]
    fn a_bad_expression_or_severity_names_its_field() {
        let rule = input("this is not cel ((", None);
        assert_eq!(
            fields(&check("site", "r1", &rule, &BTreeSet::new())),
            ["expression"]
        );
        let mut rule = input("true", None);
        rule.severity = "urgent".to_owned();
        assert_eq!(
            fields(&check("site", "r1", &rule, &BTreeSet::new())),
            ["severity"]
        );
    }

    #[test]
    fn alarm_rules_need_one_to_eight_programs_and_a_32_program_set() {
        let ok = input("event['process.name'] == 'sh'", Some(vec!["nginx"]));
        assert!(check("site-alarms", "a1", &ok, &BTreeSet::new()).is_empty());
        let none = input("true", None);
        assert_eq!(
            fields(&check("site-alarms", "a1", &none, &BTreeSet::new())),
            ["programs"]
        );
        let nine: Vec<String> = (0..9).map(|n| format!("p{n}")).collect();
        let nine = input("true", Some(nine.iter().map(String::as_str).collect()));
        assert_eq!(
            fields(&check("site-alarms", "a1", &nine, &BTreeSet::new())),
            ["programs"]
        );
        let others: BTreeSet<String> = (0..32).map(|n| format!("other{n}")).collect();
        assert_eq!(
            fields(&check("site-alarms", "a1", &ok, &others)),
            ["programs"]
        );
    }

    #[test]
    fn findings_rules_take_no_programs() {
        let rule = input("true", Some(vec!["sh"]));
        assert!(fields(&check("site", "r1", &rule, &BTreeSet::new())).contains(&"programs"));
    }
}
