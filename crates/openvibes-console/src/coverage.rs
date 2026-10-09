//! MITRE ATT&CK coverage of the platform's rules (protocol P18, spec
//! `2026-10-09-attack-coverage-design.md`): the bundled ATT&CK catalog, the
//! derived kill-chain phase, and which tactics and techniques the published
//! rule sets and the site's drafts claim.

use std::{collections::HashMap, sync::OnceLock};

use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use openvibes_core::{AttackRef, Identifier, ResourceLimits, Rule, RuleKind, SignedRuleEnvelope};
use openvibes_rules::{LoadContext, RuleLoader, TrustedRuleKey};
use platform_store::rule_drafts::{SITE, SITE_ALARMS};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{
    Permission, ProblemDetails,
    problem::problem_response,
    router::{AuthHttpState, authenticated_permission, no_store, unavailable_auth},
};

/// The test-trigger rules (spec `2026-10-09-test-triggers-design.md`): they
/// cover no technique, so coverage leaves them out. Only these exact
/// (set, rule) pairs from the baseline sets count.
pub(crate) const TEST_RULES: [(&str, &str); 2] = [
    ("baseline-alarms", "alarm.openvibes.test"),
    ("baseline", "test.openvibes.running"),
];

/// Whether `(set, rule)` is one of the test triggers.
pub(crate) fn is_test_rule(set: &str, rule: &str) -> bool {
    TEST_RULES.contains(&(set, rule))
}

#[derive(Deserialize)]
struct Catalog {
    version: String,
    notice: String,
    tactics: Vec<CatalogTactic>,
    techniques: Vec<TechniqueView>,
}

#[derive(Deserialize)]
struct CatalogTactic {
    id: String,
    name: String,
}

fn catalog() -> &'static (Catalog, HashMap<String, usize>) {
    static CATALOG: OnceLock<(Catalog, HashMap<String, usize>)> = OnceLock::new();
    CATALOG.get_or_init(|| {
        let catalog: Catalog = serde_json::from_str(include_str!("../data/attack-enterprise.json"))
            .expect("the bundled ATT&CK data file parses");
        let index = catalog
            .techniques
            .iter()
            .enumerate()
            .map(|(n, t)| (t.id.clone(), n))
            .collect();
        (catalog, index)
    })
}

/// The Lockheed Martin kill-chain phase of an ATT&CK tactic (spec §3).
pub(crate) fn phase(tactic: &str) -> &'static str {
    match tactic {
        "TA0043" => "Reconnaissance",
        "TA0042" => "Weaponization",
        "TA0001" => "Delivery",
        "TA0002" => "Exploitation",
        "TA0003" | "TA0004" | "TA0005" | "TA0112" => "Installation",
        "TA0011" => "Command and Control",
        "TA0006" | "TA0007" | "TA0008" | "TA0009" | "TA0010" | "TA0040" => "Actions on Objectives",
        _ => "Unmapped phase",
    }
}

/// Why a pair is not in the bundled ATT&CK release, if it is not.
pub(crate) fn unknown_pair(pair: &AttackRef) -> Option<String> {
    let (catalog, index) = catalog();
    if !catalog.tactics.iter().any(|t| t.id == pair.tactic) {
        return Some(format!(
            "{} is not a tactic in ATT&CK {}",
            pair.tactic, catalog.version
        ));
    }
    let technique = pair.technique.as_deref()?;
    let Some(&n) = index.get(technique) else {
        return Some(format!(
            "{technique} is not a technique in ATT&CK {}",
            catalog.version
        ));
    };
    (!catalog.techniques[n].tactics.contains(&pair.tactic)).then(|| {
        format!(
            "{technique} is not under {} in ATT&CK {}",
            pair.tactic, catalog.version
        )
    })
}

/// One ATT&CK tactic, in matrix order.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct TacticView {
    /// `TA` id.
    pub id: String,
    /// Name, e.g. Initial Access.
    pub name: String,
    /// Derived kill-chain phase.
    pub phase: String,
}

/// One ATT&CK technique or sub-technique.
#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
pub struct TechniqueView {
    /// `T` id, `T1059.004` for a sub-technique.
    pub id: String,
    /// Name.
    pub name: String,
    /// The tactics it belongs to.
    pub tactics: Vec<String>,
}

/// The bundled ATT&CK release, for the rule editor's picker.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct AttackCatalog {
    /// ATT&CK release, e.g. 19.2.
    pub version: String,
    /// MITRE's attribution, shown wherever ATT&CK content is.
    pub notice: String,
    /// Tactics in matrix order.
    pub tactics: Vec<TacticView>,
    /// Live techniques, by id.
    pub techniques: Vec<TechniqueView>,
}

/// One pair as the rule editor sends it.
#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct AttackPairInput {
    /// Tactic id, `TA0002`.
    pub tactic: String,
    /// Technique id, `T1059` or `T1059.004`; optional.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub technique: Option<String>,
}

/// One pair a rule claims, resolved against the bundled release.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct AttackPairView {
    /// Tactic id.
    pub tactic: String,
    /// Technique id, when the rule names one.
    pub technique: Option<String>,
    /// Technique name; absent when unnamed or not in this release.
    pub technique_name: Option<String>,
    /// Whether the pair is in the bundled release.
    pub known: bool,
}

/// One rule and what it covers.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct CoverageRule {
    /// Rule set id.
    pub rule_set_id: String,
    /// Rule id.
    pub rule_id: String,
    /// Title.
    pub title: String,
    /// `snapshot` (findings) or `process_event` (alarms).
    pub kind: String,
    /// Severity name.
    pub severity: String,
    /// A site draft, not yet published.
    pub draft: bool,
    /// Its pairs; empty when the rule is not mapped.
    pub attack: Vec<AttackPairView>,
}

/// The coverage page's data; the browser builds the matrix.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct AttackCoverage {
    /// ATT&CK release the names come from.
    pub attack_version: String,
    /// MITRE's attribution.
    pub notice: String,
    /// Tactics in matrix order, with their kill-chain phase.
    pub tactics: Vec<TacticView>,
    /// Current rules of every live set, then the site's drafts.
    pub rules: Vec<CoverageRule>,
    /// Sets whose current bundle could not be verified (left out).
    pub unverified_sets: Vec<String>,
}

fn tactics() -> Vec<TacticView> {
    catalog()
        .0
        .tactics
        .iter()
        .map(|t| TacticView {
            id: t.id.clone(),
            name: t.name.clone(),
            phase: phase(&t.id).into(),
        })
        .collect()
}

pub(crate) fn pair_views(attack: Option<&[AttackRef]>) -> Vec<AttackPairView> {
    let (catalog, index) = catalog();
    attack
        .unwrap_or_default()
        .iter()
        .map(|pair| AttackPairView {
            tactic: pair.tactic.clone(),
            technique: pair.technique.clone(),
            technique_name: pair
                .technique
                .as_ref()
                .and_then(|t| index.get(t))
                .map(|&n| catalog.techniques[n].name.clone()),
            known: unknown_pair(pair).is_none(),
        })
        .collect()
}

fn coverage_rule(set: &str, rule: &Rule, draft: bool) -> CoverageRule {
    CoverageRule {
        rule_set_id: set.into(),
        rule_id: rule.id.as_str().into(),
        title: rule.title.clone(),
        kind: if rule.kind == RuleKind::Snapshot {
            "snapshot"
        } else {
            "process_event"
        }
        .into(),
        severity: serde_json::to_value(rule.severity)
            .ok()
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_default(),
        draft,
        attack: pair_views(rule.attack.as_deref()),
    }
}

/// The current bundle's rules, verified with the set's trusted keys like an
/// agent would; `None` when it does not verify.
async fn current_rules(
    client: &platform_store::Client,
    set: &str,
) -> Result<Option<Vec<Rule>>, platform_store::StoreError> {
    let platform_store::rules::Served::Envelope(bytes) =
        platform_store::rules::serve(client, set, None).await?
    else {
        return Ok(Some(Vec::new()));
    };
    let Ok(set_id) = Identifier::new(set) else {
        return Ok(None);
    };
    let keys = platform_store::rules::active_trust_keys(client, set).await?;
    let trusted = keys
        .into_iter()
        .filter_map(|(public, issuer)| {
            TrustedRuleKey::new(set_id.clone(), Identifier::new(issuer).ok()?, public).ok()
        })
        .collect();
    let Ok(loader) = RuleLoader::new(trusted, ResourceLimits::V1) else {
        return Ok(None);
    };
    let Ok(envelope) = serde_json::from_slice::<SignedRuleEnvelope>(&bytes) else {
        return Ok(None);
    };
    // Verified at its own creation time: coverage describes what is
    // published, also when it has since expired.
    Ok(loader
        .load_json(
            &bytes,
            LoadContext {
                expected_rule_set_id: &set_id,
                now_unix_ms: envelope.created_at_unix_ms,
                last_accepted: None,
            },
        )
        .ok()
        .map(|bundle| bundle.rules().rules.clone()))
}

async fn global_rules_read(
    state: &AuthHttpState,
    headers: &HeaderMap,
) -> Result<platform_store::Client, Response> {
    let (scope, _) = authenticated_permission(state, headers, Permission::RulesRead, false).await?;
    if !matches!(scope, platform_store::console_read::AgentScope::Global) {
        return Err(problem_response(ProblemDetails::new(
            StatusCode::FORBIDDEN,
            "permission_denied",
            "Access is not available",
        )));
    }
    state.pool.get().await.map_err(|_| unavailable_auth())
}

#[utoipa::path(get, path = "/api/v1/attack", tag = "rules",
    responses((status = 200, description = "The bundled MITRE ATT&CK release", body = crate::coverage::AttackCatalog)))]
pub(crate) async fn attack_catalog(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = global_rules_read(&state, &headers).await {
        return response;
    }
    let catalog = &catalog().0;
    Json(AttackCatalog {
        version: catalog.version.clone(),
        notice: catalog.notice.clone(),
        tactics: tactics(),
        techniques: catalog.techniques.clone(),
    })
    .into_response()
}

#[utoipa::path(get, path = "/api/v1/rules/coverage", tag = "rules",
    responses((status = 200, description = "Which ATT&CK tactics and techniques the rules cover", body = crate::coverage::AttackCoverage),
        (status = 403, description = "Global rules.read needed", body = crate::ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn rule_coverage(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
) -> Response {
    let client = match global_rules_read(&state, &headers).await {
        Ok(client) => client,
        Err(response) => return response,
    };
    let Ok(sets) = platform_store::rules::list(&client).await else {
        return unavailable_auth();
    };
    let mut rules = Vec::new();
    let mut unverified_sets = Vec::new();
    for set in sets
        .iter()
        .filter(|s| s.retired_at.is_none() && s.current_version.is_some())
    {
        match current_rules(&client, &set.rule_set_id).await {
            Ok(Some(current)) => rules.extend(
                current
                    .iter()
                    .filter(|r| !is_test_rule(&set.rule_set_id, r.id.as_str()))
                    .map(|r| coverage_rule(&set.rule_set_id, r, false)),
            ),
            Ok(None) => unverified_sets.push(set.rule_set_id.clone()),
            Err(_) => return unavailable_auth(),
        }
    }
    for site in [SITE, SITE_ALARMS] {
        let Ok(drafts) = platform_store::rule_drafts::list(&client, site).await else {
            return unavailable_auth();
        };
        rules.extend(drafts.into_iter().filter_map(|draft| {
            let rule: Rule = serde_json::from_value(draft.rule).ok()?;
            Some(coverage_rule(site, &rule, true))
        }));
    }
    let catalog = &catalog().0;
    no_store(
        Json(AttackCoverage {
            attack_version: catalog.version.clone(),
            notice: catalog.notice.clone(),
            tactics: tactics(),
            rules,
            unverified_sets,
        })
        .into_response(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair(tactic: &str, technique: Option<&str>) -> AttackRef {
        AttackRef {
            tactic: tactic.into(),
            technique: technique.map(Into::into),
        }
    }

    #[test]
    fn the_bundled_release_loads_and_every_tactic_has_a_phase() {
        let (catalog, _) = catalog();
        assert_eq!(catalog.version, "19.2");
        assert!(catalog.techniques.len() > 500);
        for tactic in &catalog.tactics {
            assert_ne!(phase(&tactic.id), "Unmapped phase", "{}", tactic.id);
        }
    }

    #[test]
    fn pairs_are_checked_against_the_release() {
        assert_eq!(unknown_pair(&pair("TA0002", Some("T1059.004"))), None);
        assert_eq!(unknown_pair(&pair("TA0001", None)), None);
        assert!(unknown_pair(&pair("TA9999", None)).is_some());
        assert!(unknown_pair(&pair("TA0002", Some("T9999"))).is_some());
        // T1190 is Initial Access, not Execution.
        assert!(unknown_pair(&pair("TA0002", Some("T1190"))).is_some());
    }

    #[test]
    fn views_name_known_techniques_and_flag_unknown_ones() {
        let views = pair_views(Some(&[
            pair("TA0001", Some("T1190")),
            pair("TA0002", Some("T9999")),
        ]));
        assert_eq!(
            views[0].technique_name.as_deref(),
            Some("Exploit Public-Facing Application")
        );
        assert!(views[0].known);
        assert!(!views[1].known);
        assert_eq!(views[1].technique_name, None);
    }

    #[test]
    fn only_the_exact_baseline_pairs_are_tests() {
        assert!(is_test_rule("baseline", "test.openvibes.running"));
        assert!(!is_test_rule("site", "test.openvibes.running"));
    }
}
