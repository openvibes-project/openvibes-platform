//! Testing a snapshot rule against one host: the facts the platform can
//! rebuild for it (packages and listening ports), run through the agent's
//! own evaluator. A rule over a fact the platform doesn't hold, such as
//! `process.names`, is reported as unavailable here: the agent evaluates it.

use std::time::{Duration, Instant};

use axum::{
    Json,
    extract::{Path, State, rejection::JsonRejection},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{SecondsFormat, Utc};
use ed25519_dalek::{Signer, SigningKey};
use openvibes_core::{
    Fact, FactSet, FactValue, Identifier, PayloadEncoding, ResourceLimits, Rule, RuleSet,
    SchemaVersion, SignedRuleEnvelope,
};
use openvibes_rules::{
    EvaluationClock, Evaluator, LoadContext, RuleLoader, RuleOutcome, TrustedRuleKey,
    signing_preimage,
};
use platform_store::{
    console_read::AgentScope,
    rule_drafts::{SITE, SITE_ALARMS},
};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use utoipa::ToSchema;

use crate::{
    Permission, ProblemDetails,
    problem::problem_response,
    router::{AuthHttpState, authenticated_permission, unavailable_auth},
    rule_drafts::{RuleDraftInput, rule_json},
};

/// The host and rule to test.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RuleTestInput {
    /// The host to test against.
    pub agent_id: String,
    /// The rule as typed in the editor, saved or not.
    pub rule: RuleDraftInput,
}

/// What the platform held for the host when it tested.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct RuleTestFacts {
    /// Distinct installed package names.
    pub packages: usize,
    /// Listening sockets.
    pub listeners: usize,
    /// When the host last reported its listeners; absent if it never did.
    pub listeners_reported_at: Option<String>,
}

/// The rule's result on one host.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct RuleTestResult {
    /// `match`, `no_match`, `unavailable` or `failed`.
    pub outcome: String,
    /// The fact keys behind a match.
    pub evidence: Vec<String>,
    /// Why a rule failed, or why it is unavailable here.
    pub message: Option<String>,
    /// The data the test ran on.
    pub facts: RuleTestFacts,
}

struct Clock {
    started: Instant,
    now_ms: i64,
}

impl EvaluationClock for Clock {
    fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }

    fn unix_ms(&self) -> i64 {
        self.now_ms
    }
}

fn identifier(value: &str) -> Option<Identifier> {
    Identifier::new(value).ok()
}

fn fact(key: &str, value: FactValue) -> Option<Fact> {
    Some(Fact {
        key: identifier(key)?,
        source: identifier("console-rebuilt")?,
        value,
    })
}

/// The `port.*` facts the agent's ports collector would produce for these
/// listeners (`exposed` is its loopback test, kept by the platform).
fn port_facts(listeners: &[platform_store::host_services::Listener]) -> Option<Vec<Fact>> {
    use std::collections::BTreeSet;
    let mut facts = Vec::new();
    for protocol in ["tcp", "udp"] {
        let mut exposed = BTreeSet::new();
        let mut local = BTreeSet::new();
        let mut addresses = BTreeSet::new();
        for listener in listeners.iter().filter(|l| l.protocol == protocol) {
            let port = listener.port.to_string();
            if listener.exposed {
                exposed.insert(port);
            } else {
                local.insert(port);
            }
            addresses.insert(match listener.address {
                std::net::IpAddr::V4(address) => format!("{address}:{}", listener.port),
                std::net::IpAddr::V6(address) => format!("[{address}]:{}", listener.port),
            });
        }
        // A port bound to loopback and to an exposed address is exposed.
        let local: Vec<String> = local.difference(&exposed).cloned().collect();
        let count = i64::try_from(exposed.len()).ok()?;
        facts.push(fact(
            &format!("port.{protocol}.exposed"),
            FactValue::StringList(exposed.into_iter().collect()),
        )?);
        facts.push(fact(
            &format!("port.{protocol}.local"),
            FactValue::StringList(local),
        )?);
        facts.push(fact(
            &format!("port.{protocol}.listeners"),
            FactValue::StringList(addresses.into_iter().collect()),
        )?);
        facts.push(fact(
            &format!("port.{protocol}.exposed.count"),
            FactValue::Integer(count),
        )?);
    }
    Some(facts)
}

/// Signs `rule` with a key made for this call and loads it back through the
/// agent's own loader: the evaluator only takes what the loader verified.
fn verified(rule: Rule, now_ms: i64) -> Option<openvibes_rules::VerifiedRuleSet> {
    let mut seed = [0_u8; 32];
    SystemRandom::new().fill(&mut seed).ok()?;
    let key = SigningKey::from_bytes(&seed);
    let set = Identifier::new(SITE).ok()?;
    let issuer = Identifier::new("console-test").ok()?;
    let payload = serde_json::to_string(&RuleSet {
        schema_version: SchemaVersion::V1,
        rules: vec![rule],
    })
    .ok()?;
    let mut envelope = SignedRuleEnvelope {
        schema_version: SchemaVersion::V1,
        rule_set_id: set.clone(),
        rule_set_version: 1,
        issuer_key_id: issuer.clone(),
        created_at_unix_ms: now_ms,
        expires_at_unix_ms: now_ms + 60_000,
        payload_encoding: PayloadEncoding::Json,
        payload_sha256_hex: Sha256::digest(payload.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
        payload,
        signature_base64url: String::new(),
    };
    let preimage = signing_preimage(&envelope, ResourceLimits::V1).ok()?;
    envelope.signature_base64url = URL_SAFE_NO_PAD.encode(key.sign(&preimage).to_bytes());
    let bytes = serde_json::to_vec(&envelope).ok()?;
    let trusted = TrustedRuleKey::new(set.clone(), issuer, key.verifying_key().to_bytes()).ok()?;
    RuleLoader::new(vec![trusted], ResourceLimits::V1)
        .and_then(|loader| {
            loader.load_json(
                &bytes,
                LoadContext {
                    expected_rule_set_id: &set,
                    now_unix_ms: now_ms,
                    last_accepted: None,
                },
            )
        })
        .ok()
}

/// Runs the rule over `facts`.
fn run(
    rule: Rule,
    facts: Vec<Fact>,
    agent_id: &str,
) -> Option<(String, Vec<String>, Option<String>)> {
    let now_ms = Utc::now().timestamp_millis();
    let verified = verified(rule, now_ms)?;
    let set = FactSet {
        schema_version: SchemaVersion::V1,
        scan_id: identifier("console-test")?,
        collected_at_unix_ms: now_ms - 1,
        facts,
        errors: Vec::new(),
    };
    let clock = Clock {
        started: Instant::now(),
        now_ms,
    };
    let agent = identifier(agent_id).or_else(|| identifier("host"))?;
    let report = Evaluator::new(ResourceLimits::V1)
        .ok()?
        .evaluate(&verified, &set, &agent, &clock)
        .ok()?;
    let result = report.results.into_iter().next()?;
    Some(match result.outcome {
        RuleOutcome::Match(finding) => (
            "match".to_owned(),
            finding
                .evidence
                .iter()
                .map(|key| key.as_str().to_owned())
                .collect(),
            None,
        ),
        RuleOutcome::NoMatch => ("no_match".to_owned(), Vec::new(), None),
        RuleOutcome::Unavailable => (
            "unavailable".to_owned(),
            Vec::new(),
            Some(
                "The platform doesn't hold a fact this rule reads. The platform rebuilds only packages and listening ports; the agent evaluates the rest.".to_owned(),
            ),
        ),
        RuleOutcome::Failed(error) => ("failed".to_owned(), Vec::new(), Some(error.to_string())),
    })
}

#[utoipa::path(post, path = "/api/v1/rule-drafts/{rule_set_id}/{rule_id}/test", tag = "rules",
    params(("rule_set_id" = String, Path), ("rule_id" = String, Path)),
    request_body = crate::rule_test::RuleTestInput,
    responses((status = 200, description = "The rule's result on the host", body = crate::rule_test::RuleTestResult),
        (status = 404, description = "Not a site rule set, or no such host", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "The rule does not pass the agent's checks, or is an alarm rule", body = crate::ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn test_rule(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path((rule_set_id, rule_id)): Path<(String, String)>,
    payload: Result<Json<RuleTestInput>, JsonRejection>,
) -> Response {
    let (scope, _) =
        match authenticated_permission(&state, &headers, Permission::RulesWrite, true).await {
            Ok(context) => context,
            Err(response) => return response,
        };
    if !matches!(scope, AgentScope::Global) {
        return problem_response(ProblemDetails::new(
            StatusCode::FORBIDDEN,
            "permission_denied",
            "Access is not available",
        ));
    }
    if rule_set_id != SITE && rule_set_id != SITE_ALARMS {
        return problem_response(ProblemDetails::not_found(
            "rule_set_not_found",
            "Only the site's own rule sets, site and site-alarms, have drafts",
        ));
    }
    let Ok(Json(request)) = payload else {
        return problem_response(ProblemDetails::new(
            StatusCode::BAD_REQUEST,
            "invalid_rule",
            "The test needs a host and a rule",
        ));
    };
    if rule_set_id == SITE_ALARMS {
        return problem_response(ProblemDetails::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "alarm_test_unsupported",
            "Alarm rules run on process starts, which the platform doesn't hold; test them on a host",
        ));
    }
    if !crate::rule_drafts::check(&rule_set_id, &rule_id, &request.rule, &Default::default())
        .is_empty()
    {
        return problem_response(ProblemDetails::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_rule",
            "The rule does not pass the agent's checks yet",
        ));
    }
    let Ok(client) = state.pool.get().await else {
        return unavailable_auth();
    };
    let (Ok(services), Ok(names)) = (
        platform_store::host_services::for_host(&client, &scope, &request.agent_id).await,
        platform_store::console_inventory::host_package_names(&client, &scope, &request.agent_id)
            .await,
    ) else {
        return unavailable_auth();
    };
    let (Some(services), Some(names)) = (services, names) else {
        return problem_response(ProblemDetails::not_found("host_not_found", "No such host"));
    };
    let Ok(rule) =
        serde_json::from_value::<Rule>(rule_json(&rule_set_id, &rule_id, 1, &request.rule))
    else {
        return unavailable_auth();
    };
    let counts = RuleTestFacts {
        packages: names.len(),
        listeners: services.listeners.len(),
        listeners_reported_at: services
            .reported_at
            .map(|at| at.to_rfc3339_opts(SecondsFormat::Millis, true)),
    };
    let mut facts = Vec::new();
    let package_count = i64::try_from(names.len()).unwrap_or(i64::MAX);
    facts.extend(fact("package.names", FactValue::StringList(names)));
    facts.extend(fact("package.count", FactValue::Integer(package_count)));
    // A host that never reported listeners has no port facts: a port rule is
    // unavailable on it, not a no match.
    if services.reported_at.is_some() {
        match port_facts(&services.listeners) {
            Some(ports) => facts.extend(ports),
            None => return unavailable_auth(),
        }
    }
    match run(rule, facts, &request.agent_id) {
        Some((outcome, evidence, message)) => Json(RuleTestResult {
            outcome,
            evidence,
            message,
            facts: counts,
        })
        .into_response(),
        None => unavailable_auth(),
    }
}
