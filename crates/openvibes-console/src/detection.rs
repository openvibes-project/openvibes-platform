//! Original detection inputs and observation-scoped historical rule reads.
use crate::{
    Permission, ProblemDetails,
    problem::problem_response,
    router::{AuthHttpState, authenticated_permission, unavailable_auth},
};
use axum::{
    Json,
    extract::{Path, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use openvibes_core::{Identifier, ResourceLimits, Rule, SignedRuleEnvelope};
use openvibes_rules::{LoadContext, RuleLoader, TrustedRuleKey};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Original evaluation evidence; JSON scalars preserve their input types.
#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
pub struct DetectionView {
    /// Sample time in Unix milliseconds, not the last heartbeat.
    pub observed_at_unix_ms: i64,
    /// Verified set version.
    pub rule_set_version: u64,
    /// SHA-256 of the signed bundle's preimage.
    pub preimage_sha256: String,
    /// Inputs actually read.
    pub inputs: Vec<InputView>,
    /// Original Boolean results; omitted branches were not evaluated.
    pub steps: Vec<StepView>,
    /// Some explanation detail could not be retained.
    pub truncated: bool,
}
/// A recorded input, a scalar or a summarized list.
#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
pub struct InputView {
    /// Fact/event key.
    pub key: String,
    /// complete, masked, summarized, or truncated.
    pub status: String,
    /// Original scalar value; absent for lists or masked data.
    pub value: Option<serde_json::Value>,
    /// Complete source list length, when summarized.
    pub item_count: Option<usize>,
}
/// A condition evaluated at detection time.
#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
pub struct StepView {
    /// Canonical condition containing rule literals and keys.
    pub expression: String,
    /// Original result.
    pub result: bool,
}

/// Historical rule content for one authorized observation.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct DetectionRuleView {
    /// exact, legacy, or unavailable. Legacy means all examined definitions agree.
    pub status: String,
    /// Rule set ID.
    pub rule_set_id: String,
    /// Known exact set version, absent for legacy ambiguous bundle identity.
    pub rule_set_version: Option<i64>,
    /// The rule; absent when original content cannot be resolved safely.
    pub rule: Option<HistoricalRuleView>,
}
/// Complete historical rule definition, read-only.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct HistoricalRuleView {
    /// ID within its rule set.
    pub id: String,
    /// Rule version.
    pub version: u64,
    /// Rule title.
    pub title: String,
    /// Complete original CEL source.
    pub expression: String,
    /// Message emitted by this rule.
    pub finding_message: String,
    /// Severity name.
    pub severity: String,
    /// Confidence percentage.
    pub confidence: u8,
    /// snapshot or process_event.
    pub kind: String,
    /// Program prefilter, if present.
    pub programs: Option<Vec<String>>,
}
fn rule_view(rule: Rule) -> HistoricalRuleView {
    HistoricalRuleView {
        id: rule.id.as_str().into(),
        version: rule.version,
        title: rule.title,
        expression: rule.expression,
        finding_message: rule.finding_message,
        severity: serde_json::to_value(rule.severity)
            .ok()
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_default(),
        confidence: rule.confidence.value(),
        kind: if rule.kind == openvibes_core::RuleKind::Snapshot {
            "snapshot"
        } else {
            "process_event"
        }
        .into(),
        programs: rule.programs,
    }
}

async fn resolve(
    client: &platform_store::Client,
    set: &str,
    rule_id: &str,
    rule_version: i64,
    version: Option<i64>,
    hash: Option<&str>,
) -> Result<DetectionRuleView, platform_store::StoreError> {
    let mut response = DetectionRuleView {
        status: "unavailable".into(),
        rule_set_id: set.into(),
        rule_set_version: version,
        rule: None,
    };
    let Ok(set_id) = Identifier::new(set) else {
        return Ok(response);
    };
    let bundles = platform_store::rules::observation_bundles(client, set, version).await?;
    if bundles.is_empty() || bundles.len() > 8 {
        return Ok(response);
    }
    // Removed public keys remain in the store. Verify at creation time to read
    // historical content, without reactivating it for distribution or execution.
    let keys = platform_store::rules::trust_keys(client, Some(set)).await?;
    let trusted = keys
        .into_iter()
        .filter_map(|key| {
            TrustedRuleKey::new(
                set_id.clone(),
                Identifier::new(key.issuer_key_id).ok()?,
                key.public_key,
            )
            .ok()
        })
        .collect();
    let Ok(loader) = RuleLoader::new(trusted, ResourceLimits::V1) else {
        return Ok(response);
    };
    let mut selected: Option<Rule> = None;
    for bytes in bundles {
        let Ok(envelope) = serde_json::from_slice::<SignedRuleEnvelope>(&bytes) else {
            return Ok(response);
        };
        let Ok(bundle) = loader.load_json(
            &bytes,
            LoadContext {
                expected_rule_set_id: &set_id,
                now_unix_ms: envelope.created_at_unix_ms,
                last_accepted: None,
            },
        ) else {
            return Ok(response);
        };
        if hash.is_some_and(|hash| {
            hash != openvibes_core::hex(bundle.accepted_version().preimage_sha256())
        }) {
            return Ok(response);
        }
        let Some(rule) = bundle.rules().rules.iter().find(|rule| {
            rule.id.as_str() == rule_id && i64::try_from(rule.version).ok() == Some(rule_version)
        }) else {
            continue;
        };
        if selected.as_ref().is_some_and(|old| old != rule) {
            return Ok(response);
        }
        selected = Some(rule.clone());
    }
    if let Some(rule) = selected {
        response.status = if version.is_some() { "exact" } else { "legacy" }.into();
        response.rule = Some(rule_view(rule));
    }
    Ok(response)
}

#[utoipa::path(get, path="/api/v1/findings/latest/{agent_id}/{rule_set_id}/{rule_id}/rule/{finding_id}", tag="findings",
    params(("agent_id"=String,Path),("rule_set_id"=String,Path),("rule_id"=String,Path),("finding_id"=String,Path)),
    responses((status=200,description="Historical rule for the visible observation",body=DetectionRuleView),
        (status=404,description="Observation no longer current or not visible"),(status=503,description="Read unavailable")))]
pub(crate) async fn finding_rule(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path((agent, set, rule, finding_id)): Path<(String, String, String, String)>,
) -> Response {
    let (scope, _) =
        match authenticated_permission(&state, &headers, Permission::FindingsRead, false).await {
            Ok(v) => v,
            Err(r) => return r,
        };
    let Ok(client) = state.pool.get().await else {
        return unavailable_auth();
    };
    let set = if set == "~unknown" { "" } else { &set };
    let finding = match platform_store::console_read::latest_finding_in_scope(
        &client, &agent, set, &rule, &scope,
    )
    .await
    {
        Ok(Some(finding)) if finding.finding_id == finding_id => finding,
        Ok(_) => {
            return problem_response(ProblemDetails::not_found(
                "finding_not_found",
                "Finding not found or observation changed; reopen it",
            ));
        }
        Err(_) => return unavailable_auth(),
    };
    let detection = finding.detection.as_ref();
    let version = detection.and_then(|d| d["rule_set_version"].as_i64());
    let hash = detection.and_then(|d| d["preimage_sha256"].as_str());
    match resolve(&client, set, &rule, finding.rule_version, version, hash).await {
        Ok(view) => Json(view).into_response(),
        Err(_) => unavailable_auth(),
    }
}

#[utoipa::path(get, path="/api/v1/alarms/{id}/rule", tag="alarms", params(("id"=i64,Path)),
    responses((status=200,description="Historical rule for the visible alarm",body=DetectionRuleView),
        (status=404,description="Alarm not visible"),(status=503,description="Read unavailable")))]
pub(crate) async fn alarm_rule(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Response {
    let (scope, _) =
        match authenticated_permission(&state, &headers, Permission::AlarmsRead, false).await {
            Ok(v) => v,
            Err(r) => return r,
        };
    let Ok(client) = state.pool.get().await else {
        return unavailable_auth();
    };
    let alarm = match platform_store::console_alarms::detail(&client, &scope, id).await {
        Ok(Some(alarm)) => alarm,
        Ok(None) => {
            return problem_response(ProblemDetails::not_found(
                "alarm_not_found",
                "Alarm not found",
            ));
        }
        Err(_) => return unavailable_auth(),
    };
    let hash = alarm
        .detection
        .as_ref()
        .and_then(|d| d["preimage_sha256"].as_str());
    match resolve(
        &client,
        &alarm.summary.rule_set_id,
        &alarm.summary.rule_id,
        alarm.rule_version,
        Some(alarm.rule_set_version),
        hash,
    )
    .await
    {
        Ok(view) => Json(view).into_response(),
        Err(_) => unavailable_auth(),
    }
}
