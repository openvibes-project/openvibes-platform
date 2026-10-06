//! Draft rules for the site's own rule sets over `/api/v1`. Listing, checking,
//! saving and deleting all need `rules.write`: `rules.read` is Admin-only, and
//! whoever edits drafts must see them.
//! Publishing is separate (`rules.upload`) and later. A draft never reaches
//! an agent: only a signed, published set does.
//!
//! Every draft is checked with the agent's own loader code before it is
//! saved, so a saved draft is one the agent would accept; the console
//! applies the same restricted-set `programs` caps the agent and the rule
//! signer enforce.

use std::collections::BTreeSet;

use axum::{
    Json,
    extract::{Path, State, rejection::JsonRejection},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use chrono::{SecondsFormat, Utc};
use openvibes_core::{ResourceLimits, Rule, RuleKind, RuleSet, SchemaVersion, Validate};
use platform_store::rule_drafts::{self as store, Draft, SITE, SITE_ALARMS};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use utoipa::ToSchema;

use crate::{
    Permission, ProblemDetails,
    problem::problem_response,
    router::{AuthHttpState, authenticated_permission, unavailable_auth},
};

/// Most distinct programs one alarm rule may name (agent contract P14).
const RULE_PROGRAMS: usize = 8;
/// Most distinct programs across one alarm rule set.
const SET_PROGRAMS: usize = 32;
/// Most drafts one set keeps.
const MAX_DRAFTS: usize = 512;

/// What the editor sends for one rule: everything but its id and version.
#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RuleDraftInput {
    /// Short title shown on findings or alarms.
    pub title: String,
    /// `info`, `low`, `medium`, `high` or `critical`.
    pub severity: String,
    /// Confidence in a match, 0 to 100.
    pub confidence: u8,
    /// CEL expression over `facts[...]` (findings) or `event[...]` (alarms).
    pub expression: String,
    /// Message on a match.
    pub finding_message: String,
    /// Alarm rules only: the programs (exe paths or basenames) an event must
    /// match before the expression runs; one to eight.
    pub programs: Option<Vec<String>>,
}

/// One saved draft rule.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct RuleDraftView {
    /// `site` (findings) or `site-alarms` (alarms).
    pub rule_set_id: String,
    /// The rule's id within the set.
    pub rule_id: String,
    /// The rule's version: raised each time a save changes it.
    pub version: u64,
    /// Title.
    pub title: String,
    /// Severity.
    pub severity: String,
    /// Confidence, 0 to 100.
    pub confidence: u8,
    /// CEL expression.
    pub expression: String,
    /// Message on a match.
    pub finding_message: String,
    /// Alarm rules: the program prefilter.
    pub programs: Option<Vec<String>>,
    /// Who last saved it.
    pub updated_by: String,
    /// When (RFC 3339).
    pub updated_at: String,
}

/// The drafts of one rule set.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct RuleDraftList {
    /// By rule id.
    pub items: Vec<RuleDraftView>,
}

/// One thing wrong with a draft.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct RuleProblem {
    /// The field it concerns: `id`, `title`, `severity`, `confidence`,
    /// `expression`, `finding_message`, `programs` or `rule`.
    pub field: String,
    /// What is wrong.
    pub message: String,
}

/// The result of checking a draft.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct RuleCheck {
    /// Whether the agent would accept it.
    pub ok: bool,
    /// Why not, when it would not.
    pub problems: Vec<RuleProblem>,
}

fn problem(field: &str, message: impl Into<String>) -> RuleProblem {
    RuleProblem {
        field: field.to_owned(),
        message: message.into(),
    }
}

fn view(draft: Draft) -> Option<RuleDraftView> {
    let rule: Rule = serde_json::from_value(draft.rule).ok()?;
    let severity = serde_json::to_value(rule.severity)
        .ok()?
        .as_str()?
        .to_owned();
    Some(RuleDraftView {
        rule_set_id: draft.rule_set_id,
        rule_id: draft.rule_id,
        version: rule.version,
        title: rule.title,
        severity,
        confidence: rule.confidence.value(),
        expression: rule.expression,
        finding_message: rule.finding_message,
        programs: rule.programs,
        updated_by: draft.updated_by,
        updated_at: draft
            .updated_at
            .to_rfc3339_opts(SecondsFormat::Millis, true),
    })
}

fn known_set(rule_set_id: &str) -> bool {
    rule_set_id == SITE || rule_set_id == SITE_ALARMS
}

/// The rule as the agent's loader reads it.
fn rule_json(rule_set_id: &str, rule_id: &str, version: u64, input: &RuleDraftInput) -> Value {
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
    rule
}

/// What the agent's loader, the CEL compiler and the restricted-set caps say
/// about `input`. `others` are the programs the set's other drafts name.
pub(crate) fn check(
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
fn other_programs(drafts: &[Draft], rule_id: &str) -> BTreeSet<String> {
    drafts
        .iter()
        .filter(|draft| draft.rule_id != rule_id)
        .filter_map(|draft| draft.rule.get("programs")?.as_array())
        .flatten()
        .filter_map(|name| name.as_str().map(str::to_owned))
        .collect()
}

fn unknown_set() -> Response {
    problem_response(ProblemDetails::not_found(
        "rule_set_not_found",
        "Only the site's own rule sets, site and site-alarms, have drafts",
    ))
}

fn global_only() -> Response {
    problem_response(ProblemDetails::new(
        StatusCode::FORBIDDEN,
        "permission_denied",
        "Access is not available",
    ))
}

#[utoipa::path(get, path = "/api/v1/rule-drafts/{rule_set_id}", tag = "rules", params(("rule_set_id" = String, Path)),
    responses((status = 200, description = "The set's draft rules", body = crate::rule_drafts::RuleDraftList),
        (status = 404, description = "Not a site rule set", body = crate::ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn list_drafts(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path(rule_set_id): Path<String>,
) -> Response {
    let (scope, _) =
        match authenticated_permission(&state, &headers, Permission::RulesWrite, false).await {
            Ok(context) => context,
            Err(response) => return response,
        };
    if !matches!(scope, platform_store::console_read::AgentScope::Global) {
        return global_only();
    }
    if !known_set(&rule_set_id) {
        return unknown_set();
    }
    let Ok(client) = state.pool.get().await else {
        return unavailable_auth();
    };
    match store::list(&client, &rule_set_id).await {
        Ok(drafts) => Json(RuleDraftList {
            items: drafts.into_iter().filter_map(view).collect(),
        })
        .into_response(),
        Err(_) => unavailable_auth(),
    }
}

#[utoipa::path(post, path = "/api/v1/rule-drafts/{rule_set_id}/{rule_id}/check", tag = "rules",
    params(("rule_set_id" = String, Path), ("rule_id" = String, Path)),
    request_body = crate::rule_drafts::RuleDraftInput,
    responses((status = 200, description = "Whether the agent would accept the rule, and why not", body = crate::rule_drafts::RuleCheck),
        (status = 404, description = "Not a site rule set", body = crate::ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn check_draft(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path((rule_set_id, rule_id)): Path<(String, String)>,
    payload: Result<Json<RuleDraftInput>, JsonRejection>,
) -> Response {
    let (scope, _) =
        match authenticated_permission(&state, &headers, Permission::RulesWrite, true).await {
            Ok(context) => context,
            Err(response) => return response,
        };
    if !matches!(scope, platform_store::console_read::AgentScope::Global) {
        return global_only();
    }
    if !known_set(&rule_set_id) {
        return unknown_set();
    }
    let Ok(Json(input)) = payload else {
        return invalid_body();
    };
    let Ok(client) = state.pool.get().await else {
        return unavailable_auth();
    };
    let Ok(drafts) = store::list(&client, &rule_set_id).await else {
        return unavailable_auth();
    };
    let problems = check(
        &rule_set_id,
        &rule_id,
        &input,
        &other_programs(&drafts, &rule_id),
    );
    Json(RuleCheck {
        ok: problems.is_empty(),
        problems,
    })
    .into_response()
}

fn invalid_body() -> Response {
    problem_response(ProblemDetails::new(
        StatusCode::BAD_REQUEST,
        "invalid_rule",
        "The request is not a rule: title, severity, confidence, expression, finding_message and, for alarms, programs",
    ))
}

#[utoipa::path(put, path = "/api/v1/rule-drafts/{rule_set_id}/{rule_id}", tag = "rules",
    params(("rule_set_id" = String, Path), ("rule_id" = String, Path)),
    request_body = crate::rule_drafts::RuleDraftInput,
    responses((status = 200, description = "Saved", body = crate::rule_drafts::RuleDraftView),
        (status = 404, description = "Not a site rule set", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "The agent would refuse the rule", body = crate::rule_drafts::RuleCheck)))]
pub(crate) async fn save_draft(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path((rule_set_id, rule_id)): Path<(String, String)>,
    payload: Result<Json<RuleDraftInput>, JsonRejection>,
) -> Response {
    let (scope, actor) =
        match authenticated_permission(&state, &headers, Permission::RulesWrite, true).await {
            Ok(context) => context,
            Err(response) => return response,
        };
    if !matches!(scope, platform_store::console_read::AgentScope::Global) {
        return global_only();
    }
    if !known_set(&rule_set_id) {
        return unknown_set();
    }
    let Ok(Json(input)) = payload else {
        return invalid_body();
    };
    let Ok(client) = state.pool.get().await else {
        return unavailable_auth();
    };
    let Ok(drafts) = store::list(&client, &rule_set_id).await else {
        return unavailable_auth();
    };
    let problems = check(
        &rule_set_id,
        &rule_id,
        &input,
        &other_programs(&drafts, &rule_id),
    );
    if !problems.is_empty() {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(RuleCheck {
                ok: false,
                problems,
            }),
        )
            .into_response();
    }
    let earlier = drafts.iter().find(|draft| draft.rule_id == rule_id);
    if earlier.is_none() && drafts.len() >= MAX_DRAFTS {
        return problem_response(ProblemDetails::new(
            StatusCode::CONFLICT,
            "too_many_rules",
            "A rule set keeps at most 512 rules",
        ));
    }
    let version = next_version(&rule_set_id, &rule_id, &input, earlier);
    let rule = rule_json(&rule_set_id, &rule_id, version, &input);
    let saved = match store::put(&client, &rule_set_id, &rule_id, &rule, &actor, Utc::now()).await {
        Ok(saved) => saved,
        Err(_) => return unavailable_auth(),
    };
    if platform_store::audit::record(
        &client,
        &actor,
        "rule_draft.saved",
        Some(&format!("{rule_set_id}/{rule_id} v{version}")),
        "success",
    )
    .await
    .is_err()
    {
        return unavailable_auth();
    }
    match view(saved) {
        Some(saved) => Json(saved).into_response(),
        None => unavailable_auth(),
    }
}

/// 1 for a new rule; the earlier version when nothing changed; else one more.
fn next_version(
    rule_set_id: &str,
    rule_id: &str,
    input: &RuleDraftInput,
    earlier: Option<&Draft>,
) -> u64 {
    let Some(earlier) = earlier else {
        return 1;
    };
    let before = earlier
        .rule
        .get("version")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    if rule_json(rule_set_id, rule_id, before, input) == earlier.rule {
        before
    } else {
        before + 1
    }
}

#[utoipa::path(delete, path = "/api/v1/rule-drafts/{rule_set_id}/{rule_id}", tag = "rules",
    params(("rule_set_id" = String, Path), ("rule_id" = String, Path)),
    responses((status = 204, description = "Deleted"),
        (status = 404, description = "No such draft", body = crate::ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn delete_draft(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path((rule_set_id, rule_id)): Path<(String, String)>,
) -> Response {
    let (scope, actor) =
        match authenticated_permission(&state, &headers, Permission::RulesWrite, true).await {
            Ok(context) => context,
            Err(response) => return response,
        };
    if !matches!(scope, platform_store::console_read::AgentScope::Global) {
        return global_only();
    }
    if !known_set(&rule_set_id) {
        return unknown_set();
    }
    let Ok(client) = state.pool.get().await else {
        return unavailable_auth();
    };
    match store::delete(&client, &rule_set_id, &rule_id).await {
        Ok(true) => {
            if platform_store::audit::record(
                &client,
                &actor,
                "rule_draft.deleted",
                Some(&format!("{rule_set_id}/{rule_id}")),
                "success",
            )
            .await
            .is_err()
            {
                return unavailable_auth();
            }
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => problem_response(ProblemDetails::not_found(
            "draft_not_found",
            "No such draft",
        )),
        Err(_) => unavailable_auth(),
    }
}

/// What publishing would change: the drafts against the published set.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct DraftChanges {
    /// The set's current published version; absent before the first publish.
    pub published_version: Option<i64>,
    /// Rules in the drafts but not published.
    pub added: Vec<String>,
    /// Rules in both, whose content differs.
    pub changed: Vec<String>,
    /// Published rules the drafts no longer have.
    pub removed: Vec<String>,
    /// Rules in both, the same.
    pub unchanged: usize,
}

/// The password the signer checks again before it signs.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PublishDraftsRequest {
    /// The signed-in user's password, typed again for this publish.
    pub password: String,
}

/// A published draft set.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct PublishedDrafts {
    /// `site` or `site-alarms`.
    pub rule_set_id: String,
    /// The version now published.
    pub version: i64,
    /// When the signed bundle expires, in Unix milliseconds.
    pub expires_at_ms: i64,
    /// Rules in the bundle.
    pub rules: usize,
}

/// The rules of the set's current published bundle, by id.
async fn published_rules(
    client: &platform_store::Client,
    rule_set_id: &str,
) -> Result<Option<(i64, std::collections::BTreeMap<String, Rule>)>, ()> {
    use platform_store::rules::Served;
    let Served::Envelope(bytes) = platform_store::rules::serve(client, rule_set_id, None)
        .await
        .map_err(|_| ())?
    else {
        return Ok(None);
    };
    let envelope: openvibes_core::SignedRuleEnvelope =
        serde_json::from_slice(&bytes).map_err(|_| ())?;
    let set: RuleSet = serde_json::from_str(&envelope.payload).map_err(|_| ())?;
    let version = i64::try_from(envelope.rule_set_version).map_err(|_| ())?;
    Ok(Some((
        version,
        set.rules
            .into_iter()
            .map(|rule| (rule.id.as_str().to_owned(), rule))
            .collect(),
    )))
}

fn draft_rules(drafts: &[Draft]) -> Result<Vec<Rule>, ()> {
    let mut rules = drafts
        .iter()
        .map(|draft| serde_json::from_value::<Rule>(draft.rule.clone()).map_err(|_| ()))
        .collect::<Result<Vec<_>, ()>>()?;
    rules.sort_by(|a, b| a.id.as_str().cmp(b.id.as_str()));
    Ok(rules)
}

fn changes(
    published: Option<&(i64, std::collections::BTreeMap<String, Rule>)>,
    drafts: &[Rule],
) -> DraftChanges {
    let mut out = DraftChanges {
        published_version: published.map(|(version, _)| *version),
        added: Vec::new(),
        changed: Vec::new(),
        removed: Vec::new(),
        unchanged: 0,
    };
    let empty = std::collections::BTreeMap::new();
    let before = published.map_or(&empty, |(_, rules)| rules);
    for rule in drafts {
        match before.get(rule.id.as_str()) {
            None => out.added.push(rule.id.as_str().to_owned()),
            Some(old) if old == rule => out.unchanged += 1,
            Some(_) => out.changed.push(rule.id.as_str().to_owned()),
        }
    }
    out.removed = before
        .keys()
        .filter(|id| !drafts.iter().any(|rule| rule.id.as_str() == id.as_str()))
        .cloned()
        .collect();
    out
}

#[utoipa::path(get, path = "/api/v1/rule-drafts/{rule_set_id}/changes", tag = "rules", params(("rule_set_id" = String, Path)),
    responses((status = 200, description = "What publishing the drafts would change", body = crate::rule_drafts::DraftChanges),
        (status = 404, description = "Not a site rule set", body = crate::ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn draft_changes(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path(rule_set_id): Path<String>,
) -> Response {
    let (scope, _) =
        match authenticated_permission(&state, &headers, Permission::RulesWrite, false).await {
            Ok(context) => context,
            Err(response) => return response,
        };
    if !matches!(scope, platform_store::console_read::AgentScope::Global) {
        return global_only();
    }
    if !known_set(&rule_set_id) {
        return unknown_set();
    }
    let Ok(client) = state.pool.get().await else {
        return unavailable_auth();
    };
    let (Ok(drafts), Ok(published)) = (
        store::list(&client, &rule_set_id).await,
        published_rules(&client, &rule_set_id).await,
    ) else {
        return unavailable_auth();
    };
    let Ok(rules) = draft_rules(&drafts) else {
        return unavailable_auth();
    };
    Json(changes(published.as_ref(), &rules)).into_response()
}

/// Most bytes the signer reads (`openvibes_signer::MAX_REQUEST`).
const SIGNER_MAX_REQUEST: usize = 1 << 20;
/// How long a publish waits for the signer (Argon2 plus a busy signer).
const SIGNER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// One request to the rule signer; its JSON answer.
async fn ask_signer(
    socket: &std::path::Path,
    username: &str,
    password: &str,
    rule_set: &str,
    rules: &str,
) -> Result<Value, StatusCode> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    #[derive(Serialize)]
    struct Request<'a> {
        username: &'a str,
        password: &'a str,
        rule_set: &'a str,
        rules: &'a str,
    }
    // Serialized straight into a buffer that is wiped when dropped, so no
    // copy of the password lingers in a JSON value.
    let request = zeroize::Zeroizing::new(
        serde_json::to_vec(&Request {
            username,
            password,
            rule_set,
            rules,
        })
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
    );
    if request.len() > SIGNER_MAX_REQUEST {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }
    let exchange = async {
        let mut stream = tokio::net::UnixStream::connect(socket).await?;
        stream.write_all(&request).await?;
        stream.shutdown().await?;
        let mut answer = Vec::new();
        stream.take(4 << 20).read_to_end(&mut answer).await?;
        Ok::<_, std::io::Error>(answer)
    };
    let answer = tokio::time::timeout(SIGNER_TIMEOUT, exchange)
        .await
        .map_err(|_| StatusCode::GATEWAY_TIMEOUT)?
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    serde_json::from_slice(&answer).map_err(|_| StatusCode::BAD_GATEWAY)
}

/// What a signer refusal means to the person publishing.
fn refusal(code: &str) -> Response {
    let (status, code, title) = match code {
        "credentials" => (StatusCode::FORBIDDEN, "wrong_password", "Wrong password"),
        "throttled" => (
            StatusCode::TOO_MANY_REQUESTS,
            "account_locked",
            "Too many wrong passwords; try again in 15 minutes",
        ),
        "forbidden" => (
            StatusCode::FORBIDDEN,
            "publish_not_allowed",
            "This account may not publish rules, or must change its password first",
        ),
        "limits" => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "over_limit",
            "Over a limit: too many rules, or an alarm rule naming too many programs",
        ),
        "invalid" => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "rule_set_refused",
            "The signer refused the rule set",
        ),
        "rate" => (
            StatusCode::TOO_MANY_REQUESTS,
            "publish_rate",
            "The hourly publish limit is reached; try again later",
        ),
        _ => (
            StatusCode::SERVICE_UNAVAILABLE,
            "signer_unavailable",
            "The rule signer cannot sign right now; see its journal",
        ),
    };
    problem_response(ProblemDetails::new(status, code, title))
}

#[utoipa::path(post, path = "/api/v1/rule-drafts/{rule_set_id}/publish", tag = "rules", params(("rule_set_id" = String, Path)),
    request_body = crate::rule_drafts::PublishDraftsRequest,
    responses((status = 201, description = "Signed by the rule signer and published", body = crate::rule_drafts::PublishedDrafts),
        (status = 403, description = "Wrong password, or the account may not publish", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "No drafts, or nothing changed", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "The signer refused the rule set", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 429, description = "Locked out or over the hourly limit", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "The rule signer cannot be reached", body = crate::ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn publish_drafts(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path(rule_set_id): Path<String>,
    payload: Result<Json<PublishDraftsRequest>, JsonRejection>,
) -> Response {
    // Writing drafts and publishing are separate permissions: publishing
    // needs `rules.upload`, and the signer checks it again itself.
    let (scope, actor) =
        match authenticated_permission(&state, &headers, Permission::RulesUpload, true).await {
            Ok(context) => context,
            Err(response) => return response,
        };
    if !matches!(scope, platform_store::console_read::AgentScope::Global) {
        return global_only();
    }
    if !known_set(&rule_set_id) {
        return unknown_set();
    }
    let Ok(Json(request)) = payload else {
        return problem_response(ProblemDetails::new(
            StatusCode::BAD_REQUEST,
            "password_required",
            "Type your password to publish",
        ));
    };
    let password = zeroize::Zeroizing::new(request.password);
    let Ok(mut client) = state.pool.get().await else {
        return unavailable_auth();
    };
    let (Ok(drafts), Ok(published)) = (
        store::list(&client, &rule_set_id).await,
        published_rules(&client, &rule_set_id).await,
    ) else {
        return unavailable_auth();
    };
    let Ok(rules) = draft_rules(&drafts) else {
        return unavailable_auth();
    };
    if rules.is_empty() {
        return problem_response(ProblemDetails::new(
            StatusCode::CONFLICT,
            "no_rules",
            "Write at least one rule before publishing",
        ));
    }
    let diff = changes(published.as_ref(), &rules);
    if diff.added.is_empty() && diff.changed.is_empty() && diff.removed.is_empty() {
        return problem_response(ProblemDetails::new(
            StatusCode::CONFLICT,
            "nothing_changed",
            "The drafts match what is published",
        ));
    }
    let Ok(username) = client
        .query_opt(
            "SELECT username FROM console_users WHERE user_id::text = $1",
            &[&actor],
        )
        .await
        .map(|row| row.map(|row| row.get::<_, String>(0)))
    else {
        return unavailable_auth();
    };
    let Some(username) = username else {
        return global_only();
    };
    let Ok(set_json) = serde_json::to_string(&RuleSet {
        schema_version: SchemaVersion::V1,
        rules: rules.clone(),
    }) else {
        return unavailable_auth();
    };
    let answer = match ask_signer(
        &state.signer_socket,
        &username,
        &password,
        &rule_set_id,
        &set_json,
    )
    .await
    {
        Ok(answer) => answer,
        Err(StatusCode::PAYLOAD_TOO_LARGE) => return refusal("limits"),
        Err(_) => return refusal("unavailable"),
    };
    if answer["result"] != "signed" {
        return refusal(answer["code"].as_str().unwrap_or("unavailable"));
    }
    let Some(envelope_text) = answer["envelope"].as_str() else {
        return refusal("unavailable");
    };
    // What the signer returned is trusted like any uploaded envelope: it
    // must verify against the keys the platform trusts for the set.
    let bytes = envelope_text.as_bytes();
    let (envelope, hash) = match crate::router::verify_console_rule_envelope(&client, bytes).await {
        Ok(value) => value,
        Err(()) => {
            return problem_response(ProblemDetails::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "invalid_signed_envelope",
                "The signer's bundle does not verify against the keys trusted for this set; run Setup's Repair",
            ));
        }
    };
    let Ok(version) = i64::try_from(envelope.rule_set_version) else {
        return refusal("unavailable");
    };
    let bundle = platform_store::rules::NewBundle {
        rule_set_id: &rule_set_id,
        version,
        envelope: bytes,
        envelope_sha256: hash,
        issuer_key_id: envelope.issuer_key_id.as_str(),
        created_at_ms: envelope.created_at_unix_ms,
        expires_at_ms: envelope.expires_at_unix_ms,
        published_by: &actor,
    };
    match platform_store::rules::publish_and_audit(&mut client, &bundle, &actor).await {
        Ok(platform_store::rules::Published::Stored) => (
            StatusCode::CREATED,
            Json(PublishedDrafts {
                rule_set_id,
                version,
                expires_at_ms: envelope.expires_at_unix_ms,
                rules: rules.len(),
            }),
        )
            .into_response(),
        Ok(_) => problem_response(ProblemDetails::new(
            StatusCode::CONFLICT,
            "stale_version",
            "Another publish got there first; reload and try again",
        )),
        Err(_) => unavailable_auth(),
    }
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
        }
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
