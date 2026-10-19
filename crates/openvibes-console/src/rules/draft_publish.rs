//! Publishing the site's draft rules: what would change, and the signer round
//! trip that signs and stores the bundle.

use axum::{
    Json,
    extract::{Path, State, rejection::JsonRejection},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use openvibes_core::{Rule, RuleSet, SchemaVersion};
use platform_store::rule_drafts::{self as store, Draft};
use serde::Serialize;
use serde_json::Value;

use super::draft_check::known_set;
use super::draft_types::{DraftChanges, PublishDraftsRequest, PublishedDrafts};
use super::drafts::{global_only, unknown_set};
use crate::{
    Permission, ProblemDetails,
    access::guard::{authenticated_permission, unavailable_auth},
    http::AuthHttpState,
    http::problem::problem_response,
};

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
    responses((status = 200, description = "What publishing the drafts would change", body = crate::rules::DraftChanges),
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
    request_body = crate::rules::PublishDraftsRequest,
    responses((status = 201, description = "Signed by the rule signer and published", body = crate::rules::PublishedDrafts),
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
    let (envelope, hash) = match super::envelope::verify_console_rule_envelope(&client, bytes).await
    {
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
