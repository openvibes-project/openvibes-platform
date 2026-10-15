//! The agent install package and command.

use axum::{
    extract::{Json, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use zeroize::Zeroizing;

use crate::{
    access::guard::{authenticated_permission, unavailable_auth},
    http::{
        AuthHttpState,
        problem::{ProblemDetails, problem_response},
    },
    router::no_store,
};

/// What the platform serves for rule set `set`: its trust line, only when a
/// current, non-retired bundle is signed by a key the set trusts, so agents
/// are never told to fetch what they cannot verify.
async fn served_rule_trust(
    client: &platform_store::Client,
    set: &str,
) -> Option<crate::hosts::agent_package::RuleTrust> {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use platform_store::rules;
    rules::list(client).await.ok()?.into_iter().find(|row| {
        row.rule_set_id == set && row.current_version.is_some() && row.retired_at.is_none()
    })?;
    let issuer = rules::bundles(client, set)
        .await
        .ok()?
        .into_iter()
        .next()?
        .issuer_key_id;
    let (key, _) = rules::active_trust_keys(client, set)
        .await
        .ok()?
        .into_iter()
        .find(|(_, id)| *id == issuer)?;
    Some(crate::hosts::agent_package::RuleTrust {
        set: set.to_owned(),
        issuer,
        key: URL_SAFE_NO_PAD.encode(key),
    })
}

/// The agent install spec for a global `tokens.create` caller, built into
/// `T` by `build`, the hand-out audited as `action`. The package and the
/// command both carry the standing token.
async fn with_install_spec<T>(
    state: &AuthHttpState,
    headers: &HeaderMap,
    action: &str,
    build: impl FnOnce(
        &crate::hosts::agent_package::PackageSpec<'_>,
    ) -> Result<T, crate::hosts::agent_package::PackageError>,
) -> Result<T, Response> {
    use platform_store::console_read::AgentScope;
    let (scope, actor) =
        authenticated_permission(state, headers, crate::Permission::TokensCreate, false).await?;
    if !matches!(scope, AgentScope::Global) {
        return Err(problem_response(ProblemDetails::new(
            StatusCode::FORBIDDEN,
            "permission_denied",
            "Access is not available",
        )));
    }
    let Some(config) = state.agent_install.as_deref() else {
        return Err(problem_response(ProblemDetails::not_found(
            "agent_package_not_configured",
            "Set agent_install in console.toml to offer the agent install package",
        )));
    };
    let Ok(root_cert) = std::fs::read_to_string(&config.root_cert_file) else {
        return Err(unavailable_auth());
    };
    let client = state.pool.get().await.map_err(|_| unavailable_auth())?;
    let token = match platform_store::tokens::live_standing(&client).await {
        Ok(Some((_, secret))) => Zeroizing::new(secret),
        Ok(None) => {
            return Err(problem_response(ProblemDetails::not_found(
                "no_standing_token",
                "There is no standing enrollment token; create one with `openvibes-admin token fleet`",
            )));
        }
        Err(_) => return Err(unavailable_auth()),
    };
    let rules = served_rule_trust(&client, "baseline").await;
    let alarm_rules = match rules {
        Some(_) => served_rule_trust(&client, "baseline-alarms").await,
        None => None,
    };
    let built = build(&crate::hosts::agent_package::PackageSpec {
        platform: &config.platform,
        ingest_port: config.ingest_port,
        distribution_port: config.distribution_port,
        root_cert_pem: &root_cert,
        rules,
        alarm_rules,
        token: &token,
    })
    .map_err(|_| unavailable_auth())?;
    platform_store::audit::record(&client, &actor, action, Some("agent_package"), "success")
        .await
        .map_err(|_| unavailable_auth())?;
    Ok(built)
}

/// Downloads the agent install package: one script that installs and enrolls
/// an agent, the same on every host, carrying the standing fleet token.
#[utoipa::path(get,path="/api/v1/agent-package",tag="enrollment",responses((status=200,description="Install script (text/x-shellscript) carrying the standing fleet token",content_type="text/x-shellscript"),(status=404,description="The package is not configured or there is no standing token",body=ProblemDetails)))]
pub(crate) async fn authenticated_agent_package(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
) -> Response {
    let script = match with_install_spec(
        &state,
        &headers,
        "agent_package.downloaded",
        crate::hosts::agent_package::render,
    )
    .await
    {
        Ok(script) => script,
        Err(response) => return response,
    };
    let mut response = script.into_response();
    let response_headers = response.headers_mut();
    response_headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/x-shellscript; charset=utf-8"),
    );
    response_headers.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_static("attachment; filename=\"openvibes-agent-install.sh\""),
    );
    no_store(response)
}

/// The one-line agent install command to copy (install walkthrough,
/// 2026-10-08): what `openvibes-admin agent command` prints.
#[utoipa::path(get,path="/api/v1/agent-command",tag="enrollment",responses((status=200,description="The install command, carrying the standing fleet token",body=crate::AgentCommandView),(status=404,description="The package is not configured or there is no standing token",body=ProblemDetails)))]
pub(crate) async fn authenticated_agent_command(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
) -> Response {
    match with_install_spec(
        &state,
        &headers,
        "agent_command.viewed",
        crate::hosts::agent_package::command,
    )
    .await
    {
        Ok(command) => no_store(Json(crate::AgentCommandView { command }).into_response()),
        Err(response) => response,
    }
}
