//! `GET /v1/settings` and `PATCH /v1/settings/{key}`; both need `settings.manage`.

use axum::{
    extract::{Json, Path, State, rejection::JsonRejection},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use chrono::Utc;
use platform_store::console_settings::{self as store, SecretInfo, StoredSetting};

use super::types::{SettingChangeView, SettingView, SettingsView, UpdateSetting};
use crate::Permission;
use crate::access::editor::caller;
use crate::access::guard::unavailable_auth;
use crate::http::{
    AuthHttpState,
    problem::{FieldError, ProblemDetails, problem_response},
};
use platform_settings::{Applies, Definition, Kind, all, find};

/// A secret's row says only that it is set, when and by whom.
fn view(
    def: &Definition,
    stored: Option<&StoredSetting>,
    secret: Option<&SecretInfo>,
) -> SettingView {
    let (min, max) = match def.kind {
        Kind::Int { min, max, .. } => (Some(min), Some(max)),
        _ => (None, None),
    };
    let applies = match def.applies {
        Applies::Live => "live",
        Applies::Restart => "restart",
    };
    let (changed_at, changed_by) = match (stored, secret) {
        (Some(s), _) => (Some(s.changed_at.to_rfc3339()), Some(s.changed_by.clone())),
        (None, Some(s)) => (Some(s.changed_at.to_rfc3339()), Some(s.changed_by.clone())),
        (None, None) => (None, None),
    };
    SettingView {
        key: def.key.into(),
        section: def.section.into(),
        label: def.label.into(),
        help: def.help.into(),
        kind: def.kind_name().into(),
        applies: applies.into(),
        min,
        max,
        options: def
            .options()
            .map(|words| words.iter().map(|word| (*word).into()).collect()),
        default: def.default_value(),
        value: stored.map_or_else(|| def.default_value(), |s| s.value.clone()),
        is_set: def.is_secret().then_some(secret.is_some()),
        changed_at,
        changed_by,
    }
}

/// Every general setting with its value, and the last five changes.
#[utoipa::path(get, path = "/api/v1/settings", tag = "settings",
    responses((status = 200, description = "Settings", body = SettingsView),
        (status = 403, description = "Needs settings.manage", body = ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn list_settings(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
) -> Response {
    let editor = match caller(&state, &headers, false).await {
        Ok(editor) => editor,
        Err(response) => return response,
    };
    if let Some(response) = editor.denied(Permission::SettingsManage) {
        return response;
    }
    let Ok(client) = state.pool.get().await else {
        return unavailable_auth();
    };
    let (Ok(stored), Ok(secrets), Ok(recent)) = (
        store::all(&client).await,
        store::secrets_set(&client).await,
        store::recent(&client, 5).await,
    ) else {
        return unavailable_auth();
    };
    let items = all()
        .map(|def| {
            view(
                def,
                stored.iter().find(|s| s.key == def.key),
                secrets.iter().find(|s| s.key == def.key),
            )
        })
        .collect();
    let recent = recent
        .into_iter()
        .map(|line| SettingChangeView {
            at: line.at.to_rfc3339(),
            actor: line.actor,
            key: line.detail["key"].as_str().unwrap_or_default().into(),
            old: line.detail["old"].clone(),
            new: line.detail["new"].clone(),
        })
        .collect();
    Json(SettingsView { items, recent }).into_response()
}

/// Sets one setting; the change is recorded in the audit log.
#[utoipa::path(patch, path = "/api/v1/settings/{key}", tag = "settings",
    params(("key" = String, Path)), request_body = UpdateSetting,
    responses((status = 200, description = "Saved", body = SettingView),
        (status = 403, description = "Needs settings.manage", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "setting_not_found", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "invalid_setting: wrong type or out of range", body = ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn update_setting(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path(key): Path<String>,
    payload: Result<Json<UpdateSetting>, JsonRejection>,
) -> Response {
    let editor = match caller(&state, &headers, true).await {
        Ok(editor) => editor,
        Err(response) => return response,
    };
    if let Some(response) = editor.denied(Permission::SettingsManage) {
        return response;
    }
    let Some(def) = find(&key) else {
        return problem_response(ProblemDetails::new(
            StatusCode::NOT_FOUND,
            "setting_not_found",
            "No such setting",
        ));
    };
    let Ok(Json(request)) = payload else {
        return invalid("The request body is invalid");
    };
    let Ok(mut client) = state.pool.get().await else {
        return unavailable_auth();
    };
    let now = Utc::now();
    // Null puts the setting back to its default; a secret is removed.
    let mut request = request;
    if def.is_secret()
        && let Some(text) = request.value.as_str()
    {
        // A pasted key often carries a trailing newline.
        request.value = text.trim().into();
    }
    let reset = request.value.is_null();
    if !reset && let Err(message) = def.check(&request.value) {
        return invalid(&message);
    }
    if def.is_secret() {
        let text = request.value.as_str();
        if store::set_secret(&mut client, def.key, text, &editor.actor, now)
            .await
            .is_err()
        {
            return unavailable_auth();
        }
        let secret = text.map(|_| SecretInfo {
            key: key.clone(),
            changed_at: now,
            changed_by: editor.actor.clone(),
        });
        return Json(view(def, None, secret.as_ref())).into_response();
    }
    if reset {
        if store::reset(&mut client, def.key, &editor.actor, now)
            .await
            .is_err()
        {
            return unavailable_auth();
        }
        return Json(view(def, None, None)).into_response();
    }
    if store::set(&mut client, def.key, &request.value, &editor.actor, now)
        .await
        .is_err()
    {
        return unavailable_auth();
    }
    let stored = StoredSetting {
        key: key.clone(),
        value: request.value,
        changed_at: now,
        changed_by: editor.actor.clone(),
    };
    Json(view(def, Some(&stored), None)).into_response()
}

fn invalid(message: &str) -> Response {
    let mut problem = ProblemDetails::new(
        StatusCode::UNPROCESSABLE_ENTITY,
        "invalid_setting",
        "The setting value is invalid",
    );
    problem.field_errors = Some(vec![FieldError {
        field: "value".into(),
        code: "invalid".into(),
        message: message.into(),
    }]);
    problem_response(problem)
}
