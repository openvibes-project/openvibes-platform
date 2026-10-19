//! The demo's roles and people.

use axum::{
    Json,
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use serde_json::{Value, json};

use super::{
    persona::{Persona, context, read_error},
    repository::GENERATED_AT,
};
use crate::Permission;

/// The Administrator and the personas' roles (see `persona.rs`).
fn roles() -> Vec<Value> {
    let mut roles = vec![json!({
        "role_id": crate::access::rbac::ADMIN_ROLE, "name": "Administrator", "description": "",
        "builtin": true, "permissions": Permission::ALL.map(Permission::id).to_vec(),
        "reach": {"kind": "all"}, "members": 1, "version": 1
    })];
    roles.extend(crate::access::templates::TEMPLATES[..3].iter().map(|template| {
        json!({
            "role_id": template.name.to_lowercase(), "name": template.name, "description": "",
            "builtin": false,
            "permissions": template.permissions.iter().map(|p| p.id()).collect::<Vec<_>>(),
            "reach": {"kind": "all"}, "members": 0, "version": 1
        })
    }));
    roles
}

pub(super) async fn list_roles(headers: HeaderMap) -> Response {
    let mode = match context(&headers, Permission::AccessRead) {
        Ok((_, mode)) => mode,
        Err(response) => return *response,
    };
    if let Some(response) = read_error(mode) {
        return response;
    }
    Json(roles()).into_response()
}

pub(super) async fn list_people(headers: HeaderMap) -> Response {
    let (persona, mode) = match context(&headers, Permission::AccessRead) {
        Ok(context) => context,
        Err(response) => return *response,
    };
    if let Some(response) = read_error(mode) {
        return response;
    }
    // Only the Administrator's share holds the Administrator.
    let people = if matches!(persona, Persona::Admin) {
        vec![json!({
            "user_id": "seeded-admin", "username": "admin", "display_name": "Seeded administrator",
            "email": null, "enabled": true, "auth_source": "password",
            "last_sign_in_at": GENERATED_AT, "roles": [roles()[0]]
        })]
    } else {
        Vec::new()
    };
    Json(people).into_response()
}
