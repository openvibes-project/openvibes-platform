//! The demo's access inventory.

use axum::{
    Json,
    http::HeaderMap,
    response::{IntoResponse, Response},
};

use super::{
    persona::{Persona, context, read_error},
    repository::GENERATED_AT,
};
use crate::Permission;

pub(super) async fn access_inventory(headers: HeaderMap) -> Response {
    let (persona, mode) = match context(&headers, Permission::AccessRead) {
        Ok(context) => context,
        Err(response) => return *response,
    };
    if let Some(response) = read_error(mode) {
        return response;
    }
    // The Administrator and the personas' roles (see `persona.rs`).
    let mut roles = vec![serde_json::json!({
        "role_id": crate::access::rbac::ADMIN_ROLE, "display_name": "Administrator", "builtin": true,
        "permissions": Permission::ALL.map(Permission::id).to_vec()
    })];
    roles.extend(crate::access::templates::TEMPLATES[..3].iter().map(|template| {
        serde_json::json!({
            "role_id": template.name.to_lowercase(), "display_name": template.name, "builtin": false,
            "permissions": template.permissions.iter().map(|p| p.id()).collect::<Vec<_>>()
        })
    }));
    let bindings = if matches!(persona, Persona::Admin) {
        vec![serde_json::json!({
            "binding_id": "seeded-admin-binding", "user_id": "seeded-admin", "username": "admin",
            "display_name": "Seeded administrator", "role_id": "admin", "asset_group_id": null,
            "asset_group_name": null, "created_at": GENERATED_AT, "created_by": "bootstrap"
        })]
    } else {
        Vec::new()
    };
    let users = if matches!(persona, Persona::Admin) {
        vec![serde_json::json!({
            "user_id": "seeded-admin", "username": "admin", "display_name": "Seeded administrator"
        })]
    } else {
        Vec::new()
    };
    Json(serde_json::json!({ "roles": roles, "bindings": bindings, "asset_groups": [], "users": users }))
        .into_response()
}
