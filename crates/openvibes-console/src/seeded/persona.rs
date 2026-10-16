//! Who the demo caller is and what state the demo is in, chosen by request
//! headers, and the permission check every handler runs.

use axum::{http::HeaderMap, response::Response};
use serde::Deserialize;

use super::responses::{SeedError, denied, expired, invalid_header, unavailable};
use crate::{BuiltInRole, Permission, RoleBinding, resolve_capabilities};

#[derive(Clone, Copy, Debug, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum SeedMode {
    #[default]
    Mixed,
    Empty,
    Large,
    Stale,
    PartialFailure,
    ExpiredSession,
    PermissionRemoved,
}

impl SeedMode {
    fn parse(headers: &HeaderMap) -> Result<Self, SeedError> {
        let Some(value) = headers.get("x-openvibes-dev-mode") else {
            return Ok(Self::Mixed);
        };
        value
            .to_str()
            .ok()
            .and_then(|value| {
                serde_json::from_value(serde_json::Value::String(value.to_owned())).ok()
            })
            .ok_or_else(|| invalid_header("x-openvibes-dev-mode"))
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Persona {
    Viewer,
    #[default]
    Analyst,
    Operator,
    ScopedOperator,
    Admin,
}

impl Persona {
    fn parse(headers: &HeaderMap) -> Result<Self, SeedError> {
        let Some(value) = headers.get("x-openvibes-dev-persona") else {
            return Ok(Self::Analyst);
        };
        value
            .to_str()
            .ok()
            .and_then(|value| {
                serde_json::from_value(serde_json::Value::String(value.to_owned())).ok()
            })
            .ok_or_else(|| invalid_header("x-openvibes-dev-persona"))
    }

    fn permits(self, permission: Permission, mode: SeedMode) -> bool {
        if matches!(mode, SeedMode::PermissionRemoved) && permission == Permission::HostsRead {
            return false;
        }
        resolve_capabilities(&[self.binding()])
            .iter()
            .any(|capability| capability.permission == permission)
    }

    pub(super) fn global_scope(self) -> bool {
        !matches!(self, Self::ScopedOperator)
    }

    fn binding(self) -> RoleBinding {
        let role = match self {
            Self::Viewer => BuiltInRole::Viewer,
            Self::Analyst => BuiltInRole::Analyst,
            Self::Operator | Self::ScopedOperator => BuiltInRole::Operator,
            Self::Admin => BuiltInRole::Admin,
        };
        if self.global_scope() {
            RoleBinding::global(role)
        } else {
            RoleBinding::scoped(role, ["seeded-asset-group".to_owned()])
                .expect("the seeded asset-group ID is nonempty")
        }
    }
}

pub(super) fn context(
    headers: &HeaderMap,
    permission: Permission,
) -> Result<(Persona, SeedMode), SeedError> {
    let persona = Persona::parse(headers)?;
    let mode = SeedMode::parse(headers)?;
    if matches!(mode, SeedMode::ExpiredSession) {
        return Err(Box::new(expired()));
    }
    if !persona.permits(permission, mode) {
        return Err(Box::new(denied()));
    }
    Ok((persona, mode))
}

pub(super) fn read_error(mode: SeedMode) -> Option<Response> {
    matches!(mode, SeedMode::PartialFailure).then(unavailable)
}

#[cfg(test)]
mod tests {
    use super::{Persona, SeedMode};
    use crate::Permission;

    #[test]
    fn seeded_personas_use_the_approved_builtin_role_permissions() {
        assert!(!Persona::Viewer.permits(Permission::RulesRead, SeedMode::Mixed));
        assert!(!Persona::Analyst.permits(Permission::RulesRead, SeedMode::Mixed));
        assert!(Persona::Operator.permits(Permission::RulesRead, SeedMode::Mixed));
        assert!(Persona::Admin.permits(Permission::RulesRead, SeedMode::Mixed));
        assert!(Persona::Operator.permits(Permission::RulesPublish, SeedMode::Mixed));
        assert!(Persona::Operator.permits(Permission::TokensManage, SeedMode::Mixed));
        assert!(Persona::Viewer.permits(Permission::VulnerabilitiesRead, SeedMode::Mixed));
        assert!(Persona::Analyst.permits(Permission::VulnerabilitiesRead, SeedMode::Mixed));
        assert!(Persona::Operator.permits(Permission::VulnerabilitiesRead, SeedMode::Mixed));
        assert!(Persona::Admin.permits(Permission::VulnerabilitiesRead, SeedMode::Mixed));
        assert!(Persona::Analyst.permits(Permission::AssistantUse, SeedMode::Mixed));
        assert!(Persona::Admin.permits(Permission::AssistantUse, SeedMode::Mixed));
        assert!(!Persona::Viewer.permits(Permission::AssistantUse, SeedMode::Mixed));
        assert!(!Persona::Operator.permits(Permission::AssistantUse, SeedMode::Mixed));
        assert!(!Persona::Operator.permits(Permission::ComplianceTriage, SeedMode::Mixed));
        assert!(Persona::ScopedOperator.permits(Permission::HostsRevoke, SeedMode::Mixed));
        assert!(!Persona::ScopedOperator.permits(Permission::TokensManage, SeedMode::Mixed));
        assert!(!Persona::ScopedOperator.permits(Permission::ComplianceTriage, SeedMode::Mixed));
        assert!(Persona::Admin.permits(Permission::AuditRetentionManage, SeedMode::Mixed));
    }
}
