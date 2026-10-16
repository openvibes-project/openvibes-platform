//! Who the demo caller is and what state the demo is in, chosen by request
//! headers, and the permission check every handler runs.

use axum::{http::HeaderMap, response::Response};
use serde::Deserialize;

use super::responses::{SeedError, denied, expired, invalid_header, unavailable};
use platform_store::console_roles::{Grant, Reach};

use crate::{
    Permission,
    access::{rbac::ADMIN_ROLE, templates::TEMPLATES},
    resolve_capabilities,
};

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
        resolve_capabilities(&[self.grant()])
            .iter()
            .any(|capability| capability.permission == permission)
    }

    pub(super) fn global_scope(self) -> bool {
        !matches!(self, Self::ScopedOperator)
    }

    /// The persona's one role: its template (the Administrator for admin),
    /// reaching every host, or the Prod group for the scoped operator.
    fn grant(self) -> Grant {
        let template = |name: &str| {
            let template = TEMPLATES
                .iter()
                .find(|t| t.name == name)
                .expect("a template");
            template
                .permissions
                .iter()
                .map(|p| p.id().to_owned())
                .collect()
        };
        let (role_id, permissions) = match self {
            Self::Viewer => ("viewer", template("Viewer")),
            Self::Analyst => ("analyst", template("Analyst")),
            Self::Operator | Self::ScopedOperator => ("operator", template("Operator")),
            Self::Admin => (ADMIN_ROLE, Vec::new()),
        };
        let reach = if self.global_scope() {
            Reach::All
        } else {
            Reach::Groups(vec!["seeded-asset-group".to_owned()])
        };
        Grant {
            role_id: role_id.to_owned(),
            permissions,
            reach,
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
    fn seeded_personas_hold_the_templates() {
        // The Viewer and Analyst templates read rules (spec §4.2).
        assert!(Persona::Viewer.permits(Permission::RulesRead, SeedMode::Mixed));
        assert!(!Persona::Viewer.permits(Permission::RulesPublish, SeedMode::Mixed));
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
        // A role's platform permissions apply whatever its reach (spec §3).
        assert!(Persona::ScopedOperator.permits(Permission::TokensManage, SeedMode::Mixed));
        assert!(!Persona::ScopedOperator.permits(Permission::ComplianceTriage, SeedMode::Mixed));
        assert!(Persona::Admin.permits(Permission::AuditRetentionManage, SeedMode::Mixed));
    }
}
