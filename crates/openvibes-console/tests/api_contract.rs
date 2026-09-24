use openvibes_console::{
    AgentPage, AgentStatus, AgentView, AuthenticationLevel, AuthenticationMethod, CursorPage,
    CursorPagination, EffectiveCapability, FindingOrigin, FindingPage, FindingView, Permission,
    PermissionScope, SessionPrincipal, SessionResponse, Severity, openapi_json,
};

const SNAPSHOT: &str = include_str!("../../../docs/api/console-v1.openapi.json");

#[test]
fn generated_openapi_matches_the_committed_snapshot() {
    assert_eq!(openapi_json().unwrap(), SNAPSHOT);
}

#[test]
fn pagination_query_is_closed_and_bounded() {
    let default: CursorPagination = serde_json::from_str("{}").unwrap();
    assert_eq!(default.limit(), 50);
    assert!(serde_json::from_str::<CursorPagination>(r#"{"extra":true}"#).is_err());
    assert!(serde_json::from_str::<CursorPagination>(r#"{"limit":101}"#).is_err());
}

#[test]
fn session_and_page_dtos_have_stable_wire_names() {
    let session = SessionResponse {
        principal: SessionPrincipal {
            id: "user-1".to_owned(),
            display_name: "Console Admin".to_owned(),
            username: None,
        },
        authentication_method: AuthenticationMethod::LocalPassword,
        authentication_level: AuthenticationLevel::SingleFactor,
        capabilities: vec![EffectiveCapability {
            permission: Permission::AgentsRead,
            scope: PermissionScope::AssetGroups {
                asset_group_ids: vec!["group-1".to_owned()],
            },
        }],
        csrf_token: "x".repeat(32),
        idle_expires_at: "2026-09-23T12:30:00Z".to_owned(),
        absolute_expires_at: "2026-09-23T20:00:00Z".to_owned(),
    };
    let session = serde_json::to_value(session).unwrap();
    assert_eq!(session["authentication_method"], "local_password");
    assert_eq!(session["authentication_level"], "single_factor");
    assert_eq!(session["capabilities"][0]["permission"], "agents.read");
    assert_eq!(session["capabilities"][0]["scope"]["kind"], "asset_groups");
    assert!(session["principal"].get("username").is_none());

    let page = CursorPage {
        items: vec!["agent-1"],
        next_cursor: Some("opaque".to_owned()),
        generated_at: "2026-09-23T12:00:00Z".to_owned(),
    };
    assert_eq!(
        serde_json::to_value(page).unwrap(),
        serde_json::json!({
            "items": ["agent-1"],
            "next_cursor": "opaque",
            "generated_at": "2026-09-23T12:00:00Z"
        })
    );
}

#[test]
fn read_model_dtos_have_stable_wire_names() {
    let agent = AgentView {
        id: "agent-1".to_owned(),
        hostname: Some("host.example.test".to_owned()),
        status: AgentStatus::Stale,
        enrolled_at: "2026-09-01T00:00:00Z".to_owned(),
        revoked_at: None,
        last_seen_at: Some("2026-09-23T12:00:00Z".to_owned()),
        scanner_version: Some("0.4.0".to_owned()),
        capabilities: vec!["findings".to_owned()],
    };
    let agent_page = AgentPage {
        items: vec![agent],
        next_cursor: None,
        generated_at: "2026-09-23T12:00:00Z".to_owned(),
    };
    let agent_page = serde_json::to_value(agent_page).unwrap();
    assert_eq!(agent_page["items"][0]["status"], "stale");
    assert_eq!(agent_page["items"][0]["hostname"], "host.example.test");
    assert!(agent_page["next_cursor"].is_null());

    let finding_page = FindingPage {
        items: vec![FindingView {
            id: "finding-1".to_owned(),
            agent_id: "agent-1".to_owned(),
            hostname: Some("host.example.test".to_owned()),
            rule_set_id: "baseline".to_owned(),
            rule_id: "OV-001".to_owned(),
            rule_version: 3,
            severity: Severity::Critical,
            confidence: 95,
            message: "Synthetic observation".to_owned(),
            evidence: vec!["process.name=sshd".to_owned()],
            scan_id: "scan-1".to_owned(),
            authenticated: true,
            origin: FindingOrigin::Online,
            first_observed_at: "2026-09-23T11:00:00Z".to_owned(),
            last_observed_at: "2026-09-23T12:00:00Z".to_owned(),
            received_at: "2026-09-23T12:00:01Z".to_owned(),
        }],
        next_cursor: Some("opaque".to_owned()),
        generated_at: "2026-09-23T12:00:00Z".to_owned(),
    };
    let finding_page = serde_json::to_value(finding_page).unwrap();
    assert_eq!(finding_page["items"][0]["severity"], "critical");
    assert_eq!(finding_page["items"][0]["rule_set_id"], "baseline");
    assert_eq!(finding_page["items"][0]["origin"], "online");
    assert_eq!(finding_page["items"][0]["confidence"], 95);
    assert_eq!(finding_page["items"][0]["authenticated"], true);
    assert_eq!(finding_page["next_cursor"], "opaque");
}
