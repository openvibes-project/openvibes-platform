use openvibes_console::{
    AuthenticationLevel, AuthenticationMethod, CursorPage, CursorPagination, EffectiveCapability,
    Permission, PermissionScope, SessionPrincipal, SessionResponse, openapi_json,
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
