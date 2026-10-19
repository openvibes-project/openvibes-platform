//! The host-group API (spec §5.1, §13): create, edit, preview and delete
//! rule and manual groups, who may change them, and counts in reach.

use axum::http::StatusCode;
use openvibes_console::authenticated_router;
use platform_store::console_roles::Reach;
use serde_json::{Value, json};

mod common;
use common::http::{Session, TestDb, call, sign_in};

const W1: &str = "agent.00000000-0000-4000-8000-0000000000a1";
const W2: &str = "agent.00000000-0000-4000-8000-0000000000a2";
const L1: &str = "agent.00000000-0000-4000-8000-0000000000b1";

struct Fx {
    db: TestDb,
    router: axum::Router,
    admin: Session,
    /// Manual group "WindowsServers" holding W1 and W2.
    win: String,
}

impl Fx {
    async fn new() -> Option<Self> {
        let db = TestDb::create("hostgroups").await?;
        db.user("alice", "admin", 1).await;
        let client = db.pool.get().await.unwrap();
        client
            .batch_execute(&format!(
                "INSERT INTO agents (agent_id, status, enrolled_at, hostname, last_seen_at) VALUES
                    ('{W1}', 'active', now(), 'win-01', now()),
                    ('{W2}', 'active', now(), 'win-02-test', now()),
                    ('{L1}', 'active', now(), 'lin-01', now())"
            ))
            .await
            .unwrap();
        let win = common::manual_group(&client, "WindowsServers", &[W1, W2]).await;
        let router = authenticated_router(db.pool.clone(), common::http::ORIGIN);
        let admin = sign_in(&router, "alice").await;
        Some(Self {
            db,
            router,
            admin,
            win,
        })
    }

    async fn call(
        &self,
        who: &Session,
        method: &str,
        uri: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        call(&self.router, method, uri, who, body).await
    }

    /// Signs in a new user `name` holding a role with `permissions` on `reach`.
    async fn person(&self, name: &str, permissions: &[&str], reach: Reach, index: u8) -> Session {
        let mut client = self.db.pool.get().await.unwrap();
        let role = common::create_role(&mut client, name, permissions, reach).await;
        self.db.user(name, &role, index).await;
        sign_in(&self.router, name).await
    }
}

fn hostname(negate: bool, values: &[&str]) -> Value {
    json!({"field": "hostname", "negate": negate, "values": values})
}

#[tokio::test]
async fn an_administrator_creates_edits_previews_and_deletes_rule_and_manual_groups() {
    let Some(fx) = Fx::new().await else { return };
    let a = &fx.admin;

    let rule = json!([hostname(false, &["win-*"])]);
    let (status, preview) = fx
        .call(
            a,
            "POST",
            "/api/v1/host-groups/preview",
            Some(json!({"conditions": rule})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{preview}");
    assert_eq!(preview["joins_total"], 2);
    assert_eq!(preview["leaves_total"], 0);

    let body = json!({"name": "Win hosts", "kind": "rule", "conditions": rule});
    let (status, created) = fx.call(a, "POST", "/api/v1/host-groups", Some(body)).await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    assert_eq!(created["kind"], "rule");
    assert_eq!(created["hosts"], 2);
    assert_eq!(created["membership"], "Hosts where hostname matches win-*");
    let id = created["asset_group_id"].as_str().unwrap().to_owned();
    let uri = format!("/api/v1/host-groups/{id}");

    let (status, list) = fx.call(a, "GET", "/api/v1/host-groups", None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        list.as_array()
            .unwrap()
            .iter()
            .any(|g| g["name"] == "Win hosts")
    );

    let (status, got) = fx.call(a, "GET", &uri, None).await;
    assert_eq!(status, StatusCode::OK, "{got}");
    assert_eq!(got["recent"][0]["action"], "host_group.created");
    let (status, hosts) = fx.call(a, "GET", &format!("{uri}/hosts"), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(hosts.as_array().unwrap().len(), 2);
    assert_eq!(hosts[0]["why"], "Matches the rule");

    let narrower = json!([hostname(false, &["win-*"]), hostname(true, &["*test*"])]);
    let (status, preview) = fx
        .call(
            a,
            "POST",
            &format!("{uri}/preview"),
            Some(json!({"conditions": narrower})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{preview}");
    assert_eq!(preview["leaves_total"], 1);
    assert_eq!(preview["leaves"][0]["agent_id"], W2);

    let edit = json!({"conditions": narrower, "version": 1});
    let (status, edited) = fx.call(a, "PATCH", &uri, Some(edit.clone())).await;
    assert_eq!(status, StatusCode::OK, "{edited}");
    assert_eq!(edited["hosts"], 1);
    assert_eq!(edited["name"], "Win hosts");
    assert_eq!(
        edited["membership"],
        "Hosts where hostname matches win-* and hostname does not match *test*"
    );
    let (status, stale) = fx.call(a, "PATCH", &uri, Some(edit)).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(stale["code"], "stale_group");

    let body = json!({"name": "Pilot", "kind": "manual", "agent_ids": [L1]});
    let (status, pilot) = fx.call(a, "POST", "/api/v1/host-groups", Some(body)).await;
    assert_eq!(status, StatusCode::CREATED, "{pilot}");
    assert_eq!(pilot["membership"], "1 host picked by hand");
    let pilot_uri = format!(
        "/api/v1/host-groups/{}",
        pilot["asset_group_id"].as_str().unwrap()
    );
    let rename = json!({"name": "Pilot hosts", "version": 1});
    let (status, renamed) = fx.call(a, "PATCH", &pilot_uri, Some(rename)).await;
    assert_eq!(status, StatusCode::OK, "{renamed}");
    assert_eq!(renamed["hosts"], 1, "a rename keeps the picked hosts");
    let body = json!({"name": "pilot HOSTS", "kind": "manual", "agent_ids": []});
    let (status, taken) = fx.call(a, "POST", "/api/v1/host-groups", Some(body)).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(taken["code"], "group_name_taken");
    let body = json!({"name": "Ghost", "kind": "manual", "agent_ids": ["agent.nope"]});
    let (status, unknown) = fx.call(a, "POST", "/api/v1/host-groups", Some(body)).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(unknown["code"], "unknown_host");

    let (status, preview) = fx
        .call(a, "POST", &format!("{pilot_uri}/preview"), Some(json!({})))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(preview["leaves_total"], 1);
    let (status, _) = fx
        .call(a, "DELETE", &format!("{pilot_uri}?version=2"), None)
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, gone) = fx.call(a, "GET", &pilot_uri, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(gone["code"], "group_not_found");
    let actions = fx.db.audit_actions().await;
    for action in [
        "host_group.created",
        "host_group.updated",
        "host_group.deleted",
    ] {
        assert!(actions.iter().any(|a| a == action), "{action}");
    }
    fx.db.drop().await;
}

#[tokio::test]
async fn changing_groups_needs_every_host() {
    let Some(fx) = Fx::new().await else { return };
    let perms = ["host_groups.manage", "access.read", "hosts.read"];
    let lead = fx
        .person("lead", &perms, Reach::Groups(vec![fx.win.clone()]), 2)
        .await;
    let uri = format!("/api/v1/host-groups/{}", fx.win);
    let body = json!({"name": "Mine", "kind": "manual", "agent_ids": [W1]});
    for (method, uri, body) in [
        ("POST", "/api/v1/host-groups".to_owned(), Some(body)),
        (
            "PATCH",
            uri.clone(),
            Some(json!({"name": "X", "version": 1})),
        ),
        ("DELETE", format!("{uri}?version=1"), None),
        ("POST", format!("{uri}/preview"), Some(json!({}))),
    ] {
        let (status, refused) = fx.call(&lead, method, &uri, body).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{method} {uri}");
        assert_eq!(
            refused["title"],
            "Changing host groups needs access to every host"
        );
    }
    let (status, _) = fx.call(&lead, "GET", "/api/v1/host-groups", None).await;
    assert_eq!(status, StatusCode::OK);
    let nobody = fx.person("nobody", &["alarms.read"], Reach::All, 3).await;
    let (status, _) = fx.call(&nobody, "GET", "/api/v1/host-groups", None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    fx.db.drop().await;
}

#[tokio::test]
async fn group_lists_count_only_hosts_in_reach() {
    let Some(fx) = Fx::new().await else { return };
    let client = fx.db.pool.get().await.unwrap();
    let one = common::manual_group(&client, "Just one", &[W1]).await;
    common::manual_group(&client, "Lin", &[L1]).await;
    let viewer = fx
        .person(
            "viewer",
            &["access.read", "hosts.read"],
            Reach::Groups(vec![one]),
            2,
        )
        .await;
    let count = |list: &Value, name: &str| {
        list.as_array()
            .unwrap()
            .iter()
            .find(|g| g["name"] == name)
            .map(|g| g["hosts"].clone())
            .unwrap()
    };
    let (_, all) = fx.call(&fx.admin, "GET", "/api/v1/host-groups", None).await;
    assert_eq!(count(&all, "WindowsServers"), 2);
    assert_eq!(count(&all, "Lin"), 1);
    let (status, mine) = fx.call(&viewer, "GET", "/api/v1/host-groups", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(count(&mine, "WindowsServers"), 1);
    assert_eq!(count(&mine, "Lin"), 0);
    let uri = format!("/api/v1/host-groups/{}/hosts", fx.win);
    let (status, hosts) = fx.call(&viewer, "GET", &uri, None).await;
    assert_eq!(status, StatusCode::OK);
    let ids: Vec<&str> = hosts
        .as_array()
        .unwrap()
        .iter()
        .map(|h| h["agent_id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, [W1]);
    fx.db.drop().await;
}

#[tokio::test]
async fn changing_membership_needs_every_reaching_roles_host_permissions() {
    let Some(fx) = Fx::new().await else { return };
    let mut client = fx.db.pool.get().await.unwrap();
    let on_win = Reach::Groups(vec![fx.win.clone()]);
    let revokers = ["hosts.read", "hosts.revoke"];
    let revokers = common::create_role(&mut client, "Win revokers", &revokers, on_win).await;
    let perms = ["host_groups.manage", "access.read", "hosts.read"];
    let manager = fx.person("manager", &perms, Reach::All, 2).await;
    platform_store::console_people::give_role(
        &mut client,
        platform_store::console_roles::Principal::User("11111111-1111-4111-8111-111111111102"),
        &revokers,
        "test",
        chrono::Utc::now(),
    )
    .await
    .unwrap();
    let uri = format!("/api/v1/host-groups/{}", fx.win);
    let widen = json!({"agent_ids": [W1, W2, L1], "version": 1});
    let (status, refused) = fx.call(&manager, "PATCH", &uri, Some(widen.clone())).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{refused}");
    assert_eq!(refused["code"], "permission_denied");
    assert!(
        refused["title"].as_str().unwrap().contains("outside it"),
        "{refused}"
    );
    let rename = json!({"name": "Windows servers", "version": 1});
    let (status, renamed) = fx.call(&manager, "PATCH", &uri, Some(rename)).await;
    assert_eq!(status, StatusCode::OK, "{renamed}");
    let widen = json!({"agent_ids": [W1, W2, L1], "version": 2});
    let (status, widened) = fx.call(&fx.admin, "PATCH", &uri, Some(widen)).await;
    assert_eq!(status, StatusCode::OK, "{widened}");
    assert_eq!(widened["hosts"], 3);
    fx.db.drop().await;
}

#[tokio::test]
async fn previews_name_only_people_inside_the_share() {
    let Some(fx) = Fx::new().await else { return };
    let mut client = fx.db.pool.get().await.unwrap();
    let on_win = || Reach::Groups(vec![fx.win.clone()]);
    let viewers = common::create_role(&mut client, "Win viewers", &["hosts.read"], on_win()).await;
    let revokers = ["hosts.read", "hosts.revoke"];
    let revokers = common::create_role(&mut client, "Win revokers", &revokers, on_win()).await;
    let perms = ["host_groups.manage", "access.read", "hosts.read"];
    let manager = fx.person("manager", &perms, Reach::All, 2).await;
    fx.db.user("vic", &viewers, 3).await;
    fx.db.user("rev", &revokers, 4).await;
    let uri = format!("/api/v1/host-groups/{}/preview", fx.win);
    let names = |preview: &Value| -> Vec<String> {
        preview["loses"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p["username"].as_str().unwrap().to_owned())
            .collect()
    };
    let (status, mine) = fx.call(&manager, "POST", &uri, Some(json!({}))).await;
    assert_eq!(status, StatusCode::OK, "{mine}");
    assert_eq!(names(&mine), ["vic"]);
    assert_eq!(mine["people_total"], 2);
    assert_eq!(mine["leaves_total"], 2);
    let (_, all) = fx.call(&fx.admin, "POST", &uri, Some(json!({}))).await;
    assert_eq!(names(&all), ["rev", "vic"]);
    fx.db.drop().await;
}

#[tokio::test]
async fn deleting_a_group_in_use_names_the_roles() {
    let Some(fx) = Fx::new().await else { return };
    let mut client = fx.db.pool.get().await.unwrap();
    let reach = Reach::Groups(vec![fx.win.clone()]);
    common::create_role(&mut client, "Win viewers", &["hosts.read"], reach).await;
    let uri = format!("/api/v1/host-groups/{}?version=1", fx.win);
    let (status, refused) = fx.call(&fx.admin, "DELETE", &uri, None).await;
    assert_eq!(status, StatusCode::CONFLICT, "{refused}");
    assert_eq!(refused["code"], "group_in_use");
    assert_eq!(refused["roles"], json!(["Win viewers"]));
    fx.db.drop().await;
}

#[tokio::test]
async fn invalid_conditions_name_the_field() {
    let Some(fx) = Fx::new().await else { return };
    let condition =
        |field: &str, value: &str| json!({"field": field, "negate": false, "values": [value]});
    let many: Vec<Value> = (0..17).map(|_| hostname(false, &["a"])).collect();
    let cases = [
        (json!([condition("ip", "10.0.0.0/33")]), "ip"),
        (json!([condition("os_family", "macos")]), "os_family"),
        (
            json!([condition("distribution", "Debian 12")]),
            "distribution",
        ),
        (json!([condition("distribution", "debian")]), "distribution"),
        (json!([condition("label", "web")]), "label"),
        (
            json!([{"field": "hostname", "negate": false, "values": []}]),
            "hostname",
        ),
        (json!([condition("hostname", &"x".repeat(256))]), "hostname"),
        (json!([]), "conditions"),
        (json!(many), "conditions"),
    ];
    for (conditions, field) in cases {
        let body = json!({"name": "Bad", "kind": "rule", "conditions": conditions});
        let (status, refused) = fx
            .call(&fx.admin, "POST", "/api/v1/host-groups", Some(body))
            .await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{field}: {refused}"
        );
        assert_eq!(refused["code"], "invalid_condition");
        assert_eq!(refused["field_errors"][0]["field"], field, "{refused}");
    }
    let ok = json!([
        condition("ip", "10.0.0.0/16"),
        condition("distribution", "debian 12")
    ]);
    let body = json!({"name": "Good", "kind": "rule", "conditions": ok});
    let (status, created) = fx
        .call(&fx.admin, "POST", "/api/v1/host-groups", Some(body))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    assert_eq!(
        created["membership"],
        "Hosts where IP address is in 10.0.0.0/16 and distribution is Debian 12"
    );
    let body = json!({"name": "Blank", "kind": "manual", "agent_ids": [""]});
    let (status, refused) = fx
        .call(&fx.admin, "POST", "/api/v1/host-groups", Some(body))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        refused["field_errors"][0]["message"],
        "Host ids are 1–255 characters"
    );
    fx.db.drop().await;
}

#[tokio::test]
async fn the_old_tag_and_asset_group_routes_are_gone() {
    let Some(fx) = Fx::new().await else { return };
    for (method, uri) in [
        ("POST", "/api/v1/access-control/asset-groups".to_owned()),
        (
            "PUT",
            format!("/api/v1/access-control/asset-groups/{}", fx.win),
        ),
        ("POST", format!("/api/v1/agents/{W1}/tags/preview")),
        ("PUT", format!("/api/v1/agents/{W1}/tags")),
    ] {
        let (status, _) = fx.call(&fx.admin, method, &uri, Some(json!({}))).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{method} {uri}");
    }
    fx.db.drop().await;
}

#[tokio::test]
async fn rule_set_assignment_lists_groups_with_their_membership_sentence() {
    let Some(fx) = Fx::new().await else { return };
    let client = fx.db.pool.get().await.unwrap();
    common::rule_group(&client, "Web", &[("hostname", false, &["*web*", "*api*"])]).await;
    let (status, view) = fx
        .call(&fx.admin, "GET", "/api/v1/rule-set-assignments", None)
        .await;
    assert_eq!(status, StatusCode::OK, "{view}");
    let groups = view["asset_groups"].as_array().unwrap();
    let find = |name: &str| groups.iter().find(|g| g["name"] == name).unwrap().clone();
    let win = find("WindowsServers");
    assert_eq!(win["kind"], "manual");
    assert_eq!(win["summary"], "2 hosts picked by hand");
    assert!(win.get("selectors").is_none());
    let web = find("Web");
    assert_eq!(web["kind"], "rule");
    assert_eq!(
        web["summary"],
        "Hosts where hostname matches *web* or *api*"
    );
    fx.db.drop().await;
}
