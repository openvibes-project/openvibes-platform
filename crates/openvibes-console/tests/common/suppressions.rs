//! The suppression tests' fixture: two leads (Team lead template) on the
//! `linux` group, a lead on `windows`, an analyst on `linux`, the admin,
//! and one alarm on each group's host.

use axum::http::StatusCode;
use chrono::{DateTime, Duration, Utc};
use openvibes_core::{Alarm, AlarmProcess, Confidence, Identifier, Severity};
use platform_store::console_roles::Reach;
use serde_json::{Value, json};

use super::{
    http::{Session, sign_in},
    manual_group,
    people::Fx,
};

pub const LINUX_HOST: &str = "agent.00000000-0000-4000-8000-000000000401";
const WIN_HOST: &str = "agent.00000000-0000-4000-8000-000000000402";
pub const LIST: &str = "/api/v1/alarm-suppressions";

/// The Team lead template's permissions.
const TEAM_LEAD: &[&str] = &[
    "alarms.read",
    "alarms.suppressions.read",
    "compliance.read",
    "vulnerabilities.read",
    "hosts.read",
    "cases.read",
    "rules.read",
    "rules.coverage.read",
    "alarms.triage",
    "alarms.suppress",
    "compliance.triage",
    "vulnerabilities.triage",
    "cases.write",
    "assistant.use",
    "alarms.suppressions.approve",
    "hosts.label",
    "dashboards.share",
    "access.read",
    "access.grant",
];
const ANALYST: &[&str] = &[
    "alarms.read",
    "alarms.suppressions.read",
    "alarms.triage",
    "alarms.suppress",
    "hosts.read",
];

/// Two leads on `linux`, a lead on `windows`, an analyst on `linux`, the
/// admin, and one alarm on each group's host.
pub struct S {
    pub fx: Fx,
    pub lead: Session,
    pub lead2: Session,
    pub win_lead: Session,
    pub analyst: Session,
    pub linux: String,
    pub windows: String,
    pub linux_alarm: String,
    pub win_alarm: String,
}

pub async fn setup() -> Option<S> {
    let fx = Fx::new().await?;
    let mut client = fx.db.pool.get().await.unwrap();
    let now = Utc::now();
    platform_store::ensure_partitions(&client, now.date_naive() - Duration::days(1), 2)
        .await
        .unwrap();
    for (agent, host) in [(LINUX_HOST, "lin-01"), (WIN_HOST, "win-01")] {
        client
            .execute(
                "INSERT INTO agents (agent_id, status, enrolled_at, hostname)
                 VALUES ($1, 'active', $2, $3)",
                &[&agent, &now, &host],
            )
            .await
            .unwrap();
    }
    let linux = manual_group(&client, "linux", &[LINUX_HOST]).await;
    let windows = manual_group(&client, "windows", &[WIN_HOST]).await;
    let linux_alarm = alarm(&mut client, LINUX_HOST, 1, now).await;
    let win_alarm = alarm(&mut client, WIN_HOST, 2, now).await;
    drop(client);
    let on = |group: &str| Reach::Groups(vec![group.to_owned()]);
    let lead_role = fx.role("Linux lead", TEAM_LEAD, on(&linux)).await;
    let win_role = fx.role("Windows lead", TEAM_LEAD, on(&windows)).await;
    let analyst_role = fx.role("Linux analyst", ANALYST, on(&linux)).await;
    for (name, role, index) in [
        ("lead", &lead_role, 3),
        ("lead2", &lead_role, 4),
        ("winlead", &win_role, 5),
        ("ana", &analyst_role, 6),
    ] {
        fx.db.user(name, role, index).await;
    }
    Some(S {
        lead: sign_in(&fx.router, "lead").await,
        lead2: sign_in(&fx.router, "lead2").await,
        win_lead: sign_in(&fx.router, "winlead").await,
        analyst: sign_in(&fx.router, "ana").await,
        fx,
        linux,
        windows,
        linux_alarm,
        win_alarm,
    })
}

/// Stores alarm `n` on `agent`; returns its platform id.
pub async fn alarm(
    client: &mut platform_store::Client,
    agent: &str,
    n: u32,
    now: DateTime<Utc>,
) -> String {
    let process = |exe: &str| AlarmProcess {
        pid: 1,
        exe: exe.into(),
        args: vec!["sh".into(), "-c".into(), "id".into()],
        cwd: None,
        uid: 48,
        euid: 48,
        truncated: false,
        seeded: false,
    };
    let alarm = Alarm {
        detection: None,
        alarm_id: Identifier::new(format!("alarm.{n:032x}")).unwrap(),
        rule_set_id: Identifier::new("baseline").unwrap(),
        rule_set_version: 1,
        rule_id: Identifier::new("web-server-spawns-shell").unwrap(),
        rule_version: 1,
        severity: Severity::High,
        confidence: Confidence::new(80).unwrap(),
        message: "A web server started a shell".into(),
        first_seen_unix_ms: now.timestamp_millis(),
        last_seen_unix_ms: now.timestamp_millis(),
        count: 1,
        process: process("/usr/bin/sh"),
        ancestors: vec![process("/usr/sbin/nginx")],
    };
    let partitions = platform_store::partition_days_of(client, "alarms")
        .await
        .unwrap();
    let row = platform_store::alarms::row(
        &alarm,
        now - Duration::days(1),
        now + Duration::minutes(5),
        &partitions,
    )
    .unwrap();
    platform_store::alarms::insert_batch(client, agent, 0, &[row], now)
        .await
        .unwrap();
    let id: i64 = client
        .query_one("SELECT max(id) FROM alarms WHERE agent_id = $1", &[&agent])
        .await
        .unwrap()
        .get(0);
    id.to_string()
}

impl S {
    pub async fn call(
        &self,
        who: &Session,
        method: &str,
        uri: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        self.fx.call(who, method, uri, body).await
    }

    pub async fn approval(&self, on: bool) {
        let uri = "/api/v1/settings/suppressions.require_approval";
        let (status, body) = self
            .call(&self.fx.admin, "PATCH", uri, Some(json!({"value": on})))
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }

    /// `who` asks to quiet the program of `alarm` at `place` for 7 days.
    pub async fn ask(&self, who: &Session, alarm: &str, place: Value) -> (StatusCode, Value) {
        let body = json!({"alarm_id": alarm, "what": "program", "where": place,
            "for_days": 7, "reason": "nginx health check"});
        self.call(who, "POST", LIST, Some(body)).await
    }

    /// The analyst's waiting request on the `linux` group.
    pub async fn waiting(&self) -> String {
        self.approval(true).await;
        let (status, made) = self
            .ask(&self.analyst, &self.linux_alarm, self.group(&self.linux))
            .await;
        assert_eq!(status, StatusCode::CREATED, "{made}");
        assert_eq!(made["status"], "waiting");
        made["id"].as_str().unwrap().to_owned()
    }

    pub fn group(&self, id: &str) -> Value {
        json!({"kind": "group", "group_id": id})
    }

    pub async fn act(
        &self,
        who: &Session,
        id: &str,
        verb: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        self.call(who, "POST", &format!("{LIST}/{id}/{verb}"), body)
            .await
    }

    pub async fn rows(&self, who: &Session) -> Vec<Value> {
        let (status, list) = self.call(who, "GET", LIST, None).await;
        assert_eq!(status, StatusCode::OK, "{list}");
        list["items"].as_array().unwrap().clone()
    }

    pub async fn row(&self, who: &Session, id: &str) -> Option<Value> {
        self.rows(who).await.into_iter().find(|row| row["id"] == id)
    }

    pub async fn alarm_state(&self, id: &str) -> Value {
        let (_, alarm) = self
            .call(&self.fx.admin, "GET", &format!("/api/v1/alarms/{id}"), None)
            .await;
        alarm["triage"]["state"].clone()
    }

    pub async fn done(self) {
        self.fx.db.drop().await;
    }
}
