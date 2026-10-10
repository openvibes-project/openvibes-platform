//! `ConsoleReadLookups` against PostgreSQL: every lookup offered to the
//! model runs (#241), within the user's console permissions and scopes.

use std::hash::{BuildHasher, Hasher};

use chrono::{DateTime, Duration, Utc};
use openvibes_core::{
    Confidence, Identifier, PayloadEncoding, Rule, RuleSet, SchemaVersion, Severity,
    SignedRuleEnvelope,
};
use platform_assistant::{Area, Lookup, LookupError, LookupOutput, LookupRunner};
use platform_store::{Pool, console_read::AgentScope};
use serde_json::Value;

use super::{Access, ConsoleReadLookups};

const WEB: &str = "agent.00000000-0000-4000-8000-00000000000a";
const DB: &str = "agent.00000000-0000-4000-8000-00000000000b";
const PROD: &str = "00000000-0000-4000-8000-0000000000a1";

struct TestDb {
    pool: Pool,
    admin_url: String,
    name: String,
}

impl TestDb {
    async fn drop(self) {
        self.pool.close();
        let admin = platform_store::connect(&self.admin_url).await.unwrap();
        let client = admin.get().await.unwrap();
        client
            .batch_execute("SET statement_timeout = 0")
            .await
            .unwrap();
        client
            .batch_execute(&format!("DROP DATABASE {} WITH (FORCE)", self.name))
            .await
            .unwrap();
    }
}

fn envelope() -> Vec<u8> {
    let set = RuleSet {
        schema_version: SchemaVersion::V1,
        rules: ["ssh.exposed", "quiet.rule"]
            .into_iter()
            .map(|id| Rule {
                id: Identifier::new(id).unwrap(),
                version: 3,
                title: "SSH exposed on all interfaces".into(),
                severity: Severity::High,
                confidence: Confidence::new(90).unwrap(),
                expression: "'22' in facts['port.tcp.exposed']".into(),
                finding_message: "SSH listens on a non-loopback address".into(),
                kind: openvibes_core::RuleKind::Snapshot,
                programs: None,
                attack: None,
            })
            .collect(),
    };
    serde_json::to_vec(&SignedRuleEnvelope {
        schema_version: SchemaVersion::V1,
        rule_set_id: Identifier::new("baseline").unwrap(),
        rule_set_version: 7,
        issuer_key_id: Identifier::new("org.rules").unwrap(),
        created_at_unix_ms: 0,
        expires_at_unix_ms: i64::MAX,
        payload_encoding: PayloadEncoding::Json,
        payload: serde_json::to_string(&set).unwrap(),
        payload_sha256_hex: "0".repeat(64),
        signature_base64url: String::new(),
    })
    .unwrap()
}

/// web-01 (env=prod, in asset group PROD) and db-01 (env=dev): each with
/// the `ssh.exposed` finding and the openssh advisory; the rule published.
async fn seed() -> (TestDb, DateTime<Utc>) {
    let admin_url = std::env::var("OPENVIBES_TEST_DATABASE_URL")
        .expect("set OPENVIBES_TEST_DATABASE_URL via scripts/test-db.sh");
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write_u64(std::process::id().into());
    let name = format!("ov_console_assistant_{:016x}", hasher.finish());
    let admin = platform_store::connect(&admin_url).await.unwrap();
    admin
        .get()
        .await
        .unwrap()
        .batch_execute(&format!("CREATE DATABASE {name}"))
        .await
        .unwrap();
    let (head, query) = admin_url.split_once('?').unwrap_or((&admin_url, ""));
    let head = &head[..head.rfind('/').unwrap()];
    let pool = platform_store::connect(&format!("{head}/{name}?{query}"))
        .await
        .unwrap();
    let db = TestDb {
        pool,
        admin_url,
        name,
    };
    let mut client = db.pool.get().await.unwrap();
    platform_store::migrate(&mut client).await.unwrap();
    let now = Utc::now();
    platform_store::ensure_partitions(&client, (now - Duration::days(2)).date_naive(), 3)
        .await
        .unwrap();
    client
        .batch_execute(&format!(
            "INSERT INTO agents (agent_id, status, enrolled_at, hostname, last_seen_at) VALUES
                ('{WEB}', 'active', now(), 'web-01', now()),
                ('{DB}', 'active', now(), 'db-01', now());
             INSERT INTO console_agent_tags VALUES
                ('{WEB}', 'env', 'prod', now(), 't'), ('{DB}', 'env', 'dev', now(), 't');
             INSERT INTO console_asset_groups VALUES ('{PROD}', 'prod', now(), 't');
             INSERT INTO console_asset_group_selectors VALUES ('{PROD}', 'env', 'prod', now());
             INSERT INTO advisories (advisory_id, source, os_id, os_version, severity, title, url)
             VALUES ('FEDORA-2026-1', 'fedora-44', 'fedora', '44', 'important', 'openssh', 'u');
             INSERT INTO advisory_cves VALUES ('FEDORA-2026-1', 'CVE-2026-0001');
             INSERT INTO vulnerabilities (agent_id, advisory_id, packages, first_seen_at,
                 last_evaluated_at) VALUES
                ('{WEB}', 'FEDORA-2026-1', '[]', now(), now()),
                ('{DB}', 'FEDORA-2026-1', '[]', now(), now());
             INSERT INTO rule_sets (rule_set_id) VALUES ('baseline');"
        ))
        .await
        .unwrap();
    for id in [WEB, DB] {
        client
            .execute(
                "INSERT INTO current_findings (agent_id, rule_set_id, rule_id, last_finding_id,
                     rule_version, severity, first_observed_at, last_observed_at,
                     last_observed_day, scan_id, confidence, message, evidence, received_at,
                     origin, authenticated)
                 VALUES ($1, 'baseline', 'ssh.exposed', $1, 3, 'high', $2, $2, $3,
                         'scan.test', 90, 'SSH exposure', '{}', $2, 'online', true)",
                &[&id, &(now - Duration::hours(1)), &now.date_naive()],
            )
            .await
            .unwrap();
    }
    client
        .execute(
            "INSERT INTO rule_bundles (rule_set_id, version, envelope, envelope_sha256,
                 issuer_key_id, created_at_ms, expires_at_ms, published_by)
             VALUES ('baseline', 7, $1, sha256($1), 'org.rules', 0, 9223372036854775807, 't')",
            &[&envelope()],
        )
        .await
        .unwrap();
    drop(client);
    (db, now)
}

fn access(agents: AgentScope, vulnerabilities: Option<AgentScope>, rules: bool) -> Access {
    Access {
        agents,
        vulnerabilities,
        rules,
    }
}

fn groups() -> AgentScope {
    AgentScope::AssetGroups(vec![PROD.into()])
}

/// A valid request for each lookup offered to the model.
fn sample(name: &str) -> Lookup {
    let arguments = match name {
        "search_findings" => "{}",
        "finding_endpoints" => r#"{"rule":"ssh.exposed"}"#,
        "agent_summary" | "host_vulnerabilities" => r#"{"agent":"web-01"}"#,
        "vulnerability_hosts" => r#"{"id":"CVE-2026-0001"}"#,
        "fleet_overview" => "{}",
        "rule_description" => r#"{"rule":"ssh.exposed"}"#,
        other => panic!("add a sample request for the new lookup {other}"),
    };
    Lookup::parse(name, arguments).unwrap()
}

async fn run(
    db: &TestDb,
    now: DateTime<Utc>,
    access: Access,
    name: &str,
) -> Result<LookupOutput, LookupError> {
    let lookups = ConsoleReadLookups::for_user(db.pool.clone(), access, now)
        .await
        .unwrap();
    lookups.run(&sample(name), 10).await
}

fn hosts(output: &LookupOutput) -> Vec<&str> {
    output.data["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["hostname"].as_str().unwrap())
        .collect()
}

#[tokio::test]
async fn the_console_runs_every_lookup_it_offers() {
    let (db, now) = seed().await;
    for spec in platform_assistant::lookups::specs() {
        for user in [
            access(AgentScope::Global, Some(AgentScope::Global), true),
            access(groups(), None, false),
        ] {
            let result = run(&db, now, user, &spec.name).await;
            assert_ne!(result, Err(LookupError::Unknown), "{}", spec.name);
        }
        let full = access(AgentScope::Global, Some(AgentScope::Global), true);
        assert!(
            run(&db, now, full, &spec.name).await.unwrap().found(),
            "{} finds the seeded data",
            spec.name
        );
    }
    db.drop().await;
}

#[tokio::test]
async fn newly_routed_lookups_return_data_in_scope() {
    let (db, now) = seed().await;
    let full = || access(AgentScope::Global, Some(AgentScope::Global), true);
    let vulns = run(&db, now, full(), "host_vulnerabilities").await.unwrap();
    assert_eq!(vulns.data["items"][0]["cite"], "[advisory:FEDORA-2026-1]");
    let affected = run(&db, now, full(), "vulnerability_hosts").await.unwrap();
    assert_eq!(hosts(&affected).len(), 2);
    let overview = run(&db, now, full(), "fleet_overview").await.unwrap();
    assert_eq!(overview.data["agents"]["seen_recently"], 2);
    assert_eq!(overview.data["open_vulnerabilities"], 2);
    let rule = run(&db, now, full(), "rule_description").await.unwrap();
    assert_eq!(rule.data["rule"]["title"], "SSH exposed on all interfaces");
    db.drop().await;
}

#[tokio::test]
async fn missing_permissions_answer_no_access_not_no_data() {
    let (db, now) = seed().await;
    for name in [
        "host_vulnerabilities",
        "vulnerability_hosts",
        "fleet_overview",
    ] {
        let user = access(AgentScope::Global, None, true);
        assert_eq!(
            run(&db, now, user, name).await,
            Err(LookupError::Forbidden(Area::Vulnerabilities)),
            "{name}"
        );
    }
    // Without rules.read, the rule of a finding in scope is still described
    // (the Compliance page shows it); any other rule is not.
    let quiet = Lookup::parse(
        "rule_description",
        r#"{"rule_set":"baseline","rule":"quiet.rule"}"#,
    )
    .unwrap();
    for user in [
        access(AgentScope::Global, Some(AgentScope::Global), false),
        access(groups(), Some(groups()), false),
    ] {
        let lookups = ConsoleReadLookups::for_user(db.pool.clone(), user, now)
            .await
            .unwrap();
        let own = lookups.run(&sample("rule_description"), 10).await.unwrap();
        assert_eq!(own.data["rule"]["title"], "SSH exposed on all interfaces");
        let refused = lookups.run(&quiet, 10).await.unwrap_err();
        assert_eq!(refused, LookupError::Forbidden(Area::Rules));
        assert!(refused.message().contains("no access to rules"));
    }
    let admin = access(AgentScope::Global, Some(AgentScope::Global), true);
    let lookups = ConsoleReadLookups::for_user(db.pool.clone(), admin, now)
        .await
        .unwrap();
    assert!(lookups.run(&quiet, 10).await.unwrap().data["rule"].is_object());
    db.drop().await;
}

#[tokio::test]
async fn vulnerability_lookups_use_the_vulnerability_scope() {
    let (db, now) = seed().await;
    let scoped = || access(groups(), Some(groups()), false);
    let affected = run(&db, now, scoped(), "vulnerability_hosts")
        .await
        .unwrap();
    assert_eq!(hosts(&affected), ["web-01"]);
    assert_eq!(affected.data["omitted"], 0, "db-01 is not even counted");
    let lookups = ConsoleReadLookups::for_user(db.pool.clone(), scoped(), now)
        .await
        .unwrap();
    let hidden = Lookup::parse("host_vulnerabilities", r#"{"agent":"db-01"}"#).unwrap();
    let hidden = lookups.run(&hidden, 10).await.unwrap();
    assert_eq!(
        hidden.data["agent"],
        Value::Null,
        "out of scope looks unknown"
    );
    assert_eq!(hidden.data["items"], Value::Array(Vec::new()));
    let overview = run(&db, now, scoped(), "fleet_overview").await.unwrap();
    assert_eq!(overview.data["open_vulnerabilities"], 1);
    // A vulnerability scope narrower than the agent scope is never widened.
    let narrower = || access(AgentScope::Global, Some(groups()), false);
    let affected = run(&db, now, narrower(), "vulnerability_hosts")
        .await
        .unwrap();
    assert_eq!(hosts(&affected), ["web-01"]);
    assert_eq!(
        run(&db, now, narrower(), "fleet_overview").await,
        Err(LookupError::Forbidden(Area::Vulnerabilities))
    );
    db.drop().await;
}
