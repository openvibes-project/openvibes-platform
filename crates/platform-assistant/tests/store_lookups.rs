//! `StoreLookups` against PostgreSQL: every lookup respects the scope,
//! host names resolve to one agent or are refused as ambiguous, and rules
//! are read from published bundles.

use std::hash::{BuildHasher, Hasher};

use chrono::{Duration, Utc};
use openvibes_core::{
    Confidence, Identifier, PayloadEncoding, Rule, RuleSet, SchemaVersion, Severity,
    SignedRuleEnvelope,
};
use platform_assistant::{Citation, Lookup, LookupError, LookupRunner, StoreLookups};
use platform_store::{Pool, assistant::AgentScope};
use serde_json::Value;

const WEB: &str = "agent.00000000-0000-4000-8000-00000000000a";
const WEB_TWIN: &str = "agent.00000000-0000-4000-8000-00000000000b";
const OTHER: &str = "agent.00000000-0000-4000-8000-00000000000c";

struct Db {
    pool: Pool,
    admin_url: String,
    name: String,
}

fn with_database(url: &str, name: &str) -> String {
    let (head, query) = url
        .split_once('?')
        .map_or((url, None), |(h, q)| (h, Some(q)));
    let head = &head[..head.rfind('/').unwrap()];
    query.map_or_else(
        || format!("{head}/{name}"),
        |q| format!("{head}/{name}?{q}"),
    )
}

impl Db {
    async fn create() -> Self {
        let admin_url = std::env::var("OPENVIBES_TEST_DATABASE_URL")
            .expect("set OPENVIBES_TEST_DATABASE_URL, see scripts/test-db.sh");
        let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
        hasher.write_u64(std::process::id().into());
        let name = format!("ov_assistant_{:016x}", hasher.finish());
        let admin = platform_store::connect(&admin_url).await.unwrap();
        admin
            .get()
            .await
            .unwrap()
            .batch_execute(&format!("CREATE DATABASE {name}"))
            .await
            .unwrap();
        let pool = platform_store::connect(&with_database(&admin_url, &name))
            .await
            .unwrap();
        Self {
            pool,
            admin_url,
            name,
        }
    }

    async fn drop(self) {
        self.pool.close();
        let admin = platform_store::connect(&self.admin_url).await.unwrap();
        admin
            .get()
            .await
            .unwrap()
            .batch_execute(&format!("DROP DATABASE {} WITH (FORCE)", self.name))
            .await
            .unwrap();
    }
}

fn envelope(encoding: PayloadEncoding) -> Vec<u8> {
    let set = RuleSet {
        schema_version: SchemaVersion::V1,
        rules: vec![Rule {
            id: Identifier::new("ssh.exposed").unwrap(),
            version: 3,
            title: "SSH exposed on all interfaces".into(),
            severity: Severity::High,
            confidence: Confidence::new(90).unwrap(),
            expression: "'22' in facts['port.tcp.exposed']".into(),
            finding_message: "SSH listens on a non-loopback address".into(),
        }],
    };
    serde_json::to_vec(&SignedRuleEnvelope {
        schema_version: SchemaVersion::V1,
        rule_set_id: Identifier::new("baseline").unwrap(),
        rule_set_version: 7,
        issuer_key_id: Identifier::new("org.rules").unwrap(),
        created_at_unix_ms: 0,
        expires_at_unix_ms: i64::MAX,
        payload_encoding: encoding,
        payload: serde_json::to_string(&set).unwrap(),
        payload_sha256_hex: "0".repeat(64),
        signature_base64url: String::new(),
    })
    .unwrap()
}

async fn seed() -> (Db, chrono::DateTime<Utc>) {
    let db = Db::create().await;
    let mut client = db.pool.get().await.unwrap();
    platform_store::migrate(&mut client).await.unwrap();
    let now = Utc::now();
    platform_store::ensure_partitions(&client, (now - Duration::days(2)).date_naive(), 3)
        .await
        .unwrap();
    for (id, host) in [(WEB, "web-01"), (WEB_TWIN, "twin"), (OTHER, "twin")] {
        client
            .execute(
                "INSERT INTO agents (agent_id, status, enrolled_at, last_seen_at, hostname)
                 VALUES ($1, 'active', now(), now(), $2)",
                &[&id, &host],
            )
            .await
            .unwrap();
        client
            .execute(
                "INSERT INTO current_findings (agent_id, rule_set_id, rule_id, last_finding_id,
                     rule_version, severity, first_observed_at, last_observed_at)
                 VALUES ($1, 'baseline', 'ssh.exposed', $1, 3, 'high', $2, $2)",
                &[&id, &(now - Duration::hours(1))],
            )
            .await
            .unwrap();
    }
    client
        .batch_execute(
            "INSERT INTO advisories (advisory_id, source, os_id, os_version, severity, title, url)
             VALUES ('FEDORA-2026-1', 'fedora-44', 'fedora', '44', 'important', 'openssh', 'u');
             INSERT INTO advisory_cves VALUES ('FEDORA-2026-1', 'CVE-2026-0001');",
        )
        .await
        .unwrap();
    for id in [WEB, OTHER] {
        client
            .execute(
                "INSERT INTO vulnerabilities (agent_id, advisory_id, packages, first_seen_at,
                     last_evaluated_at) VALUES ($1, 'FEDORA-2026-1', '[]', now(), now())",
                &[&id],
            )
            .await
            .unwrap();
    }
    client
        .batch_execute("INSERT INTO rule_sets (rule_set_id) VALUES ('baseline'), ('yaml')")
        .await
        .unwrap();
    for (set, bytes) in [
        ("baseline", envelope(PayloadEncoding::Json)),
        ("yaml", envelope(PayloadEncoding::Yaml)),
    ] {
        client
            .execute(
                "INSERT INTO rule_bundles (rule_set_id, version, envelope, envelope_sha256,
                     issuer_key_id, created_at_ms, expires_at_ms, published_by)
                 VALUES ($1, 7, $2, sha256($2), 'org.rules', 0, 9223372036854775807, 'test')",
                &[&set, &bytes],
            )
            .await
            .unwrap();
    }
    (db, now)
}

fn scoped(db: &Db, now: chrono::DateTime<Utc>) -> StoreLookups {
    StoreLookups::new(
        db.pool.clone(),
        AgentScope::Only(vec![WEB.into(), WEB_TWIN.into()]),
        now,
    )
}

#[tokio::test]
async fn lookups_stay_in_scope() {
    let (db, now) = seed().await;
    let lookups = scoped(&db, now);
    let run = |name: &str, arguments: &str| {
        let lookup = Lookup::parse(name, arguments).unwrap();
        let lookups = &lookups;
        async move { lookups.run(&lookup, 10).await }
    };

    let findings = run("search_findings", "{}").await.unwrap();
    assert_eq!(
        findings.data["items"][0]["endpoints"], 2,
        "OTHER is not counted"
    );
    assert_eq!(
        findings.data["items"][0]["cite"],
        "[finding:baseline/ssh.exposed]"
    );

    let endpoints = run(
        "finding_endpoints",
        r#"{"rule_set":"baseline","rule":"ssh.exposed"}"#,
    )
    .await
    .unwrap();
    let citations = endpoints.citations();
    assert!(citations.contains(&Citation::Agent(WEB.into())));
    assert!(!citations.contains(&Citation::Agent(OTHER.into())));

    let overview = run("fleet_overview", "{}").await.unwrap();
    assert_eq!(overview.data["agents"]["seen_recently"], 2);
    assert_eq!(overview.data["open_vulnerabilities"], 1);

    let hosts = run("vulnerability_hosts", r#"{"id":"CVE-2026-0001"}"#)
        .await
        .unwrap();
    assert_eq!(hosts.data["items"].as_array().unwrap().len(), 1);
    assert_eq!(
        hosts.data["omitted"], 0,
        "OTHER is not even counted as left out"
    );
    db.drop().await;
}

#[tokio::test]
async fn host_names_resolve_to_one_agent_in_scope() {
    let (db, now) = seed().await;
    let lookups = scoped(&db, now);
    let vulns = lookups
        .run(
            &Lookup::parse("host_vulnerabilities", r#"{"agent":"WEB-01"}"#).unwrap(),
            10,
        )
        .await
        .unwrap();
    assert_eq!(vulns.data["agent"], format!("[agent:{WEB}]"));
    assert_eq!(vulns.data["items"][0]["cite"], "[advisory:FEDORA-2026-1]");
    assert!(vulns.citations().contains(&Citation::Agent(WEB.into())));
    // "twin" names WEB_TWIN in scope and OTHER outside it: only one is
    // visible, so it resolves (and reveals nothing about OTHER).
    let twin = lookups
        .run(
            &Lookup::parse("host_vulnerabilities", r#"{"agent":"twin"}"#).unwrap(),
            10,
        )
        .await
        .unwrap();
    assert_eq!(twin.data["agent"], format!("[agent:{WEB_TWIN}]"));
    assert_eq!(twin.data["items"], Value::Array(Vec::new()));
    // With every agent in scope the name is ambiguous.
    let everyone = StoreLookups::new(db.pool.clone(), AgentScope::All, now);
    assert_eq!(
        everyone
            .run(
                &Lookup::parse("host_vulnerabilities", r#"{"agent":"twin"}"#).unwrap(),
                10
            )
            .await
            .unwrap_err(),
        LookupError::Ambiguous
    );
    let summary = everyone
        .run(
            &Lookup::parse("agent_summary", r#"{"agent":"twin"}"#).unwrap(),
            10,
        )
        .await
        .unwrap();
    assert_eq!(
        summary.data["items"].as_array().unwrap().len(),
        2,
        "a summary lists both"
    );
    // Out of scope looks exactly like unknown.
    let hidden = lookups
        .run(
            &Lookup::parse("host_vulnerabilities", &format!(r#"{{"agent":"{OTHER}"}}"#)).unwrap(),
            10,
        )
        .await
        .unwrap();
    assert_eq!(hidden.data["agent"], Value::Null);
    db.drop().await;
}

#[tokio::test]
async fn rules_are_read_from_published_json_bundles() {
    let (db, now) = seed().await;
    let lookups = scoped(&db, now);
    let rule = lookups
        .run(
            &Lookup::parse(
                "rule_description",
                r#"{"rule_set":"baseline","rule":"ssh.exposed"}"#,
            )
            .unwrap(),
            10,
        )
        .await
        .unwrap();
    assert_eq!(rule.data["rule"]["title"], "SSH exposed on all interfaces");
    assert_eq!(rule.data["rule"]["severity"], "high");
    assert_eq!(rule.data["rule"]["bundle_version"], 7);
    for (set, name) in [
        ("baseline", "absent.rule"),
        ("unknown", "ssh.exposed"),
        ("yaml", "ssh.exposed"),
    ] {
        let missing = lookups
            .run(
                &Lookup::parse(
                    "rule_description",
                    &format!(r#"{{"rule_set":"{set}","rule":"{name}"}}"#),
                )
                .unwrap(),
                10,
            )
            .await
            .unwrap();
        assert_eq!(missing.data["rule"], Value::Null, "{set}/{name}");
    }
    db.drop().await;
}
