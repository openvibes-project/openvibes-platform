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
        let drop_client = admin.get().await.unwrap();
        // DROP grows with partitions; no statement timeout for it.
        drop_client
            .batch_execute("SET statement_timeout = 0")
            .await
            .unwrap();
        drop_client
            .batch_execute(&format!("DROP DATABASE {} WITH (FORCE)", self.name))
            .await
            .unwrap();
    }
}

fn envelope(encoding: PayloadEncoding) -> Vec<u8> {
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
    // A wrong or missing set resolves from the findings (all in baseline),
    // and the store's spelling of the rule id is used.
    let mixed = lookups
        .run(
            &Lookup::parse(
                "rule_description",
                r#"{"rule_set":"nope","rule":"SSH.Exposed"}"#,
            )
            .unwrap(),
            10,
        )
        .await
        .unwrap();
    assert_eq!(mixed.data["rule"]["cite"], "[finding:baseline/ssh.exposed]");
    let resolved = lookups
        .run(
            &Lookup::parse("rule_description", r#"{"rule":"ssh.exposed"}"#).unwrap(),
            10,
        )
        .await
        .unwrap();
    assert_eq!(resolved.data["rule"]["bundle_version"], 7);
    for (set, name) in [
        ("baseline", "absent.rule"),
        // No findings, so resolution cannot rescue a wrong set.
        ("unknown", "quiet.rule"),
        // A real rule in a non-JSON bundle is not read.
        ("yaml", "quiet.rule"),
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

#[tokio::test]
async fn resolution_stays_in_scope_and_never_picks_silently() {
    let (db, now) = seed().await;
    let client = db.pool.get().await.unwrap();
    let insert = |agent: &'static str, set: &'static str| {
        let client = &client;
        async move {
            client
                .execute(
                    "INSERT INTO current_findings (agent_id, rule_set_id, rule_id, last_finding_id,
                         rule_version, severity, first_observed_at, last_observed_at,
                         last_observed_day, scan_id, confidence, message, evidence, received_at,
                         origin, authenticated)
                     VALUES ($1, $3, 'ssh.exposed', $1, 3, 'high', $2, $2, $4,
                             'scan.test', 90, 'SSH exposure', '{}', $2, 'online', true)",
                    &[&agent, &(now - Duration::hours(1)), &set, &now.date_naive()],
                )
                .await
                .unwrap();
        }
    };
    // A second set only on an agent outside the scope.
    insert(OTHER, "yaml").await;
    let lookups = scoped(&db, now);
    let desc = Lookup::parse("rule_description", r#"{"rule":"ssh.exposed"}"#).unwrap();
    assert!(lookups.run(&desc, 10).await.unwrap().data["rule"].is_object());
    let ends = Lookup::parse("finding_endpoints", r#"{"rule":"SSH.EXPOSED"}"#).unwrap();
    let out = lookups.run(&ends, 10).await.unwrap();
    assert_eq!(out.data["items"].as_array().unwrap().len(), 2);
    assert!(out.data["items"][0].get("rule_set").is_none(), "not merged");
    // The same set on an agent in scope makes it ambiguous.
    insert(WEB, "yaml").await;
    assert_eq!(
        lookups.run(&desc, 10).await.unwrap_err(),
        platform_assistant::LookupError::AmbiguousRule
    );
    let out = lookups.run(&ends, 10).await.unwrap();
    assert_eq!(out.data["items"].as_array().unwrap().len(), 3);
    drop(client);
    db.drop().await;
}

const REVOKED: &str = "agent.00000000-0000-4000-8000-00000000000d";

#[tokio::test]
async fn ports_services_and_software_stay_in_scope() {
    let (db, now) = seed().await;
    let mut client = db.pool.get().await.unwrap();
    // OTHER (outside the scope) and REVOKED have the same port and package
    // as WEB. `a_b%` and `axbyc` check that `_` and `%` match literally.
    client
        .batch_execute(&format!(
            "INSERT INTO agents (agent_id, status, enrolled_at, last_seen_at, hostname)
             VALUES ('{REVOKED}', 'revoked', now(), now(), 'old-01');
             UPDATE agents SET services_at = now(), services_owners = 'partial',
                 services_truncated = false WHERE agent_id = '{WEB}';
             INSERT INTO host_listeners (agent_id, protocol, address, port, exposed, service, program)
             VALUES ('{WEB}', 'tcp', '0.0.0.0', 22, true, 'sshd.service', 'sshd'),
                    ('{WEB}', 'tcp', '::', 22, true, 'sshd.service', 'sshd'),
                    ('{WEB}', 'tcp', '127.0.0.1', 5432, false, NULL, 'postgres'),
                    ('{OTHER}', 'tcp', '0.0.0.0', 22, true, 'sshd.service', 'sshd'),
                    ('{REVOKED}', 'tcp', '0.0.0.0', 22, true, 'sshd.service', 'sshd');
             INSERT INTO host_services (agent_id, unit, programs, processes, run_as)
             VALUES ('{WEB}', 'sshd.service', '{{sshd}}', 1, 'root'),
                    ('{OTHER}', 'sshd.service', '{{sshd}}', 1, 'root');
             INSERT INTO package_versions (id, manager, name, epoch, version, release, arch)
             VALUES (1, 'rpm', 'google-chrome-stable', 0, '141.0', '1', 'x86_64'),
                    (2, 'rpm', 'openssh-server', 0, '9.9p1', '3.fc44', 'x86_64'),
                    (3, 'rpm', 'a_b%', 0, '1', '', 'x86_64'),
                    (4, 'rpm', 'axbyc', 0, '1', '', 'x86_64'),
                    (5, 'rpm', 'otheronly', 0, '1', '', 'x86_64');
             INSERT INTO host_packages VALUES ('{WEB}', 1), ('{WEB}', 2), ('{WEB}', 3),
                 ('{WEB}', 4), ('{OTHER}', 1), ('{OTHER}', 5), ('{REVOKED}', 1);"
        ))
        .await
        .unwrap();
    // The store reads themselves never return a host outside the scope.
    let only_web = AgentScope::Only(vec![WEB.into()]);
    use platform_store::assistant_inventory as inv;
    let listeners = inv::host_listeners(&mut client, &only_web, OTHER, None, 10)
        .await
        .unwrap();
    assert_eq!((listeners.items.len(), listeners.total), (0, 0));
    let services = inv::host_services(&mut client, &only_web, OTHER, 10)
        .await
        .unwrap();
    assert_eq!((services.items.len(), services.total), (0, 0));
    assert!(
        inv::host_report(&mut client, &only_web, OTHER)
            .await
            .unwrap()
            .is_none()
    );

    let lookups = scoped(&db, now);
    let everyone = StoreLookups::new(db.pool.clone(), AgentScope::All, now);
    let ask = |all: bool, name: &str, arguments: &str| {
        let lookup = Lookup::parse(name, arguments).unwrap();
        let lookups = if all { &everyone } else { &lookups };
        async move {
            let out = lookups.run(&lookup, 10).await;
            out.unwrap_or_else(|e| panic!("{lookup:?}: {e:?}"))
        }
    };

    let port = ask(false, "host_services", r#"{"port":22}"#).await;
    assert_eq!(
        port.data["items"].as_array().unwrap().len(),
        2,
        "two addresses"
    );
    assert_eq!(port.data["hosts"], 1, "OTHER is not counted");
    assert_eq!(port.data["omitted"], 0);
    assert_eq!(port.data["items"][0]["cite"], format!("[agent:{WEB}]"));
    assert_eq!(port.data["items"][0]["service"], "sshd.service");
    let port = ask(true, "host_services", r#"{"port":22}"#).await;
    assert_eq!(port.data["hosts"], 2, "WEB and OTHER, not the revoked host");

    let host = ask(false, "host_services", r#"{"agent":"web-01"}"#).await;
    let items = host.data["items"].as_array().unwrap();
    assert_eq!(items.len(), 4, "three listeners and one service");
    assert_eq!(items[2]["port"], 5432, "loopback after exposed");
    assert_eq!(items[2]["exposed"], false);
    assert_eq!(items[3]["kind"], "running service");
    assert!(host.data["reported_at"].is_string());
    assert!(
        host.data["notes"][0]
            .as_str()
            .unwrap()
            .contains("not visible")
    );
    let one = ask(false, "host_services", r#"{"agent":"web-01","port":5432}"#).await;
    assert_eq!(one.data["items"].as_array().unwrap().len(), 1);
    // Out of scope looks exactly like unknown.
    let hidden = ask(false, "host_services", &format!(r#"{{"agent":"{OTHER}"}}"#)).await;
    assert_eq!(hidden.data["agent"], Value::Null);
    assert_eq!(hidden.data["items"], Value::Array(Vec::new()));
    // In scope but never reported: said so, also when asking for a port.
    for arguments in [r#"{"agent":"twin"}"#, r#"{"agent":"twin","port":5432}"#] {
        let quiet = ask(false, "host_services", arguments).await;
        assert!(quiet.data["reported_at"].is_null(), "{arguments}");
        assert!(
            quiet.data["notes"][0]
                .as_str()
                .unwrap()
                .contains("never reported"),
            "{arguments}"
        );
    }
    // A named revoked host is still read, and marked.
    let old = ask(true, "host_services", r#"{"agent":"old-01"}"#).await;
    assert_eq!(old.data["state"], "revoked");
    assert_eq!(old.data["items"][0]["port"], 22);

    let chrome = ask(false, "software", r#"{"name":"CHROME"}"#).await;
    assert_eq!(chrome.data["hosts_with_these_names"], 1);
    assert_eq!(chrome.data["package_names"], 1);
    assert_eq!(chrome.data["items"][0]["cite"], format!("[agent:{WEB}]"));
    assert_eq!(chrome.data["items"][0]["version"], "141.0-1");
    assert!(!chrome.citations().contains(&Citation::Agent(OTHER.into())));
    let chrome = ask(true, "software", r#"{"name":"chrome"}"#).await;
    assert_eq!(
        chrome.data["hosts_with_these_names"], 2,
        "not the revoked host"
    );
    let old = ask(true, "software", r#"{"name":"chrome","agent":"old-01"}"#).await;
    assert_eq!(old.data["items"][0]["package"], "google-chrome-stable");
    assert_eq!(old.data["state"], "revoked");
    let active = ask(true, "software", r#"{"name":"chrome","agent":"web-01"}"#).await;
    assert!(
        active.data.get("state").is_none(),
        "only a revoked host is marked"
    );
    // A name installed only outside the scope is not even counted.
    let only_web = StoreLookups::new(db.pool.clone(), only_web.clone(), now);
    let lookup = Lookup::parse("software", r#"{"name":"otheronly"}"#).unwrap();
    let out = only_web.run(&lookup, 10).await.unwrap();
    assert_eq!(out.data["package_names"], 0);
    assert_eq!(out.data["omitted"], 0);
    assert_eq!(
        ask(true, "software", r#"{"name":"otheronly"}"#).await.data["package_names"],
        1
    );
    let on_web = ask(false, "software", r#"{"name":"openssh","agent":"web-01"}"#).await;
    assert_eq!(on_web.data["items"][0]["package"], "openssh-server");
    assert_eq!(on_web.data["items"][0]["version"], "9.9p1-3.fc44");
    for (text, found) in [("a_b", 1), ("_b%", 1), ("b%", 1), ("x_", 0), ("%c", 0)] {
        let out = ask(false, "software", &format!(r#"{{"name":"{text}"}}"#)).await;
        assert_eq!(out.data["package_names"], found, "{text}");
    }
    let on_twin = ask(false, "software", r#"{"name":"chrome","agent":"twin"}"#).await;
    assert_eq!(on_twin.data["items"], Value::Array(Vec::new()));
    assert_eq!(on_twin.data["agent"], format!("[agent:{WEB_TWIN}]"));
    let hidden = ask(
        false,
        "software",
        &format!(r#"{{"name":"chrome","agent":"{OTHER}"}}"#),
    )
    .await;
    assert_eq!(hidden.data["agent"], Value::Null);
    drop(client);
    db.drop().await;
}
