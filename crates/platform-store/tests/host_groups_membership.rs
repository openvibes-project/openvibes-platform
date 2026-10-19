//! Host-group membership is one SQL function, `console_host_in_group`
//! (schema 53; spec 2026-10-16-roles-permissions-design.md §5.1): automatic
//! and rule groups by what agents report, manual groups by hand-picked
//! hosts; revoked and imported hosts are in no group.
mod common;

use platform_store::{
    Client,
    console_read::{AgentScope, agent_ids_in_scope},
};

/// An active agent `agent.<n>` reporting these facts (`None` = unknown).
async fn host(
    c: &Client,
    n: u32,
    os: Option<(&str, &str)>,
    hostname: Option<&str>,
    address: Option<&str>,
) -> String {
    let id = format!("agent.00000000-0000-4000-8000-{n:012}");
    common::seed_agent(c, &id).await;
    c.execute(
        "UPDATE agents SET os_id = $2, os_version = $3, hostname = $4, last_address = $5::text::inet
         WHERE agent_id = $1",
        &[
            &id,
            &os.map(|o| o.0),
            &os.map(|o| o.1),
            &hostname,
            &address,
        ],
    )
    .await
    .unwrap();
    id
}

async fn members(c: &Client, group: &str) -> Vec<String> {
    c.query(
        "SELECT agent_id FROM agents WHERE console_host_in_group(agent_id, $1::text::uuid) ORDER BY 1",
        &[&group],
    )
    .await
    .unwrap()
    .iter()
    .map(|r| r.get(0))
    .collect()
}

#[tokio::test]
async fn os_family_and_distribution_match_reported_facts() {
    let (db, c) = common::migrated().await;
    let debian = host(&c, 1, Some(("debian", "12")), None, None).await;
    let fedora = host(&c, 2, Some(("fedora", "44")), None, None).await;
    host(&c, 3, None, Some("bare"), None).await;
    let linux = common::rule_group(&c, "L", &[("os_family", false, &["linux"])]).await;
    let deb12 = common::rule_group(&c, "D", &[("distribution", false, &["debian 12"])]).await;
    let mut both = vec![debian.clone(), fedora];
    both.sort();
    assert_eq!(members(&c, &linux).await, both);
    assert_eq!(members(&c, &deb12).await, vec![debian]);
    db.drop().await;
}

#[tokio::test]
async fn rocky_and_alma_distributions_collapse_to_the_major_release() {
    let (db, c) = common::migrated().await;
    let rocky = host(&c, 1, Some(("rocky", "9.4")), None, None).await;
    let distribution: String = c
        .query_one(
            "SELECT distribution FROM agents WHERE agent_id = $1",
            &[&rocky],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(distribution, "rocky 9");
    db.drop().await;
}

#[tokio::test]
async fn hostname_patterns_are_literal_except_star_and_ignore_case() {
    let (db, c) = common::migrated().await;
    let web = host(&c, 1, None, Some("WEB-01"), None).await;
    let web_dash = host(&c, 2, None, Some("web-01"), None).await;
    let percent = host(&c, 3, None, Some("a%b"), None).await;
    let axb = host(&c, 4, None, Some("axb"), None).await;
    let win = host(&c, 5, None, Some("win-test-01"), None).await;
    let star = common::rule_group(&c, "S", &[("hostname", false, &["web-*"])]).await;
    let mut webs = vec![web.clone(), web_dash.clone()];
    webs.sort();
    assert_eq!(members(&c, &star).await, webs);
    let underscore = common::rule_group(&c, "U", &[("hostname", false, &["web_01"])]).await;
    assert!(members(&c, &underscore).await.is_empty());
    let literal = common::rule_group(&c, "P", &[("hostname", false, &["a%b"])]).await;
    assert_eq!(members(&c, &literal).await, vec![percent]);
    assert!(!members(&c, &literal).await.contains(&axb));
    let test = common::rule_group(&c, "T", &[("hostname", false, &["*test*"])]).await;
    assert_eq!(members(&c, &test).await, vec![win]);
    db.drop().await;
}

#[tokio::test]
async fn ip_conditions_take_cidrs_and_single_addresses_v4_and_v6() {
    let (db, c) = common::migrated().await;
    let lan = host(&c, 1, None, None, Some("10.0.1.10")).await;
    let lab = host(&c, 2, None, None, Some("10.9.0.44")).await;
    let six = host(&c, 3, None, None, Some("2001:db8::5")).await;
    let cidr = common::rule_group(&c, "C", &[("ip", false, &["10.0.0.0/16"])]).await;
    assert_eq!(members(&c, &cidr).await, vec![lan]);
    let single = common::rule_group(&c, "S", &[("ip", false, &["10.9.0.44"])]).await;
    assert_eq!(members(&c, &single).await, vec![lab]);
    let v6 = common::rule_group(&c, "6", &[("ip", false, &["2001:db8::/32"])]).await;
    assert_eq!(members(&c, &v6).await, vec![six.clone()]);
    let v6_single = common::rule_group(&c, "61", &[("ip", false, &["2001:db8::5"])]).await;
    assert_eq!(members(&c, &v6_single).await, vec![six]);
    db.drop().await;
}

#[tokio::test]
async fn negated_conditions_exclude() {
    let (db, c) = common::migrated().await;
    let web = host(&c, 1, None, Some("web-01"), None).await;
    host(&c, 2, None, Some("win-test-01"), None).await;
    let group = common::rule_group(&c, "N", &[("hostname", true, &["*test*"])]).await;
    assert_eq!(members(&c, &group).await, vec![web]);
    db.drop().await;
}

#[tokio::test]
async fn unknown_facts_never_match_even_when_negated() {
    let (db, c) = common::migrated().await;
    host(&c, 1, None, None, None).await;
    for (name, negate, values, field) in [
        ("H", false, ["*"], "hostname"),
        ("NH", true, ["*test*"], "hostname"),
        ("NI", true, ["10.0.0.0/8"], "ip"),
        ("NO", true, ["windows"], "os_family"),
        ("ND", true, ["debian 12"], "distribution"),
    ] {
        let group = common::rule_group(&c, name, &[(field, negate, &values[..])]).await;
        assert!(members(&c, &group).await.is_empty(), "{name}");
    }
    db.drop().await;
}

#[tokio::test]
async fn any_value_in_a_condition_and_all_conditions() {
    let (db, c) = common::migrated().await;
    let deb = host(&c, 1, Some(("debian", "12")), Some("web-01"), None).await;
    let fed = host(&c, 2, Some(("fedora", "44")), Some("db-01"), None).await;
    host(&c, 3, Some(("ubuntu", "24.04")), Some("web-02"), None).await;
    let any = common::rule_group(
        &c,
        "Any",
        &[("distribution", false, &["debian 12", "fedora 44"])],
    )
    .await;
    let mut both = vec![deb.clone(), fed];
    both.sort();
    assert_eq!(members(&c, &any).await, both);
    let all = common::rule_group(
        &c,
        "All",
        &[
            ("distribution", false, &["debian 12", "fedora 44"]),
            ("hostname", false, &["web-*"]),
        ],
    )
    .await;
    assert_eq!(members(&c, &all).await, vec![deb]);
    db.drop().await;
}

#[tokio::test]
async fn a_rule_group_with_no_conditions_holds_no_one() {
    let (db, c) = common::migrated().await;
    host(&c, 1, Some(("debian", "12")), Some("web-01"), None).await;
    let empty = common::rule_group(&c, "E", &[]).await;
    assert!(members(&c, &empty).await.is_empty());
    db.drop().await;
}

#[tokio::test]
async fn manual_groups_hold_exactly_their_picked_hosts() {
    let (db, c) = common::migrated().await;
    let a = host(&c, 1, Some(("debian", "12")), None, None).await;
    host(&c, 2, Some(("debian", "12")), None, None).await;
    let group = common::manual_group(&c, "M", &[&a]).await;
    assert_eq!(members(&c, &group).await, vec![a]);
    db.drop().await;
}

#[tokio::test]
async fn revoked_and_imported_hosts_are_in_no_group() {
    let (db, c) = common::migrated().await;
    let revoked = host(&c, 1, Some(("debian", "12")), Some("web-01"), None).await;
    c.execute(
        "UPDATE agents SET status = 'revoked', revoked_at = now() WHERE agent_id = $1",
        &[&revoked],
    )
    .await
    .unwrap();
    c.batch_execute(
        "INSERT INTO agents (agent_id, status, enrolled_at, hostname, os_id, os_version)
         VALUES ('import.1', 'imported', now(), 'web-02', 'debian', '12')",
    )
    .await
    .unwrap();
    let rule = common::rule_group(&c, "R", &[("os_family", false, &["linux"])]).await;
    let manual = common::manual_group(&c, "M", &[&revoked, "import.1"]).await;
    assert!(members(&c, &rule).await.is_empty());
    assert!(members(&c, &manual).await.is_empty());
    db.drop().await;
}

#[tokio::test]
async fn agent_visibility_uses_the_function() {
    let (db, c) = common::migrated().await;
    let deb = host(&c, 1, Some(("debian", "12")), None, None).await;
    let fed = host(&c, 2, Some(("fedora", "44")), None, None).await;
    host(&c, 3, Some(("ubuntu", "24.04")), None, None).await;
    let rule = common::rule_group(&c, "R", &[("distribution", false, &["debian 12"])]).await;
    let manual = common::manual_group(&c, "M", &[&fed]).await;
    let scope = AgentScope::AssetGroups(vec![rule, manual]);
    let mut expected = vec![deb, fed];
    expected.sort();
    assert_eq!(agent_ids_in_scope(&c, &scope).await.unwrap(), expected);
    db.drop().await;
}
