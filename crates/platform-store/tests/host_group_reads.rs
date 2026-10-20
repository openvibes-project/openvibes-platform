//! Host-group reads: lists and counts inside the caller's scope, member
//! hosts, and the preview before a save.
mod common;

use common::groups::*;
use common::{manual_group, migrated, rule_group, seed_alarm, seed_host_vuln_counts, seed_role};
use platform_store::{
    console_read::AgentScope,
    host_group_writes::{self, GroupContent, HostRef, PersonRef, PreviewOutcome},
    host_groups::{self, GroupKind},
};

#[tokio::test]
async fn groups_are_listed_with_counts_inside_the_scope() {
    let (db, c) = migrated().await;
    fleet(&c).await;
    seed_alarm(&c, A1, "high", "open").await;
    seed_alarm(&c, A2, "high", "open").await;
    seed_host_vuln_counts(&c, A1, 2, 0, 0, 0).await;
    seed_host_vuln_counts(&c, A2, 5, 0, 0, 0).await;
    let linux = rule_group(&c, "Linux hosts", &[("os_family", false, &["linux"])]).await;
    let web = manual_group(&c, "Web", &[A1]).await;
    group_role(&c, "webteam", &web).await;
    person(&c, U1, "ann", true).await;
    person(&c, U2, "bob", false).await;
    bind(&c, U1, "webteam").await;
    bind(&c, U2, "webteam").await;
    manual_group(&c, "Both", &[A1, A2, A3]).await;

    let all = host_groups::list(&c, &AgentScope::Global).await.unwrap();
    let l = named(&all, "Linux hosts");
    assert_eq!((l.kind, l.hosts, l.online), (GroupKind::Rule, 2, 1));
    assert_eq!((l.open_alarms, l.critical, l.people), (2, 7, 0));
    assert_eq!(l.conditions, [cond("os_family", false, &["linux"])]);
    assert!(l.roles.is_empty());
    let w = named(&all, "Web");
    assert_eq!(
        (w.kind, w.picked, w.hosts, w.people),
        (GroupKind::Manual, 1, 1, 1)
    );
    assert_eq!(w.roles, [("webteam".to_string(), "Webteam".to_string())]);

    let scope = AgentScope::AssetGroups(vec![web.clone()]);
    let scoped = host_groups::list(&c, &scope).await.unwrap();
    assert_eq!(scoped.len(), 3, "every group is listed");
    assert_eq!(
        named(&all, "Both").picked,
        2,
        "the revoked old-03 is not counted"
    );
    assert_eq!(
        named(&scoped, "Both").picked,
        1,
        "db-02 is outside the scope"
    );
    let l = named(&scoped, "Linux hosts");
    assert_eq!((l.hosts, l.online, l.open_alarms, l.critical), (1, 1, 1, 2));

    let detail = host_groups::detail(&c, &linux, &scope)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(detail.hosts, 1);
    assert!(
        host_groups::detail(&c, "nope", &scope)
            .await
            .unwrap()
            .is_none()
    );

    let hosts = host_groups::hosts(&c, &linux, &AgentScope::Global, None, 10)
        .await
        .unwrap();
    let ids: Vec<&str> = hosts.iter().map(|h| h.agent_id.as_str()).collect();
    assert_eq!(ids, [A2, A1], "by hostname");
    let h = &hosts[1];
    assert_eq!(h.hostname.as_deref(), Some("web-01"));
    assert_eq!(h.distribution.as_deref(), Some("Debian 12"));
    assert_eq!(h.last_address.as_deref(), Some("10.0.0.1"));
    assert_eq!((h.online, h.open_alarms, h.critical), (true, 1, 2));
    assert_eq!(h.why, "Matches the rule");
    assert!(!hosts[0].online);
    let page = host_groups::hosts(&c, &linux, &AgentScope::Global, Some(A2), 10)
        .await
        .unwrap();
    assert_eq!(page.len(), 1);
    assert_eq!(page[0].agent_id, A1);
    let scoped = host_groups::hosts(&c, &linux, &scope, None, 10)
        .await
        .unwrap();
    assert_eq!(scoped.len(), 1);
    let past_hidden = host_groups::hosts(&c, &linux, &scope, Some(A2), 10)
        .await
        .unwrap();
    assert!(past_hidden.is_empty(), "db-02 is outside the scope");
    let picked = host_groups::hosts(&c, &web, &AgentScope::Global, None, 10)
        .await
        .unwrap();
    assert_eq!(picked[0].why, "Picked by hand");
    db.drop().await;
}

#[tokio::test]
async fn preview_lists_joins_leaves_and_who_gains_or_loses() {
    let (db, c) = migrated().await;
    fleet(&c).await;
    let web = manual_group(&c, "Web", &[A1]).await;
    group_role(&c, "webteam", &web).await;
    seed_role(&c, "everything", &["hosts.read"]).await;
    person(&c, U1, "ann", true).await;
    person(&c, U2, "bob", true).await;
    person(&c, U3, "cid", false).await;
    bind(&c, U1, "webteam").await;
    bind(&c, U2, "webteam").await;
    bind(&c, U2, "everything").await;
    bind(&c, U3, "webteam").await;

    let picked = [A2.to_string()];
    let p = host_group_writes::preview(&c, Some(&web), Some(&GroupContent::Manual(&picked)))
        .await
        .unwrap()
        .ready();
    assert_eq!(
        p.joins,
        [HostRef {
            agent_id: A2.into(),
            hostname: Some("db-02".into())
        }]
    );
    assert_eq!(
        p.leaves,
        [HostRef {
            agent_id: A1.into(),
            hostname: Some("web-01".into())
        }]
    );
    let ann = PersonRef {
        user_id: U1.into(),
        username: "ann".into(),
        display_name: "Ann".into(),
    };
    assert_eq!(
        p.gains,
        std::slice::from_ref(&ann),
        "bob reaches all hosts anyway; cid is disabled"
    );
    assert_eq!(p.loses, [ann]);
    assert_eq!(
        (p.joins_total, p.leaves_total, p.overrides_removed),
        (1, 1, 0)
    );

    let rule = [cond("hostname", false, &["WEB-*"])];
    let p = host_group_writes::preview(&c, None, Some(&GroupContent::Rule(&rule)))
        .await
        .unwrap()
        .ready();
    assert_eq!(
        p.joins.len(),
        1,
        "case-insensitive; the revoked old-03 never joins"
    );
    assert!(p.leaves.is_empty() && p.gains.is_empty());
    let p = host_group_writes::preview(
        &c,
        Some(&web),
        Some(&GroupContent::Manual(&[A1.to_string()])),
    )
    .await
    .unwrap()
    .ready();
    assert!(p.joins.is_empty() && p.leaves.is_empty() && p.gains.is_empty() && p.loses.is_empty());
    let missing = "00000000-0000-4000-8000-00000000ffff";
    let gone = host_group_writes::preview(&c, Some(missing), None)
        .await
        .unwrap();
    assert!(matches!(gone, PreviewOutcome::NotFound), "{gone:?}");
    // a bad rule is refused by name before any value reaches the database
    for (rule, part) in [
        (vec![cond("ip", false, &["10.0.0.0/33"])], "ip"),
        (vec![cond("hostname", false, &[])], "hostname"),
    ] {
        let refused = host_group_writes::preview(&c, Some(&web), Some(&GroupContent::Rule(&rule)))
            .await
            .unwrap();
        assert!(
            matches!(&refused, PreviewOutcome::Invalid(p) if p == part),
            "{refused:?}"
        );
    }
    db.drop().await;
}

/// Group pages count critical as the Hosts list and the host page do
/// (`host_listed_critical`), not the fleet summary's fixable-only count.
#[tokio::test]
async fn group_critical_is_the_hosts_list_count() {
    let (db, c) = migrated().await;
    fleet(&c).await;
    seed_host_vuln_counts(&c, A1, 2, 0, 0, 0).await;
    c.execute(
        "UPDATE host_listed_critical SET critical = 4 WHERE agent_id = $1",
        &[&A1],
    )
    .await
    .unwrap();
    let web = manual_group(&c, "Web", &[A1]).await;
    let all = host_groups::list(&c, &AgentScope::Global).await.unwrap();
    assert_eq!(named(&all, "Web").critical, 4);
    let hosts = host_groups::hosts(&c, &web, &AgentScope::Global, None, 10)
        .await
        .unwrap();
    assert_eq!(hosts[0].critical, 4);
    db.drop().await;
}
