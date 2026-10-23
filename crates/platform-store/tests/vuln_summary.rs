//! A vulnerability's page (step 5b rulings 2, 7, 9, 12): the summary and
//! the Hosts table of one CVE (or CVE-less advisory) over the pairs in the
//! viewer's reach, and how a key resolves.

mod common;

use chrono::Utc;
use common::{
    hosts::id,
    vulns::{ANN, fixture},
};
use platform_store::{
    Client,
    console_read::AgentScope,
    vuln_list::{AssigneeSummary, Fixed, VulnSeverity},
    vuln_summary::{
        Fix, HostSegment, Lookup, PageScopes, VulnHostsPage, VulnPageSummary, reaches_any,
        vuln_hosts, vuln_summary,
    },
};

fn scopes(read: &AgentScope) -> PageScopes<'_> {
    PageScopes {
        read,
        alarms: None,
        cases: None,
    }
}

async fn summary(c: &Client, key: &str, s: &PageScopes<'_>) -> Lookup<VulnPageSummary> {
    vuln_summary(c, key, s, Utc::now().date_naive())
        .await
        .unwrap()
}

async fn found(c: &Client, key: &str, s: &PageScopes<'_>) -> VulnPageSummary {
    match summary(c, key, s).await {
        Lookup::Found(v) => v,
        other => panic!("{key}: {other:?}"),
    }
}

async fn hosts(
    c: &Client,
    key: &str,
    scope: &AgentScope,
    segment: HostSegment,
    offset: i64,
    limit: i64,
) -> VulnHostsPage {
    match vuln_hosts(
        c,
        key,
        scope,
        segment,
        offset,
        limit,
        Utc::now().date_naive(),
    )
    .await
    .unwrap()
    {
        Lookup::Found(p) => p,
        other => panic!("{key}: {other:?}"),
    }
}

/// Host 4 (outside Web) also has DEBIAN-A open, a triage change, an open
/// alarm and a case holding the pair; so does host 1.
async fn outside(c: &Client) {
    c.batch_execute(&format!(
        "INSERT INTO vulnerabilities (agent_id, advisory_id, packages, first_seen_at, fixed_at, last_evaluated_at)
         VALUES ('{h4}', 'DEBIAN-A', '[{{\"name\":\"curl\",\"installed\":\"7.88-0\",\"fixed\":\"7.88-2\"}}]', now(), NULL, now());
         INSERT INTO vulnerability_triage_history (agent_id, advisory_id, from_state, to_state, note, changed_at, changed_by)
         VALUES ('{h4}', 'DEBIAN-A', 'open', 'mitigated', 'secret note', now() + interval '1 hour', '{ANN}');
         INSERT INTO vulnerability_triage_history (agent_id, advisory_id, from_state, to_state, note, changed_at, changed_by)
         SELECT '{h1}', 'DEBIAN-A', 'open', 'open', 'n' || g, now() - g * interval '1 minute', '{ANN}'
         FROM generate_series(1, 60) g;
         INSERT INTO cases (case_id, title, status, severity, opened_by_user_id, created_at, updated_at) VALUES
           ('00000000-0000-0000-0000-0000000000c1', 'Curl', 'open', 'high', '{ANN}', now(), now()),
           ('00000000-0000-0000-0000-0000000000c2', 'Secret', 'open', 'high', '{ANN}', now(), now());
         INSERT INTO case_items (item_id, case_id, kind, ref, agent_id, added_by_user_id, added_at) VALUES
           (gen_random_uuid(), '00000000-0000-0000-0000-0000000000c1', 'vulnerability', '{h1}/DEBIAN-A', '{h1}', '{ANN}', now()),
           (gen_random_uuid(), '00000000-0000-0000-0000-0000000000c2', 'vulnerability', '{h4}/DEBIAN-A', '{h4}', '{ANN}', now());",
        h1 = id(1),
        h4 = id(4),
    ))
    .await
    .unwrap();
    common::seed_alarm(c, id(1), "high", "open").await;
    common::seed_alarm(c, id(4), "critical", "open").await;
}

#[tokio::test]
async fn cve_summary_stays_inside_the_scope() {
    let (db, c) = common::migrated().await;
    let (web, alpha) = fixture(&c).await;
    outside(&c).await;
    let web = AgentScope::AssetGroups(vec![web]);
    let s = found(
        &c,
        "CVE-A",
        &PageScopes {
            read: &web,
            alarms: Some(&web),
            cases: Some(&web),
        },
    )
    .await;
    assert_eq!(s.key, "CVE-A");
    assert_eq!((s.header.open, s.header.total), (1, 3), "host 4 left out");
    assert_eq!(s.agents.len(), 3);
    assert!(!s.agents.contains(&id(4).to_owned()));
    let debian = s.what_to_do.iter().find(|d| d.os_id == "debian").unwrap();
    assert_eq!(debian.hosts, 2, "hosts 1 and 2, not 4");
    assert!(s.history.iter().all(|e| e.agent_id != id(4)));
    assert!(
        s.history
            .iter()
            .all(|e| e.note.as_deref() != Some("secret note"))
    );
    let alarms = s.related.alarms.as_ref().unwrap();
    assert_eq!(alarms.total, 1);
    assert!(alarms.items.iter().all(|a| a.severity != "critical"));
    let cases = s.related.cases.as_ref().unwrap();
    assert_eq!(cases.len(), 1);
    assert_eq!(cases[0].title, "Curl");
    let page = hosts(&c, "CVE-A", &web, HostSegment::All, 0, 50).await;
    assert_eq!(page.total, 3);
    assert!(page.rows.iter().all(|r| r.agent_id != id(4)));

    // Alpha holds host 1 only: one Debian pair, no Fedora step.
    let alpha = AgentScope::AssetGroups(vec![alpha]);
    let s = found(&c, "CVE-A", &scopes(&alpha)).await;
    assert_eq!((s.header.open, s.header.total), (1, 1));
    assert_eq!(s.what_to_do.len(), 1);
    assert_eq!(s.details.advisories.len(), 1);
    assert!(s.also_covers.is_empty(), "FEDORA-1 is out of reach");
    // A CVE only on an out-of-reach host reads as missing, as a missing one.
    assert!(matches!(
        summary(&c, "CVE-OUT", &scopes(&web)).await,
        Lookup::Missing
    ));
    assert!(matches!(
        vuln_hosts(
            &c,
            "CVE-OUT",
            &web,
            HostSegment::All,
            0,
            50,
            Utc::now().date_naive()
        )
        .await
        .unwrap(),
        Lookup::Missing
    ));
    found(&c, "CVE-OUT", &scopes(&AgentScope::Global)).await;
    db.drop().await;
}

#[tokio::test]
async fn each_kind_of_key_resolves() {
    let (db, c) = common::migrated().await;
    let (web, _) = fixture(&c).await;
    let web = AgentScope::AssetGroups(vec![web]);
    let s = scopes(&web);
    // a CVE: its page
    assert_eq!(found(&c, "CVE-B", &s).await.key, "CVE-B");
    // an advisory with one CVE: that CVE's page
    let a = found(&c, "DEBIAN-A", &s).await;
    assert_eq!(a.key, "CVE-A");
    assert_eq!(a.header.total, 3, "every advisory naming CVE-A");
    // an advisory with no CVE: its own page
    assert_eq!(found(&c, "DSA-NOCVE", &s).await.key, "DSA-NOCVE");
    // an advisory with several CVEs
    match summary(&c, "FEDORA-1", &s).await {
        Lookup::SeveralCves(cves) => assert_eq!(cves, ["CVE-A", "CVE-B"]),
        other => panic!("{other:?}"),
    }
    // ...but not out of reach, nor a CPE match key, nor nothing
    let alpha_only = AgentScope::AssetGroups(vec!["00000000-0000-4000-8000-00000000dead".into()]);
    for (key, scope) in [
        ("FEDORA-1", &alpha_only),
        ("CPE:CVE-CPE:nginx", &web),
        ("CVE-NOPE", &web),
        ("", &web),
    ] {
        assert!(
            matches!(summary(&c, key, &scopes(scope)).await, Lookup::Missing),
            "{key}"
        );
    }
    // A CVE with only lower-confidence matches shows them.
    let cpe = found(&c, "CVE-CPE", &s).await;
    assert_eq!(cpe.header.total, 1);
    assert_eq!(cpe.details.confidence.max, 60);
    db.drop().await;
}

#[tokio::test]
async fn what_to_do_is_per_distribution_with_reboot() {
    let (db, c) = common::migrated().await;
    let (web, _) = fixture(&c).await;
    let web = AgentScope::AssetGroups(vec![web]);
    let s = found(&c, "CVE-A", &scopes(&web)).await;
    let steps: Vec<_> = s
        .what_to_do
        .iter()
        .map(|d| {
            (
                d.os_id.as_str(),
                d.os_version.as_str(),
                d.advisory_id.as_str(),
                d.packages.clone(),
                d.hosts,
                d.reboot,
            )
        })
        .collect();
    assert_eq!(
        steps,
        [
            (
                "debian",
                "12",
                "DEBIAN-A",
                vec![("curl".to_owned(), Some("7.88-2".to_owned()))],
                2,
                false
            ),
            (
                "fedora",
                "44",
                "FEDORA-1",
                vec![("curl".to_owned(), Some("2".to_owned()))],
                1,
                false
            ),
        ]
    );
    assert_eq!(s.tiles.fix, Fix::All);
    assert_eq!(s.header.title, "curl: flaw A");
    assert_eq!(s.header.severity, VulnSeverity::Critical);
    assert_eq!(s.header.packages, ["curl"]);
    assert_eq!(s.header.fixed, Fixed::Several(2));
    assert_eq!(
        s.header.assignee,
        AssigneeSummary::One(ANN.into(), "Ann".into())
    );
    assert!(s.header.kev_due.is_some());
    assert_eq!(s.tiles.cvss, Some(9.8));
    assert_eq!(s.tiles.epss_percentile, Some(0.9));
    assert_eq!(s.details.confidence.min, 95);
    assert_eq!(s.details.confidence.max, 98);
    let ids: Vec<_> = s.details.advisories.iter().map(|a| a.id.as_str()).collect();
    assert_eq!(ids, ["DEBIAN-A", "FEDORA-1"]);
    let nocve = found(&c, "DSA-NOCVE", &scopes(&web)).await;
    assert!(nocve.what_to_do[0].reboot);
    let nf = found(&c, "CVE-NF", &scopes(&web)).await;
    assert_eq!(nf.tiles.fix, Fix::None);
    assert_eq!(nf.what_to_do[0].packages, [("zlib".to_owned(), None)]);
    assert_eq!(nf.what_to_do[0].hosts, 2);
    assert_eq!((nf.header.open, nf.header.total), (2, 2));
    assert_eq!(nf.details.confidence.max, 90);
    db.drop().await;
}

#[tokio::test]
async fn the_four_segments_add_up_and_page() {
    let (db, c) = common::migrated().await;
    let (web, _) = fixture(&c).await;
    let web = AgentScope::AssetGroups(vec![web]);
    let all = hosts(&c, "CVE-A", &web, HostSegment::All, 0, 50).await;
    let g = all.segments;
    assert_eq!((g.all, g.open, g.mitigated, g.resolved), (3, 1, 1, 1));
    assert_eq!(g.open + g.mitigated + g.resolved, g.all);
    let names: Vec<_> = all
        .rows
        .iter()
        .map(|r| r.hostname.as_deref().unwrap())
        .collect();
    assert_eq!(names, ["db-01", "web-01", "web-02"]);
    let h1 = &all.rows[1];
    assert_eq!(h1.advisory_id, "DEBIAN-A");
    assert_eq!(h1.installed, "7.88-1");
    assert_eq!(h1.state, "open");
    assert_eq!(h1.assignee, Some((ANN.to_owned(), "Ann".to_owned())));
    assert_eq!(h1.triage_version, Some(1));
    assert_eq!(all.rows[0].state, "accepted_risk");
    let second = hosts(&c, "CVE-A", &web, HostSegment::All, 1, 1).await;
    assert_eq!(second.total, 3);
    assert_eq!(second.rows.len(), 1);
    assert_eq!(second.rows[0].agent_id, id(1));
    for (segment, want) in [
        (HostSegment::Open, vec![id(1)]),
        (HostSegment::Mitigated, vec![id(2)]),
        (HostSegment::Resolved, vec![id(3)]),
    ] {
        let p = hosts(&c, "CVE-A", &web, segment, 0, 50).await;
        let got: Vec<_> = p.rows.iter().map(|r| r.agent_id.as_str()).collect();
        assert_eq!(got, want, "{segment:?}");
        assert_eq!(p.total, 1);
    }
    // No-fix pairs: open, untriaged, the installed version from inventory.
    let nf = hosts(&c, "CVE-NF", &web, HostSegment::All, 0, 50).await;
    assert_eq!(nf.total, 2);
    assert_eq!(nf.rows[0].triage_version, None);
    assert_eq!(nf.rows[0].state, "open");
    assert!(!nf.rows[0].installed.is_empty());
    // An advisory with one CVE answers for the CVE.
    assert_eq!(
        hosts(&c, "DEBIAN-A", &web, HostSegment::All, 0, 50)
            .await
            .total,
        3
    );
    db.drop().await;
}

#[tokio::test]
async fn history_is_scoped_and_capped() {
    let (db, c) = common::migrated().await;
    let (web, _) = fixture(&c).await;
    outside(&c).await;
    let web = AgentScope::AssetGroups(vec![web]);
    let s = found(&c, "CVE-A", &scopes(&web)).await;
    assert_eq!(s.history.len(), 50);
    assert!(s.history.windows(2).all(|w| w[0].at >= w[1].at));
    let first = &s.history[0];
    assert_eq!(first.note.as_deref(), Some("n1"));
    assert_eq!(first.actor, "Ann");
    assert_eq!(first.hostname.as_deref(), Some("web-01"));
    assert_eq!(first.advisory_id, "DEBIAN-A");
    assert_eq!(
        (first.from_state.as_deref(), first.to_state.as_str()),
        (Some("open"), "open")
    );
    db.drop().await;
}

#[tokio::test]
async fn related_respects_alarms_read_and_cases_read() {
    let (db, c) = common::migrated().await;
    let (web, _) = fixture(&c).await;
    outside(&c).await;
    let web = AgentScope::AssetGroups(vec![web]);
    let s = found(&c, "CVE-A", &scopes(&web)).await;
    assert!(s.related.alarms.is_none());
    assert!(s.related.cases.is_none());
    // Same package: CVE-B on curl, critical (FEDORA-1).
    assert_eq!(s.related.same_package.cves, 1);
    assert_eq!(
        s.related.same_package.severities,
        [(VulnSeverity::Critical, 1)]
    );
    let global = AgentScope::Global;
    let s = found(
        &c,
        "CVE-A",
        &PageScopes {
            read: &web,
            alarms: Some(&global),
            cases: Some(&global),
        },
    )
    .await;
    assert_eq!(
        s.related.alarms.unwrap().total,
        1,
        "only hosts in read reach"
    );
    assert_eq!(s.related.cases.unwrap().len(), 1);
    db.drop().await;
}

#[tokio::test]
async fn also_covers_lists_the_sibling_cves() {
    let (db, c) = common::migrated().await;
    let (web, _) = fixture(&c).await;
    let web = AgentScope::AssetGroups(vec![web]);
    assert_eq!(
        found(&c, "CVE-A", &scopes(&web)).await.also_covers,
        ["CVE-B"]
    );
    assert_eq!(
        found(&c, "CVE-B", &scopes(&web)).await.also_covers,
        ["CVE-A"]
    );
    assert!(
        found(&c, "CVE-NF", &scopes(&web))
            .await
            .also_covers
            .is_empty()
    );
    db.drop().await;
}

#[tokio::test]
async fn reaches_any_checks_the_hosts_against_a_scope() {
    let (db, c) = common::migrated().await;
    let (web, alpha) = fixture(&c).await;
    let web = AgentScope::AssetGroups(vec![web]);
    let alpha = AgentScope::AssetGroups(vec![alpha]);
    let s = found(&c, "CVE-B", &scopes(&web)).await;
    assert!(!reaches_any(&c, &s.agents, &alpha).await.unwrap(), "host 3");
    assert!(reaches_any(&c, &s.agents, &web).await.unwrap());
    assert!(
        reaches_any(&c, &s.agents, &AgentScope::Global)
            .await
            .unwrap()
    );
    db.drop().await;
}

/// The header says whether the CVE is exploited as the list does (KEV or
/// EUVD; EUVD alone has no due date), and names the advisory its title is from.
#[tokio::test]
async fn header_marks_euvd_only_exploitation_and_names_the_lead_advisory() {
    let (db, c) = common::migrated().await;
    let (web, _) = fixture(&c).await;
    let web = AgentScope::AssetGroups(vec![web]);
    let s = scopes(&web);
    let a = found(&c, "CVE-A", &s).await;
    assert!(a.header.exploited, "on KEV");
    assert_eq!(
        (a.header.advisory_id.as_str(), a.header.title.as_str()),
        ("DEBIAN-A", "curl: flaw A"),
        "two pairs beat FEDORA-1's one"
    );
    assert!(!found(&c, "CVE-EXP", &s).await.header.exploited);
    c.execute(
        "UPDATE cve_enrichment SET euvd_exploited = true WHERE cve_id = 'CVE-EXP'",
        &[],
    )
    .await
    .unwrap();
    let exp = found(&c, "CVE-EXP", &s).await;
    assert!(exp.header.exploited, "EUVD only");
    assert_eq!(exp.header.kev_due, None);
    assert_eq!(exp.header.advisory_id, "DEBIAN-EXP");
    assert_eq!(
        found(&c, "DSA-NOCVE", &s).await.header.advisory_id,
        "DSA-NOCVE"
    );
    db.drop().await;
}
