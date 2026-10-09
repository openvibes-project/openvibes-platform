//! The Database and Health screens against the fake host, at 80×24.

use chrono::{DateTime, Duration, Utc};
use platform_host::{Database, DiskUse, HostError, ServiceStatus, Unit};

use super::{
    app::{Key, Tab},
    database::{checks, tune_check},
    tests::{app, screen},
};

#[test]
fn database_shows_the_status_and_migrates_only_after_yes() {
    let mut app = app(false);
    app.open_database();
    let text = screen(&app, 80, 24);
    assert!(text.contains("[Database]"), "{text}");
    assert!(text.contains("partition count 98"), "{text}");
    assert!(text.contains("database size 42 MiB"), "{text}");
    app.key(Key::Char('m'));
    assert!(screen(&app, 80, 24).contains("Migrate the database schema? y/n"));
    app.key(Key::Char('x'));
    app.key(Key::Char('n'));
    app.key(Key::Char('y'));
    assert_eq!(
        *app.host.database_calls.borrow(),
        [Database::Status, Database::Maintenance, Database::Status]
    );
    assert!(
        screen(&app, 80, 24).contains("created 1 partitions, dropped 1"),
        "{}",
        screen(&app, 80, 24)
    );
}

#[test]
fn a_refused_database_command_names_the_group() {
    let mut app = app(true);
    app.open_database();
    assert!(screen(&app, 80, 24).contains("openvibes-operators"));
}

#[test]
fn health_lists_problems_first() {
    let mut app = app(false);
    app.open_database();
    app.key(Key::Tab);
    assert_eq!(app.tab, Tab::Health);
    let text = screen(&app, 80, 24);
    let rows: Vec<&str> = text.lines().collect();
    let first = rows.iter().position(|r| r.contains("problem  ")).unwrap();
    let last_problem = rows.iter().rposition(|r| r.contains("problem  ")).unwrap();
    let first_ok = rows.iter().position(|r| r.contains("ok       ")).unwrap();
    assert!(first < first_ok && last_problem < first_ok, "{text}");
    // Fake host: vulns failed, llm inactive, the certificate unreadable, one feed error.
    assert!(text.contains("health: 4 problems"), "{text}");
    for want in [
        "vulns: failed",
        "ingest.crt: failed: permission denied",
        "feed osv-rocky",
        "ingest: active, ready",
        "/var/lib/pgsql: 40% used, 20G free",
    ] {
        assert!(text.contains(want), "missing {want:?} in\n{text}");
    }
}

#[test]
fn certificates_disk_and_feeds_become_problems_at_their_thresholds() {
    let pem = platform_pki::generate_root(Utc::now()).unwrap().cert_pem;
    let expires = platform_pki::not_after(&pem).unwrap();
    let certificate = [("/c.crt", Ok(pem))];
    let disk = |used_percent| {
        Ok(vec![DiskUse {
            path: "/d".into(),
            used_percent,
            available: "1G".into(),
        }])
    };
    let only = |now, used, feeds: &str| {
        checks(
            &[] as &[ServiceStatus],
            &certificate,
            Ok(feeds.into()),
            disk(used),
            Ok(String::new()),
            now,
        )
    };
    let fine = only(expires - Duration::days(80), 89, "no feeds yet\n");
    assert!(fine.iter().all(|c| !c.problem), "{fine:?}");
    assert!(fine.iter().any(|c| c.text == "feeds: 0, no errors"));
    assert!(fine.iter().any(|c| c.text.contains("expires in 80 days")));
    let bad = only(
        expires - Duration::days(10),
        90,
        "a 1 advisories error: x\n",
    );
    assert_eq!(bad.iter().filter(|c| c.problem).count(), 3, "{bad:?}");
    let expired = only(expires + Duration::days(1), 0, "");
    assert!(expired[0].problem && expired[0].text.contains("expired on"));
}

#[test]
fn an_unreachable_database_is_a_problem_and_uninstalled_units_are_left_out() {
    let services = [ServiceStatus {
        unit: Unit::Console,
        installed: false,
        enabled: false,
        active: "inactive".into(),
        ready: None,
        since: None,
    }];
    let checks = checks(
        &services,
        &[],
        Err(HostError::Failed("connection refused".into())),
        Ok(Vec::new()),
        Ok(String::new()),
        Utc::now(),
    );
    assert_eq!(checks.len(), 1);
    assert!(checks[0].problem && checks[0].text == "database: failed: connection refused");
}

#[test]
fn rule_sets_near_expiry_are_problems() {
    let now = DateTime::parse_from_rfc3339("2026-09-28T00:00:00Z")
        .unwrap()
        .with_timezone(&Utc);
    let list = "baseline v1 keys 1 expires 2028-09-27T00:00:00Z\n\
                soon v3 keys 1 expires 2026-10-20T00:00:00Z\n\
                gone v2 keys 1 expires 2026-09-01T00:00:00Z\n\
                old v1 keys 1 expires 2026-09-02T00:00:00Z retired\n\
                empty none keys 1 expires -\n";
    let got = checks(
        &[] as &[ServiceStatus],
        &[],
        Ok(String::new()),
        Ok(Vec::new()),
        Ok(list.into()),
        now,
    );
    let text = |set: &str| got.iter().find(|c| c.text.contains(set)).cloned();
    let fine = text("rule set baseline v1").unwrap();
    assert!(
        !fine.problem && fine.text.contains("expires in 730 days (2028-09-27)"),
        "{got:?}"
    );
    let soon = text("rule set soon v3").unwrap();
    assert!(
        soon.problem && soon.text.contains("expires in 22 days"),
        "{got:?}"
    );
    assert!(soon.text.contains("run Repair"), "{got:?}");
    let gone = text("rule set gone v2").unwrap();
    assert!(
        gone.problem && gone.text.contains("expired on 2026-09-01"),
        "{got:?}"
    );
    assert!(text("old").is_none() && text("empty").is_none(), "{got:?}");
}

#[test]
fn unreadable_rule_sets_are_a_problem() {
    let got = checks(
        &[] as &[ServiceStatus],
        &[],
        Ok(String::new()),
        Ok(Vec::new()),
        Err(HostError::NotOperator),
        Utc::now(),
    );
    assert!(
        got.iter()
            .any(|c| c.problem && c.text.starts_with("rule sets: ")),
        "{got:?}"
    );
}

#[test]
fn a_certificate_missing_one_of_the_hosts_addresses_is_a_problem() {
    let now = Utc::now();
    let root = platform_pki::generate_root(now).unwrap();
    let issuer = platform_pki::Issuer::load(&root.cert_pem, &root.key_pem).unwrap();
    let names = ["metabox-lnx".to_owned(), "192.168.1.10".to_owned()];
    let pem = issuer.issue_server(&names, now).unwrap().cert_pem;
    let certificate = [("/c.crt", Ok(pem))];
    assert!(crate::tui::database::uncovered(&certificate, &["192.168.1.10".into()]).is_empty());
    let moved = crate::tui::database::uncovered(
        &certificate,
        &["192.168.1.10".into(), "192.168.1.23".into()],
    );
    assert_eq!(moved.len(), 1);
    assert!(moved[0].problem);
    assert_eq!(
        moved[0].text,
        "/c.crt: does not cover 192.168.1.23 (this host): press r on Setup to repair"
    );
}

/// Board #107: the site's own sets warn a month ahead and say to publish
/// again (the signer never re-signs on its own); a baseline set at the same
/// distance is fine.
#[test]
fn site_rule_sets_warn_a_month_ahead_to_publish_again() {
    let now = DateTime::parse_from_rfc3339("2026-09-28T00:00:00Z")
        .unwrap()
        .with_timezone(&Utc);
    let list = "site v4 keys 1 expires 2026-10-20T00:00:00Z\n\
                site-alarms v2 keys 1 expires 2026-12-28T00:00:00Z\n";
    let got = checks(
        &[] as &[ServiceStatus],
        &[],
        Ok(String::new()),
        Ok(Vec::new()),
        Ok(list.into()),
        now,
    );
    let soon = got
        .iter()
        .find(|c| c.text.contains("rule set site v4"))
        .unwrap();
    assert!(soon.problem, "{got:?}");
    assert!(
        soon.text.contains("publish again in the console to renew"),
        "{got:?}"
    );
    let later = got
        .iter()
        .find(|c| c.text.contains("site-alarms v2"))
        .unwrap();
    assert!(!later.problem, "91 days left: no warning yet ({got:?})");
}

#[test]
fn the_signers_state_and_refusals_show_in_health() {
    use super::database::signer_checks;
    use platform_host::SignerFiles;
    let key = "Zm9vYmFyYmF6".to_owned() + &"A".repeat(31);
    let trust = Some(format!("site site.key {key}\nsite-alarms site.key {key}\n"));
    let quiet = signer_checks(&SignerFiles {
        status: Ok(
            r#"{"version_state":true,"publishes_last_hour":2,"refusals_last_day":{}}"#.into(),
        ),
        trust: trust.clone(),
    });
    assert!(quiet.iter().all(|c| !c.problem), "{quiet:?}");
    assert!(
        quiet[0].text.contains("2 publishes in the last hour"),
        "{quiet:?}"
    );
    assert!(quiet[1].text.contains("site key Zm9vYmFy…"), "{quiet:?}");
    assert!(
        quiet[1].text.contains("agents trusting an old site key"),
        "{quiet:?}"
    );

    // A wrong password now and then is no problem; the hourly limit is.
    let typo = signer_checks(&SignerFiles {
        status: Ok(r#"{"version_state":true,"refusals_last_day":{"credentials":1}}"#.into()),
        trust: None,
    });
    assert!(
        !typo[0].problem && typo[0].text.contains("credentials 1"),
        "{typo:?}"
    );
    let busy = signer_checks(&SignerFiles {
        status: Ok(
            r#"{"version_state":true,"refusals_last_day":{"rate":3,"credentials":1}}"#.into(),
        ),
        trust: None,
    });
    assert!(
        busy[0].problem && busy[0].text.contains("4 publishes refused"),
        "{busy:?}"
    );

    let lost = signer_checks(&SignerFiles {
        status: Ok(r#"{"version_state":false,"refusals_last_day":{}}"#.into()),
        trust: None,
    });
    assert!(
        lost.iter()
            .any(|c| c.problem && c.text.contains("run Repair")),
        "{lost:?}"
    );
    let denied = signer_checks(&SignerFiles {
        status: Err(HostError::Failed("status.json: permission denied".into())),
        trust: None,
    });
    assert!(
        denied[0].problem && denied[0].text.contains("permission denied"),
        "{denied:?}"
    );
}

/// Board #111: distribution with nothing published leaves every agent
/// without rules; Health says so. Without distribution there's nothing to say.
#[test]
fn distribution_with_no_rule_set_published_is_a_problem() {
    let distribution = |installed| ServiceStatus {
        unit: Unit::Distribution,
        installed,
        enabled: true,
        active: "active".into(),
        ready: Some(true),
        since: None,
    };
    let health = |installed, list: &str| {
        checks(
            &[distribution(installed)],
            &[],
            Ok(String::new()),
            Ok(Vec::new()),
            Ok(list.into()),
            Utc::now(),
        )
    };
    let empty = health(true, "baseline none keys 1 expires -\n");
    assert!(
        empty
            .iter()
            .any(|c| c.problem && c.text.starts_with("no rule set published")),
        "{empty:?}"
    );
    let published = health(true, "baseline v2 keys 1 expires 2030-01-01T00:00:00Z\n");
    assert!(
        !published.iter().any(|c| c.text.starts_with("no rule set")),
        "{published:?}"
    );
    let without = health(false, "");
    assert!(
        !without.iter().any(|c| c.text.starts_with("no rule set")),
        "{without:?}"
    );
}

#[test]
fn fedoras_task_never_audit_rule_is_a_health_problem() {
    use super::database::audit_check;
    use crate::setup::audit_off;
    let fedora = "## First rule - delete all\n-D\n-b 8192\n-a task,never\n\
                  -a always,exit -F arch=b64 -S execve,execveat -F key=openvibes-exec\n";
    assert!(audit_off(fedora));
    assert!(audit_off("-a never,task\n"));
    let check = audit_check(fedora).expect("a problem line");
    assert!(check.problem);
    assert!(check.text.contains("rules.d/audit.rules"), "{}", check.text);
    // Commented out, or only our exec rule: nothing to report.
    assert!(!audit_off(
        "#-a task,never\n-a always,exit -F key=openvibes-exec\n"
    ));
    assert!(audit_check("-a always,exit -S execve -F key=openvibes-exec\n").is_none());
}

#[test]
fn tune_line_shows_the_summary_or_the_hint() {
    let json = r#"{"mode":"cpu","threads":6,"model":"qwen","seconds_per_call":8.4}"#;
    let ok = tune_check(true, Some(json.into())).unwrap();
    assert!(!ok.problem && ok.text.contains("CPU (6 threads) · model qwen · ~8 s"));
    let hint = tune_check(true, None).unwrap();
    assert!(hint.text.contains("turn the assistant on in Setup again"));
    assert!(tune_check(false, None).is_none());
}
