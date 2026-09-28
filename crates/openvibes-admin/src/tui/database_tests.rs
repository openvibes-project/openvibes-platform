//! The Database and Health screens against the fake host, at 80×24.

use chrono::{Duration, Utc};
use platform_host::{Database, DiskUse, HostError, ServiceStatus, Unit};

use super::{
    app::{Key, Tab},
    database::checks,
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
        Utc::now(),
    );
    assert_eq!(checks.len(), 1);
    assert!(checks[0].problem && checks[0].text == "database: failed: connection refused");
}
