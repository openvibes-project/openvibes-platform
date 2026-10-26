//! Status's line about the console's own certificate (4c). You renew it, so
//! the platform's "automatic renewal is failing" never applies: Status says
//! when it ends, that it ended, or that it covers none of the console's names.

use chrono::{DateTime, Utc};
use platform_host::Host;

use super::database::{Check, check};

/// Days before it ends that Status (and Certificates) warns.
pub const WARN_DAYS: i64 = 30;
const HELP: &str = "Use a new one in Maintenance › Certificates.";

/// The console's names: the plan's, then this host's addresses. Names come
/// from the plan; without it, none.
pub fn console_names<H: Host>(host: &H) -> Vec<String> {
    let mut names = host
        .setup_plan()
        .ok()
        .and_then(|text| crate::setup::plan::plan_of(&text).ok())
        .map(|plan| plan.names())
        .unwrap_or_default();
    if !names.is_empty() {
        names.extend(host.addresses());
    }
    names
}

/// The line for the own certificate `pem`, if anything is wrong. `names` are
/// the console's (the plan's, then the host's addresses); none known, none
/// judged.
pub fn console_cert_check(pem: &str, names: &[String], now: DateTime<Utc>) -> Option<Check> {
    let Ok(expires) = platform_pki::not_after(pem) else {
        return Some(check(
            true,
            "Console certificate: yours cannot be read".into(),
        ));
    };
    let date = expires.format("%Y-%m-%d");
    if expires <= now {
        return Some(Check {
            red: true,
            ..check(true, format!("Console certificate: yours ended on {date}"))
        });
    }
    let days = (expires - now).num_days();
    if days <= WARN_DAYS {
        let left = days_left(days);
        return Some(Check {
            help: Some(HELP.into()),
            ..check(
                true,
                format!("Console certificate: yours ends {date}, {left}"),
            )
        });
    }
    let covered = names.iter().any(|name| platform_pki::covers(pem, name));
    (!names.is_empty() && !covered).then(|| {
        check(
            true,
            "Console certificate: covers none of this console's names".into(),
        )
    })
}

/// "today", "in 1 day", "in 21 days".
pub fn days_left(days: i64) -> String {
    match days {
        0 => "today".to_owned(),
        1 => "in 1 day".to_owned(),
        n => format!("in {n} days"),
    }
}

#[cfg(test)]
mod tests {
    use chrono::Duration;

    use super::*;

    const OWN: &str = include_str!("../../../platform-pki/tests/fixtures/server.crt");

    fn names() -> Vec<String> {
        platform_pki::subject_alt_names(OWN).unwrap()
    }

    fn at(days_before_end: i64, names: &[String]) -> Option<Check> {
        let end = platform_pki::not_after(OWN).unwrap();
        console_cert_check(OWN, names, end - Duration::days(days_before_end))
    }

    #[test]
    fn yours_warns_30_days_before() {
        assert_eq!(at(31, &names()), None);
        let line = at(30, &names()).unwrap();
        assert!(line.problem);
        assert!(!line.red);
        assert!(
            line.text.starts_with("Console certificate: yours ends 20")
                && line.text.ends_with(", in 30 days"),
            "{}",
            line.text
        );
        assert_eq!(
            line.help.as_deref(),
            Some("Use a new one in Maintenance › Certificates.")
        );
    }

    #[test]
    fn yours_is_red_once_ended() {
        let line = at(-1, &names()).unwrap();
        assert!(line.problem && line.red);
        assert!(
            line.text
                .starts_with("Console certificate: yours ended on 20")
        );
    }

    #[test]
    fn yours_never_says_renewal_is_failing() {
        for days in [-1, 10, 30] {
            assert!(!at(days, &names()).unwrap().text.contains("renewal"));
        }
    }

    #[test]
    fn one_day_and_less_than_a_day_read_naturally() {
        let end = platform_pki::not_after(OWN).unwrap();
        let text = |left: Duration| console_cert_check(OWN, &names(), end - left).unwrap().text;
        assert!(text(Duration::days(1)).ends_with(", in 1 day"));
        assert!(text(Duration::hours(12)).ends_with(", today"));
    }

    #[test]
    fn an_unreadable_plan_never_says_covers_none() {
        use crate::tui::{database::health_checks, script_host::app_with_plan};
        let mut app = app_with_plan("", vec![]);
        app.host.own = Some(OWN.into());
        let health = health_checks(&app.host);
        assert!(
            health.iter().all(|c| !c.text.contains("covers none")),
            "{health:?}"
        );
    }

    #[test]
    fn names_dropped_after_says_so() {
        let other = ["gone.example.org".to_owned()];
        assert_eq!(
            at(90, &other).unwrap().text,
            "Console certificate: covers none of this console's names"
        );
        assert_eq!(at(90, &names()), None);
    }

    #[test]
    fn health_judges_the_console_by_this_check_alone() {
        use crate::tui::{database::health_checks, script_host::app_with_plan};
        const EXPIRED: &str =
            include_str!("../../../platform-pki/tests/fixtures/server-expired.crt");
        let mut app = app_with_plan(crate::tui::script_host::PLAN, vec![]);
        app.host.pems = vec![("/etc/openvibes/tls/console-chain.pem", EXPIRED.into())];
        app.host.own = Some(OWN.into());
        let health = health_checks(&app.host);
        // The plan's names are not on the fixture: only the names line.
        assert!(
            health
                .iter()
                .any(|c| c.text == "Console certificate: covers none of this console's names"),
            "{health:?}"
        );
        assert!(
            health.iter().all(|c| !c.text.contains("console-chain")),
            "{health:?}"
        );
    }
}
