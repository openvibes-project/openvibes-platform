//! The timer's run: skipped while Setup works, a failure only when the
//! step failed.

use std::process::ExitCode;

use chrono::{Duration, Utc};

use super::{renew_gate, renew_plan, renew_run, system};
use crate::setup::{
    fake::{Fake, plan},
    pki::{INTERMEDIATE, INTERMEDIATE_KEY},
    pki_tests::{ADMIN, installed_certificates, with},
    plan::Component::*,
    replace::{PREVIOUS, PREVIOUS_UNTIL},
};

#[test]
fn a_held_setup_lock_skips_the_renewal() {
    let fake = Fake::new("renew-lock");
    let first = system::lock(&fake.root);
    assert!(renew_gate(&first).is_none());
    let (text, code) = renew_gate(&system::lock(&fake.root)).unwrap();
    assert_eq!(
        text,
        "certificate renewal skipped: another Setup run is in progress"
    );
    assert_eq!(code, ExitCode::SUCCESS);
    let (_, code) = renew_gate::<()>(&Err("/run: read-only".into())).unwrap();
    assert_eq!(code, ExitCode::FAILURE);
}

#[test]
fn certificates_with_time_left_are_left_alone() {
    let fake = Fake::new("renew-nothing");
    let names = ["platform.example.com", "10.0.0.5", "localhost", "127.0.0.1"];
    installed_certificates(&fake, &names, 60);
    let (text, code) = renew_run(&fake.ctx(&plan(&[Ingest, Distribution])));
    assert!(text.starts_with("done\t"), "{text}");
    assert_eq!(code, ExitCode::SUCCESS);
}

#[test]
fn a_failed_renewal_exits_with_failure() {
    let fake = Fake::new("renew-fails");
    let names = ["platform.example.com", "10.0.0.5", "localhost", "127.0.0.1"];
    installed_certificates(&fake, &names, 5);
    // No intermediate on the fake host: the reissue cannot start.
    let (text, code) = renew_run(&fake.ctx(&plan(&[Ingest, Distribution])));
    assert!(text.starts_with("failed\t"), "{text}");
    assert_eq!(code, ExitCode::FAILURE);
}

#[test]
fn a_setup_toml_that_cannot_be_read_fails_the_renewal() {
    let fake = Fake::new("renew-broken-plan");
    fake.file("/etc/openvibes/setup.toml", "components = [");
    let (text, code) = renew_plan(&fake.root).unwrap_err();
    assert!(text.starts_with("openvibes-admin: "), "{text}");
    assert!(text.contains("setup.toml"), "{text}");
    assert_eq!(code, ExitCode::FAILURE);
}

#[test]
fn a_failed_renewal_keeps_the_previous_intermediate() {
    let fake = Fake::new("renew-fails-keeps-previous");
    let root = platform_pki::generate_root(Utc::now() - Duration::days(40)).unwrap();
    let intermediate = || {
        let (csr, key) = platform_pki::intermediate_request().unwrap();
        let at = Utc::now() - Duration::days(40);
        (
            platform_pki::sign_intermediate(&root, &csr, at).unwrap(),
            key,
        )
    };
    let (old, new) = (intermediate(), intermediate());
    let bundle = format!("{}{}", new.0, old.0);
    fake.file(INTERMEDIATE, &bundle);
    fake.file(INTERMEDIATE_KEY, &new.1);
    fake.file(PREVIOUS, &old.0);
    let yesterday = (Utc::now() - Duration::days(1)).to_rfc3339();
    fake.file(PREVIOUS_UNTIL, &format!("{yesterday}\n"));
    // Ingest moved over long ago, but this run's reissue fails.
    let names = vec!["platform.example.com".to_owned()];
    let issued = platform_pki::Issuer::load(&new.0, &new.1)
        .unwrap()
        .issue_server(&names, Utc::now() - Duration::days(32))
        .unwrap();
    fake.file("/etc/openvibes/tls/ingest.crt", &issued.cert_pem);
    fake.file("/etc/openvibes/tls/ingest.key", &issued.key_pem);
    fake.fail(&with(&ADMIN, &["ca", "issue-server"]), "boom");
    fake.answer(&["/usr/bin/systemctl", "try-restart"], 0, "");
    let (text, code) = renew_run(&fake.ctx(&plan(&[Ingest])));
    assert!(text.starts_with("failed\t"), "{text}");
    assert_eq!(code, ExitCode::FAILURE);
    assert_eq!(fake.text(INTERMEDIATE), bundle);
    assert!(fake.root.join(&PREVIOUS[1..]).exists());
}

#[test]
fn the_timer_undoes_a_replace_that_never_took_effect() {
    let fake = Fake::new("renew-interrupted");
    let old = crate::setup::pki_tests::certificate(&["ca"], 400);
    let old = platform_pki::first_certificate(&old).unwrap();
    fake.file(INTERMEDIATE, &old);
    fake.file(PREVIOUS, &old);
    fake.file(PREVIOUS_UNTIL, "2026-11-25T10:00:00Z\n");
    let (text, _) = renew_run(&fake.ctx(&plan(&[Ingest])));
    assert!(
        text.starts_with("removed an interrupted replacement that never took effect\n"),
        "{text}"
    );
    assert!(!fake.root.join(&PREVIOUS[1..]).exists());
}
