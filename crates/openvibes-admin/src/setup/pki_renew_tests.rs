//! Renewal: which certificates the timer reissues, and what it writes.

use std::os::unix::fs::PermissionsExt;

use platform_host::{Step, StepState};

use crate::setup::{
    check,
    fake::{Fake, plan},
    pki_tests::{certificate, installed_certificates, issuing},
    plan::Component::*,
    run_step,
};

const NAMES: [&str; 4] = ["platform.example.com", "10.0.0.5", "localhost", "127.0.0.1"];
const CHAIN: &str = "/etc/openvibes/tls/console-chain.pem";

fn chmod(fake: &Fake, abs: &str, mode: u32) {
    let path = fake.root.join(abs.trim_start_matches('/'));
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// Ingest, distribution and console certificates with DAYS_LEFT, the
/// console chain with MODE.
fn installed(test: &str, days_left: i64, mode: u32) -> Fake {
    let fake = Fake::new(test);
    installed_certificates(&fake, &NAMES, days_left);
    fake.file(CHAIN, &certificate(&NAMES, days_left));
    fake.file("/etc/openvibes/tls/console-key.pem", "KEY");
    chmod(&fake, CHAIN, mode);
    fake
}

#[test]
fn certificates_due_for_renewal_are_todo() {
    let components = plan(&[Ingest, Console, Distribution]);
    let due = installed("renew-due", 29, 0o644);
    assert_eq!(
        check(&due.ctx(&components), Step::Certificates),
        StepState::Todo
    );
    let later = installed("renew-later", 31, 0o644);
    assert!(matches!(
        check(&later.ctx(&components), Step::Certificates),
        StepState::Done(_)
    ));
}

#[test]
fn a_console_chain_not_world_readable_is_todo() {
    let fake = installed("renew-chain-mode", 60, 0o640);
    let state = check(
        &fake.ctx(&plan(&[Ingest, Console, Distribution])),
        Step::Certificates,
    );
    assert_eq!(state, StepState::Todo);
}

#[test]
fn renewal_writes_the_console_chain_0644_with_one_intermediate() {
    let fake = issuing("renew-chain");
    // The issuer file: the new intermediate, then the old one.
    let bundle = format!(
        "{}{}",
        certificate(&["new"], 400),
        certificate(&["old"], 100)
    );
    fake.file("/etc/openvibes/pki/intermediate.crt", &bundle);
    fake.answer(&["/usr/bin/systemctl", "try-restart"], 0, "");
    let state = run_step(
        &fake.ctx(&plan(&[Ingest, Console, Distribution])),
        Step::Certificates,
    );
    assert!(matches!(state, StepState::Done(_)), "{state:?}");
    let chain = fake.text(CHAIN);
    assert_eq!(
        chain.matches("BEGIN CERTIFICATE").count(),
        1,
        "leaf is fake"
    );
    assert!(chain.ends_with(&platform_pki::first_certificate(&bundle).unwrap()));
    let mode = std::fs::metadata(fake.root.join(CHAIN.trim_start_matches('/')))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o644);
}
