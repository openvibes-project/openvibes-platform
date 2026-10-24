//! The timer's run: skipped while Setup works, a failure only when the
//! step failed.

use std::process::ExitCode;

use super::{renew_gate, renew_run, system};
use crate::setup::{
    fake::{Fake, plan},
    pki_tests::installed_certificates,
    plan::Component::*,
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
