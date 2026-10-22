//! The console admin's break-glass password reset (2b-2).
use platform_host::StepState;

use super::{admin_reset, readable_password};
use crate::setup::fake::{Fake, plan};

const ALPHABET: &str = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";

#[test]
fn readable_password_has_four_groups_from_the_alphabet() {
    for _ in 0..50 {
        let password = readable_password().unwrap();
        let groups: Vec<&str> = password.split('-').collect();
        assert_eq!(groups.len(), 4, "{}", *password);
        for group in groups {
            assert_eq!(group.chars().count(), 4, "{}", *password);
            assert!(group.chars().all(|c| ALPHABET.contains(c)), "{}", *password);
        }
        assert!(password.chars().count() >= 15);
    }
}

#[test]
fn admin_reset_passes_the_password_on_stdin_only() {
    let fake = Fake::new("admin-reset");
    fake.answer(&["/usr/sbin/runuser"], 0, "");
    let plan = plan(&[]);
    let state = admin_reset(&fake.ctx(&plan)).unwrap();
    let StepState::Done(password) = state else {
        panic!("{state:?}");
    };
    let call = fake.call(&["/usr/sbin/runuser"]);
    assert_eq!(
        call[call.len() - 5..],
        [
            "user",
            "reset-password",
            "admin",
            "--password-stdin",
            "--must-change"
        ]
    );
    assert!(!call.iter().any(|arg| arg.contains(&password)), "{call:?}");
    assert_eq!(*fake.inputs.borrow(), [format!("{password}\n")]);
}

#[test]
fn a_failed_reset_is_an_error_without_the_password() {
    let fake = Fake::new("admin-reset-fail");
    fake.fail(&["/usr/sbin/runuser"], "no local user named admin");
    let plan = plan(&[]);
    let error = admin_reset(&fake.ctx(&plan)).unwrap_err();
    assert!(error.contains("no local user named admin"), "{error}");
    let input = fake.inputs.borrow()[0].clone();
    assert!(!error.contains(input.trim_end()), "{error}");
}
