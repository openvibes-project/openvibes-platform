//! `login-password` against a scripted chpasswd.

use super::{check, read_password, run_password};
use crate::setup::fake::Fake;

const GETENT: &str = "/usr/bin/getent";
const CHPASSWD: &str = "/usr/sbin/chpasswd";

fn host(uid: &str) -> Fake {
    let fake = Fake::new(&format!("login-{uid}-{:?}", std::thread::current().id()));
    fake.answer(
        &[GETENT, "passwd", "alice"],
        0,
        &format!("alice:x:{uid}:{uid}::/home/alice:/bin/bash\n"),
    );
    fake.answer(&[CHPASSWD], 0, "");
    fake
}

#[test]
fn the_password_goes_to_chpasswd_on_stdin_only() {
    let fake = host("1000");
    assert_eq!(
        run_password(&fake, Some("alice"), "correct horse battery").unwrap(),
        "done\tchanged"
    );
    assert_eq!(
        fake.inputs.borrow().as_slice(),
        ["alice:correct horse battery\n"]
    );
    let calls = fake.calls.borrow();
    let chpasswd = calls.iter().find(|c| c[0] == CHPASSWD).unwrap();
    assert_eq!(chpasswd.len(), 1, "no argument: {chpasswd:?}");
    assert!(calls.iter().all(|c| c.iter().all(|a| !a.contains("horse"))));
}

#[test]
fn only_a_person_signed_in_through_sudo_is_changed() {
    let fake = host("1000");
    assert!(run_password(&fake, None, "correct horse battery").is_err());
    for bad in ["root", "a b", "", "x;y", "Alice"] {
        assert!(
            run_password(&fake, Some(bad), "correct horse battery").is_err(),
            "{bad:?}"
        );
    }
    assert!(!fake.called(&[CHPASSWD]));
    let service = host("999");
    let error = run_password(&service, Some("alice"), "correct horse battery").unwrap_err();
    assert!(error.contains("system account"), "{error}");
    assert!(!service.called(&[CHPASSWD]));
}

#[test]
fn a_weak_or_odd_password_is_refused_before_chpasswd() {
    let fake = host("1000");
    for bad in [
        "short",
        "has\nnewline in it",
        "tab\tcharacter here",
        &"x".repeat(129),
    ] {
        assert!(check(bad).is_err(), "{bad:?}");
        assert!(run_password(&fake, Some("alice"), bad).is_err());
    }
    assert!(!fake.called(&[CHPASSWD]));
    assert!(check("with:colon and spaces ok").is_ok());
}

#[test]
fn a_refusal_from_chpasswd_is_told_without_the_password() {
    let fake = Fake::new("login-refused");
    fake.answer(
        &[GETENT, "passwd", "alice"],
        0,
        "alice:x:1000:1000::/home/alice:/bin/bash\n",
    );
    fake.fail(&[CHPASSWD], "BAD PASSWORD: too similar");
    let error = run_password(&fake, Some("alice"), "correct horse battery").unwrap_err();
    assert!(error.contains("too similar"), "{error}");
    assert!(!error.contains("horse"));
}

#[test]
fn standard_input_gives_one_line() {
    let mut input: &[u8] = b"correct horse battery\n";
    assert_eq!(
        &*read_password(&mut input).unwrap(),
        "correct horse battery"
    );
    let mut raw: &[u8] = b"no newline";
    assert_eq!(&*read_password(&mut raw).unwrap(), "no newline");
}
