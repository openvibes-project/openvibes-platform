//! `Privileged`: arguments, stdin and journal lines.

use super::{Privileged, Secret};

#[test]
fn ca_import_keeps_the_pem_out_of_argv_and_journal() {
    let bundle = Secret::new("-----BEGIN PRIVATE KEY-----\nK\n".into());
    let import = Privileged::CaImport(&bundle);
    assert_eq!(import.args(), ["ca-import"]);
    assert_eq!(import.journal(), "ca-import /run/openvibes-import");
    assert!(!format!("{import:?}").contains("BEGIN"));
    let password = Secret::new("pw".into());
    let sudo = import.stdin(Some(&password)).unwrap();
    assert_eq!(*sudo, b"pw\n-----BEGIN PRIVATE KEY-----\nK\n");
    assert_eq!(*import.stdin(None).unwrap(), bundle.expose().as_bytes());
    assert_eq!(
        *Privileged::SetupStatus.stdin(Some(&password)).unwrap(),
        b"pw\n"
    );
    assert!(Privileged::SetupStatus.stdin(None).is_none());
}

#[test]
fn ca_verbs_keep_the_pem_out_of_the_journal() {
    assert_eq!(Privileged::CaRequest(None).args(), ["ca-request"]);
    assert_eq!(
        Privileged::CaRequest(Some("/home/alice/openvibes-request.csr")).args(),
        ["ca-request", "--copy", "/home/alice/openvibes-request.csr"]
    );
    assert_eq!(
        Privileged::CaRequest(Some("/x")).journal(),
        "ca-request /etc/openvibes/pki/request"
    );
    let accept = Privileged::CaAccept("CERT PEM", "ROOT PEM");
    assert_eq!(
        accept.args(),
        ["ca-accept", "--cert", "CERT PEM", "--root-cert", "ROOT PEM"]
    );
    assert_eq!(accept.journal(), "ca-accept /etc/openvibes/pki/request");
}

#[test]
fn ca_replace_keeps_the_key_path_out_of_the_journal() {
    assert_eq!(Privileged::CaReplace(None).args(), ["ca-replace"]);
    let quick = Privileged::CaReplace(Some("/media/usb/openvibes-root.key"));
    assert_eq!(
        quick.args(),
        ["ca-replace", "--root-key", "/media/usb/openvibes-root.key"]
    );
    assert_eq!(
        quick.journal(),
        "ca-replace /etc/openvibes/pki/intermediate.crt"
    );
}

#[test]
fn console_cert_keeps_the_pem_out_of_argv_and_journal() {
    let pair = Secret::new("-----BEGIN PRIVATE KEY-----\nK\n".into());
    let set = Privileged::ConsoleCertSet(&pair);
    assert_eq!(set.args(), ["console-cert-set"]);
    assert_eq!(
        set.journal(),
        "console-cert-set /etc/openvibes/tls/console-own.crt"
    );
    assert!(!format!("{set:?}").contains("BEGIN"));
    let password = Secret::new("pw".into());
    assert_eq!(
        *set.stdin(Some(&password)).unwrap(),
        b"pw\n-----BEGIN PRIVATE KEY-----\nK\n"
    );
    let reset = Privileged::ConsoleCertReset;
    assert_eq!(reset.args(), ["console-cert-reset"]);
    assert_eq!(
        reset.journal(),
        "console-cert-reset /etc/openvibes/tls/console-own.crt"
    );
    assert!(reset.stdin(None).is_none());
}

#[test]
fn the_os_verbs_take_no_arguments_and_no_input() {
    for (verb, name) in [
        (Privileged::OsCheck, "os-check"),
        (Privileged::OsUpdate, "os-update"),
        (Privileged::OsRestart, "os-restart"),
        (Privileged::OsPowerOff, "os-power-off"),
    ] {
        assert_eq!(verb.args(), [name]);
        assert_eq!(verb.journal(), name);
        assert!(verb.stdin(None).is_none());
    }
}

#[test]
fn the_network_verbs_carry_their_arguments_and_nothing_else() {
    let args = vec!["--mode".to_owned(), "dhcp".to_owned()];
    assert_eq!(
        Privileged::NetApply(&args).args(),
        ["net-apply", "--mode", "dhcp"]
    );
    assert_eq!(Privileged::NetKeep.args(), ["net-keep"]);
    assert_eq!(Privileged::NetRevert.args(), ["net-revert"]);
    assert_eq!(
        Privileged::HostnameSet("va.lab").args(),
        ["hostname-set", "va.lab"]
    );
    let time = [
        "--servers".to_owned(),
        "ntp.lab".to_owned(),
        "--zone".to_owned(),
        "UTC".to_owned(),
    ];
    assert_eq!(
        Privileged::TimeSet(&time).args(),
        ["time-set", "--servers", "ntp.lab", "--zone", "UTC"]
    );
    let ssh = [
        "--keys".to_owned(),
        "yes".to_owned(),
        "--passwords".to_owned(),
        "no".to_owned(),
    ];
    assert_eq!(
        Privileged::SshSet(&ssh).args(),
        ["ssh-set", "--keys", "yes", "--passwords", "no"]
    );
    let secret = crate::Secret::new("a new password".into());
    assert_eq!(
        Privileged::LoginPassword(&secret).args(),
        ["login-password"]
    );
    let stdin = Privileged::LoginPassword(&secret).stdin(None).unwrap();
    assert_eq!(&**stdin, b"a new password");
    assert!(Privileged::NetKeep.stdin(None).is_none());
}
