//! The root key file of the quick CA: checked before any CA material, and
//! kept on a retry when the CA got installed but the key was not written.

use platform_host::{Step, StepState};

use crate::setup::{
    check,
    fake::{Fake, plan},
    pki_tests::ca_commands,
    plan::Component::Ingest,
    run_step,
};

const KEY: &str = "/media/usb/openvibes-root.key";

fn refused_before_init_root(test: &str, setup: impl Fn(&Fake), expected: &str) {
    let fake = Fake::new(test);
    ca_commands(&fake);
    setup(&fake);
    let mut plan = plan(&[Ingest]);
    plan.root_key_out = Some(KEY.into());
    let state = run_step(&fake.ctx(&plan), Step::Ca);
    assert!(matches!(state, StepState::Failed(_)), "{state:?}");
    assert!(state.detail().contains(expected), "{state:?}");
    assert!(
        !fake.called(&["/usr/bin/openvibes-admin", "ca", "init-root"]),
        "checked before any CA material"
    );
}

#[test]
fn a_dangling_link_at_the_root_key_file_is_refused_before_init_root() {
    refused_before_init_root(
        "ca-key-dangling",
        |fake| {
            std::fs::create_dir_all(fake.root.join("media/usb")).unwrap();
            std::os::unix::fs::symlink("/nowhere", fake.root.join(&KEY[1..])).unwrap();
        },
        "already exists",
    );
}

#[test]
fn a_root_key_folder_that_is_a_file_is_refused_before_init_root() {
    refused_before_init_root(
        "ca-key-parent-file",
        |fake| fake.file("/media/usb", "not a folder"),
        "/media/usb is not a folder",
    );
}

#[test]
fn a_missing_root_key_folder_is_refused_before_init_root() {
    refused_before_init_root("ca-key-no-folder", |_| {}, "/media/usb does not exist");
}

#[test]
fn a_retry_keeps_the_staged_root_key_of_an_installed_ca() {
    let fake = Fake::new("ca-key-retry");
    ca_commands(&fake);
    let mut plan = plan(&[Ingest]);
    plan.root_key_out = Some(KEY.into());
    // The CA got installed, then writing the key failed (no folder yet).
    let root = platform_pki::generate_root(chrono::Utc::now()).unwrap();
    fake.file("/etc/openvibes/pki/root.crt", &root.cert_pem);
    fake.file("/etc/openvibes/pki/intermediate.crt", "INTERMEDIATE");
    fake.file("/var/lib/openvibes-ingest/intermediate.key", "KEY");
    fake.file("/run/openvibes-ca/root/root.key", "THE ROOT KEY");
    let ctx = fake.ctx(&plan);
    assert_eq!(check(&ctx, Step::Ca), StepState::Todo);
    std::fs::create_dir_all(fake.root.join("media/usb")).unwrap();
    let state = run_step(&ctx, Step::Ca);
    assert!(matches!(state, StepState::Done(_)), "{state:?}");
    assert!(state.detail().contains(KEY), "{state:?}");
    assert_eq!(fake.text(KEY), "THE ROOT KEY");
    assert!(
        !fake.root.join("run/openvibes-ca").exists(),
        "stage removed"
    );
    assert!(!fake.called(&["/usr/bin/openvibes-admin", "ca", "init-root"]));
    assert_eq!(fake.text("/etc/openvibes/pki/root.crt"), root.cert_pem);
}
