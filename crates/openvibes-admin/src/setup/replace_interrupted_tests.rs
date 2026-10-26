//! A Replace a crash cut short inside the swap: finished, or undone when
//! it never took effect.

use chrono::{Duration, Utc};

use super::{
    PREVIOUS, PREVIOUS_UNTIL, finish_interrupted, replace,
    tests::{certificates, installed, intermediate},
};
use crate::setup::{
    fake::plan,
    pki::{INTERMEDIATE, INTERMEDIATE_KEY},
    plan::Component::*,
};

const BUNDLE_NEW: &str = "/etc/openvibes/pki/intermediate.crt.new";
const KEY_NEW: &str = "/var/lib/openvibes-ingest/intermediate.key.new";

#[test]
fn a_bundle_renamed_without_its_key_is_finished() {
    let (fake, root, old) = installed("interrupted-key");
    let new = intermediate(&root);
    fake.file(PREVIOUS, &old.0);
    fake.file(PREVIOUS_UNTIL, &format!("{}\n", Utc::now().to_rfc3339()));
    fake.file(INTERMEDIATE, &format!("{}{}", new.0, old.0));
    fake.file(KEY_NEW, &new.1);
    assert_eq!(
        finish_interrupted(&fake.ctx(&plan(&[Ingest]))),
        Ok(Some("finished an interrupted replacement".into()))
    );
    assert_eq!(fake.text(INTERMEDIATE_KEY), new.1);
    assert!(!fake.root.join(&KEY_NEW[1..]).exists());
    assert_eq!(certificates(&fake.text(INTERMEDIATE)).len(), 2);
    assert_eq!(fake.text(PREVIOUS), old.0);
}

#[test]
fn a_swap_that_never_renamed_anything_is_undone_and_replace_runs() {
    let (fake, root, old) = installed("interrupted-none");
    let new = intermediate(&root);
    fake.file(PREVIOUS, &old.0);
    let until = Utc::now() + Duration::days(31);
    fake.file(PREVIOUS_UNTIL, &format!("{}\n", until.to_rfc3339()));
    fake.file(KEY_NEW, &new.1);
    fake.file(BUNDLE_NEW, &format!("{}{}", new.0, old.0));
    assert_eq!(
        finish_interrupted(&fake.ctx(&plan(&[Ingest]))),
        Ok(Some(
            "removed an interrupted replacement that never took effect".into()
        ))
    );
    for left in [PREVIOUS, PREVIOUS_UNTIL, KEY_NEW, BUNDLE_NEW] {
        assert!(!fake.root.join(&left[1..]).exists(), "{left}");
    }
    assert_eq!(fake.text(INTERMEDIATE), old.0);
    assert_eq!(fake.text(INTERMEDIATE_KEY), old.1);

    // Replace undoes it first instead of refusing for a month.
    fake.file(PREVIOUS, &old.0);
    fake.file(PREVIOUS_UNTIL, &format!("{}\n", until.to_rfc3339()));
    let error = replace(&fake.ctx(&plan(&[Ingest])), None).unwrap_err();
    assert!(!error.contains("still trusted"), "{error}");
}

#[test]
fn a_host_mid_transition_or_untouched_is_left_alone() {
    let (fake, root, old) = installed("interrupted-normal");
    assert_eq!(finish_interrupted(&fake.ctx(&plan(&[Ingest]))), Ok(None));
    assert_eq!(fake.text(INTERMEDIATE), old.0);
    // A finished Replace: new + old, the new key, previous.* until dropped.
    let new = intermediate(&root);
    let bundle = format!("{}{}", new.0, old.0);
    fake.file(INTERMEDIATE, &bundle);
    fake.file(INTERMEDIATE_KEY, &new.1);
    fake.file(PREVIOUS, &old.0);
    fake.file(PREVIOUS_UNTIL, "2026-11-25T10:00:00Z\n");
    assert_eq!(finish_interrupted(&fake.ctx(&plan(&[Ingest]))), Ok(None));
    assert_eq!(fake.text(INTERMEDIATE), bundle);
    assert_eq!(fake.text(INTERMEDIATE_KEY), new.1);
    assert_eq!(fake.text(PREVIOUS), old.0);
    assert!(fake.calls.borrow().is_empty());
}

#[test]
fn repair_finishes_it_through_the_certificates_step() {
    let (fake, root, old) = installed("interrupted-repair");
    let new = intermediate(&root);
    fake.file(PREVIOUS, &old.0);
    fake.file(INTERMEDIATE, &format!("{}{}", new.0, old.0));
    fake.file(KEY_NEW, &new.1);
    let mut plan = plan(&[Ingest]);
    plan.ca = crate::setup::plan::CaMode::Quick;
    let mut ctx = fake.ctx(&plan);
    ctx.repair = true;
    // Whatever the reissue does next, the key is in place first.
    let _ = crate::setup::pki::certificates_apply(&ctx);
    assert_eq!(fake.text(INTERMEDIATE_KEY), new.1);
}

#[test]
fn a_folder_sync_that_fails_after_the_rename_is_no_failure() {
    use std::os::unix::fs::PermissionsExt;
    let (fake, root, old) = installed("interrupted-sync");
    let new = intermediate(&root);
    crate::setup::replace::tests::careful_request(&fake, &new.0, &new.1, &root.cert_pem);
    let mut plan = plan(&[Ingest]);
    plan.ca = crate::setup::plan::CaMode::Careful;
    // Renames into the folder work; opening it to sync does not.
    let pki = fake.root.join("etc/openvibes/pki");
    let chmod = |mode| std::fs::set_permissions(&pki, std::fs::Permissions::from_mode(mode));
    chmod(0o300).unwrap();
    let _ = replace(&fake.ctx(&plan), None);
    chmod(0o755).unwrap();
    assert_eq!(fake.text(INTERMEDIATE), format!("{}{}", new.0, old.0));
    assert_eq!(fake.text(INTERMEDIATE_KEY), new.1);
    assert_eq!(fake.text(PREVIOUS), old.0);
}

/// Finishing it still says so when your own console pair then fails.
#[test]
fn the_finished_replacement_is_said_before_your_pairs_failure() {
    let (fake, root, old) = installed("interrupted-own");
    let new = intermediate(&root);
    fake.file(PREVIOUS, &old.0);
    fake.file(PREVIOUS_UNTIL, &format!("{}\n", Utc::now().to_rfc3339()));
    fake.file(INTERMEDIATE, &format!("{}{}", new.0, old.0));
    fake.file(KEY_NEW, &new.1);
    fake.file(crate::setup::pki_console::OWN_CERT, "half a pair");
    let state = crate::setup::run_step(
        &fake.ctx(&plan(&[Ingest, Console])),
        platform_host::Step::Certificates,
    );
    assert!(
        matches!(&state, platform_host::StepState::Failed(e)
            if e.starts_with("finished an interrupted replacement; ")
                && e.contains("console-own.key is missing")),
        "{state:?}"
    );
}
