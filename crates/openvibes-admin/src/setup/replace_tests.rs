//! Replacing the intermediate: the new one first and the old one second
//! until the agents have moved over, then the old one dropped.

use std::os::unix::fs::PermissionsExt;

use chrono::{Duration, Utc};
use platform_pki::KeyAndCert;

use super::{PREVIOUS, PREVIOUS_UNTIL, PROGRESS, drop_previous, replace};
use platform_host::{Step, StepState};

use crate::setup::{
    check,
    fake::{Fake, plan},
    pki::{INTERMEDIATE, INTERMEDIATE_KEY, ROOT_CERT, ca_apply},
    pki_tests::{ADMIN, issuing, with},
    plan::{CaMode, Component::*},
    request::REQUEST_DIR,
};

const KEY: &str = "/media/usb/openvibes-root.key";

/// A new intermediate of `root`: (certificate, key).
pub(super) fn intermediate(root: &KeyAndCert) -> (String, String) {
    let (csr, key) = platform_pki::intermediate_request().unwrap();
    (
        platform_pki::sign_intermediate(root, &csr, Utc::now()).unwrap(),
        key,
    )
}

/// An installed host: its root and the intermediate in use.
pub(super) fn installed(test: &str) -> (Fake, KeyAndCert, (String, String)) {
    host(issuing(test))
}

/// `fake` with a root and the intermediate in use.
fn host(fake: Fake) -> (Fake, KeyAndCert, (String, String)) {
    let root = platform_pki::generate_root(Utc::now()).unwrap();
    let old = intermediate(&root);
    fake.file(ROOT_CERT, &root.cert_pem);
    fake.file(INTERMEDIATE, &old.0);
    fake.file(INTERMEDIATE_KEY, &old.1);
    fake.answer(&with(&ADMIN, &["ca", "import-intermediate"]), 0, "");
    fake.answer(&["/usr/bin/systemctl", "try-restart"], 0, "");
    (fake, root, old)
}

pub(super) fn certificates(bundle: &str) -> Vec<String> {
    bundle
        .split_inclusive("-----END CERTIFICATE-----\n")
        .map(str::to_owned)
        .collect()
}

fn mode(fake: &Fake, abs: &str) -> u32 {
    std::fs::metadata(fake.root.join(abs.trim_start_matches('/')))
        .unwrap()
        .permissions()
        .mode()
        & 0o777
}

pub(super) fn careful_request(fake: &Fake, cert: &str, key: &str, root: &str) {
    for (name, text) in [
        ("intermediate.key", key),
        ("intermediate.csr", "CSR"),
        ("intermediate.crt", cert),
        ("root.crt", root),
    ] {
        fake.file(&format!("{REQUEST_DIR}/{name}"), text);
    }
}

#[test]
fn replace_careful_trusts_old_and_new() {
    let (fake, root, old) = installed("replace-careful");
    let new = intermediate(&root);
    careful_request(&fake, &new.0, &new.1, &root.cert_pem);
    let mut plan = plan(&[Ingest, Console, Distribution]);
    plan.ca = CaMode::Careful;
    let detail = replace(&fake.ctx(&plan), None).unwrap();

    let bundle = certificates(&fake.text(INTERMEDIATE));
    assert_eq!(bundle.len(), 2);
    assert_eq!(bundle[0], platform_pki::first_certificate(&new.0).unwrap());
    assert_eq!(bundle[1], platform_pki::first_certificate(&old.0).unwrap());
    // An agent's certificate from the old intermediate still verifies.
    let names = vec!["agent".to_owned()];
    let by_old = platform_pki::Issuer::load(&old.0, &old.1)
        .unwrap()
        .issue_server(&names, Utc::now())
        .unwrap();
    assert!(platform_pki::verify_signed_by(&by_old.cert_pem, &bundle[1]).is_ok());
    assert!(platform_pki::verify_signed_by(&by_old.cert_pem, &bundle[0]).is_err());

    let until = chrono::DateTime::parse_from_rfc3339(fake.text(PREVIOUS_UNTIL).trim()).unwrap();
    let ahead = until.with_timezone(&Utc) - Utc::now();
    assert!(
        ahead > Duration::days(31) - Duration::minutes(1) && ahead <= Duration::days(31),
        "{ahead:?}"
    );
    assert_eq!(fake.text(PREVIOUS), bundle[1]);
    assert_eq!(mode(&fake, PREVIOUS), 0o644);
    assert_eq!(mode(&fake, PREVIOUS_UNTIL), 0o644);
    assert_eq!(fake.text(INTERMEDIATE_KEY), new.1);
    assert_eq!(mode(&fake, INTERMEDIATE_KEY), 0o600);
    let expires = platform_pki::not_after(&new.0).unwrap();
    assert_eq!(
        detail,
        format!(
            "{}\t{}",
            expires.format("%Y-%m-%d"),
            until.format("%Y-%m-%d")
        )
    );
    let import = fake.call(&with(&ADMIN, &["ca", "import-intermediate"]));
    assert_eq!(
        import[7..],
        [
            "--cert",
            "/run/openvibes-ca/int/intermediate.crt",
            "--key",
            "/run/openvibes-ca/int/intermediate.key",
            "--root-cert",
            ROOT_CERT
        ]
    );
    // The server certificates came from the new intermediate.
    assert!(fake.called(&with(&ADMIN, &["ca", "issue-server"])));
    assert!(fake.called(&["/usr/bin/systemctl", "try-restart"]));
    assert!(!fake.root.join(&REQUEST_DIR[1..]).exists());
    assert!(!fake.root.join("run/openvibes-ca").exists());
    // The TUI's progress file goes once it succeeded.
    assert!(!fake.root.join(PROGRESS).exists());
}

#[test]
fn repair_never_installs_a_replace_request() {
    // An own-CA Replace left after ca-accept: the request is ca-replace's.
    let (fake, root, old) = installed("replace-left-request");
    let new = intermediate(&root);
    careful_request(&fake, &new.0, &new.1, &root.cert_pem);
    let mut plan = plan(&[Ingest]);
    plan.ca = CaMode::Careful;
    let mut ctx = fake.ctx(&plan);
    ctx.repair = true;
    assert!(matches!(ca_apply(&ctx), Ok(StepState::Done(_))));
    assert_eq!(fake.text(INTERMEDIATE), old.0);
    assert_eq!(fake.text(INTERMEDIATE_KEY), old.1);
    assert!(
        fake.root
            .join(&REQUEST_DIR[1..])
            .join("intermediate.crt")
            .exists()
    );
    assert!(!fake.called(&with(&ADMIN, &["ca", "import-intermediate"])));
}

/// Nothing on disk changed and nothing ran.
fn unchanged(fake: &Fake, old: &(String, String)) {
    assert_eq!(fake.text(INTERMEDIATE), old.0);
    assert_eq!(fake.text(INTERMEDIATE_KEY), old.1);
    assert!(!fake.root.join(&PREVIOUS[1..]).exists());
    assert!(!fake.root.join(&PREVIOUS_UNTIL[1..]).exists());
    assert!(!fake.root.join("run/openvibes-ca").exists());
    assert_eq!(*fake.calls.borrow(), Vec::<Vec<String>>::new());
}

#[test]
fn replace_careful_refuses_another_root() {
    let (fake, _, old) = installed("replace-careful-root");
    let other = platform_pki::generate_root(Utc::now()).unwrap();
    let new = intermediate(&other);
    careful_request(&fake, &new.0, &new.1, &other.cert_pem);
    let mut plan = plan(&[Ingest]);
    plan.ca = CaMode::Careful;
    assert_eq!(
        replace(&fake.ctx(&plan), None).unwrap_err(),
        "Your CA's certificate is not this host's root: agents trust only that one."
    );
    unchanged(&fake, &old);
    assert!(fake.root.join(&REQUEST_DIR[1..]).exists());
}

#[test]
fn replace_quick_refuses_a_foreign_key() {
    let (fake, _, old) = installed("replace-quick-foreign");
    let other = platform_pki::generate_root(Utc::now()).unwrap();
    fake.file(KEY, &other.key_pem);
    assert_eq!(
        replace(&fake.ctx(&plan(&[Ingest])), Some(KEY)).unwrap_err(),
        "Not the key of this host's root: pick the root key kept at install."
    );
    unchanged(&fake, &old);
}

/// `ca intermediate-request` and `ca sign-intermediate` as the real ones;
/// the signature checks the key copy is staged while it runs.
fn quick_commands(fake: &Fake, sign_fails: bool) {
    fake.effect(&with(&ADMIN, &["ca", "intermediate-request"]), |root| {
        let dir = root.join("run/openvibes-ca/int");
        std::fs::create_dir_all(&dir).unwrap();
        let (csr, key) = platform_pki::intermediate_request().unwrap();
        std::fs::write(dir.join("intermediate.csr"), csr).unwrap();
        std::fs::write(dir.join("intermediate.key"), key).unwrap();
    });
    let sign = ["/usr/bin/openvibes-admin", "ca", "sign-intermediate"];
    if sign_fails {
        fake.fail(&sign, "boom");
        return;
    }
    fake.effect(&sign, |root| {
        let stage = root.join("run/openvibes-ca");
        let read = |name: &str| std::fs::read_to_string(stage.join(name)).unwrap();
        let ca = KeyAndCert {
            cert_pem: read("root/root.crt"),
            key_pem: read("root/root.key"),
        };
        let cert = platform_pki::sign_intermediate(&ca, &read("int/intermediate.csr"), Utc::now())
            .unwrap();
        std::fs::write(stage.join("int/intermediate.crt"), cert).unwrap();
    });
}

#[test]
fn replace_quick_removes_the_key_copy() {
    for sign_fails in [false, true] {
        let (fake, root, old) = installed(&format!("replace-quick-{sign_fails}"));
        quick_commands(&fake, sign_fails);
        fake.file(KEY, &root.key_pem);
        let result = replace(&fake.ctx(&plan(&[Ingest])), Some(KEY));
        assert_eq!(result.is_err(), sign_fails, "{result:?}");
        assert!(fake.called(&["/usr/bin/openvibes-admin", "ca", "sign-intermediate"]));
        assert!(
            !fake.root.join("run/openvibes-ca/root/root.key").exists(),
            "the key copy is removed"
        );
        let bundle = certificates(&fake.text(INTERMEDIATE));
        if sign_fails {
            assert_eq!(bundle, std::slice::from_ref(&old.0));
        } else {
            assert_eq!(bundle.len(), 2);
            assert_eq!(bundle[1], old.0);
            assert!(
                platform_pki::check_intermediate(&bundle[0], &root.cert_pem, Utc::now()).is_ok()
            );
        }
    }
}

#[test]
fn drop_previous_waits_then_drops() {
    let (fake, root, old) = installed("replace-drop");
    let new = intermediate(&root);
    let bundle = format!("{}{}", new.0, old.0);
    fake.file(INTERMEDIATE, &bundle);
    fake.file(PREVIOUS, &old.0);
    let tomorrow = (Utc::now() + Duration::days(1)).to_rfc3339();
    fake.file(PREVIOUS_UNTIL, &format!("{tomorrow}\n"));
    ingest_certificate(&fake, &new, 32);
    let plan = plan(&[Ingest, Distribution]);
    assert_eq!(drop_previous(&fake.ctx(&plan)), Ok(None));
    assert_eq!(fake.text(INTERMEDIATE), bundle);
    assert!(fake.calls.borrow().is_empty());

    let yesterday = (Utc::now() - Duration::days(1)).to_rfc3339();
    fake.file(PREVIOUS_UNTIL, &format!("{yesterday}\n"));
    assert_eq!(
        drop_previous(&fake.ctx(&plan)),
        Ok(Some("previous intermediate no longer trusted".into()))
    );
    assert_eq!(certificates(&fake.text(INTERMEDIATE)), [new.0]);
    assert!(!fake.root.join(&PREVIOUS[1..]).exists());
    assert!(!fake.root.join(&PREVIOUS_UNTIL[1..]).exists());
    assert_eq!(
        fake.call(&["/usr/bin/systemctl", "try-restart"]),
        [
            "/usr/bin/systemctl",
            "try-restart",
            "openvibes-ingest",
            "openvibes-distribution"
        ]
    );
}

#[test]
fn drop_previous_without_the_files_does_nothing() {
    let (fake, _, old) = installed("replace-drop-none");
    assert_eq!(drop_previous(&fake.ctx(&plan(&[Ingest]))), Ok(None));
    assert_eq!(fake.text(INTERMEDIATE), old.0);
}

#[test]
fn replace_refuses_while_the_previous_is_trusted() {
    // An earlier Replace that finished: new + old, the new key.
    let (fake, root, old) = installed("replace-pending");
    let new = intermediate(&root);
    let bundle = format!("{}{}", new.0, old.0);
    fake.file(INTERMEDIATE, &bundle);
    fake.file(INTERMEDIATE_KEY, &new.1);
    fake.file(PREVIOUS, &old.0);
    fake.file(PREVIOUS_UNTIL, "2026-11-25T10:00:00Z\n");
    assert_eq!(
        replace(&fake.ctx(&plan(&[Ingest])), Some(KEY)).unwrap_err(),
        "The previous intermediate is still trusted until 2026-11-25, while agents move over: \
         replace it again after that."
    );
    assert_eq!(fake.text(INTERMEDIATE), bundle);
    assert_eq!(fake.text(INTERMEDIATE_KEY), new.1);
    assert_eq!(fake.text(PREVIOUS_UNTIL), "2026-11-25T10:00:00Z\n");
    assert!(fake.calls.borrow().is_empty());
}

const NAMES: [&str; 4] = ["platform.example.com", "10.0.0.5", "localhost", "127.0.0.1"];

/// Ingest's certificate for NAMES, issued by `issuer` (certificate, key)
/// `ago` days back.
fn ingest_certificate(fake: &Fake, issuer: &(String, String), ago: i64) {
    let names: Vec<String> = NAMES.iter().map(|n| (*n).to_owned()).collect();
    let issued = platform_pki::Issuer::load(&issuer.0, &issuer.1)
        .unwrap()
        .issue_server(&names, Utc::now() - Duration::days(ago))
        .unwrap();
    fake.file("/etc/openvibes/tls/ingest.crt", &issued.cert_pem);
    fake.file("/etc/openvibes/tls/ingest.key", &issued.key_pem);
    fake.file(
        "/etc/openvibes/tls/setup-names",
        &format!("{}\n", NAMES.join("\n")),
    );
}

#[test]
fn a_failed_reissue_after_the_swap_says_run_repair() {
    let fake = Fake::new("replace-reissue-fails");
    fake.fail(&with(&ADMIN, &["ca", "issue-server"]), "boom");
    let (fake, root, old) = host(fake);
    ingest_certificate(&fake, &old, 0);
    let new = intermediate(&root);
    careful_request(&fake, &new.0, &new.1, &root.cert_pem);
    let mut plan = plan(&[Ingest]);
    plan.ca = CaMode::Careful;
    assert!(matches!(
        check(&fake.ctx(&plan), Step::Certificates),
        StepState::Done(_)
    ));
    let error = replace(&fake.ctx(&plan), None).unwrap_err();
    assert!(
        error.starts_with(
            "The intermediate was replaced, but the server certificates were not reissued: \
             run Repair in Maintenance (they stay valid until then)."
        ),
        "{error}"
    );
    assert!(error.contains("boom"), "{error}");
    assert_eq!(certificates(&fake.text(INTERMEDIATE)).len(), 2);
    // The TUI's step list: what finished before the failure.
    let progress = std::fs::read_to_string(fake.root.join(PROGRESS)).unwrap();
    assert_eq!(
        progress,
        "Making the new intermediate\nTrusting the old and the new one\n"
    );
    assert_eq!(mode(&fake, &format!("/{PROGRESS}")), 0o644);
    // Repair reissues: ingest's certificate is not from the new intermediate.
    assert_eq!(check(&fake.ctx(&plan), Step::Certificates), StepState::Todo);
}

#[test]
fn server_certificates_from_the_new_intermediate_are_done() {
    let (fake, root, old) = installed("replace-check-signed");
    let new = intermediate(&root);
    fake.file(INTERMEDIATE, &format!("{}{}", new.0, old.0));
    ingest_certificate(&fake, &old, 0);
    let plan = plan(&[Ingest]);
    assert_eq!(check(&fake.ctx(&plan), Step::Certificates), StepState::Todo);
    ingest_certificate(&fake, &new, 0);
    assert!(matches!(
        check(&fake.ctx(&plan), Step::Certificates),
        StepState::Done(_)
    ));
}

#[test]
fn the_old_intermediate_stays_until_ingest_issues_from_the_new_one() {
    let fake = Fake::new("replace-drop-after-ingest");
    fake.fail(&with(&ADMIN, &["ca", "issue-server"]), "boom");
    let (fake, root, old) = host(fake);
    ingest_certificate(&fake, &old, 0);
    let new = intermediate(&root);
    careful_request(&fake, &new.0, &new.1, &root.cert_pem);
    let mut plan = plan(&[Ingest]);
    plan.ca = CaMode::Careful;
    assert!(replace(&fake.ctx(&plan), None).is_err());
    // Ingest still issues from the old one: kept after previous-until.
    let yesterday = (Utc::now() - Duration::days(1)).to_rfc3339();
    fake.file(PREVIOUS_UNTIL, &format!("{yesterday}\n"));
    assert_eq!(drop_previous(&fake.ctx(&plan)), Ok(None));
    assert_eq!(certificates(&fake.text(INTERMEDIATE)).len(), 2);
    // Reissued from the new one 30 days ago: its agents' certificates from
    // the old one last client_certificate_days (30) + 1 from then.
    ingest_certificate(&fake, &new, 30);
    assert_eq!(drop_previous(&fake.ctx(&plan)), Ok(None));
    assert_eq!(certificates(&fake.text(INTERMEDIATE)).len(), 2);
    ingest_certificate(&fake, &new, 32);
    assert_eq!(
        drop_previous(&fake.ctx(&plan)),
        Ok(Some("previous intermediate no longer trusted".into()))
    );
    assert_eq!(certificates(&fake.text(INTERMEDIATE)), [new.0]);
}

#[test]
fn a_failed_swap_puts_the_old_pair_back() {
    let (fake, root, old) = installed("replace-swap-fails");
    let new = intermediate(&root);
    careful_request(&fake, &new.0, &new.1, &root.cert_pem);
    // The key cannot be renamed into place: a folder is in the way.
    fake.remove(INTERMEDIATE_KEY);
    std::fs::create_dir(fake.root.join(&INTERMEDIATE_KEY[1..])).unwrap();
    let mut plan = plan(&[Ingest]);
    plan.ca = CaMode::Careful;
    assert!(replace(&fake.ctx(&plan), None).is_err());
    assert_eq!(fake.text(INTERMEDIATE), old.0);
    assert!(!fake.root.join(&PREVIOUS[1..]).exists());
    assert!(!fake.root.join(&PREVIOUS_UNTIL[1..]).exists());
    let mut left: Vec<_> = ["etc/openvibes/pki", "var/lib/openvibes-ingest"]
        .iter()
        .flat_map(|dir| std::fs::read_dir(fake.root.join(dir)).unwrap())
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    left.sort();
    // The request stays for the next try.
    assert_eq!(
        left,
        [
            "intermediate.crt",
            "intermediate.key",
            "request",
            "root.crt"
        ]
    );
}
