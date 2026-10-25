//! `helper ca-import` on a temp root, with the platform-pki fixtures.

use std::os::unix::fs::PermissionsExt;

use chrono::{DateTime, TimeZone, Utc};
use platform_pki::{ChainError, PkiError, ServerLimit};

use super::{IMPORT_DIR, MAX, import, import_message, imported, read_bundle};
use crate::setup::{
    fake::{Fake, plan},
    pki::{INTERMEDIATE, INTERMEDIATE_KEY, ROOT_CERT},
    plan::Component::Ingest,
};

const ROOT: &str = include_str!("../../../platform-pki/tests/fixtures/root.crt");
const ISSUING: &str = include_str!("../../../platform-pki/tests/fixtures/issuing.crt");
const OURS: &str = include_str!("../../../platform-pki/tests/fixtures/ours-ec.crt");
const OURS_KEY: &str = include_str!("../../../platform-pki/tests/fixtures/ours-ec.pkcs8.pem");
const RSA_KEY: &str = include_str!("../../../platform-pki/tests/fixtures/ours-rsa.key");
const STRICT: &str = include_str!("../../../platform-pki/tests/fixtures/strict.crt");
const STRICT_KEY: &str = include_str!("../../../platform-pki/tests/fixtures/strict.key");
const CLIENT_ONLY: &str = include_str!("../../../platform-pki/tests/fixtures/client-only.crt");
const CLIENT_ONLY_KEY: &str = include_str!("../../../platform-pki/tests/fixtures/client-only.key");

fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2027, 6, 1, 0, 0, 0).unwrap()
}

fn staged(name: &str) -> String {
    format!("{IMPORT_DIR}/{name}")
}

fn mode(fake: &Fake, abs: &str) -> u32 {
    std::fs::metadata(fake.root.join(abs.trim_start_matches('/')))
        .unwrap()
        .permissions()
        .mode()
        & 0o777
}

fn full() -> String {
    format!("{OURS}{ISSUING}{ROOT}{OURS_KEY}")
}

#[test]
fn stages_the_three_files_and_the_key() {
    let fake = Fake::new("import-stages");
    let plan = plan(&[Ingest]);
    let chain = import(&fake.ctx(&plan), &full(), now()).unwrap();
    assert_eq!(
        imported(&chain),
        "imported\tLime Lab OpenVIBES CA\tLime Lab Issuing CA › Lime Lab Root CA\t2046-01-01\n"
    );
    assert_eq!(fake.text(&staged("intermediate.crt")), OURS);
    assert_eq!(fake.text(&staged("chain.crt")), ISSUING);
    assert_eq!(fake.text(&staged("root.crt")), ROOT);
    assert!(
        fake.text(&staged("intermediate.key"))
            .starts_with("-----BEGIN PRIVATE KEY-----")
    );
    assert_eq!(mode(&fake, IMPORT_DIR), 0o700);
    assert_eq!(mode(&fake, &staged("intermediate.key")), 0o600);
    // In tmpfs: a company key never lands in /etc or its backups.
    assert_eq!(IMPORT_DIR, "/run/openvibes-import");
    assert!(!fake.root.join("etc/openvibes/pki/request").exists());
    for name in ["intermediate.crt", "chain.crt", "root.crt"] {
        assert_eq!(mode(&fake, &staged(name)), 0o644, "{name}");
    }
}

/// Makes the write of `name` fail: its temp file's place is a folder.
fn block(fake: &Fake, name: &str) {
    let temp = format!("{IMPORT_DIR}/.{name}.setup");
    std::fs::create_dir_all(fake.root.join(temp.trim_start_matches('/'))).unwrap();
}

/// The regular files staged.
fn files(fake: &Fake) -> Vec<String> {
    std::fs::read_dir(fake.root.join(IMPORT_DIR.trim_start_matches('/')))
        .unwrap()
        .map(|entry| entry.unwrap())
        .filter(|entry| entry.file_type().unwrap().is_file())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect()
}

#[test]
fn a_failed_write_leaves_nothing_staged() {
    let fake = Fake::new("import-write-fails");
    let plan = plan(&[Ingest]);
    // The key is written first, then the certificate's write fails.
    block(&fake, "intermediate.crt");
    assert!(import(&fake.ctx(&plan), &full(), now()).is_err());
    assert_eq!(files(&fake), Vec::<String>::new());
}

#[test]
fn a_failed_reimport_leaves_no_old_certificates_beside_a_new_key() {
    let fake = Fake::new("import-reimport-fails");
    let plan = plan(&[Ingest]);
    import(&fake.ctx(&plan), &full(), now()).unwrap();
    block(&fake, "root.crt");
    let strict = format!("{STRICT}{ROOT}{STRICT_KEY}");
    assert!(import(&fake.ctx(&plan), &strict, now()).is_err());
    assert_eq!(files(&fake), Vec::<String>::new());
}

#[test]
fn refuses_and_writes_nothing() {
    let fake = Fake::new("import-refuses");
    let plan = plan(&[Ingest]);
    let error = import(
        &fake.ctx(&plan),
        &format!("{OURS}{ISSUING}{ROOT}{RSA_KEY}"),
        now(),
    )
    .unwrap_err();
    assert_eq!(
        error,
        "Not the key of Lime Lab OpenVIBES CA: paste the key it was made with."
    );
    assert!(!fake.root.join(IMPORT_DIR.trim_start_matches('/')).exists());
}

#[test]
fn an_installed_ca_needs_the_same_root() {
    let fake = Fake::new("import-same-root");
    let plan = plan(&[Ingest]);
    let other = platform_pki::generate_root(Utc::now()).unwrap();
    fake.file(INTERMEDIATE, OURS);
    fake.file(INTERMEDIATE_KEY, OURS_KEY);
    fake.file(ROOT_CERT, &other.cert_pem);
    assert_eq!(
        import(&fake.ctx(&plan), &full(), now()).unwrap_err(),
        "Replace: under Lime Lab Root CA, not OpenVIBES Root CA, so agents would stop \
         trusting this host. Ask for one under the same root."
    );
    assert!(!fake.root.join(IMPORT_DIR.trim_start_matches('/')).exists());
    fake.file(ROOT_CERT, &format!("\n{ROOT}\n"));
    assert!(import(&fake.ctx(&plan), &full(), now()).is_ok());
}

#[test]
fn chain_is_left_out_when_there_is_none() {
    let fake = Fake::new("import-no-chain");
    let plan = plan(&[Ingest]);
    import(&fake.ctx(&plan), &full(), now()).unwrap();
    let chain = import(
        &fake.ctx(&plan),
        &format!("{STRICT}{ROOT}{STRICT_KEY}"),
        now(),
    )
    .unwrap();
    assert_eq!(chain.path, ["Lime Lab Root CA"]);
    assert_eq!(fake.text(&staged("intermediate.crt")), STRICT);
    // The chain of an earlier import does not stay behind.
    assert!(
        !fake
            .root
            .join(staged("chain.crt").trim_start_matches('/'))
            .exists()
    );
}

#[test]
fn a_bundle_is_certificates_then_one_key() {
    let fake = Fake::new("import-bundle");
    let plan = plan(&[Ingest]);
    let ctx = fake.ctx(&plan);
    let two_keys = format!("{}{OURS_KEY}", full());
    let after = format!("{OURS}{ISSUING}{OURS_KEY}{ROOT}");
    let other = format!(
        "{OURS}{ISSUING}{ROOT}-----BEGIN RSA PRIVATE KEY-----\nAA\n-----END RSA PRIVATE KEY-----\n"
    );
    for (bundle, why) in [
        (format!("{OURS}{ISSUING}{ROOT}"), "no private key"),
        (two_keys, "one private key"),
        (after, "the key last"),
        (other, "RSA PRIVATE KEY"),
        ("-----BEGIN CERTIFICATE-----\nAA\n".into(), "no END line"),
    ] {
        let error = import(&ctx, &bundle, now()).unwrap_err();
        assert!(error.contains(why), "{error}");
        assert!(!error.contains("MIG"), "{error}");
    }
}

#[test]
fn the_bundle_is_at_most_one_mib() {
    let text = read_bundle(&mut "x".repeat(MAX).as_bytes()).unwrap();
    assert_eq!(text.len(), MAX);
    assert_eq!(
        read_bundle(&mut "x".repeat(MAX + 1).as_bytes()).unwrap_err(),
        "The certificate and key are too large (over 1 MiB)."
    );
}

#[test]
fn every_refusal_has_its_sentence() {
    let day = Utc.with_ymd_and_hms(2026, 12, 1, 0, 0, 0).unwrap();
    let name = "Lime Lab OpenVIBES CA";
    let message = |e: ChainError| import_message(&e, name, None);
    assert_eq!(
        message(ChainError::NotCa("Web".into())),
        "Web is not a CA, so it cannot sign agent certificates."
    );
    assert_eq!(
        message(ChainError::Missing("Root".into())),
        "Signed by Root, missing here: paste it below this one."
    );
    assert_eq!(
        message(ChainError::IsRoot("Root".into())),
        "Root is a root CA: paste the intermediate made for OpenVIBES first, then the CAs above it."
    );
    assert_eq!(
        message(ChainError::NotYetValid(day)),
        "Valid from 2026-12-01: not valid yet."
    );
    assert_eq!(
        message(ChainError::NoCaBelow("Strict".into())),
        "Strict allows no CA below it: ask for one more level."
    );
    assert_eq!(
        message(ChainError::Expiring(day)),
        "Valid until 2026-12-01: under the 90 days a server certificate lasts."
    );
    assert_eq!(
        message(ChainError::InvalidPem),
        "This is not a certificate in PEM form (-----BEGIN CERTIFICATE-----)."
    );
    let pki = |e: PkiError| message(ChainError::Pki(e));
    assert_eq!(
        pki(PkiError::WeakKey(1024)),
        "A 1024-bit RSA key is too weak: 2048 bits or more."
    );
    assert_eq!(pki(PkiError::WrongPassword), "Wrong password.");
    assert_eq!(
        import_message(
            &ChainError::Pki(PkiError::WrongPassword),
            name,
            Some("ours.key")
        ),
        "Wrong password for ours.key."
    );
    assert_eq!(
        pki(PkiError::KeyMismatch),
        "Not the key of Lime Lab OpenVIBES CA: paste the key it was made with."
    );
    assert_eq!(
        pki(PkiError::NameMismatch),
        "OpenVIBES cannot reproduce Lime Lab OpenVIBES CA's name exactly, so its certificates \
         would not chain: ask for a certificate with a UTF-8 name."
    );
    assert_eq!(
        pki(PkiError::UnsupportedKey),
        "This key type is not supported: use RSA (2048 to 4096 bits), EC P-256 or P-384, or \
         Ed25519."
    );
    assert_eq!(
        pki(PkiError::KeyLocked),
        "The key is locked: give its password."
    );
    assert_eq!(
        pki(PkiError::OldEncryption),
        "This key's encryption is too old to open here: ask for it with AES."
    );
    let servers = |limit| message(ChainError::NotForServers("Issuing".into(), limit));
    for (limit, reason) in [
        (ServerLimit::KeyUsage, "its extended key usage"),
        (ServerLimit::NameConstraints, "its name constraints"),
        (ServerLimit::OldSignature, "an old signature algorithm"),
        (
            ServerLimit::UnknownExtension,
            "an extension OpenVIBES cannot read",
        ),
        (ServerLimit::Other, "a check agents make"),
    ] {
        assert_eq!(
            servers(limit),
            format!(
                "Issuing may not sign server certificates ({reason}): ask for one without that \
                 limit."
            )
        );
    }
    assert_eq!(
        pki(PkiError::NotCa),
        "The certificate was refused: certificate is not a CA."
    );
}

#[test]
fn a_ca_agents_refuse_for_servers_is_refused() {
    let fake = Fake::new("import-not-for-servers");
    let plan = plan(&[Ingest]);
    let bundle = format!("{CLIENT_ONLY}{ROOT}{CLIENT_ONLY_KEY}");
    assert_eq!(
        import(&fake.ctx(&plan), &bundle, now()).unwrap_err(),
        "Lime Lab Client Only CA may not sign server certificates (its extended key usage): \
         ask for one without that limit."
    );
    assert!(!fake.root.join(IMPORT_DIR.trim_start_matches('/')).exists());
}

#[test]
fn a_key_that_is_not_pkcs8_is_said_as_a_key() {
    let fake = Fake::new("import-not-pkcs8");
    let plan = plan(&[Ingest]);
    let bundle = format!(
        "{OURS}{ISSUING}{ROOT}-----BEGIN PRIVATE KEY-----\nAA\n-----END PRIVATE KEY-----\n"
    );
    assert_eq!(
        import(&fake.ctx(&plan), &bundle, now()).unwrap_err(),
        "This is not a private key in PEM form (-----BEGIN PRIVATE KEY-----)."
    );
}
