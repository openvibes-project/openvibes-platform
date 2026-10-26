//! The console's own certificate: what it must be, and which names it covers.

use chrono::{DateTime, TimeZone, Utc};
use platform_pki::{PkiError, ServerCertError, check_server_cert, check_server_key, covers};

const ISSUING: &str = include_str!("fixtures/issuing.crt");
const ROOT: &str = include_str!("fixtures/root.crt");
const SERVER: &str = include_str!("fixtures/server.crt");
const SERVER_KEY: &str = include_str!("fixtures/server.key");
const EXPIRED: &str = include_str!("fixtures/server-expired.crt");
const FUTURE: &str = include_str!("fixtures/server-future.crt");
const CLIENT_ONLY: &str = include_str!("fixtures/server-client-only.crt");
const CN_ONLY: &str = include_str!("fixtures/server-cn-only.crt");
const OTHER_KEY: &str = include_str!("fixtures/ours-ec.pkcs8.pem");

fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2027, 6, 1, 0, 0, 0).unwrap()
}

fn names(list: &[&str]) -> Vec<String> {
    list.iter().map(|name| (*name).to_owned()).collect()
}

#[test]
fn a_server_certificate_is_accepted() {
    let cert = check_server_cert(
        SERVER,
        &names(&["limebox.lan", "openvibes.limebox.se"]),
        now(),
    )
    .unwrap();
    assert_eq!(cert.covers, ["openvibes.limebox.se"]);
    assert_eq!(cert.name, "*.limebox.se");
    assert_eq!(cert.chain_pem, SERVER);
    assert_eq!(
        cert.not_after,
        Utc.with_ymd_and_hms(2046, 1, 1, 0, 0, 0).unwrap()
    );
}

#[test]
fn a_wildcard_covers_one_label() {
    assert!(covers(SERVER, "a.limebox.se"));
    assert!(covers(SERVER, "A.LimeBox.SE"));
    assert!(!covers(SERVER, "limebox.se"));
    assert!(!covers(SERVER, "a.b.limebox.se"));
    assert!(!covers(SERVER, "limebox.lan"));
}

#[test]
fn an_ip_san_matches_exactly() {
    assert!(covers(SERVER, "10.0.0.5"));
    assert!(!covers(SERVER, "10.0.0.6"));
    assert!(!covers(SERVER, "10.0.0.50"));
}

#[test]
fn a_ca_is_refused() {
    let result = check_server_cert(ISSUING, &names(&["a.limebox.se"]), now());
    assert_eq!(result.unwrap_err(), ServerCertError::IsCa);
}

#[test]
fn client_only_is_refused() {
    let result = check_server_cert(CLIENT_ONLY, &names(&["a.limebox.se"]), now());
    assert_eq!(result.unwrap_err(), ServerCertError::NotForServers);
}

#[test]
fn expired_and_not_yet_valid_are_refused() {
    let wanted = names(&["a.limebox.se"]);
    let end = Utc.with_ymd_and_hms(2026, 6, 1, 0, 0, 0).unwrap();
    let start = Utc.with_ymd_and_hms(2040, 1, 1, 0, 0, 0).unwrap();
    assert_eq!(
        check_server_cert(EXPIRED, &wanted, now()).unwrap_err(),
        ServerCertError::Expired(end)
    );
    assert_eq!(
        check_server_cert(FUTURE, &wanted, now()).unwrap_err(),
        ServerCertError::NotYetValid(start)
    );
}

#[test]
fn covering_no_name_is_refused() {
    let result = check_server_cert(SERVER, &names(&["limebox.se", "10.0.0.6"]), now());
    assert_eq!(result.unwrap_err(), ServerCertError::CoversNone);
}

#[test]
fn a_common_name_alone_covers_nothing() {
    let name = names(&["openvibes.limebox.se"]);
    assert!(!covers(CN_ONLY, "openvibes.limebox.se"));
    let result = check_server_cert(CN_ONLY, &name, now());
    assert_eq!(result.unwrap_err(), ServerCertError::CoversNone);
}

#[test]
fn garbage_is_refused() {
    let wanted = names(&["a.limebox.se"]);
    assert_eq!(
        check_server_cert("", &wanted, now()).unwrap_err(),
        ServerCertError::InvalidPem
    );
    assert_eq!(
        check_server_cert("not pem", &wanted, now()).unwrap_err(),
        ServerCertError::InvalidPem
    );
}

#[test]
fn the_key_must_match() {
    let cert = check_server_cert(SERVER, &names(&["a.limebox.se"]), now()).unwrap();
    assert!(check_server_key(&cert, SERVER_KEY).is_ok());
    assert_eq!(
        check_server_key(&cert, OTHER_KEY).unwrap_err(),
        ServerCertError::Pki(PkiError::KeyMismatch)
    );
    assert_eq!(
        check_server_key(&cert, include_str!("fixtures/weak.key")).unwrap_err(),
        ServerCertError::Pki(PkiError::WeakKey(1024))
    );
}

#[test]
fn the_chain_is_kept_in_order() {
    let given = format!("{SERVER}{ISSUING}{ROOT}");
    let cert = check_server_cert(&given, &names(&["a.limebox.se"]), now()).unwrap();
    assert_eq!(cert.chain_pem, given);
}

/// A self-signed certificate with these DNS names (rcgen's defaults: no
/// extended key usage, valid long before and after `now`).
fn with_names(sans: &[&str]) -> String {
    let names = sans
        .iter()
        .map(|name| (*name).to_owned())
        .collect::<Vec<_>>();
    rcgen::generate_simple_self_signed(names)
        .unwrap()
        .cert
        .pem()
}

#[test]
fn a_wildcard_over_a_public_suffix_covers_nothing() {
    let cert = with_names(&["*.com", "*.lan"]);
    assert!(!covers(&cert, "example.com"));
    assert!(!covers(&cert, "console.lan"));
    let result = check_server_cert(&cert, &names(&["console.lan"]), now());
    assert_eq!(result.unwrap_err(), ServerCertError::CoversNone);
}

#[test]
fn a_malformed_ip_name_is_refused() {
    // "abcde" as a DNS name ([2], 0x82), retagged as a five-byte IP address
    // ([7], 0x87): the same length, so the DER still parses.
    let pem = with_names(&["console.lan", "abcde"]);
    let mut der = platform_pki::certificates(&pem).unwrap().remove(0);
    let at = der.windows(7).position(|w| w == b"\x82\x05abcde").unwrap();
    der[at] = 0x87;
    let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &der);
    let pem = format!("-----BEGIN CERTIFICATE-----\n{b64}\n-----END CERTIFICATE-----\n");
    let result = check_server_cert(&pem, &names(&["console.lan"]), now());
    assert_eq!(result.unwrap_err(), ServerCertError::InvalidPem);
}
