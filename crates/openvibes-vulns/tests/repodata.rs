//! Fedora mirror list (metalink) and repository index (repomd.xml), against
//! trimmed real Fedora 44 files.

use std::path::PathBuf;

use openvibes_vulns::repodata::{self, hex};

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name),
    )
    .unwrap()
}

#[test]
fn metalink_gives_accepted_hashes_and_web_mirrors() {
    let metalink = repodata::metalink(&fixture("metalink-f44.xml")).unwrap();
    assert_eq!(
        hex(&metalink.sha256[0]),
        "d843ccef8d1aa4aedfccf8004815459ccd7913bc47060bf7a54082064120e911",
        "current repomd.xml first"
    );
    assert!(
        metalink.sha256.len() > 1,
        "alternates for lagging mirrors are accepted too"
    );
    assert_eq!(metalink.urls.len(), 3, "rsync dropped");
    assert!(metalink.urls[0].starts_with("https://") && metalink.urls[1].starts_with("https://"));
    assert!(
        metalink.urls[2].starts_with("http://"),
        "https first, then http"
    );
    assert!(
        metalink
            .urls
            .iter()
            .all(|u| u.ends_with("/repodata/repomd.xml"))
    );
}

#[test]
fn repomd_names_the_updateinfo_file() {
    let location = repodata::updateinfo_location(&fixture("repomd-f44.xml")).unwrap();
    assert_eq!(
        location.href,
        "repodata/04b5397e768e2dd2e73337dcc0078490a48597f5af1b5a2ce60cbf8966e1cbb5-updateinfo.xml.zst"
    );
    assert_eq!(
        hex(&location.sha256),
        "04b5397e768e2dd2e73337dcc0078490a48597f5af1b5a2ce60cbf8966e1cbb5"
    );
    assert_eq!(location.size, 2_143_567);
}

#[test]
fn malformed_input_is_refused() {
    assert!(repodata::metalink(b"<metalink>").is_err());
    assert!(
        repodata::updateinfo_location(b"<repomd></repomd>").is_err(),
        "no updateinfo"
    );
    let traversal = String::from_utf8(fixture("repomd-f44.xml"))
        .unwrap()
        .replace("repodata/04b5", "../../etc/04b5");
    assert!(
        repodata::updateinfo_location(traversal.as_bytes()).is_err(),
        "the location must stay under repodata/"
    );
}
