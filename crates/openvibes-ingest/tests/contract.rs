//! Every protocol fixture for the ingest requests through the parsing and
//! validation layer. (Full acceptance is covered with the real agent client:
//! fixture tokens and CSRs are placeholders.)

use std::{fs, path::Path};

use openvibes_core::{EnrollmentRequest, FindingBatch, Heartbeat, RenewalRequest};
use openvibes_ingest::accepts;

#[test]
fn request_fixtures_parse_or_are_refused() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../protocol/fixtures/v1");
    let mut checked = 0;
    for (message, accept) in [
        (
            "enrollment-request",
            accepts::<EnrollmentRequest> as fn(&[u8]) -> bool,
        ),
        ("renewal-request", accepts::<RenewalRequest>),
        ("heartbeat", accepts::<Heartbeat>),
        ("finding-batch", accepts::<FindingBatch>),
    ] {
        for fixture in fs::read_dir(root.join(message)).expect("protocol submodule") {
            let path = fixture.unwrap().path();
            let valid = path
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("valid");
            assert_eq!(
                accept(&fs::read(&path).unwrap()),
                valid,
                "{}",
                path.display()
            );
            checked += 1;
        }
    }
    assert!(checked >= 8);
}
