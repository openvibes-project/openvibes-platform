//! Every `rule-bundle-request` fixture is accepted or refused as named, and
//! every valid `signed-rule-envelope` fixture is served byte for byte.

mod support;

use std::{fs, path::PathBuf};

use support::{World, request};

fn fixtures(message: &str) -> Vec<(String, Vec<u8>)> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../protocol/fixtures/v1")
        .join(message);
    let mut files: Vec<_> = fs::read_dir(&dir)
        .unwrap_or_else(|_| panic!("protocol fixtures missing; run `git submodule update --init`"))
        .map(|entry| {
            let path = entry.unwrap().path();
            let name = path.file_name().unwrap().to_str().unwrap().to_owned();
            (name, fs::read(&path).unwrap())
        })
        .collect();
    files.sort();
    assert!(!files.is_empty(), "no {message} fixtures");
    files
}

#[test]
fn rule_bundle_requests_match_their_fixtures() {
    for (name, bytes) in fixtures("rule-bundle-request") {
        assert_eq!(
            openvibes_distribution::accepts(&bytes),
            name.starts_with("valid"),
            "{name}"
        );
    }
}

#[tokio::test]
async fn valid_envelopes_are_served_byte_for_byte() {
    let world = World::start().await;
    let agent = world.agent(1).await;
    let valid: Vec<_> = fixtures("signed-rule-envelope")
        .into_iter()
        .filter(|(name, _)| name.starts_with("valid"))
        .collect();
    for (index, (name, bytes)) in valid.iter().enumerate() {
        let set = format!("fixture{index}");
        world.publish(&set, 1, bytes).await;
        let served = world.fetch(&agent, &set, None).await.unwrap();
        assert_eq!(served.as_deref(), Some(bytes.as_slice()), "{name}");
    }
    world.stop().await;
    let _ = request;
}
