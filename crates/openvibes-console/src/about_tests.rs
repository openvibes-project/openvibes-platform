//! Tests for the About page and the newer-version check.

use std::{
    io::{Read, Write},
    net::TcpListener,
};

use super::*;

fn release(tag: &str) -> Vec<u8> {
    format!(
        r#"{{"tag_name":"{tag}","html_url":"{RELEASE_PAGE_PREFIX}releases/tag/{tag}","draft":false,"prerelease":false,"assets":[]}}"#
    )
    .into_bytes()
}

#[test]
fn newest_version_compares_numerically() {
    let versions = ["0.2.9", "0.2.10", "junk"].map(String::from);
    assert_eq!(
        newest_version(versions.into_iter()).as_deref(),
        Some("0.2.10")
    );
    assert_eq!(newest_version(std::iter::empty()), None);
}

#[test]
fn parses_plain_versions_only() {
    assert_eq!(parse_version("0.2.4"), Some([0, 2, 4]));
    for bad in ["", "1.2", "1.2.3.4", "1.2.x", "1.2.3-rc1", "v1.2.3", "1..3"] {
        assert_eq!(parse_version(bad), None, "{bad}");
    }
}

#[test]
fn compares_numerically() {
    let latest = |v: &str| parse_release(&release(v), RELEASE_PAGE_PREFIX).unwrap();
    assert_eq!(
        classify("0.2.4", Some(latest("v0.2.10"))).state,
        UpdateState::Available
    );
    assert_eq!(
        classify("0.2.4", Some(latest("v0.2.4"))).state,
        UpdateState::UpToDate
    );
    assert_eq!(
        classify("0.3.0", Some(latest("v0.2.9"))).state,
        UpdateState::UpToDate
    );
    assert_eq!(classify("0.2.4", None).state, UpdateState::Unavailable);
}

#[test]
fn ignores_prereleases_foreign_links_and_junk() {
    let pre = br#"{"tag_name":"v9.9.9","html_url":"https://github.com/openvibes-project/openvibes-platform/x","prerelease":true}"#;
    assert!(parse_release(pre, RELEASE_PAGE_PREFIX).is_none());
    let foreign = br#"{"tag_name":"v9.9.9","html_url":"https://evil.example/x"}"#;
    assert!(parse_release(foreign, RELEASE_PAGE_PREFIX).is_none());
    assert!(parse_release(b"not json", RELEASE_PAGE_PREFIX).is_none());
    assert!(parse_release(br#"{"tag_name":"nightly","html_url":"https://github.com/openvibes-project/openvibes-platform/x"}"#, RELEASE_PAGE_PREFIX).is_none());
}

fn serve_once(body: Vec<u8>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/latest", listener.local_addr().unwrap());
    std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut request = [0u8; 2048];
            let _ = stream.read(&mut request);
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(&body);
        }
    });
    url
}

#[tokio::test]
async fn fetches_once_then_serves_from_cache() {
    let checker = UpdateChecker::with_urls(&serve_once(release("v0.9.0")), &refused());
    let first = checker.check("0.2.4").await;
    assert_eq!(first.state, UpdateState::Available);
    assert_eq!(first.latest_version.as_deref(), Some("0.9.0"));
    // The server above answered once and is gone; this must be cached.
    assert_eq!(checker.check("0.2.4").await.state, UpdateState::Available);
}

#[tokio::test]
async fn offline_is_unavailable_not_an_error() {
    let unused = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/latest", unused.local_addr().unwrap());
    drop(unused);
    let checker = UpdateChecker::with_urls(&url, &url);
    let result = checker.check("0.2.4").await;
    assert_eq!(result.state, UpdateState::Unavailable);
    assert!(result.latest_version.is_none());
}

fn refused() -> String {
    let unused = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/latest", unused.local_addr().unwrap());
    drop(unused);
    url
}

fn agent_release(tag: &str) -> Vec<u8> {
    format!(r#"{{"tag_name":"{tag}","html_url":"{AGENT_RELEASE_PAGE_PREFIX}releases/tag/{tag}"}}"#)
        .into_bytes()
}

#[test]
fn an_agent_release_links_only_into_the_agent_repository() {
    assert_eq!(
        parse_release(&agent_release("v0.2.7"), AGENT_RELEASE_PAGE_PREFIX).map(|l| l.version),
        Some("0.2.7".to_owned())
    );
    assert!(parse_release(&release("v0.2.7"), AGENT_RELEASE_PAGE_PREFIX).is_none());
}

#[tokio::test]
async fn the_latest_agent_release_is_looked_up_on_its_own() {
    let checker = UpdateChecker::with_urls(&refused(), &serve_once(agent_release("v0.2.7")));
    let result = checker.check("0.2.9").await;
    // The platform's own release could not be fetched; the agent's could.
    assert_eq!(result.state, UpdateState::Unavailable);
    assert_eq!(result.latest_agent_version.as_deref(), Some("0.2.7"));
}
