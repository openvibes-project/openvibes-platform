//! `serve::handle` against a fake `Http`.

use std::cell::RefCell;

use chrono::Utc;
use openvibes_fetch::{
    http::Http,
    protocol::{Kind, Refusal, Request, Response},
    serve::handle,
};
use platform_store::assistant_internet::Setting;

const OSV: &str = include_str!("fixtures/osv-CVE-2024-6387.json");
const BODHI: &str = include_str!("fixtures/bodhi-FEDORA-2026-7617430be1.json");

struct Fake {
    reply: Result<Vec<u8>, String>,
    seen: RefCell<Vec<String>>,
}

impl Http for Fake {
    fn get(&self, url: &str) -> Result<Vec<u8>, String> {
        self.seen.borrow_mut().push(url.to_owned());
        self.reply.clone()
    }
}

fn fake(body: &[u8]) -> Fake {
    Fake {
        reply: Ok(body.to_vec()),
        seen: RefCell::default(),
    }
}

fn setting(level: i16) -> Setting {
    Setting {
        level,
        searxng_url: None,
        internal_domains: vec![],
        version: 1,
        updated_at: Utc::now(),
        updated_by: "t".into(),
    }
}

fn reference(id: &str) -> Request {
    Request {
        user: "alex".into(),
        kind: Kind::Reference { id: id.into() },
    }
}

fn items(r: Response) -> Vec<openvibes_fetch::protocol::Item> {
    match r {
        Response::Ok { items, .. } => items,
        other => panic!("{other:?}"),
    }
}

#[test]
fn refuses_when_level_is_zero() {
    let h = fake(OSV.as_bytes());
    let r = handle(&reference("CVE-2024-6387"), &setting(0), &[], &h);
    assert_eq!(r, Response::Refused { code: Refusal::Off });
    assert!(h.seen.borrow().is_empty());
}

#[test]
fn osv_reference_summary_references_and_fixed_versions() {
    let h = fake(OSV.as_bytes());
    let r = handle(&reference("CVE-2024-6387"), &setting(1), &[], &h);
    assert_eq!(
        *h.seen.borrow(),
        ["https://api.osv.dev/v1/vulns/CVE-2024-6387"]
    );
    let Response::Ok { source, items } = r else {
        panic!()
    };
    assert_eq!(source, "osv.dev");
    assert!(
        items[0]
            .title
            .starts_with("CVE-2024-6387: Openssh: regresshion")
    );
    assert!(items[0].snippet.starts_with("Openssh: regresshion"));
    assert!(items.len() <= 6 && items.len() > 1);
    assert!(items[1..].iter().all(|i| i.url.starts_with("https://")));
}

#[test]
fn osv_fixed_versions_per_package_and_long_text_cut() {
    let long = "é".repeat(2000);
    let body = format!(
        r#"{{"id":"CVE-2024-0001","summary":"s","details":"{long}","affected":[
        {{"package":{{"name":"openssh"}},"ranges":[{{"type":"ECOSYSTEM","events":[{{"introduced":"0"}},{{"fixed":"9.8p1"}}]}}]}}]}}"#
    );
    let h = fake(body.as_bytes());
    let it = items(handle(&reference("CVE-2024-0001"), &setting(1), &[], &h));
    assert_eq!(it[0].snippet, "s\nopenssh: fixed in 9.8p1");
    let body = body.replace(r#""summary":"s","#, "");
    let h = fake(body.as_bytes());
    let it = items(handle(&reference("CVE-2024-0001"), &setting(1), &[], &h));
    assert!(it[0].snippet.starts_with("éé"));
    assert_eq!(it[0].snippet.chars().count(), 1000);
    assert!(it[0].snippet.ends_with("\nopenssh: fixed in 9.8p1"));
}

#[test]
fn fedora_ids_go_to_bodhi() {
    let h = fake(BODHI.as_bytes());
    let r = handle(&reference("FEDORA-2026-7617430be1"), &setting(1), &[], &h);
    assert_eq!(
        *h.seen.borrow(),
        ["https://bodhi.fedoraproject.org/updates/FEDORA-2026-7617430be1"]
    );
    let Response::Ok { source, items } = r else {
        panic!()
    };
    assert_eq!(source, "bodhi.fedoraproject.org");
    assert_eq!(items[0].title, "python-drgn-0.3.0-1.fc43");
    assert_eq!(
        items[0].snippet,
        "Update to 0.3.0\nfixed in python-drgn-0.3.0-1.fc43"
    );
}

#[test]
fn limits_and_redirects() {
    let big = fake(&vec![b' '; 256 * 1024 + 1]);
    assert_eq!(
        handle(&reference("CVE-2024-6387"), &setting(1), &[], &big),
        Response::Refused {
            code: Refusal::TooLarge
        }
    );
    let text = fake(b"<html>");
    assert_eq!(
        handle(&reference("CVE-2024-6387"), &setting(1), &[], &text),
        Response::Refused {
            code: Refusal::Unavailable
        }
    );
    let redirect = Fake {
        reply: Err("status 302".into()),
        seen: RefCell::default(),
    };
    assert_eq!(
        handle(&reference("CVE-2024-6387"), &setting(1), &[], &redirect),
        Response::Refused {
            code: Refusal::Unavailable
        }
    );
    assert_eq!(redirect.seen.borrow().len(), 1);
}

#[test]
fn invalid_ids_and_search() {
    let h = fake(OSV.as_bytes());
    assert_eq!(
        handle(&reference("../x"), &setting(1), &[], &h),
        Response::Refused {
            code: Refusal::Invalid
        }
    );
    let search = Request {
        user: "a".into(),
        kind: Kind::Search { query: "x".into() },
    };
    assert_eq!(
        handle(&search, &setting(1), &[], &h),
        Response::Refused { code: Refusal::Off }
    );
    assert!(h.seen.borrow().is_empty());
}

#[test]
fn record_without_affected_and_long_fixed_versions() {
    let h = fake(br#"{"id":"CVE-2024-0002","summary":"only a summary"}"#);
    let it = items(handle(&reference("CVE-2024-0002"), &setting(1), &[], &h));
    assert_eq!(it[0].snippet, "only a summary");
    let v = "9".repeat(300);
    let body = format!(
        r#"{{"id":"CVE-2024-0003","summary":"s","affected":[{{"package":{{"name":"p"}},"ranges":[{{"type":"SEMVER","events":[{{"fixed":"{v}"}}]}}]}}]}}"#
    );
    let it = items(handle(
        &reference("CVE-2024-0003"),
        &setting(1),
        &[],
        &fake(body.as_bytes()),
    ));
    assert_eq!(it[0].snippet, format!("s\np: fixed in {}", "9".repeat(100)));
}

#[test]
fn reference_ids_are_checked_against_the_deny_list() {
    let h = fake(OSV.as_bytes());
    let deny = vec!["web01".to_string()];
    assert_eq!(
        handle(&reference("HOST-2026-web01"), &setting(1), &deny, &h),
        Response::Refused {
            code: Refusal::Blocked
        }
    );
    assert!(h.seen.borrow().is_empty());
}

const SEARX: &str = include_str!("fixtures/searxng-openvibes.json");

fn search_setting(level: i16, url: &str) -> Setting {
    Setting {
        searxng_url: Some(url.into()),
        ..setting(level)
    }
}

fn search(query: &str) -> Request {
    Request {
        user: "a".into(),
        kind: Kind::Search {
            query: query.into(),
        },
    }
}

#[test]
fn search_asks_searxng_and_bounds_the_results() {
    let h = fake(SEARX.as_bytes());
    for base in ["http://10.0.0.5:8080", "http://10.0.0.5:8080/"] {
        h.seen.borrow_mut().clear();
        let r = handle(&search("rust & tls"), &search_setting(2, base), &[], &h);
        assert_eq!(
            *h.seen.borrow(),
            ["http://10.0.0.5:8080/search?q=rust%20%26%20tls&format=json"]
        );
        let Response::Ok { source, items } = r else {
            panic!("{r:?}")
        };
        assert_eq!(source, "10.0.0.5:8080");
        assert_eq!(items.len(), 5);
        // result 1 is javascript: and dropped; 2 has the 900-char snippet
        assert_eq!(items[0].title, "Result 2 about openvibes");
        assert_eq!(items[0].snippet.chars().count(), 300);
        assert!(items.iter().all(|i| i.url.starts_with("https://")));
    }
}

#[test]
fn search_is_filtered_gated_and_needs_a_url() {
    let h = fake(SEARX.as_bytes());
    let s2 = search_setting(2, "https://searx.example.org");
    let deny = vec!["web01".to_string()];
    assert_eq!(
        handle(&search("why is web01 slow"), &s2, &deny, &h),
        Response::Refused {
            code: Refusal::Blocked
        }
    );
    assert_eq!(
        handle(
            &search("openvibes"),
            &search_setting(1, "https://s.example.org"),
            &[],
            &h
        ),
        Response::Refused { code: Refusal::Off }
    );
    assert_eq!(
        handle(&search("openvibes"), &setting(2), &[], &h),
        Response::Refused {
            code: Refusal::Unavailable
        }
    );
    assert!(h.seen.borrow().is_empty());
    let bad = fake(b"<html>");
    assert_eq!(
        handle(&search("openvibes"), &s2, &[], &bad),
        Response::Refused {
            code: Refusal::Unavailable
        }
    );
}

#[test]
fn a_stored_searxng_url_the_console_would_refuse_is_never_contacted() {
    let h = fake(SEARX.as_bytes());
    for url in [
        "http://203.0.113.5",
        "https://user@x.example",
        "ftp://x",
        "https://x.example/?a=b",
        "https://x.example:0",
    ] {
        assert_eq!(
            handle(&search("openvibes"), &search_setting(2, url), &[], &h),
            Response::Refused {
                code: Refusal::Unavailable
            },
            "{url}"
        );
    }
    assert!(h.seen.borrow().is_empty());
}
