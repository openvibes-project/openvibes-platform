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
    assert_eq!(
        it[0].snippet.chars().count(),
        1000 + "\nopenssh: fixed in 9.8p1".len()
    );
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
    assert_eq!(
        handle(&search, &setting(2), &[], &h),
        Response::Refused {
            code: Refusal::Unavailable
        }
    );
    assert!(h.seen.borrow().is_empty());
}
