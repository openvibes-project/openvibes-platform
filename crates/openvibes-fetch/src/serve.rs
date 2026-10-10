//! Request handling: pure (no database, no network of its own), so tests
//! drive it with a fake [`Http`].

use crate::{
    bodhi,
    filter::{check_query, is_public_id},
    http::{Http, MAX_BODY, allowed},
    osv,
    protocol::{Kind, Refusal, Request, Response},
    searxng,
};
use platform_store::assistant_internet::Setting;

/// Answers one request under `setting`. `deny` (host and user names, internal
/// domains) is checked against reference IDs too, since a well-formed ID can
/// still carry a host name.
pub fn handle(req: &Request, setting: &Setting, deny: &[String], http: &dyn Http) -> Response {
    let refuse = |code| Response::Refused { code };
    if setting.level < 1 {
        return refuse(Refusal::Off);
    }
    let id = match &req.kind {
        Kind::Reference { id } if is_public_id(id) => id,
        Kind::Reference { .. } => return refuse(Refusal::Invalid),
        Kind::Search { query } if setting.level >= 2 => return search(query, setting, deny, http),
        Kind::Search { .. } => return refuse(Refusal::Off),
    };
    if let Err(code) = check_query(id, deny) {
        return refuse(code);
    }
    let fedora = id.starts_with("FEDORA-");
    let (url, source) = if fedora {
        (
            format!("https://bodhi.fedoraproject.org/updates/{id}"),
            "bodhi.fedoraproject.org",
        )
    } else {
        (format!("https://api.osv.dev/v1/vulns/{id}"), "osv.dev")
    };
    if !allowed(&url) {
        return refuse(Refusal::Unavailable);
    }
    let Ok(body) = http.get(&url) else {
        return refuse(Refusal::Unavailable);
    };
    if body.len() > MAX_BODY {
        return refuse(Refusal::TooLarge);
    }
    let Ok(value) = serde_json::from_slice(&body) else {
        return refuse(Refusal::Unavailable);
    };
    let items = if fedora {
        bodhi::extract(id, &value)
    } else {
        osv::extract(id, &value)
    };
    match items {
        Some(items) => Response::Ok {
            source: source.into(),
            items,
        },
        None => refuse(Refusal::Unavailable),
    }
}

/// Level 2: the query (after the filter) to the stored SearXNG.
fn search(query: &str, setting: &Setting, deny: &[String], http: &dyn Http) -> Response {
    let refuse = |code| Response::Refused { code };
    if let Err(code) = check_query(query, deny) {
        return refuse(code);
    }
    let Some(base) = setting.searxng_url.as_deref() else {
        return refuse(Refusal::Unavailable);
    };
    let Ok(body) = http.get(&searxng::search_url(base, query)) else {
        return refuse(Refusal::Unavailable);
    };
    if body.len() > MAX_BODY {
        return refuse(Refusal::TooLarge);
    }
    match serde_json::from_slice(&body)
        .ok()
        .and_then(|v: serde_json::Value| searxng::extract(&v))
    {
        Some(items) => Response::Ok {
            source: searxng::host(base),
            items,
        },
        None => refuse(Refusal::Unavailable),
    }
}
