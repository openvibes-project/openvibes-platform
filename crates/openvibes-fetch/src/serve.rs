//! Request handling: pure (no database, no network of its own), so tests
//! drive it with a fake [`Http`].

use crate::{
    bodhi,
    filter::{check_query, is_public_id},
    http::{Http, MAX_BODY, allowed},
    osv,
    protocol::{Kind, Refusal, Request, Response},
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
        // Web search is built with the SearXNG task; until then level 2
        // answers Unavailable and lower levels Off.
        Kind::Search { .. } if setting.level >= 2 => return refuse(Refusal::Unavailable),
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
