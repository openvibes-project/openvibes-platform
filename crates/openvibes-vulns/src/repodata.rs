//! Fedora's mirror list (metalink) and repository index (`repomd.xml`).

use quick_xml::{
    Reader, XmlVersion,
    events::{BytesStart, Event},
};

/// What a metalink says about `repomd.xml`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Metalink {
    /// Accepted SHA-256 digests: the current one first, then alternates
    /// (older versions still served by lagging mirrors).
    pub sha256: Vec<[u8; 32]>,
    /// Mirror URLs of `repomd.xml`: https first, then http (integrity comes
    /// from the digests, fetched over HTTPS).
    pub urls: Vec<String>,
}

/// Where the updateinfo file is, per `repomd.xml`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Location {
    /// Path relative to the repository root, under `repodata/`.
    pub href: String,
    /// SHA-256 of the file as served (compressed).
    pub sha256: [u8; 32],
    /// Size as served, in bytes.
    pub size: u64,
}

/// Lowercase hex of a digest.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Option<[u8; 32]> {
    let text = text.trim();
    if text.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(text.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

fn attr(element: &BytesStart<'_>, name: &str) -> Option<String> {
    element
        .try_get_attribute(name)
        .ok()
        .flatten()
        .and_then(|value| value.normalized_value(XmlVersion::Explicit1_0).ok())
        .map(|value| value.into_owned())
}

/// Parses a metalink: every SHA-256 in document order (the file's own
/// digest precedes its alternates) and the https and http mirror URLs.
pub fn metalink(bytes: &[u8]) -> Result<Metalink, ()> {
    let mut reader = Reader::from_reader(bytes);
    let mut buf = Vec::new();
    let (mut sha256, mut https, mut http) = (Vec::new(), Vec::new(), Vec::new());
    let mut collecting: Option<(bool, Option<String>)> = None; // (is hash, url protocol)
    let mut text = String::new();
    loop {
        match reader.read_event_into(&mut buf).map_err(drop)? {
            Event::Eof => break,
            Event::Start(element) => match element.local_name().as_ref() {
                "hash" if attr(&element, "type").as_deref() == Some("sha256") => {
                    collecting = Some((true, None));
                    text.clear();
                }
                "url" => {
                    collecting = Some((false, attr(&element, "protocol")));
                    text.clear();
                }
                _ => {}
            },
            Event::Text(t) if collecting.is_some() => text.push_str(&t.xml10_content()),
            Event::GeneralRef(r) if collecting.is_some() => {
                if r.xml10_content() == "amp" {
                    text.push('&');
                }
            }
            Event::End(element) => {
                let name = element.local_name();
                match (collecting.take(), name.as_ref()) {
                    (Some((true, _)), "hash") => sha256.push(unhex(&text).ok_or(())?),
                    (Some((false, protocol)), "url") => match protocol.as_deref() {
                        Some("https") => https.push(text.trim().to_owned()),
                        Some("http") => http.push(text.trim().to_owned()),
                        _ => {}
                    },
                    (other, _) => collecting = other,
                }
            }
            _ => {}
        }
        buf.clear();
    }
    if sha256.is_empty() || (https.is_empty() && http.is_empty()) {
        return Err(());
    }
    https.extend(http);
    Ok(Metalink {
        sha256,
        urls: https,
    })
}

/// Finds the `updateinfo` entry (not `updateinfo_zck`) in `repomd.xml`.
/// Its location must stay under `repodata/`.
pub fn updateinfo_location(bytes: &[u8]) -> Result<Location, ()> {
    let mut reader = Reader::from_reader(bytes);
    let mut buf = Vec::new();
    let mut inside = false;
    let (mut href, mut sha256, mut size) = (None, None, None);
    let mut field: Option<&str> = None;
    let mut text = String::new();
    loop {
        match reader.read_event_into(&mut buf).map_err(drop)? {
            Event::Eof => break,
            Event::Start(element) | Event::Empty(element) => match element.local_name().as_ref() {
                "data" => inside = attr(&element, "type").as_deref() == Some("updateinfo"),
                "location" if inside => href = attr(&element, "href"),
                "checksum" if inside && attr(&element, "type").as_deref() == Some("sha256") => {
                    field = Some("checksum");
                    text.clear();
                }
                "size" if inside => {
                    field = Some("size");
                    text.clear();
                }
                _ => {}
            },
            Event::Text(t) if field.is_some() => text.push_str(&t.xml10_content()),
            Event::End(element) => match element.local_name().as_ref() {
                "data" => inside = false,
                "checksum" if field == Some("checksum") => {
                    sha256 = unhex(&text);
                    field = None;
                }
                "size" if field == Some("size") => {
                    size = text.trim().parse().ok();
                    field = None;
                }
                _ => {}
            },
            _ => {}
        }
        buf.clear();
    }
    let href = href.ok_or(())?;
    let safe = href.starts_with("repodata/")
        && !href.contains("..")
        && !href.contains("//")
        && !href.contains(['\\', '?', '#']);
    if !safe {
        return Err(());
    }
    Ok(Location {
        href,
        sha256: sha256.ok_or(())?,
        size: size.ok_or(())?,
    })
}
