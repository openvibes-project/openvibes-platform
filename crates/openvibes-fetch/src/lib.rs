//! `openvibes-fetch`: the only component that makes outbound requests for
//! the console assistant's internet lookups. This crate holds the pure
//! parts (protocol, filter, extraction, request handling) and the HTTP client.
#![forbid(unsafe_code)]

pub mod bodhi;
pub mod config;
pub mod filter;
pub mod http;
pub mod osv;
pub mod protocol;
pub mod searxng;
pub mod serve;

/// Cuts `s` to at most `max` characters, on a character boundary.
pub fn cut(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

/// `tail` (the fixed versions, itself cut to 400 characters) first, then
/// `text`, the whole at most 1,000 characters. The text gives way, and a
/// later cut (the assistant's result room) drops prose, not versions.
pub fn snippet(text: &str, tail: &str) -> String {
    let tail = cut(tail.trim_start_matches('\n'), 400);
    if tail.is_empty() {
        return cut(text, 1000);
    }
    if text.is_empty() {
        return tail;
    }
    let room = 999 - tail.chars().count();
    format!("{tail}\n{}", cut(text, room))
}
