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
pub mod serve;

/// Cuts `s` to at most `max` characters, on a character boundary.
pub fn cut(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}
