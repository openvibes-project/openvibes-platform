//! `openvibes-fetch`: the only component that makes outbound requests for
//! the console assistant's internet lookups. This crate holds the pure
//! parts: the wire protocol and the query filter.
#![forbid(unsafe_code)]

pub mod filter;
pub mod protocol;
