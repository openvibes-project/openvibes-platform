#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! `openvibes-feed`: fetches the upstream vulnerability data a site's
//! platforms use, and publishes it as one signed feed (openvibes-protocol
//! `spec/feed-v1.md`) a platform reads from a static web server or from a
//! bundle file. It needs no database.

pub mod build;
pub mod config;
pub mod key;
pub mod pack;
