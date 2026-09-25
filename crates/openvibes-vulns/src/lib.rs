#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Vulnerability management: Fedora security advisories matched against
//! stored package inventories (VM spec 2026-09-25).

pub mod config;
pub mod dpkgver;
pub mod enrich;
pub mod feed;
pub mod fetch;
pub mod matching;
pub mod repodata;
pub mod rpmver;
pub mod service;
pub mod sources;
pub mod updateinfo;
