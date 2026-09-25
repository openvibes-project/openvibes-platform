#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Vulnerability management: Fedora security advisories matched against
//! stored package inventories (VM spec 2026-09-25).

pub mod matching;
pub mod rpmver;
pub mod updateinfo;
