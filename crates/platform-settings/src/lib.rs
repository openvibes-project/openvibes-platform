#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! The settings the console changes for the whole platform: each one's key,
//! wording, type, range and default, and the check of a new value. The
//! console checks a change with these; a service that takes its settings
//! from the database applies the same ones over its file, so both sides
//! agree on what is valid. No database code lives here.

mod definition;
mod general;
mod vulns;

pub use definition::{Applies, Definition, Kind, Text};

/// Every setting, in display order.
#[must_use]
pub fn all() -> impl Iterator<Item = &'static Definition> {
    general::DEFINITIONS.iter().chain(vulns::DEFINITIONS.iter())
}

/// The setting with this key.
#[must_use]
pub fn find(key: &str) -> Option<&'static Definition> {
    all().find(|definition| definition.key == key)
}

/// The vulnerability service's keys; the service reads them under this prefix.
pub mod vulns_keys {
    pub use crate::vulns::{
        ARCH, CHECK_INTERVAL_MINUTES, EPSS_URL, EUVD_URL, KEV_URL, MAX_DOWNLOAD_MIB,
        METALINK_URL, NVD_API_KEY, NVD_URL, OSV_MAX_DOWNLOAD_MIB, OSV_URL, PREFIX, PROXY_URL,
    };
}
