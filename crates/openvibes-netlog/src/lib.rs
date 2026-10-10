#![forbid(unsafe_code)]

//! `openvibes-netlog`: UniFi IPS/IDS events over syslog (CEF, UDP) become
//! alarms (spec 2026-10-10-network-device-alarms).

pub mod cef;
pub mod collapse;
pub mod config;
pub mod handle;
pub mod service;
pub mod unifi;
