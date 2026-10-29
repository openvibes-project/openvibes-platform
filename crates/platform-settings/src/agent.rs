use crate::{Applies, Definition, Kind};

pub(crate) mod ingest {
    use super::*;
    /// Every key of this service starts with this.
    pub const PREFIX: &str = "ingest.";
    /// Agent certificate lifetime (days).
    pub const CLIENT_CERTIFICATE_DAYS: &str = "ingest.client_certificate_days";
    /// Requests served at once.
    pub const MAX_IN_FLIGHT: &str = "ingest.max_in_flight";
    /// Inventory upload deadline (seconds).
    pub const INVENTORY_REQUEST_TIMEOUT_SECONDS: &str = "ingest.inventory_request_timeout_seconds";
    /// Inventory uploads at once.
    pub const MAX_INVENTORY_IN_FLIGHT: &str = "ingest.max_inventory_in_flight";
    /// Keep findings (days).
    pub const FINDING_RETENTION_DAYS: &str = "ingest.finding_retention_days";
    /// Request deadline (seconds).
    pub const REQUEST_TIMEOUT_SECONDS: &str = "ingest.request_timeout_seconds";
    /// Open agent connections.
    pub const MAX_CONNECTIONS: &str = "ingest.max_connections";
    const SECTION: &str = "Agent connections";

    pub(crate) static DEFINITIONS: [Definition; 7] = [
        Definition {
            key: CLIENT_CERTIFICATE_DAYS,
            section: SECTION,
            label: "Agent certificate lifetime (days)",
            help: "How long an agent certificate is valid before it renews itself.",
            kind: Kind::Int {
                min: 1,
                max: 365,
                default: 30,
            },
            applies: Applies::Restart,
        },
        Definition {
            key: MAX_IN_FLIGHT,
            section: SECTION,
            label: "Requests served at once",
            help: "Above this, an agent gets 503 and retries.",
            kind: Kind::Int {
                min: 1,
                max: 100000,
                default: 4096,
            },
            applies: Applies::Restart,
        },
        Definition {
            key: INVENTORY_REQUEST_TIMEOUT_SECONDS,
            section: SECTION,
            label: "Inventory upload deadline (seconds)",
            help: "The whole upload of one host's package list. The default carries 8 MiB at 500 kbit/s.",
            kind: Kind::Int {
                min: 1,
                max: 900,
                default: 180,
            },
            applies: Applies::Restart,
        },
        Definition {
            key: MAX_INVENTORY_IN_FLIGHT,
            section: SECTION,
            label: "Inventory uploads at once",
            help: "Each upload can be up to 8 MiB, so this bounds the memory they use.",
            kind: Kind::Int {
                min: 1,
                max: 128,
                default: 4,
            },
            applies: Applies::Restart,
        },
        Definition {
            key: FINDING_RETENTION_DAYS,
            section: SECTION,
            label: "Keep findings (days)",
            help: "Findings older than this are not stored. Keep it equal to the maintenance timer's --retention-days.",
            kind: Kind::Int {
                min: 1,
                max: 36500,
                default: 90,
            },
            applies: Applies::Restart,
        },
        Definition {
            key: REQUEST_TIMEOUT_SECONDS,
            section: SECTION,
            label: "Request deadline (seconds)",
            help: "The TLS handshake, the headers and each request.",
            kind: Kind::Int {
                min: 1,
                max: 300,
                default: 10,
            },
            applies: Applies::Restart,
        },
        Definition {
            key: MAX_CONNECTIONS,
            section: SECTION,
            label: "Open agent connections",
            help: "Further connections wait. Keep it below the service's file limit.",
            kind: Kind::Int {
                min: 1,
                max: 65536,
                default: 1024,
            },
            applies: Applies::Restart,
        },
    ];
}

pub(crate) mod distribution {
    use super::*;
    /// Every key of this service starts with this.
    pub const PREFIX: &str = "distribution.";
    /// Requests served at once.
    pub const MAX_IN_FLIGHT: &str = "distribution.max_in_flight";
    /// Request deadline (seconds).
    pub const REQUEST_TIMEOUT_SECONDS: &str = "distribution.request_timeout_seconds";
    /// Open agent connections.
    pub const MAX_CONNECTIONS: &str = "distribution.max_connections";
    const SECTION: &str = "Rule distribution";

    pub(crate) static DEFINITIONS: [Definition; 3] = [
        Definition {
            key: MAX_IN_FLIGHT,
            section: SECTION,
            label: "Requests served at once",
            help: "Above this, an agent gets 503 and retries.",
            kind: Kind::Int {
                min: 1,
                max: 100000,
                default: 4096,
            },
            applies: Applies::Restart,
        },
        Definition {
            key: REQUEST_TIMEOUT_SECONDS,
            section: SECTION,
            label: "Request deadline (seconds)",
            help: "The TLS handshake, the headers and each request.",
            kind: Kind::Int {
                min: 1,
                max: 300,
                default: 10,
            },
            applies: Applies::Restart,
        },
        Definition {
            key: MAX_CONNECTIONS,
            section: SECTION,
            label: "Open agent connections",
            help: "Further connections wait. Keep it below the service's file limit.",
            kind: Kind::Int {
                min: 1,
                max: 65536,
                default: 1024,
            },
            applies: Applies::Restart,
        },
    ];
}
