//! The fields the Configuration screen may change, per service (admin TUI
//! spec §5). A key not listed here cannot be added from the TUI; a listed
//! key the type does not know fails `every_listed_field_is_known_to_its_service_type`.

use Kind::{Bool, Choice, Integer, IntegerList, Text, TextList};
use platform_host::Service;

/// How a field is typed in and stored.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    /// A TOML string.
    Text,
    /// A whole number.
    Integer,
    /// `true` or `false`.
    Bool,
    /// One of these strings.
    Choice(&'static [&'static str]),
    /// Comma-separated strings, stored as an array.
    TextList,
    /// Comma-separated whole numbers, stored as an array.
    IntegerList,
}

/// One editable key; dotted keys live in tables (`assistant.backend.url`).
#[derive(Clone, Copy, Debug)]
pub struct Field {
    pub key: &'static str,
    pub kind: Kind,
    pub help: &'static str,
}

const fn field(key: &'static str, kind: Kind, help: &'static str) -> Field {
    Field { key, kind, help }
}

const INGEST: &[Field] = &[
    field(
        "listen",
        Text,
        "Agent-facing TLS listener, e.g. 0.0.0.0:18423.",
    ),
    field(
        "health_listen",
        Text,
        "Loopback health listener (/health, /ready), e.g. 127.0.0.1:18480.",
    ),
    field(
        "server_certificate_file",
        Text,
        "Server certificate chain, leaf first (absolute path).",
    ),
    field(
        "server_key_file",
        Text,
        "Server private key (absolute path).",
    ),
    field(
        "client_ca_file",
        Text,
        "CA that issued accepted agent certificates (absolute path).",
    ),
    field(
        "issuing_certificate_file",
        Text,
        "Intermediate that signs agent certificates (absolute path).",
    ),
    field(
        "issuing_key_file",
        Text,
        "Its private key, 0600 for openvibes-ingest only (absolute path).",
    ),
    field(
        "database_url",
        Text,
        "PostgreSQL connection for the openvibes-ingest role.",
    ),
    field(
        "client_certificate_days",
        Integer,
        "Agent certificate lifetime, 1 to 365 days (default 30).",
    ),
    field(
        "max_in_flight",
        Integer,
        "Requests served at once; above this, 503 (default 4096).",
    ),
    field(
        "inventory_request_timeout_seconds",
        Integer,
        "Deadline for a whole inventory upload, 1 to 900 s (default 180).",
    ),
    field(
        "max_inventory_in_flight",
        Integer,
        "Inventory uploads handled at once, 1 to 128 (default 4).",
    ),
    field(
        "finding_retention_days",
        Integer,
        "Findings older than this are not stored, 1 to 36500 days (default 90); match maintenance --retention-days.",
    ),
    field(
        "request_timeout_seconds",
        Integer,
        "Deadline for the handshake, headers and each request, 1 to 300 s (default 10).",
    ),
    field(
        "max_connections",
        Integer,
        "Open agent connections at once, 1 to 65536 (default 1024).",
    ),
    field(
        "database_pool_size",
        Integer,
        "Database connections, 1 to 1024 (default 16).",
    ),
];

const DISTRIBUTION: &[Field] = &[
    field(
        "listen",
        Text,
        "Agent-facing TLS listener, e.g. 0.0.0.0:18424.",
    ),
    field(
        "health_listen",
        Text,
        "Loopback health listener (/health, /ready), e.g. 127.0.0.1:18481.",
    ),
    field(
        "server_certificate_file",
        Text,
        "Server certificate chain, leaf first (absolute path).",
    ),
    field(
        "server_key_file",
        Text,
        "Server private key (absolute path).",
    ),
    field(
        "client_ca_file",
        Text,
        "CA that issued accepted agent certificates (absolute path).",
    ),
    field(
        "database_url",
        Text,
        "PostgreSQL connection for the openvibes-distribution role.",
    ),
    field(
        "max_in_flight",
        Integer,
        "Requests served at once; above this, 503 (default 4096).",
    ),
    field(
        "request_timeout_seconds",
        Integer,
        "Deadline for the handshake, headers and each request, 1 to 300 s (default 10).",
    ),
    field(
        "max_connections",
        Integer,
        "Open agent connections at once, 1 to 65536 (default 1024).",
    ),
    field(
        "database_pool_size",
        Integer,
        "Database connections, 1 to 1024 (default 16).",
    ),
];

const VULNS: &[Field] = &[
    field(
        "database_url",
        Text,
        "PostgreSQL connection for the openvibes-vulns role.",
    ),
    field(
        "health_listen",
        Text,
        "Loopback health listener (default 127.0.0.1:18483).",
    ),
    field(
        "check_interval_minutes",
        Integer,
        "Minutes between feed checks, 15 to 1440 (default 60); downloads only on change.",
    ),
    field(
        "metalink_url",
        Text,
        "Fedora mirror list (HTTPS) with {release} and {arch}; a local mirror when offline.",
    ),
    field(
        "arch",
        Text,
        "Repository architecture fetched (default x86_64).",
    ),
    field(
        "proxy_url",
        Text,
        "Outbound proxy, e.g. http://proxy.example:3128; empty for none.",
    ),
    field(
        "max_download_bytes",
        Integer,
        "Largest feed download, 1 to 1073741824 bytes (default 67108864).",
    ),
    field(
        "kev_url",
        Text,
        "CISA KEV catalog (HTTPS); empty turns it off.",
    ),
    field(
        "epss_url",
        Text,
        "FIRST EPSS scores (HTTPS); empty turns it off.",
    ),
    field(
        "nvd_url",
        Text,
        "NVD CVE API 2.0 (HTTPS); empty turns it off.",
    ),
    field(
        "nvd_api_key_file",
        Text,
        "File holding an NVD API key, mode 0600 (absolute path); empty for none.",
    ),
    field(
        "euvd_url",
        Text,
        "ENISA EUVD search API (HTTPS); empty turns it off.",
    ),
    field(
        "osv_url",
        Text,
        "OSV.dev bucket (HTTPS) for Debian, Ubuntu, Rocky, Alma; empty turns it off.",
    ),
    field(
        "osv_dir",
        Text,
        "Where OSV downloads are unpacked (absolute path; default /var/lib/openvibes-vulns).",
    ),
    field(
        "osv_max_download_bytes",
        Integer,
        "Largest OSV download, 1 to 8589934592 bytes (default 2147483648).",
    ),
];

const CONSOLE: &[Field] = &[
    field(
        "development_listen",
        Text,
        "TCP listener for development, direct TLS or TCP proxy mode, e.g. 0.0.0.0:443.",
    ),
    field(
        "health_listen",
        Text,
        "Loopback health listener, e.g. 127.0.0.1:18482.",
    ),
    field(
        "transport_mode",
        Choice(&["development", "direct_tls", "reverse_proxy"]),
        "development (loopback), direct_tls (needs both TLS files), or reverse_proxy.",
    ),
    field(
        "database_url",
        Text,
        "PostgreSQL connection for the openvibes-console role; needed for login.",
    ),
    field(
        "public_origin",
        Text,
        "Canonical origin, e.g. https://console.example.org.",
    ),
    field(
        "server_certificate_file",
        Text,
        "TLS certificate chain for direct_tls (absolute path).",
    ),
    field(
        "server_key_file",
        Text,
        "TLS private key for direct_tls (absolute path).",
    ),
    field(
        "trusted_proxy_addresses",
        TextList,
        "reverse_proxy: loopback addresses of the proxy, comma-separated.",
    ),
    field(
        "unix_socket_file",
        Text,
        "reverse_proxy: Unix socket used instead of development_listen (absolute path).",
    ),
    field(
        "trusted_proxy_uids",
        IntegerList,
        "reverse_proxy: uids allowed on the Unix socket, comma-separated.",
    ),
    field(
        "assistant.enabled",
        Bool,
        "The assistant chat panel: true or false (default false).",
    ),
    field(
        "assistant.profile",
        Choice(&["small", "medium", "large"]),
        "Prompt budget for the model's hardware (default small).",
    ),
    field(
        "assistant.lookup_mode",
        Choice(&["auto", "native", "json_schema", "prompted"]),
        "How the model asks for lookups (default auto).",
    ),
    field(
        "assistant.conversation_retention_days",
        Integer,
        "Days a conversation is kept, 1 to 3650 (default 30).",
    ),
    field(
        "assistant.max_lookups",
        Integer,
        "Lookups per question, 1 to 8 (default 4).",
    ),
    field(
        "assistant.questions_per_user_per_hour",
        Integer,
        "Questions one user may ask per hour, 1 to 1000 (default 30).",
    ),
    field(
        "assistant.concurrency",
        Integer,
        "Questions answered at once, 1 to 64.",
    ),
    field(
        "assistant.backend.url",
        Text,
        "Model API base URL, e.g. http://127.0.0.1:18430/v1.",
    ),
    field(
        "assistant.backend.model",
        Text,
        "Model name sent with each request (openvibes-llm: its alias).",
    ),
    field(
        "assistant.backend.api_key_file",
        Text,
        "File holding the API key, owner-only (absolute path).",
    ),
    field(
        "assistant.backend.ca_file",
        Text,
        "CAs trusted for the backend (absolute path).",
    ),
    field(
        "assistant.backend.client_certificate_file",
        Text,
        "Client certificate chain for mutual TLS (absolute path).",
    ),
    field(
        "assistant.backend.client_key_file",
        Text,
        "Client private key for mutual TLS (absolute path).",
    ),
    field(
        "assistant.backend.allow_remote",
        Bool,
        "Must be true for a backend not on loopback.",
    ),
    field(
        "assistant.backend.data_location",
        Choice(&["own-network", "external"]),
        "Where a remote backend runs; required for one.",
    ),
    field(
        "assistant.backend.pseudonymize",
        Bool,
        "Replace hostnames, agent IDs and addresses before sending.",
    ),
    field(
        "assistant.backend.proxy_url",
        Text,
        "Outbound proxy for a remote backend.",
    ),
    field(
        "assistant.backend.deadline_seconds",
        Integer,
        "Seconds one request may take, 2 to 600.",
    ),
];

const ADMIN: &[Field] = &[field(
    "database_url",
    Text,
    "PostgreSQL connection for the openvibes-admin role (owns the schema).",
)];

/// The editable fields of `service`, in display order.
#[must_use]
pub fn fields(service: Service) -> &'static [Field] {
    match service {
        Service::Ingest => INGEST,
        Service::Distribution => DISTRIBUTION,
        Service::Vulns => VULNS,
        Service::Console => CONSOLE,
        Service::Admin => ADMIN,
    }
}
