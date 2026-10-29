use crate::{Applies, Definition, Kind, Text};

/// Every assistant key starts with this.
pub const PREFIX: &str = "assistant.";
/// Whether the assistant is on.
pub const ENABLED: &str = "assistant.enabled";
/// Prompt budget.
pub const PROFILE: &str = "assistant.profile";
/// How lookups are requested.
pub const LOOKUP_MODE: &str = "assistant.lookup_mode";
/// Days a conversation is kept.
pub const CONVERSATION_RETENTION_DAYS: &str = "assistant.conversation_retention_days";
/// Lookups per question.
pub const MAX_LOOKUPS: &str = "assistant.max_lookups";
/// Questions per user per hour.
pub const QUESTIONS_PER_USER_PER_HOUR: &str = "assistant.questions_per_user_per_hour";
/// Questions answered at once.
pub const CONCURRENCY: &str = "assistant.concurrency";
/// Backend address.
pub const URL: &str = "assistant.backend.url";
/// Model name.
pub const MODEL: &str = "assistant.backend.model";
/// Backend API key (a secret, kept in the console's own table).
pub const API_KEY: &str = "assistant.backend.api_key";
/// Whether prompts may leave this host.
pub const ALLOW_REMOTE: &str = "assistant.backend.allow_remote";
/// Where a remote backend runs.
pub const DATA_LOCATION: &str = "assistant.backend.data_location";
/// Whether identifying values are replaced before sending.
pub const PSEUDONYMIZE: &str = "assistant.backend.pseudonymize";
/// Outbound proxy for a remote backend.
pub const PROXY_URL: &str = "assistant.backend.proxy_url";
/// Seconds one request may take.
pub const DEADLINE_SECONDS: &str = "assistant.backend.deadline_seconds";

const SECTION: &str = "Assistant";

pub(crate) static DEFINITIONS: [Definition; 15] = [
    Definition {
        key: ENABLED,
        section: SECTION,
        label: "Assistant",
        help: "Turns the assistant on. It stays off, and nothing connects to a model, until a backend is set.",
        kind: Kind::Bool { default: false },
        applies: Applies::Restart,
    },
    Definition {
        key: URL,
        section: SECTION,
        label: "Backend address",
        help: "Base address of an OpenAI-compatible API, e.g. http://127.0.0.1:8080/v1. A local backend is on this host.",
        kind: Kind::Text {
            check: Text::HttpUrlOrEmpty,
            default: "",
        },
        applies: Applies::Restart,
    },
    Definition {
        key: MODEL,
        section: SECTION,
        label: "Model",
        help: "The model name sent with each request.",
        kind: Kind::Text {
            check: Text::Plain,
            default: "",
        },
        applies: Applies::Restart,
    },
    Definition {
        key: API_KEY,
        section: SECTION,
        label: "Backend API key",
        help: "Sent to the backend with each request. It is never shown again after you save it.",
        kind: Kind::Secret,
        applies: Applies::Restart,
    },
    Definition {
        key: PROFILE,
        section: SECTION,
        label: "Hardware profile",
        help: "How much of each question is sent: small for a CPU and a 2 to 4B model, medium for a GPU or an 8 to 14B model, large for a remote GPU server or a provider.",
        kind: Kind::Choice {
            options: &["small", "medium", "large"],
            default: "small",
        },
        applies: Applies::Restart,
    },
    Definition {
        key: LOOKUP_MODE,
        section: SECTION,
        label: "How the model asks for lookups",
        help: "Auto lets a capability check at start choose.",
        kind: Kind::Choice {
            options: &["auto", "native", "json_schema", "prompted"],
            default: "auto",
        },
        applies: Applies::Restart,
    },
    Definition {
        key: CONVERSATION_RETENTION_DAYS,
        section: SECTION,
        label: "Keep conversations (days)",
        help: "Days a conversation is kept, 1 to 3650.",
        kind: Kind::Int {
            min: 1,
            max: 3650,
            default: 30,
        },
        applies: Applies::Restart,
    },
    Definition {
        key: MAX_LOOKUPS,
        section: SECTION,
        label: "Lookups per question",
        help: "How many lookups the assistant may run to answer one question, 1 to 8.",
        kind: Kind::Int {
            min: 1,
            max: 8,
            default: 4,
        },
        applies: Applies::Restart,
    },
    Definition {
        key: QUESTIONS_PER_USER_PER_HOUR,
        section: SECTION,
        label: "Questions per person per hour",
        help: "How many questions one person may ask in an hour, 1 to 1000.",
        kind: Kind::Int {
            min: 1,
            max: 1000,
            default: 30,
        },
        applies: Applies::Restart,
    },
    Definition {
        key: CONCURRENCY,
        section: SECTION,
        label: "Questions answered at once",
        help: "1 to 64. When nobody set it: 1 for a local backend, 4 for a remote one.",
        kind: Kind::Int {
            min: 1,
            max: 64,
            default: 1,
        },
        applies: Applies::Restart,
    },
    Definition {
        key: ALLOW_REMOTE,
        section: SECTION,
        label: "Allow a backend off this host",
        help: "Must be on before prompts are sent to a backend that is not on this host.",
        kind: Kind::Bool { default: false },
        applies: Applies::Restart,
    },
    Definition {
        key: DATA_LOCATION,
        section: SECTION,
        label: "Where a remote backend runs",
        help: "own-network for a server on your network (needs a CA file in the configuration file), external for a third party. Leave unset for a local backend.",
        kind: Kind::Choice {
            options: &["unset", "own-network", "external"],
            default: "unset",
        },
        applies: Applies::Restart,
    },
    Definition {
        key: PSEUDONYMIZE,
        section: SECTION,
        label: "Replace host names and addresses",
        help: "Replaces host names, agent IDs and addresses before a prompt is sent. Automatic means on for an external backend, off otherwise.",
        kind: Kind::Choice {
            options: &["automatic", "on", "off"],
            default: "automatic",
        },
        applies: Applies::Restart,
    },
    Definition {
        key: PROXY_URL,
        section: SECTION,
        label: "Outbound proxy",
        help: "Used for a remote backend only, e.g. http://proxy.example:3128. Empty means none.",
        kind: Kind::Text {
            check: Text::ProxyOrEmpty,
            default: "",
        },
        applies: Applies::Restart,
    },
    Definition {
        key: DEADLINE_SECONDS,
        section: SECTION,
        label: "Request deadline (seconds)",
        help: "How long one request to the backend may take, 2 to 600. When nobody set it: 60 for a local backend, 120 for a remote one.",
        kind: Kind::Int {
            min: 2,
            max: 600,
            default: 60,
        },
        applies: Applies::Restart,
    },
];
