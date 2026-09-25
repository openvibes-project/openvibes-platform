# platform-assistant

The console's assistant (spec `docs/specs/2026-09-25-assistant-design.md`).
AS1 delivers its configuration, a client for any OpenAI-compatible model
backend, and the capability probe. Lookups and the orchestrator (AS2), the
operator commands (AS3), and the console routes and chat panel (AS4) build
on it. It has no server and no database role of its own.

## Interface

- `AssistantConfig` (the `[assistant]` TOML section, unknown keys refused) →
  `validate()` → `Assistant`, with `Backend` holding the checked URL,
  `Location` (`Local`, `OwnNetwork`, `External`), model, limits, and the
  secrets and certificates read once at startup. `Profile::budget()` gives
  the prompt, output, and lookup-result budget.
- `BackendClient::new(&Backend)`; `chat(&ChatRequest, on_text)` streams one
  answer (text pieces to `on_text` as they arrive) and returns
  `ChatResponse` (text, tool calls, finish reason, usage, time to first
  token); `models()` lists the backend's models. Blocking (`ureq`); the
  async console calls it from a blocking thread.
- `probe(&client, LookupMode)` → `ProbeReport`: models, whether the
  configured model is listed, time to first token, text pieces and tokens
  per second, whether native tool calls and JSON-schema output work, and
  the lookup mode to use (`auto`: native, then JSON schema, then prompted).
- `STANDARD_FIELDS`: the only top-level request fields ever sent.

## Configuration

```toml
[assistant]
enabled = false                  # nothing runs or connects until true
profile = "small"                # small | medium | large (spec §8)
lookup_mode = "auto"             # auto | native | json_schema | prompted
conversation_retention_days = 30 # 1–3650
max_lookups = 4                  # 1–8
questions_per_user_per_hour = 30 # 1–1000
# concurrency = 1                # 1–64; default 1 local, 4 remote

[assistant.backend]
url = "http://127.0.0.1:8080/v1" # OpenAI-compatible base URL
model = "qwen3.5-4b"
# api_key_file = "/etc/openvibes/assistant.key"      # owner-only
# ca_file = "/etc/openvibes/assistant-ca.crt"        # pinned CAs
# client_certificate_file = "/etc/openvibes/assistant-client.crt"
# client_key_file = "/etc/openvibes/assistant-client.key"  # owner-only
# allow_remote = true            # required for a non-loopback URL
# data_location = "own-network"  # own-network | external (remote only)
# pseudonymize = true            # default on for external
# proxy_url = "http://proxy.example:3128"  # remote only
# deadline_seconds = 60          # 2–600; default 60 local, 120 remote
```

Rules (each a fixed `ConfigError` naming the setting, never its value):

| Backend | Requires |
|---|---|
| loopback (`localhost`, `127.0.0.0/8`, `::1`) | nothing more; plain HTTP allowed; `data_location` and `proxy_url` refused |
| any other host | HTTPS, `allow_remote = true`, and `data_location` |
| `own-network` | `ca_file` (the operator's CA; public roots are not used) |
| `external` | nothing more; without `ca_file` public roots are trusted |
| mutual TLS | both certificate and key, HTTPS only |

Secret files (`api_key_file`, `client_key_file`) must not be readable by
group or others. Every file is read once, at most 1 MiB, regular files
only, opened without blocking.

## Failure behaviour

The client sends only standard Chat Completions fields, TLS 1.3 only, never
follows a redirect, never uses proxy environment variables, and bounds the
whole request by the deadline. Every failure is a fixed `BackendError` that
carries no backend content:

| Input | Result |
|---|---|
| connection refused | `Connect` |
| untrusted certificate, refused client certificate | `Tls` |
| deadline passed | `Timeout` |
| 401, 403 / 404 / 429 / 5xx | `Unauthorized` / `NotFound` / `RateLimited` / `Unavailable` |
| other 4xx, or a redirect (not followed) | `Rejected` (a probe reads it as "not supported") |
| line over 256 KiB, body over 8 MiB, answer over 256 KiB, tool arguments over 16 KiB | `ResponseTooLarge` |
| malformed JSON, an error object, more than 8 tool calls, a nameless tool call, a stream cut off before `[DONE]` or a finish reason | `InvalidResponse` |

A cut-off answer is refused, never used as a partial answer. Tool calls and
text are returned unchecked: the orchestrator (AS2) validates them.

## Test

`cargo test --locked -p platform-assistant` runs against a mock backend
(`tests/support`) over plain HTTP and TLS 1.3 with a pinned CA and mutual
TLS; no network or model is needed.
