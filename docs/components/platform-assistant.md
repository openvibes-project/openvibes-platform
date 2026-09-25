# platform-assistant

The console's assistant (spec `docs/specs/2026-09-25-assistant-design.md`):
configuration, a client for any OpenAI-compatible model backend, and the
capability probe (AS1); the fixed read-only lookups, the orchestrator that
answers one question, and output sanitising (AS2). The operator commands
(AS3) and the console routes and chat panel (AS4) build on it. It has no
server and no database role of its own: the console calls it with the
asking user's scope.

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
- `answer(backend, &runner, Settings, history, question, events)` →
  `Answer` (`segments`, `lookups` for audit, `usage`, `requests`,
  `hit_lookup_limit`) or a fixed `AnswerError` (`EmptyQuestion`,
  `QuestionTooLong`, `Backend`, `Deadline`, `NoAnswer`). `Settings::new`
  takes the mode from the probe, the profile budget, `max_lookups`, and a
  whole-question deadline of one backend deadline per possible request (at
  most 15 minutes). `ChatBackend` is implemented by `BackendClient`; it is
  called on a blocking thread. `events` streams `Lookup`, `Text` (native
  mode), and `Reset`.
- `StoreLookups::new(pool, AgentScope, now)` runs lookups through
  `platform_store::assistant` with the user's scope; `LookupRunner` lets
  tests substitute their own.
- `sanitize(text, allowed)` → `Vec<Segment>` and `plain_text`: see below.

## Lookups

| Lookup | Arguments | Result |
|---|---|---|
| `search_findings` | `text?`, `min_severity?` (finding severity), `rule_set?`, `window_hours?` | Finding groups: severity, endpoints, versions, first/last observed, latest message |
| `finding_endpoints` | `rule_set`, `rule`, `window_hours?` | Endpoints in the window, and how many were not seen in it |
| `agent_summary` | `agent` (ID or host name) | State, last seen, OS, kernel, capabilities, counts (at most 5 agents) |
| `host_vulnerabilities` | `agent`, `min_severity?` (advisory severity) | Open vulnerabilities by priority; a host name matching several agents in scope is refused as ambiguous |
| `vulnerability_hosts` | `id` (CVE or advisory) | Hosts where it is open |
| `fleet_overview` | `window_hours?` | Agent counts, open and exploited vulnerabilities, top findings and advisories |
| `rule_description` | `rule_set`, `rule` | Title, severity, message, and expression from the latest published JSON bundle |

Arguments are parsed with unknown fields refused, strings trimmed and at most
128 characters without control characters, windows 1–720 hours (default
24), and severities from fixed lists. A refused request is answered with a
fixed error message, counted against `max_lookups`, and recorded without
the model's raw name or arguments. Results are JSON with at most the
profile's `result_items`, a `cite` value per object, and `omitted`; the
orchestrator drops trailing items to fit the prompt and counts them as
omitted.

## Answering a question

Modes (from the probe): **native** offers the lookups as tools; **JSON
schema** constrains each reply to `{"action":"lookup",...}` or
`{"action":"answer","text":...}`; **prompted** asks for the same object in
the system prompt and takes prose as the answer. At most `max_lookups`
lookups run (several calls in one turn count one by one, and every call ID
gets a result); after that the model is told to answer and offered no
lookups, and a model that still asks gets a fixed "lookup limit" answer.
Lookup results reach the model labelled as data, never instructions.

Prompt budget: the profile's `prompt_tokens` at 3 characters per token.
The system prompt, lookup definitions, and question must fit (else
`QuestionTooLong`); older conversation turns are dropped first; each lookup
result gets an equal share of the room left.

## Output sanitising

`sanitize` removes control characters (except newline and tab),
bidirectional controls, and invisible formatting; writes `scheme://` as
`scheme[:]//`; cuts the answer to 8,000 characters; and turns
`[agent:ID]`, `[finding:SET/RULE]` (`~unknown` for no rule set), and
`[advisory:ID]` into citations only when this question's lookups returned
that object under a platform-written key (`cite`, `agent`, `finding`,
`advisory`), never from host-chosen text such as a host name. Everything
else stays plain text for the console to render as text.

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
TLS, a scripted model for the orchestrator, and PostgreSQL for
`StoreLookups` (`OPENVIBES_TEST_DATABASE_URL`, see `scripts/test-db.sh`); no
network or model is needed.
