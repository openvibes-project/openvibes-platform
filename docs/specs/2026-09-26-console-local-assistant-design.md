# Console Local Assistant Design

Status: **approved by the project owner in conversation on 2026-09-26**. This
spec turns the planned “small build in LLM” request into a bounded, opt-in
console chat feature. It supersedes the earlier assistant design's external
provider and persisted-history choices for this first console release.

## 1. Goal and boundary

Add a compact assistant panel to the authenticated console. An analyst can ask
questions in ordinary language to find relevant agents, findings, and
vulnerabilities and get a short explanation that helps with triage. The
assistant uses a model hosted by the operator, sends no requests to a vendor
cloud, and cannot change platform state.

The assistant is a guided interface to existing read operations, not an
independent data source or general purpose agent. It must never run SQL,
shell commands, arbitrary URLs, or model-selected tools. It may call only a
small allowlist of typed, bounded console read operations. It cites the
records returned by those operations with links to their normal detail pages.
The user verifies the underlying records before acting.

Initial supported data: agents, findings, and analyst triage metadata. Add
vulnerabilities and package inventory only after their console read models
exist. No log search, file access, remediation, writes, or external web
search in this milestone.

## 2. User experience

- Add **Assistant** as a workspace destination for users with at least one
  supported read permission. Keep it out of the way until opened; do not add
  a permanently expanded dashboard card.
- Provide a simple conversation view with a clear question field, send
  action, stop action while a response is running, and new-chat action.
- Responses are concise and state what data they used. Record citations are
  clickable links into the normal console views. Empty results and missing
  permissions are explained without implying that the assistant searched
  inaccessible data.
- Show a persistent, unobtrusive “Local model” indicator and the configured
  model name. Show an actionable service-unavailable message when the model
  endpoint cannot be reached.
- Conversation history is held in browser memory only. Reloading, signing
  out, or starting a new chat clears it. The first release does not persist
  prompts or responses in the database.
- Limit each prompt to 4,000 UTF-8 bytes, each conversation to 20 turns, and
  generated output to 1,500 tokens. Display a remaining-turn count and ask
  the user to start a new chat when the limit is reached.
- Meet keyboard, screen-reader, reduced-motion, and narrow-screen behavior of
  the console. Do not stream untrusted model text as HTML; render plain text
  with safe link handling.

## 3. Model configuration and privacy

The feature is disabled by default. An administrator enables it in the
console service configuration, not in a browser setting. Configuration
contains an explicit HTTP(S) base URL, model identifier, request timeout,
and optional credential-file path. The default URL is unset: operators must
choose their local endpoint explicitly. Ollama and llama.cpp servers that
implement the OpenAI chat-completions shape are initial supported targets.

The endpoint must be loopback, a Unix socket, or an explicitly configured
private-network destination. HTTPS is required for non-loopback destinations.
Redirects are disabled. The server validates the resolved destination and
rejects public addresses, link-local metadata addresses, and URL credentials.
The credential is read from a root/service-readable file and never returned
by config APIs, shown in the UI, or logged. No provider fallback or telemetry
is permitted.

Only the current question, a bounded recent conversation summary, and the
minimum necessary results from authorized read operations are sent to the
configured local model. The UI identifies this data flow before the first
question. No prompts, answers, or result payloads are retained after the
request except in the user's current browser tab. Operational logs contain
request ID, duration, outcome, and bounded error category only; they exclude
the question, model answer, credentials, and retrieved records.

## 4. Authorization and data access

Every request uses the existing authenticated session and CSRF protections.
Introduce a capability `assistant.use`; it is granted only when the user has
at least one supported read permission. Each typed data operation then runs
through the same SQL-scoped store query and permission check as its ordinary
console endpoint. The assistant does not receive a broader service identity
or database role.

The caller's effective asset scope is applied inside each query before
filtering, counts, or result selection. The model never chooses a permission,
scope, SQL fragment, table, or endpoint. Tool arguments are schema-validated,
bounded, and normalized by server code. A tool call returning forbidden or
missing data is represented to the model as no accessible result, without
revealing whether hidden records exist.

Treat user prompts, stored finding text, agent hostnames, notes, and all other
retrieved fields as untrusted data. They may contain prompt injection. The
system instruction tells the model to treat retrieved content as evidence,
not instructions. More importantly, tool access remains in server control:
the model can request only the allowlisted read operations, each call is
re-authorized, and no model output is executed. Tool-call count is capped at
6 per user turn.

## 5. HTTP contract and execution

Add `POST /api/v1/assistant/messages`, authenticated and CSRF-protected. The
request contains a client-generated conversation ID, the bounded prior
turns, and the new question. The server ignores client claims about user,
permissions, or scope. The response contains plain-text answer content and
zero or more typed citations (`kind`, stable record ID, safe console path,
short display label). It does not include raw tool payloads.

The server builds the system prompt, performs at most six tool cycles, and
calls the configured model with a fixed timeout. Total wall time is bounded
to 30 seconds per turn. No streaming in the first release; this keeps
cancellation, content handling, and reverse-proxy behavior simple. Client
disconnect cancels downstream work where supported. Responses are
`Cache-Control: no-store`; request and response bodies are excluded from
tracing. A bounded per-user in-flight limit prevents concurrent request
fan-out.

Typed initial tools:

1. `search_agents`: bounded text query and known status filters; returns at
   most 10 scoped agent summaries.
2. `search_findings`: bounded severity, triage state, time window, and text
   filters; returns at most 10 scoped finding summaries.
3. `get_agent`: one agent by stable ID, subject to `agents.read` and scope.
4. `get_finding`: one finding by stable ID, subject to `compliance.read` and
   scope.

The exact arguments reuse existing read DTO semantics and are finalized
against the shipped console API during implementation. Citations point to
the same detail routes that a user could open directly.

## 6. Failure behavior and audit

If disabled, the feature is absent from navigation and the endpoint returns
a stable `assistant_disabled` problem response. Invalid model configuration
keeps readiness false when the feature is enabled. An unreachable model,
timeout, invalid response, unsupported tool request, token limit, or rate
limit returns a safe user-facing error and does not disclose upstream body
content. Do not silently retry a request that may have consumed model work.

Write one audit event per user turn with actor ID, request ID, outcome,
duration, and model identifier. Do not include prompt, answer, citations,
retrieved data, or credential material. The audit event uses the existing
audit retention policy. It is not an audit log of each internal tool call.

## 7. Delivery and component documentation

Implement as a console-owned assistant service module plus an Assistant UI
page. Reuse existing session, permission, store, audit, configuration, and
API error layers. Add a component page describing configuration, interfaces,
data handling, failure behavior, and how to operate/test it in the same
change. No cross-repository protocol changes are needed.

Suggested milestones:

- **A — Local provider boundary:** validated configuration, no-network
  default, OpenAI-compatible local client, safe health/readiness behavior.
- **B — Authorized read tools:** capability wiring and four bounded,
  scope-enforced tools with audit events.
- **C — Chat surface:** navigation entry, conversation UI, citations,
  keyboard support, clear failure and limit states.
- **D — Review:** adversarial authorization and prompt-injection review,
  privacy review, component docs, and manual UI verification.

## 8. Acceptance checks

- Feature cannot send a network request until explicitly enabled and
  configured; it never falls back to a cloud provider.
- A user without supported read permissions cannot use the endpoint.
- Scoped users cannot infer hidden record existence from answer, citation,
  count, error, or timing distinctions attributable to the assistant.
- Model output cannot invoke an unlisted operation, modify state, render HTML,
  or cause a server request to an arbitrary destination.
- Prompt injection in a user question or retrieved field cannot expand
  access or cause an action.
- Prompt, answer, and retrieved data are absent from logs and audit records.
- Size, turn, tool-cycle, timeout, concurrency, and output limits are
  enforced server-side.
- Chat resets on reload, new chat, and sign-out; the UI explains local model
  routing and shows citations to ordinary detail pages.
- Tests cover disabled/misconfigured provider, provider failures, malformed
  tool calls, scope enforcement, citation safety, CSRF, and audit redaction.

## 9. Approved choices

The console uses a separate global `assistant.use` capability and requires
the user's existing agent and finding read permissions for each answer. The
first release accepts only a loopback endpoint or a private literal IP with
HTTPS and an explicit CA. It does not support third-party providers. Chat
history stays in the browser tab and is not persisted by the platform.
