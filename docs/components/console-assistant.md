# Console assistant

The opt-in assistant dock (Ctrl+J, from any view of the web console) lets an authorized analyst ask questions about
agents and observed compliance findings using an operator-hosted OpenAI-compatible model.
The console authenticates every request, applies the caller's existing
`agents.read` and `compliance.read` scopes to SQL lookups, and returns only
sanitized answer text, verified citations, and a short lookup summary. The
model cannot run SQL, commands, arbitrary URLs, or mutations. Vulnerability
lookups are refused until they have console read pages and permissions.

## Interfaces

- `GET /api/v1/assistant/status` returns availability, model label, and
  whether the endpoint is local or on the operator's network.
- `POST /api/v1/assistant/messages` accepts one question plus bounded recent
  turns from the current browser tab. It requires an authenticated session,
  `assistant.use`, and the same effective scope for `agents.read` and
  `compliance.read`.
- The dock is offered only to a principal with `assistant.use`. It renders
  plain text, and its citations open the cited objects in the inspector.
  (The first interface's `/assistant` page was retired on 2026-09-28.)

## Configuration

The `[assistant]` section is disabled when omitted. To enable it, set
`enabled = true`, choose `lookup_mode` (or `auto`), and configure a
`[assistant.backend]` with an OpenAI-compatible endpoint and model. Loopback
URLs may use HTTP. A network backend must use HTTPS, an explicit CA file, and
a private literal IP address; third-party endpoints and DNS names are
refused. The optional API key is read from an owner-only file. Configuration
validation fails closed. With the `openvibes-llm` package, `sudo openvibes-admin helper
assistant-setup` writes this section for the bundled llama.cpp and model
([openvibes-llm.md](openvibes-llm.md)). Another local service such as Ollama
is run separately and configured by hand.

Example:

```toml
[assistant]
enabled = true
lookup_mode = "auto"
profile = "small"

[assistant.backend]
url = "http://127.0.0.1:8080/v1"
model = "local-security-model"
```

## Data handling and limits

No connection is attempted unless enabled with a valid backend configuration.
The question, bounded recent turns, and scoped lookup results are sent only
to that configured model endpoint. The browser keeps chat history in memory;
reload, sign-out, and New chat clear it. The server does not persist prompts
or answers. Logs and audit rows exclude question text, answers, and retrieved
records. Each question is audited with actor, outcome, duration, and model.

Questions are limited to 4,000 UTF-8 bytes; a chat to 20 turns; tool cycles to
the platform assistant's configured maximum; the output budget follows the
selected model profile; and each model call is capped at the backend's
`deadline_seconds` (default 60 for a local model), so a whole question may take
one such deadline per call it makes (at most 15 minutes; a small model on a CPU
needs tens of seconds just to read the prompt). A timed-out question returns
504 `assistant_timeout`, never 408, which browsers silently resend. One question
may run per user at a time, with a global backend concurrency limit. If the
browser stops waiting, an in-flight call may continue until its deadline, and
keeps its per-user and global capacity permits until it finishes. A reply cut
off by the output limit before any text (a thinking model spending its budget
reasoning) returns 502 `assistant_truncated`: run the model with
`--reasoning off` (the packaged unit does).

## Failure behavior

Disabled assistant routes return `assistant_disabled`. An unreachable or
unsupported model reports unavailable. The console probes the model at
start; while the model server cannot be reached or times out (still loading) it probes again every 10
seconds for the first minute, otherwise (and after that) every 15 minutes
until it passes: longer than `openvibes-llm`'s 5-minute idle time, since each
probe through its socket loads the model.
Backend errors, invalid model output,
rate capacity, and timeouts return fixed problem codes without upstream
response bodies. Permission failures do not reveal hidden record existence.
An aborted browser request is not saved. The Stop waiting action ends the
browser wait; an already-running blocking model call can continue until its
`deadline_seconds` limit.

## How to operate and verify

Run `openvibes-admin assistant check` and `openvibes-admin assistant eval`
(as `openvibes-console`, which reads the configuration and key) against the configured local endpoint before enabling the section. Verify
that an Analyst can open the dock, a user without `assistant.use` cannot, and
scoped users only receive citations to records in their asset groups. Review
the Console API specification and browser behavior with a local mock model.
