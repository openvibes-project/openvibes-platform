# Assistant — Implementation Plan

> **For agentic workers:** superpowers:executing-plans (native). Steps use checkboxes.

**Goal:** A chat panel in the console that answers fleet questions through a
fixed set of read-only lookups, with the model backend running on the
platform's CPU, its GPU, a separate server, or an external provider.

**Spec:** `docs/specs/2026-09-25-assistant-design.md` (approved 2026-09-25;
decisions in its section 12).

**Priority (user, 2026-09-25):** local backends first (AS1–AS5: platform CPU
and GPU, then an own server in AS6). External providers and pseudonymization
(AS7) are supported but built last.

## Global Constraints

- Ownership: `platform-assistant` and `openvibes-llm` packaging are Claude
  Code's; routes, storage, and UI in `openvibes-console` are Codex's (AS4),
  built on the interfaces AS1–AS3 deliver.
- AS1–AS3 need no console and can start now. AS4 needs console C3
  (authentication, RBAC, scope) and the audit contract; AS5–AS7 follow AS3.
- New dependencies: none. The client uses `ureq` (already used by
  `openvibes-vulns`) over the workspace `rustls`, on a blocking thread from
  the async console, and `serde_json`.
- Migrations: the conversation tables take the next free number at AS4 start.
- Every task is tests first. Security controls get negative tests (spec §6).
- Runtime and model stay replaceable (spec §10): standard Chat Completions
  fields only, no model-specific prompts, recommended models as a data file.
- Nothing runs or connects while `[assistant] enabled = false` (the default).

## Review Focus

- A lookup outside the fixed list, or with arguments failing its schema, is
  refused and counted against `max_lookups` (AS2 tests).
- A lookup never returns objects outside the caller's scope, including
  through counts (AS2 tests with two scopes).
- Model output containing HTML, Markdown images, links, or citations of
  objects outside scope renders as inert text (AS2 and AS4 tests).
- A remote backend over plain HTTP, without `allow_remote`, or without
  `data_location` is refused at startup (AS1 tests).
- Requests carry only standard Chat Completions fields, so any compatible
  runtime works (AS1 test on the mock's received bodies).
- Pseudonymization round-trips: no real hostname or agent ID in any request
  body sent to an `external` backend (AS7 test inspects the mock's received
  bodies).

### Task AS1: backend client and configuration (`platform-assistant`)
- [x] `[assistant]` section in `platform-config`: `enabled`, `backend.url`,
  `backend.api_key_file`, `backend.ca_file`, `backend.client_cert_file` and
  `key_file`, `backend.model`, `profile` (`small|medium|large`),
  `lookup_mode` (`auto|native|json_schema|prompted`), `allow_remote`,
  `data_location` (`own-network|external`), `pseudonymize`, limits
  (`max_lookups`, deadlines, concurrency, rate limit). Tests first: loopback
  HTTP accepted; non-loopback requires HTTPS, `allow_remote`, and
  `data_location`; secrets read from files with owner-only permissions.
- [x] OpenAI-compatible client: chat completions with streaming (SSE parser
  bounded by line and total size), tool calls and `response_format`
  JSON schema, TLS 1.3 with the pinned CA and optional mTLS, no redirects,
  explicit proxy only, deadlines. Tests against a mock backend in the crate's
  tests covering streaming, split SSE frames, oversized responses,
  redirects, slow responses, and malformed tool calls.
- [x] Capability probe: model name, context size, which lookup modes work
  (a fixed probe prompt per mode), time to first token and tokens per second.
- [x] Standard-fields test: every request body the client sends is checked
  against the standard Chat Completions field list; nothing
  runtime-specific.

### Task AS2: lookups and orchestrator (`platform-assistant`)
- [ ] `platform-store` read functions for the seven lookups (spec §5), each
  taking a `Scope` and bounded arguments, returning compact results with
  object IDs and an "items left out" count. Uses the console's scope type
  once C3 defines it; until then a `Scope` trait with an all-access and a
  tag-filtered test implementation. Tests first against the test database
  with two scopes.
- [ ] Orchestrator: prompt builder with the profile budget (trimming history
  first, then result items), lookup loop with `max_lookups`, schema
  validation of every lookup request, `prompted`-mode parser, final-answer
  extraction, host data quoted and labelled as data.
- [ ] Output sanitiser and citation check: plain text only, citations as
  `[agent:ID]`, `[finding:SET/RULE]`, `[vuln:ID]` verified against the lookup
  results of this question; anything else becomes inert text. Tests with
  hostile model outputs (HTML, images, links, forged citations).

### Task AS3: operator commands and the quality gate
- [ ] `openvibes-admin assistant check`: runs the capability probe and prints
  what the backend supports and its measured speed. Audited.
- [ ] Question set: ~50 questions over the console seed data with expected
  lookups and facts, plus the injection cases (spec §11), as data files.
- [ ] `openvibes-admin assistant eval`: runs the set against the configured
  backend, prints accuracy, injection results, and latency percentiles;
  non-zero exit when the gate fails.
- [ ] Recommended models as a data file (name, size, profile, SHA-256 of the
  tested GGUF, date tested), shown by `assistant check`; updated per release
  after the gate, never compiled in.
- [ ] Run the gate on the minimum tier (4 cores, 8 GB, no GPU) with
  Qwen3.5-4B and Gemma 4 E4B, and on one GPU; record the measured numbers in
  the spec's profile table and in `docs/sizing.md`. Adjust `small` budgets if
  the minimum tier misses the gate.

### Task AS4: console integration (Codex, after C3)
- [ ] Migration: `assistant_conversations` and `assistant_messages`
  (owner principal, created, retention), private to their user; lookup
  records per message (name, arguments, object IDs).
- [ ] Routes: create conversation, list own conversations, post a question
  (returns a message ID), stream the answer (SSE, same origin, CSRF as other
  mutations), delete a conversation. Permission `assistant.use`; per-user
  rate limit and one active question; global queue.
- [ ] Audit events: question asked, each lookup (name, arguments, result
  object count), backend errors. No answer text in the audit log.
- [ ] Chat panel: opened from any page, can start with the page's context
  ("ask about this finding"); streaming plain-text answer; citations as
  console links; "AI draft, verify" label; backend location notice for
  remote and external backends; "not available" state when disabled or the
  backend is down.
- [ ] Retention job for conversations in the existing maintenance run.

### Task AS5: `openvibes-llm` packaging (options A and B)
- [ ] RPM subpackage with a pinned llama.cpp `llama-server` build: CPU build,
  plus a Vulkan build for GPUs (NVIDIA, AMD, Intel), selected at install.
  Hardened unit: own user, no capabilities, `IPAddressAllow=localhost`,
  `IPAddressDeny=any`, `MemoryMax` and `CPUWeight` from configuration, RPC
  and idle-sleep off, API key from a file readable by the console user.
- [ ] `openvibes-admin assistant model install FILE --sha256 HEX`: verifies
  and installs the GGUF file read-only; the unit refuses to start on a
  digest mismatch.
- [ ] systemd test in CI (like the existing packaging job): install, model
  install with a tiny test model, `assistant check` through the console
  configuration, and the unit's sandbox assertions.

### Task AS6: own server elsewhere (option C)
- [ ] Documented, tested configurations: vLLM on a separate GPU server with
  the operator's CA and mutual TLS; `llama-server` with a CUDA build on
  localhost. The integration test uses the mock backend over TLS with mTLS.
- [ ] Console notice for `own-network` backends (AS4 panel).

### Task AS7: external providers and pseudonymization (option D, priority 2)
- [ ] Pseudonymizer: stable per-conversation placeholders for hostnames,
  agent IDs, and IP addresses in lookup results and user questions; mapped
  back when rendering. Default on for `data_location = "external"`.
- [ ] A documented generic OpenAI-compatible provider configuration, tested
  against the mock backend.
- [ ] Console notice for `external` backends (AS4 panel).

### Task AS8: documentation
- [ ] Component pages: `platform-assistant.md`, `openvibes-llm.md`, and the
  console's assistant section; `packaging.md` for the RPM; the operator
  guide "choosing where the model runs" (options A–D, hardware tiers, what
  data leaves the host) and "replacing the runtime or the model" (spec §10,
  checked with `assistant eval`).
