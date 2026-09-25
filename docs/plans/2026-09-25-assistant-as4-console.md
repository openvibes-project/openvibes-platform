# AS4: Assistant in the Console — Implementation Plan (Codex)

> **For agentic workers:** superpowers:executing-plans (native). Steps use checkboxes.

**Goal:** the chat panel inside the console: an authorised analyst asks a
question, sees the answer stream in, and follows its citations to the
agents and findings it is based on. Every lookup runs with the analyst's
own permissions and scope.

**Owner:** Codex (`openvibes-console`, its UI, and its `platform-store`
additions). **Reviewer:** Claude Code (owner of `platform-assistant`).

**Spec:** `docs/specs/2026-09-25-assistant-design.md` §2, §4, §6, §7, §9;
console product design §15 and technical design decision 18 (fleet
grouping, on `console-current`).

## Preconditions

- AS1–AS3 merged: `platform-assistant` (configuration, `BackendClient`,
  `probe`, `answer`, `StoreLookups`, `sanitize`, `Segment`, `Citation`) and
  `platform_store::assistant` (scoped lookups taking `AgentScope`).
- Console C3: sessions, CSRF, the permission registry, asset-group scope
  resolution, and the audit contract (technical design §7, §8, §10). AS4
  adds no authentication of its own.
- Rebase the console branch on `main` first; the next free migration number
  is checked at that point (`main` is at 0011 today).

## What `platform-assistant` gives you

```rust
// Startup (once): configuration and the backend.
let assistant = config.assistant.validate()?;              // AssistantConfig -> Assistant
let backend = assistant.backend.clone();                   // Some when configured
let client = Arc::new(BackendClient::new(&backend)?);
let report = probe(&client, assistant.lookup_mode);        // blocking: spawn_blocking
// Per question:
let settings = Settings::new(&assistant, &backend, report.selected, Utc::now());
let lookups = StoreLookups::new(pool.clone(), scope, settings.now);  // AgentScope of the user
let answer = answer(client.clone(), &lookups, settings, &history, question, Some(&events)).await?;
// answer.segments: Vec<Segment> (Text | Cite(Citation)); answer.lookups: Vec<LookupRecord>
```

`answer` is async and runs the blocking client on the blocking pool; it
never needs the console's database role beyond the reads in
`platform_store::assistant` and `rules::serve`. `history` is the
conversation so far as `Turn { question, answer: plain_text(&segments) }`.
Events are `Lookup(name)`, `Text(piece)` (native mode only), and `Reset`.

## Global Constraints

- **Permission** `assistant.use` (new `Permission` variant, registry entry,
  in no default role). The panel does not render without it; every route
  answers 403 and audits `authorization.denied`.
- **Scope:** resolve the session's scope for `findings.read` and
  `agents.read` to `AgentScope` at each question (`Global` → `All`,
  asset groups → `Only(agent IDs)`), never cached across questions. A user
  who lacks either read permission cannot use the assistant.
- **Off by default:** without `[assistant] enabled = true` the routes answer
  404 and nothing connects to a backend.
- **The console never forwards client input to the backend** except the
  question text; every request is built by `platform-assistant`.
- **Rendering is text-only:** `Segment::Text` becomes text nodes
  (`white-space: pre-wrap`), never HTML; `Segment::Cite` becomes a console
  link the console builds. Streamed `Text` pieces are shown as plain text
  and replaced by the final segments. A lint rule forbids
  `dangerouslySetInnerHTML` in the assistant components.
- **Migrations are append-only**, numbered at implementation start; all SQL
  in `platform-store`, in its own commit, merged first.

## Review Focus

- A user scoped to asset group A never receives, in lookups, counts, or
  citations, anything from an agent outside A (integration test with two
  users and a scripted backend that asks for everything).
- Conversations are private: another user's conversation ID answers 404,
  including for delete and stream routes.
- Hostile model output (HTML, `javascript:` text, Markdown images, forged
  citations) renders inert (web unit test on `Segment` rendering).
- The backend being down at startup does not stop the console; the panel
  shows "unavailable" and the status recovers without a restart.

### Task AS4a: conversation storage (`platform-store`, separate commit)
- [ ] Migration: `assistant_conversations` (`id uuid`, `principal_id`,
  `title` = first question cut to 120 characters, `created_at`,
  `updated_at`) and `assistant_messages` (`conversation_id`, `seq`,
  `question`, `answer_segments jsonb` or `error_code`, `lookups jsonb`
  (the `LookupRecord`s: name, validated arguments, object count, error),
  `prompt_tokens`, `completion_tokens`, `created_at`); `ON DELETE CASCADE`;
  index on (`principal_id`, `updated_at DESC`). Grants to `openvibes_console`
  only.
- [ ] `platform_store::assistant_conversations`: create, list own (keyset on
  `updated_at DESC, id`), load own with messages (at most the last 50),
  append message, delete own, count own questions in the last hour (rate
  limit), and delete conversations with `updated_at` older than the
  retention (for maintenance). Every function takes the principal ID and
  filters by it. Tests first, including another principal's ID.
- [ ] `openvibes-admin maintenance` also applies the conversation retention
  (`conversation_retention_days`, default 30) in bounded batches.

### Task AS4b: configuration and runtime state (`openvibes-console`)
- [ ] `ConsoleConfig` gains `assistant: Option<AssistantConfig>` (it denies
  unknown fields today, so this is required); validated at startup, and an
  invalid section fails startup like any configuration error.
- [ ] An `AssistantRuntime` in the router state: the checked `Assistant`,
  the `BackendClient`, the probe result (mode, availability), a semaphore
  of `backend.concurrency`, and the set of principals with a question in
  flight. The probe runs at startup in the background and again every 5
  minutes while unavailable; the console never waits for it.
- [ ] With `openvibes-llm` (AS5), the console unit gets the backend key as a
  credential, `LoadCredential=llm-api-key:/etc/openvibes/llm-api-key`, and
  `api_key_file = "/run/credentials/openvibes-console.service/llm-api-key"`.
  The key file stays root's (docs/components/openvibes-llm.md).
- [ ] Tests: disabled → routes 404 and no connection attempt (mock backend
  records none); invalid section → startup error; backend down → status
  `unavailable`, then `available` after the mock starts.

### Task AS4c: API routes, rate limits, and audit
- [ ] Routes (OpenAPI via `utoipa`, generated client regenerated):
  - `GET /api/v1/assistant/status` → `{ available, location, model,
    notice }`; `notice` is set for `own_network` ("Answers are generated on
    a server on your network") and `external` ("Answers are generated on an
    external service").
  - `GET /api/v1/assistant/conversations` (own, cursor pagination),
    `POST` (create), `GET /{id}` (with messages), `DELETE /{id}`.
  - `POST /api/v1/assistant/conversations/{id}/messages` with
    `{ question, context? }` (CSRF, `Idempotency-Key`). `context` is
    `{ kind: "finding" | "agent", id }`; it is checked in scope (404
    otherwise) and prepended to the question as a visible line ("About
    finding baseline/ssh.exposed:").
  - The response is `text/event-stream` read with `fetch`: `lookup {name}`,
    `text {piece}`, `reset`, then `done {message}` (the stored message with
    segments) or `error {code}`. If the browser disconnects, the answer
    still completes (bounded by its deadline) and is stored.
- [ ] Limits: one question in flight per principal (409
  `assistant_busy`), `questions_per_user_per_hour` counted in the database
  (429 with `Retry-After`), the global semaphore (queue position in
  `status`), question length 2,000 characters (422).
- [ ] Errors map `AnswerError` to stable codes: `question_too_long`,
  `backend_unavailable`, `backend_timeout`, `no_answer`; no backend text is
  ever returned.
- [ ] Audit (technical design §10): `assistant.question.asked` (target: the
  conversation; detail: question cut to 2,000 characters, lookup names with
  validated arguments and object counts, backend location and model,
  outcome code) and `assistant.conversation.deleted`. Answer text is never
  audited. The message row and its audit event commit together.
- [ ] Tests (scripted `ChatBackend` + real `StoreLookups` on the test
  database): the Review Focus cases, 403 without `assistant.use` (audited),
  CSRF required, 409, 429, the stream event order, error codes, audit
  rows.

### Task AS4d: the chat panel (web)
- [ ] A side panel opened from the header ("Ask") and from finding-group and
  agent detail ("Ask about this", which sets `context`); hidden without
  `assistant.use` or when the assistant is disabled.
- [ ] Conversation list (own) with delete; message view; composer with a
  2,000-character counter; `aria-live="polite"` for the streaming answer.
- [ ] Rendering: `Text` as text; `Cite` as links: agent → agent detail,
  finding → finding-group detail (decision 18), advisory → plain label until
  the console has a vulnerability page. Each answer is labelled "AI draft —
  check the linked records" and never uses "resolved" or "compliant" in
  the console's own wording.
- [ ] "Looked up:" disclosure listing the lookups each answer used.
- [ ] States: unavailable, busy, rate limited (with retry time), deadline,
  and error codes, each with a plain message; location notice for
  `own_network` and `external`.
- [ ] Web unit tests: hostile segments render inert; citations route
  correctly; state messages.

### Task AS4e: end to end and documentation
- [ ] Playwright: the console with a scripted OpenAI-compatible mock backend
  (fixed replies: a lookup, then an answer citing an agent); ask, see
  streaming, follow the citation, reload and see the stored conversation,
  delete it.
- [ ] Docs: `openvibes-console.md` (routes, permission, states, audit
  events), the operator guide's "enable the assistant" steps
  (`assistant check`, `assistant eval`, then `enabled = true`), and the
  product design's page inventory.
