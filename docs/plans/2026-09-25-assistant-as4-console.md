# AS4: Console Local Assistant

Owner: Codex (`openvibes-console` and its UI). The project owner approved the
current scope on 2026-09-26 in
[`../specs/2026-09-26-console-local-assistant-design.md`](../specs/2026-09-26-console-local-assistant-design.md).
It supersedes the initial assistant design's third-party provider,
persisted-history, and streaming choices for this first console release.

## Scope

- Opt-in local or private-network OpenAI-compatible model; no vendor cloud.
- `assistant.use`, plus the caller's matching `agents.read` and
  `findings.read` scopes on each question.
- Agent and finding lookups only. Do not expose the assistant library's
  vulnerability or rule lookups until the console has corresponding read
  models and permissions.
- Plain-text responses with verified citations rendered as internal links.
- Browser-tab-only history, cleared on reload, sign-out, or New chat.
- No conversation database migration, write tools, arbitrary SQL, commands,
  external URLs, or prompt/answer logging.

## Implementation checklist

- [x] Import the assistant core and SQL-scoped read lookup support.
- [x] Add strict opt-in config; refuse external endpoints, DNS hostnames, and
  outbound proxies; permit loopback or HTTPS to a private literal IP.
- [x] Add the assistant capability, authenticated status/message routes,
  scoped lookup gate, concurrency limits, bounded inputs, 30-second deadline,
  and metadata-only audit record.
- [x] Add the Assistant page with a local-model notice, in-memory conversation,
  text-only rendering, citations, lookup disclosure, stop, and reset controls.
- [x] Generate the OpenAPI snapshot and TypeScript client.
- [x] Add component/operator documentation and complete source-level security
  review; adversarial checks remain.
- [ ] Manual browser verification and project acceptance review.

## Review focus

- Scoped asset group membership is resolved before assistant queries and the
  store applies that ID set to every lookup.
- The model can request only read lookups; unsupported lookup names return a
  fixed refusal and never touch vulnerability or rule tables.
- Untrusted prompt and host fields stay inert; model answers are sanitized by
  `platform-assistant`, rendered as React text, and citations are created by
  the server from verified returned objects.
- Configuration, request logs, and audit rows never disclose API keys,
  prompts, answers, or retrieved records.
- Disabled mode does not construct a client, probe a model, expose a
  navigation item, or register assistant routes in the authenticated router.
