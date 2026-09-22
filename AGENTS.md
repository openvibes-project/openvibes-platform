# AGENTS.md

Guidance for AI coding agents working in this repository.

Cross-repo status, decisions, and the handover routine shared by all AI tools live outside this repository in `../AGENTS.md`, `../status.md`, and `../decisions.md` (local only, never pushed). Read them at the start of a session.

No platform code exists yet. The platform is planned as separate modules: a
receive-only collector service (agents connect on port 18423), a rule
distribution service, correlation, third-party/CMDB sync, and a web interface
on 443. Everything exchanged with agents is specified in the
`openvibes-protocol` repository; build against its schemas and fixtures.
