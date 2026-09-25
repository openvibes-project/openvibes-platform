# OpenVIBES Console Design Plan

Status: approved by the owner on 2026-09-23; superseded in detail by `docs/specs/2026-09-23-console-product-design.md` and `-technical-design.md`. Moved here from the repository root.

## Goal

Define the first coherent product and technical design for `openvibes-console`:
the human-facing admin API and web UI described in the platform architecture.
The design must be implementable before ingest is complete by using stable API
contracts and seeded test data.

## Assumptions for the first pass

- Primary users are security analysts and platform operators in organisations
  with 1,000–50,000 managed hosts.
- The console is desktop-first and responsive down to tablet width; it is not
  a mobile administration app.
- Version 1 is read-heavy. Destructive or trust-changing actions require
  deliberate confirmation and are always audited.
- Human authentication and agent mTLS remain separate trust domains.
- PostgreSQL is accessed only through `platform-store`; browser clients never
  access it directly.
- The UI can be developed against a seeded database and a documented API while
  ingest, PKI, and agent management are built in parallel.

## Workstreams

1. Product and UX: operator jobs, information architecture, page hierarchy,
   core workflows, empty/loading/error states, accessibility, and visual tone.
2. API, RBAC, and data: browser/API boundary, endpoint resources, permissions,
   scopes, audit requirements, pagination/filtering, and schema gaps.
3. Implementation: frontend stack, Rust serving boundary, repository layout,
   testing, packaging, seeded development mode, and staged delivery plan.
4. Synthesis: reconcile the workstreams into one console specification,
   decision log, page-level wireframes, and an executable milestone plan.

## Deliverables

- `docs/specs/2026-09-23-console-product-design.md`
- `docs/specs/2026-09-23-console-technical-design.md`
- `docs/plans/2026-09-23-console-implementation.md`
- Cross-repository decisions appended to `../decisions.md` only for choices
  that are accepted as durable platform direction.

## Definition of done for this design pass

- Primary personas and their first-day workflows are explicit.
- Navigation and the first release's screen inventory are bounded.
- Every screen maps to API resources and an RBAC permission.
- Authentication modes and session/CSRF boundaries are specified.
- The frontend stack has a written rationale and deployment model.
- Loading, empty, unavailable, stale, and unauthorised states are designed.
- Accessibility, testing, observability, and security requirements are testable.
- Open product decisions are isolated in a short approval list.
