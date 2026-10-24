# src/http

The HTTP plumbing every area shares: how the routers are put together, the route table, the middleware, serving the web app, the error answers, and the OpenAPI document.

| File | What it does |
|---|---|
| `mod.rs` | The folder's modules and the router builders it exports. |
| `router.rs` | Builds the public, authenticated, development and health routers; `AuthHttpState`. |
| `routes.rs` | The route table: merges every area's `routes()`, adds the About routes, the unauthenticated session route, the auth routes and the API fallbacks. |
| `middleware.rs` | Body and concurrency limits, deadlines, logging, security headers, `Host` checks and the 421 page. |
| `misdirected.css` | The 421 page's stylesheet. |
| `frontend.rs` | Hashed assets, public files, the SPA entry document, and their not-found answers. |
| `assets.rs` | The web app's files embedded at build time (`embedded-ui`). |
| `frontend_contract.rs` | The browser routes and public files generated from `web/frontend-contract.json`. |
| `problem.rs` | Problem-details error answers and request IDs. |
| `error.rs` | `ConsoleError`, the server's startup and run errors. |
| `openapi.rs` | The OpenAPI document generated from the handlers and types. |
| `openapi_schemas.rs` | The document's schemas that no path names, merged into it by `openapi.rs`. |
| `headers.rs` | The no-store cache header and `If-Match` version parsing, for several areas. |
| `validate.rs` | UUID and agent-id checks on path segments, and the answer to a bad finding or vulnerability query, for several areas. |
| `pagination.rs` | Cursor pagination: the validated cursor and limit, the page type, the bounds. |

More: [docs/components/openvibes-console.md](../../../../docs/components/openvibes-console.md)
