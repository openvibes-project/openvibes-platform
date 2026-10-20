# src/lists

Saved views and hidden columns of the list pages (roles spec §10): each person's own, per page. Needs a signed-in browser session; writes check CSRF. Pages are a fixed list in code (`hosts` first).

| File | What it does |
|---|---|
| `mod.rs` | The page list, the hideable column keys per page, and `routes()`: `GET/POST /v1/saved-views`, `DELETE /v1/saved-views/{id}`, `GET/PUT /v1/list-columns/{page}`. |
| `saved_views.rs` | The five handlers, their validation and their request and response types. |
