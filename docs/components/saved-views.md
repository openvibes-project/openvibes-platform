# Saved views and list columns

`platform-store::saved_views` (schema 56) and `crates/openvibes-console/src/lists/`
keep two things per person and list page (roles spec §10): named saved views
(a URL query) and the columns the person hid. Pages are a fixed list in code
(`lists::PAGES`: `hosts`, `alarms`); hideable columns per page are in
`lists::hideable` (`hosts`: `os`, `groups`, `labels`, `problems`, `heartbeat`,
`agent`; `host` never; `alarms`: `alarm`, `host`, `count`, `seen`, `state`,
`assignee`, `case`; `severity` never).

## Interfaces

- `GET /api/v1/saved-views?page=hosts` returns `{items}` by name, ignoring case.
- `POST /api/v1/saved-views` `{page, name, query}` returns 201 with the view.
- `DELETE /api/v1/saved-views/{id}` returns 204.
- `GET /api/v1/list-columns/{page}` returns `{hidden}`.
- `PUT /api/v1/list-columns/{page}` `{hidden}` returns 200 with `{hidden}`.

All need a signed-in browser session (bearer tokens are refused); writes
need the CSRF token. Nothing needs a permission: each person sees only their
own rows.

## Failure behaviour

- Unknown page: 404 `list_page_not_found`.
- Name empty or over 60 characters, or query over 1000: 422
  `invalid_saved_view` with a field error on `name` or `query`.
- Same name again (any case): 409 `view_name_taken`; the 51st view on a
  page: 409 `too_many_views`.
- Deleting someone else's or an unknown id: 404 `saved_view_not_found`.
- Hiding `host`, an unknown or repeated key, or more than 32: 422
  `invalid_columns`.
- Database failure: the usual 503. Deleting a person deletes their rows.

## How to test

`cargo test -p platform-store --test saved_views` and
`cargo test -p openvibes-console --test saved_views_http` (need
`scripts/test-db.sh`).
