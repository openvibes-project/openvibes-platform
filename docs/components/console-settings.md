# Console settings

`crates/openvibes-console/src/settings/` serves the general settings
(roles spec §7). Storage is `platform-store::console_settings` (schema 54).

## Interfaces

- `GET /api/v1/settings` returns `{items, recent}`: each item has `key`,
  `section`, `label`, `help`, `kind` (`bool` or `int`), `min`/`max` (int),
  `default`, `value`, and `changed_at`/`changed_by` once changed; `recent`
  holds the last five changes (`at`, `actor`, `key`, `old`, `new`), newest
  first.
- `PATCH /api/v1/settings/{key}` with `{"value": …}` returns the item.

Both need `settings.manage` (Administrator only); the PATCH needs the CSRF
token. The definitions live in `definitions.rs`; a key with no stored row
has its default. Keys now: `suppressions.require_approval` (bool, false),
`sso.remove_inactive_days` (int 1 to 3650, 90).

## Failure behaviour

An unknown key is 404 `setting_not_found`. A wrong type or out-of-range
value is 422 `invalid_setting` with a field error on `value`; nothing is
stored. A database failure is the usual 503. Every change is audited as
`settings.changed` with the old and new value.

## How to test

`cargo test -p platform-store --test console_settings` and
`cargo test -p openvibes-console --test settings_http` (with
`OPENVIBES_TEST_DATABASE_URL`, see `scripts/test-db.sh`), plus the unit test
in `definitions.rs`.
