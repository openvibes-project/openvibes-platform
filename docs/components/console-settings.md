# Console settings

`crates/openvibes-console/src/settings/` serves the general settings
(roles spec §7). Storage is `platform-store::console_settings` (schema 54).

## Interfaces

- `GET /api/v1/settings` returns `{items, recent}`: each item has `key`,
  `section`, `label`, `help`, `kind` (`bool`, `int`, `text`, `choice` or `secret`),
  `applies` (`live` or `restart`), `min`/`max` (int), `options` (choice: the allowed words), `default`, `value`
  (null for a secret), `is_set` (secrets only) and `changed_at`/`changed_by`
  once changed; `recent`
  holds the last five changes (`at`, `actor`, `key`, `old`, `new`), newest
  first.
- `PATCH /api/v1/settings/{key}` with `{"value": …}` returns the item. A
  `null` value puts the setting back to its default (a secret: removes it).
  A secret goes to `service_secrets` (the assistant's API key, `assistant.backend.api_key`, to `console_secrets`), is never returned, and the audit line
  says only `set` or `not set`.

Both need `settings.manage` (Administrator only); the PATCH needs the CSRF
token. The definitions live in the `platform-settings` crate
([platform-settings.md](platform-settings.md)) so the services check the
same rules; a key with no stored row has its default. Keys: the two general
one (`suppressions.require_approval`), the eight single sign-on ones
(`sso.*`: on/off, the identity provider's entity ID, sign-in address and
signing certificates, three attribute names, and `sso.remove_inactive_days`)
and the
twelve `vulns.*` feed settings, which the vulnerability service applies over
its file within about a minute ([openvibes-vulns.md](openvibes-vulns.md)), the
ingest and distribution ones (applied at their next restart) and the fifteen
`assistant.*` ones, which the console reads once at start over `[assistant]`
of `console.toml`; settings that fail the assistant's own rules together leave
the assistant off, with a log line ([console-assistant.md](console-assistant.md)).

## Single sign-on settings

Setting `sso.enabled` to true is refused until the entity ID, the sign-in
address and at least one certificate are stored, and those three cannot be
removed or emptied while it is on. `sso.idp_certificates` holds up to three
PEM certificates; each must parse, be valid now and differ from the others,
and the list shows each one's SHA-256 fingerprint and expiry. Our side is
`GET /api/v1/sso/service-provider` (needs `settings.manage`: entity ID, reply
URL, metadata URL) and `GET /auth/saml/metadata`, the SAML 2.0 service
provider metadata (HTTP-POST binding, persistent NameID), which needs no
session. Signing in with the identity provider is not part of this slice.

## Failure behaviour

An unknown key is 404 `setting_not_found`. A wrong type or out-of-range
value is 422 `invalid_setting` with a field error on `value`; nothing is
stored. A database failure is the usual 503. Every change is audited as
`settings.changed` with the old and new value.

## How to test

`cargo test -p platform-store --test console_settings` and
`cargo test -p openvibes-console --test settings_http` (with
`OPENVIBES_TEST_DATABASE_URL`, see `scripts/test-db.sh`), plus
`cargo test -p platform-settings`.
