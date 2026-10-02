# openvibes-signer

The rule signer (board #107; own rules, `docs/specs/2026-10-02-own-rules-design.md`
§4 and §9). It holds the **site key** and signs the site's own rule sets,
`site` (findings rules) and `site-alarms` (alarm rules), for the console.
It signs only after checking the publishing user's password and
permission **itself**, so a compromised console can't sign without a live
password.

## Interface

- **Socket:** a Unix socket (`socket`, mode 0660, group
  `openvibes-signer-clients`). **Two local accounts** are in that group:
  `openvibes-console` (the console's publish screen, board #109) and
  `openvibes-admin` (`openvibes-admin rules publish-site`, for scripts and
  for testing the chain before the console screen exists). That is fine
  because the group isn't the boundary: every request still needs a
  console user's live password, `rules.upload` through a global binding,
  and the signer's limits, and wrong passwords lock the account as at
  sign-in (lead, #2110).
- **Request:** one JSON object per connection, at most 1 MiB, all of it
  within 5 seconds, then the client shuts its write side:

  ```json
  {"username": "alice", "password": "…", "rule_set": "site-alarms", "rules": "<rule set JSON>"}
  ```

- **Answer:** `{"result":"signed","envelope":"…","version":7,"expires_at_unix_ms":…}`,
  or `{"result":"refused","code":"…"}`. The codes are fixed and never
  echo input:

  | Code | Meaning |
  |---|---|
  | `credentials` | unknown user, wrong password or disabled account: one answer, after the same Argon2id work (a dummy credential for unknown names) |
  | `throttled` | the account is locked: the same per-account bucket and limit (5 in 15 minutes) as console sign-in |
  | `forbidden` | the account must change its password, or lacks `rules.upload` through a global role binding |
  | `limits` | more than `rules_per_publish` rules, or an alarm rule naming more than 8 distinct `programs`, or a set naming more than 32 |
  | `invalid` | not a valid request or rule set: a `site` set with alarm rules, a `site-alarms` rule without `programs`, a rule the agent's loader or compiler refuses |
  | `rate` | more than `publishes_per_hour` signed publishes in the last hour, all users together |
  | `version_state` | no version state (Setup seeds it): the signer won't guess a version |
  | `unavailable` | the database or the state directory can't be used |

- **CLI:** `openvibes-signer [--config PATH]` serves. `openvibes-signer seed
<<<<<<< HEAD
  --min-version N` creates the version state so the next version signed is
  `N`, keeps a readable one (seeding never lowers a version), and replaces
  one it can't read (corrupt, or missing a set), saying so.
=======
  --min-version N` creates the site key (0600) if it's missing and the
  version state so the next version signed is `N`, keeps an existing state
  (seeding never lowers a version), and prints the agents' trust lines
  (`site site.key KEY`, `site-alarms site.key KEY`). Setup runs it as the
  signer's user; packaging and the unit are in
  [packaging.md](packaging.md).
>>>>>>> 0e14fe9 (openvibes-signer: RPM, unit and Setup (board #107, part B1))

## Configuration

`/etc/openvibes/signer.toml`:

| Key | Default | Meaning |
|---|---|---|
| `socket` | (required) | the Unix socket |
| `database_url` | (required) | PostgreSQL as the `openvibes-signer` role |
| `key_file` | (required) | the site key: 32 bytes, mode 0600 |
| `issuer_key_id` | (required) | the issuer id agents trust the key under |
| `state_dir` | (required) | `versions.json`, the last signed rules per set, `status.json` |
| `publishes_per_hour` | 12 | 1 to 1,000 |
| `rules_per_publish` | 200 | 1 to 10,000 |
| `validity_days` | 365 | 1 to 3,650; Health warns 30 days before expiry (Setup and Health: board #107 part B) |

## What it may touch

- **Database** (migration 32, role `openvibes-signer`): read `console_users`
  (`user_id`, `username`, `enabled`, `password_must_change`),
  `console_credentials` (`user_id`, `password_phc`, `must_change`),
  `console_role_bindings` (`user_id`, `role_id`, `asset_group_id`,
  `revoked_at`) and `console_role_permissions`; read and write
  `console_auth_throttle`. Nothing else, and no `audit_log` rows.
- **Audit:** one JSON line per request on stderr (the journal):
  `{"audit":"rules.sign","user":…,"rule_set":…,"result":"signed"|code}`, and
  for a signature its `version`, `rules` and `sha256`. Never the rules or
  the password.
- **Versions:** it always signs the set's last version + 1, and writes the
  new version and the signed rules to `state_dir` (temp file, fsync,
  rename) before handing the envelope out, so a console can't roll a set
  back and a version is never signed twice. One lock covers the rate
  check, the version, the signature and its record, so two publishes at
  once get consecutive versions and can't both pass the hourly limit.
- **`status.json`** (0640, for the admin Health screen): whether version
  state exists, each set's last version and expiry, publishes in the last
  hour, and refusals by code in the last day (counted in hourly buckets,
  so memory stays bounded however many requests arrive). Written
  atomically, at most once a second (a signature at once; the rest on a
  one-second tick), so a flood of bad requests causes no fsync storm.

## Failure behaviour

- At most 2 password checks at once (each Argon2id takes ~19 MiB); more
  wait. At most 8 connections at once; more are closed unread. A
  connection that doesn't send its whole request within 5 seconds gets
  `invalid`.
- The password stays in a redacting, zeroizing wrapper; the request body
  is cleared after use and never logged, also on `invalid`.
- A wrong key file (not 32 bytes, or readable by group or others) stops
  the service at start.
- A refused envelope is never returned: the signer proves the agent's
  loader accepts it and every alarm rule compiles first.

## Tests

`cargo test -p openvibes-signer` with `eval "$(scripts/test-db.sh)"`. The
tests connect **as the `openvibes-signer` role**, so the grants are what's
tested (removing one fails them): signing at the next version and after a
restart, every refusal code, the lock after 5 wrong passwords, no version
state, the hourly limit, the socket's mode, one request over it, and a slow
body cut at the timeout, two concurrent publishes getting consecutive
versions (the old ordering gives both the same, and fails it), the
connection cap, and `seed` keeping a readable state and replacing a
corrupt one.
