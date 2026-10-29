# platform-settings

The settings the console changes for the whole platform: each one's key,
section, wording, type, range, default and whether a change is live or needs
a restart. No database code and no I/O: the console checks a new value with
`Definition::check`, and a service that takes settings from the database
applies the same keys over its file, so both agree on what is valid.

## Interfaces

- `all()` (display order) and `find(key)`.
- `Definition { key, section, label, help, kind, applies }`; `Kind` is
  `Bool`, `Int { min, max, default }`, `Text { check, default }` or `Secret`;
  `Text` is `HttpsUrl`, `HttpsUrlOrEmpty` (empty turns a source off),
  `ProxyOrEmpty` or `Arch`. `Applies::Live` reaches the service within about
  a minute, `Applies::Restart` at its next start.
- `Definition::check(&Value) -> Result<(), String>` (the words for the
  field), `default_value()`, `is_secret()`, `kind_name()`.
- `vulns_keys::*`: the `vulns.*` key names the vulnerability service reads.

## Keys

Agent connections (`ingest.*`, 7 numbers: certificate lifetime, requests at
once, inventory deadline and uploads at once, findings kept, request
deadline, open connections) and Rule distribution (`distribution.*`, 3:
requests at once, request deadline, open connections) are all `Restart`:
the service reads them once at start. General (console reads them itself): `suppressions.require_approval`,
`sso.remove_inactive_days`. Vulnerability feeds (all live): check interval,
metalink URL, architecture, proxy, largest download (MiB), KEV, EPSS, NVD,
EUVD and OSV addresses, largest OSV download (MiB), and the NVD API key (a
secret, stored in `service_secrets`, never shown again). Text must be one
line without spaces; an address must be HTTPS (plain HTTP only on loopback) and may not carry a user name and password (the value is shown again and audited). A secret is trimmed by the console and may hold visible ASCII only (it goes into an HTTP header).

## How to test

`cargo test -p platform-settings`.
