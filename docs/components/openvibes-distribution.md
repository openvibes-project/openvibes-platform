# openvibes-distribution

Serves operator-published, offline-signed rule bundles to authenticated
agents. It cannot sign rules, and agents verify every bundle against their
own trusted keys, so the worst a compromised service can do is withhold
updates or serve bundles the agent refuses. Spec:
[`../specs/2026-09-24-distribution-subproject-design.md`](../specs/2026-09-24-distribution-subproject-design.md).
Built on [platform-agent-server](platform-agent-server.md); bundles are
published with `openvibes-admin rules publish` ([openvibes-admin.md](openvibes-admin.md)).

## Run

`openvibes-distribution [--config PATH]`, default
`/etc/openvibes/distribution.toml`. JSON logs on stderr. On SIGINT it stops
accepting, drains requests in flight, and exits.

## Interface

`POST /v1/rule-bundle` with a client certificate and a `RuleBundleRequest`
body (`schema_version`, `rule_set_id`, optional `current_version` ≥ 1).

| Condition | Response |
|---|---|
| `current_version` absent or below the current version | 200, `application/json`, the envelope exactly as published |
| `current_version` at or above the current version | 204, no body |
| Unknown or retired rule set, or nothing published yet | 404 |
| An assignable set (`hardening-linux-l1`, `-l2`) switched off on this agent's host (P20; [rule-set-assignment.md](rule-set-assignment.md)); checked after the 404 cases, also when the agent is current | 410, no body |
| Malformed, invalid, or oversized (> 1 MiB) body | 400 |
| No, unknown, or expired certificate | 401 (authentication runs before the body is parsed) |
| Revoked agent | 403 `identity_revoked` |
| Database unreachable, or `max_in_flight` reached | 503 |
| Certificate from another CA | TLS handshake failure |

Every request is one primary-key query ([platform-store.md](platform-store.md),
`rules::serve`), plus one indexed assignment lookup for a set that is
served (`rule_assignment::assigned`); the envelope bytes are read only for
a 200. There is no cache, and the service writes nothing, so replicas can sit behind an L4
load balancer.

## Configuration

```toml
listen = "0.0.0.0:18424"
health_listen = "127.0.0.1:18481"          # loopback only
server_certificate_file = "/etc/openvibes/tls/distribution.crt"
server_key_file = "/etc/openvibes/tls/distribution.key"
client_ca_file = "/etc/openvibes/pki/intermediate.crt"
database_url = "postgresql:///openvibes?host=/run/postgresql&user=openvibes-distribution"
max_in_flight = 4096            # default
request_timeout_seconds = 10    # default, 1 to 300
max_connections = 1024          # default, 1 to 65536
database_pool_size = 16         # default, 1 to 1024
```

Unknown keys, relative paths, a non-loopback `health_listen`, or
out-of-range values stop startup with "invalid distribution configuration".
The database role `openvibes-distribution` may only read `agents`,
`certificates`, `rule_sets`, `rule_bundles`, `schema_version`, `console_settings` (its own
settings, read at start), the
rule-set assignment tables, and the tag and selector columns that decide
group membership ([rule-set-assignment.md](rule-set-assignment.md)).

### Settings from the console

The numbers above (all but the paths, listeners, `database_url` and
`database_pool_size`) can also be set in the console under Settings ›
General › Rule distribution (`distribution.*` rows of `console_settings`, see
[platform-settings.md](platform-settings.md)). The service reads them once at
start, over the file, so a change applies at the next restart of the service
(Maintenance › Service in the admin tool). The file value is what applies for
anything nobody changed. If the settings cannot be read or are not valid the
service starts with the file alone and logs why. The database grant is read access to the whole `console_settings` table (not only this service's prefix); secrets live in a table the service cannot read. Tests:
`tests/console_settings.rs`.

## Failure behaviour

- Database down: requests get 503, `/ready` 503, `/health` stays 200; it
  recovers by itself when the database returns.
- Switching a set off answers 410 from the next request; the agent stops
  using its stored bundle and keeps its rollback floor (P20). Switching it
  on serves it again.
- Retiring a set answers 404 from the next request; agents keep evaluating
  the bundle they already accepted while it is valid.
- Logs are one line per request: `endpoint` (`/v1/rule-bundle` or
  `other`), `status`, `latency_ms`, `agent_id`. Rule set names, bodies, and
  envelopes are never logged.

## Test

`eval "$(scripts/test-db.sh)"; cargo test -p openvibes-distribution`:
- `bundle.rs`: 200 with exact bytes and content type, 204 (current and
  newer versions), 404 (unknown, no bundle, retired), 400 cases;
- `assignment.rs`: 410 when off (also when current), on wins across groups,
  group deletion falls back, unpublished or retired stays 404, other sets
  unchanged;
- `auth.rs`: revoked 403, unknown and expired 401, no certificate 401 even
  with a malformed body, foreign CA handshake failure;
- `limits.rs`: oversized body, database outage and readiness, in-flight
  limit, strict configuration;
- `logging.rs`: log fields, no secrets;
- `protocol_fixtures.rs`: every `rule-bundle-request` fixture, and every
  valid `signed-rule-envelope` fixture served byte for byte through the
  agent's own transport.
