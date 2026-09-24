# platform-agent-server

The agent-facing server shared by `openvibes-ingest` and
`openvibes-distribution`: TLS 1.3 with expiry-tolerant mTLS, agent
authentication, load controls, request logs, health, and the accept loop
with drain. Each service supplies only its routes and state.

## Interfaces

```rust
pub struct Settings { listen, health_listen, server_certificate_file, server_key_file,
    client_ca_file, database_url, max_in_flight, request_timeout_seconds,
    max_connections, database_pool_size }
impl Settings { pub fn validate(&self) -> Result<(), ServerError>; }
pub async fn run(settings: &Settings, listener: TcpListener, health: TcpListener,
                 app: impl FnOnce(Pool) -> Router, shutdown: impl Future<Output = ()>)
                 -> Result<(), ServerError>;
pub struct AuthenticatedAgent(pub String);  // extractor; needs Pool: FromRef<S>
pub enum ApiError { BadRequest, Unauthorized, Revoked, NotFound, Unavailable, Busy, Timeout }
pub enum ServerError { Config, Tls, Database, Listen }
pub const MAX_BODY_BYTES: usize;            // 1 MiB, the V1 document limit
pub fn parse<T: DeserializeOwned + Validate>(body: &[u8]) -> Result<T, ApiError>;
pub fn read_pem(path: &Path) -> Result<String, ServerError>;
```

`run` validates the settings, connects the pool, builds the TLS acceptor,
calls `app(pool)`, and wraps its routes in the body limit, the load controls,
and the request log. It then serves `/health` and `/ready` on the health
listener and accepts agent connections until `shutdown`, then drains.

## Configuration

`Settings` is not read from a file: each service maps its own TOML onto it
(`IngestConfig::settings`, `DistributionConfig::settings`). `validate`
requires absolute certificate and key paths, a loopback `health_listen`,
`max_in_flight >= 1`, `request_timeout_seconds` 1 to 300,
`max_connections` 1 to 65,536, and `database_pool_size` 1 to 1024.

## Failure behaviour

| Condition | Result |
|---|---|
| Client certificate from another CA | handshake failure |
| Expired or not-yet-valid certificate that otherwise chains | handshake passes; 401 (or 403 if revoked) |
| Unknown certificate, or none on an authenticated route | 401 |
| Revoked agent | 403 `{"schema_version":1,"code":"identity_revoked"}` |
| Declared or actual body over 1 MiB, malformed or invalid body | 400 |
| More than `max_in_flight` requests | 503 `busy` |
| Database unreachable or query failed | 503, one warning log line |
| Request (body included) past `request_timeout_seconds` | 408 |
| `ApiError::NotFound` from a handler | 404 |
| Peer accepts no response bytes for `request_timeout_seconds` | connection closed (a slow reader that keeps draining is served) |
| At startup: bad certificate/key file and bad database URL | the TLS error first: local files are checked before the database |

- Handshake and header reads share the request deadline; at most
  `max_connections` connections are open, the rest wait in the backlog;
  accept errors back off for 100 ms; sockets set `TCP_NODELAY`.
- Logs are one JSON line per request: `endpoint` (the matched route, or
  `other`: a raw path is never copied), `status`, `latency_ms`, and
  `agent_id` once authenticated.
- On `shutdown`, accepting stops, requests in flight finish (bounded by the
  deadline), and idle keep-alive connections close.
- `/health` is 200 while the process runs. `/ready` is 200 only when the
  database answers at the expected schema version.

## Test

`cargo test -p platform-agent-server` covers the log label and
`TCP_NODELAY`. The behaviour above is tested end to end through each
service's suite: `cargo test -p openvibes-ingest -p openvibes-distribution`
(needs `eval "$(scripts/test-db.sh)"`), `scripts/integration-agent.sh`, and
`scripts/load/run.sh`.
