# src/server

The console's listeners and serving them: direct TLS, the capped TCP and Unix listeners, the trusted reverse proxy, readiness and graceful shutdown.

| File | What it does |
|---|---|
| `mod.rs` | The folder's modules and its public names: `serve`, `run`, `TrustedPeer`. |
| `serve.rs` | Binds the configured listeners and serves the public and health routers; readiness, HSTS and graceful shutdown. |
| `listeners.rs` | The capped TCP (plain or TLS) and Unix socket listeners, their connection limits, and `TrustedPeer`. |
| `tls.rs` | Certificate and key loading, the TLS handshake, the redirect for plain http on the TLS port, the certificate's names. |
| `trusted_proxy.rs` | Behind a reverse proxy: only the trusted proxy may connect; the client address it forwards. |

More: [docs/components/openvibes-console.md](../../../../docs/components/openvibes-console.md)
