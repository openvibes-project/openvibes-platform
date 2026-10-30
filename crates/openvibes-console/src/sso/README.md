# src/sso

Single sign-on: the extra rules for the `sso.*` settings, the identity provider's pasted certificates, our side for the identity provider's administrator, and the sign-in itself.

| File | What it does |
|---|---|
| `mod.rs` | The module list and the route sets: `/api/v1/sso/service-provider`, `/auth/saml/metadata`, `/auth/saml/start`, `/auth/saml/acs` and `/auth/v1/sso`. |
| `certificates.rs` | Reads the pasted PEM certificates: fingerprint and dates, and refuses unreadable, expired, not yet valid or repeated ones; `current_bodies` lists the ones valid now for checking a response. |
| `change.rs` | The rules a change must also satisfy: certificates must parse, the switch needs the entity ID, address and a certificate, and those cannot be removed while it is on. |
| `provider.rs` | Builds the response checker from the stored settings on every request; gives none unless sign-in is on and complete. Only strong signature algorithms count. |
| `service_provider.rs` | Our entity ID, reply URL and the SAML metadata document. |
| `signin.rs` | The login page status, starting a sign-in and receiving the response: every check, role mapping, the session, and the audit reason for a refusal. |
| `tests.rs` | Unit tests for the above. |

More: [docs/components/console-sso.md](../../../../docs/components/console-sso.md), [docs/components/console-settings.md](../../../../docs/components/console-settings.md)
