# src/sso

Single sign-on, first slice: the extra rules for the `sso.*` settings, the identity provider's pasted certificates, and our side for the identity provider's administrator. Signing in comes later.

| File | What it does |
|---|---|
| `mod.rs` | The module list and the two route sets: `/api/v1/sso/service-provider` and `/auth/saml/metadata`. |
| `certificates.rs` | Reads the pasted PEM certificates: fingerprint and dates, and refuses unreadable, expired, not yet valid or repeated ones. |
| `change.rs` | The rules a change must also satisfy: certificates must parse, the switch needs the entity ID, address and a certificate, and those cannot be removed while it is on. |
| `service_provider.rs` | Our entity ID, reply URL and the SAML metadata document. |
| `tests.rs` | Unit tests for the above. |

More: [docs/components/console-settings.md](../../../../docs/components/console-settings.md)
